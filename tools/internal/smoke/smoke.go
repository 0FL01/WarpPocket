package smoke

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Identity is obtained from a retained native process handle, not a report or
// an executable-name match. Created is the OS creation-time counter.
type Identity struct {
	PID       int
	ParentPID int
	Image     string
	Created   uint64
}

type Process interface {
	PID() int
	Exited(time.Duration) (bool, error)
	ExitCode() (uint32, error)
	Identity() (Identity, error)
	Terminate() error
	Close() error
}

// Launch retains the safety job and the original GUI process handle. Closing
// the job or terminating it is never part of the ownership proof itself.
type Launch interface {
	GUI() Process
	Contains(Process) (bool, error)
	Empty() (bool, error)
	WorkingSets() ([]ProcessMemory, error)
	TerminateJob() error
	Close() error
}

// Platform is injectable so all report/orchestration assertions run on Linux.
// Launch must contain a suspended process before allowing any application code
// to execute. OpenProcess must grant query/synchronize rights, not termination.
type Platform interface {
	Launch(argv []string, cwd string) (Launch, error)
	OpenProcess(pid int) (Process, error)
}

type Timeouts struct {
	Graceful time.Duration
	Report   time.Duration
	GUI      time.Duration
	Child    time.Duration
	Port     time.Duration
	Cleanup  time.Duration
	Poll     time.Duration
}

func DefaultTimeouts() Timeouts {
	return Timeouts{180 * time.Second, 120 * time.Second, 30 * time.Second,
		30 * time.Second, 30 * time.Second, 10 * time.Second, 100 * time.Millisecond}
}

type Options struct {
	Executable string
	Output     string
	SourceRoot string
	// TempDir is only the parent for a newly created, driver-owned cwd.
	TempDir  string
	Timeouts Timeouts
	Platform Platform
	PortOpen func(context.Context, int) (bool, error)
}

type ProcessMemory struct {
	PID             int    `json:"pid"`
	Role            string `json:"role"`
	WorkingSetBytes uint64 `json:"working_set_bytes"`
}

type Footprint struct {
	// Measured from immediately before native launch until the valid wait-mode
	// report is observed. It includes actual Gio frames and engine SOCKS startup.
	StartToReadyMS       float64         `json:"start_to_ready_ms"`
	OwnedWorkingSetBytes uint64          `json:"owned_working_set_bytes"`
	Processes            []ProcessMemory `json:"processes"`
}

type Phase struct {
	OK                 bool            `json:"ok"`
	ReportedOK         bool            `json:"reported_ok"`
	PID                int             `json:"pid"`
	ChildPID           int             `json:"child_pid,omitempty"`
	Port               int             `json:"port,omitempty"`
	Checks             map[string]bool `json:"checks"`
	ReportAfterMS      float64         `json:"report_after_ms"`
	ExitCode           *uint32         `json:"exit_code,omitempty"`
	GUIAlive           bool            `json:"gui_alive,omitempty"`
	EngineAlive        bool            `json:"engine_alive,omitempty"`
	GUIOnlyTermination bool            `json:"gui_only_termination,omitempty"`
	EngineStopped      bool            `json:"engine_stopped,omitempty"`
	PortClosed         bool            `json:"port_closed,omitempty"`
	AllOwnedStopped    bool            `json:"all_owned_stopped"`
}

type Cleanup struct {
	OK         bool     `json:"ok"`
	ErrorCodes []string `json:"error_codes"`
}

// Summary is an allowlisted payload: no paths, arguments, raw application
// errors, environment, profile content, or process output are included.
type Summary struct {
	SchemaVersion   int        `json:"schema_version"`
	OK              bool       `json:"ok"`
	ExecutableBytes int64      `json:"executable_bytes"`
	Graceful        *Phase     `json:"graceful"`
	ForcedKill      *Phase     `json:"forced_kill"`
	Footprint       *Footprint `json:"footprint"`
	ErrorCode       *string    `json:"error_code"`
	Cleanup         Cleanup    `json:"cleanup"`
}

func (s Summary) ExitStatus() int {
	if s.OK {
		return 0
	}
	if s.ErrorCode != nil && (*s.ErrorCode == "windows_required" || *s.ErrorCode == "windows_amd64_required") {
		return 2
	}
	return 1
}

type driver struct {
	options    Options
	summary    Summary
	files      *outputFiles
	copied     string
	cwd        string
	launches   []Launch
	handles    []Process
	workspaces []string
}

// Run executes graceful and forced-GUI-exit phases and always attempts a safe,
// atomic summary.json. Native ownership proof is Windows-only; fakes are portable.
func Run(ctx context.Context, options Options) Summary {
	d := &driver{options: options, summary: Summary{
		SchemaVersion: 2, Cleanup: Cleanup{OK: true, ErrorCodes: []string{}},
	}}
	if d.options.Timeouts == (Timeouts{}) {
		d.options.Timeouts = DefaultTimeouts()
	}
	if d.options.PortOpen == nil {
		d.options.PortOpen = PortOpen
	}
	err := d.run(ctx)
	if err != nil {
		code := safeCode(err)
		d.summary.ErrorCode = &code
	} else {
		d.summary.OK = true
	}
	// Persist a failed proof BEFORE any safety-job cleanup. A worker killed by
	// emergency cleanup can never retroactively make the proof pass.
	if !d.summary.OK && d.files != nil {
		_ = d.files.writeSummary(d.summary)
	}
	d.cleanup()
	if d.files != nil {
		if err := d.files.writeSummary(d.summary); err != nil {
			d.summary.OK = false
			code := "summary_write_failed"
			d.summary.ErrorCode = &code
		}
		_ = d.files.root.Close()
	}
	return d.summary
}

func (d *driver) run(ctx context.Context) error {
	var err error
	d.files, err = openOutput(d.options.Output)
	if err != nil {
		return err
	}
	if err = d.files.removeStale("summary.json"); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if d.options.Timeouts.Poll <= 0 || d.options.Timeouts.Graceful < 0 ||
		d.options.Timeouts.Report < 0 || d.options.Timeouts.GUI < 0 ||
		d.options.Timeouts.Child < 0 || d.options.Timeouts.Port < 0 || d.options.Timeouts.Cleanup < 0 {
		return failure("timeouts_invalid")
	}
	if d.options.Platform == nil {
		d.options.Platform, err = newNativePlatform()
		if err != nil {
			return err
		}
	}
	d.copied, d.summary.ExecutableBytes, err = d.files.copyExecutable(d.options.Executable)
	if err != nil {
		return err
	}
	source := d.options.SourceRoot
	if source == "" {
		source, err = sourceRoot()
		if err != nil {
			return err
		}
	}
	source, err = filepath.Abs(source)
	if err == nil {
		source, err = filepath.EvalSymlinks(source)
	}
	if err != nil {
		return failure("source_root_invalid")
	}
	d.cwd, err = os.MkdirTemp(d.options.TempDir, "warppocket-smoke-cwd-")
	if err != nil {
		return failure("working_directory_create_failed")
	}
	canonicalCWD, err := filepath.EvalSymlinks(d.cwd)
	if err != nil {
		return failure("working_directory_invalid")
	}
	d.cwd = canonicalCWD
	if contained(source, d.cwd) {
		return failure("working_directory_inside_source")
	}
	for _, mode := range []string{"graceful", "wait"} {
		if err := d.phase(ctx, mode); err != nil {
			return err
		}
	}
	return nil
}

func (d *driver) phase(ctx context.Context, mode string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name, option := "graceful.json", "--smoke"
	if mode == "wait" {
		name, option = "wait.json", "--smoke-wait"
	}
	if err := d.files.removeStale(name); err != nil {
		return err
	}
	existingWorkspaces, err := d.files.runtimeNames()
	if err != nil {
		return err
	}
	stamp, err := d.files.filesystemTimestamp()
	if err != nil {
		return err
	}
	started := time.Now()
	launch, err := d.options.Platform.Launch([]string{d.copied, option, filepath.Join(d.files.path, name)}, d.cwd)
	if err != nil {
		return err
	}
	d.launches = append(d.launches, launch)
	gui := launch.GUI() // Retained CreateProcessW handle; never reopen report.pid.
	phase := &Phase{PID: gui.PID(), Checks: map[string]bool{}}
	if mode == "graceful" {
		d.summary.Graceful = phase
	} else {
		d.summary.ForcedKill = phase
	}
	if gui.PID() <= 0 || gui.PID() == os.Getpid() {
		return failure("process_identity_invalid")
	}
	if mode == "graceful" {
		exited, err := d.waitExit(ctx, gui, d.options.Timeouts.Graceful)
		if err != nil {
			return err
		}
		if !exited {
			return failure("graceful_timeout")
		}
		code, err := gui.ExitCode()
		if err != nil {
			return err
		}
		phase.ExitCode = &code
	}
	report, err := d.waitReport(ctx, name, mode, stamp, gui)
	if err != nil {
		return err
	}
	phase.ReportAfterMS = float64(time.Since(started)) / float64(time.Millisecond)
	phase.ReportedOK, phase.Checks = report.OK, report.Checks
	if report.PID != gui.PID() || report.ChildPID == gui.PID() || report.ChildPID == os.Getpid() {
		return failure("process_identity_invalid")
	}
	workspaceName, err := d.files.workspaceName(report.Workspace)
	if err != nil {
		return err
	}
	if existingWorkspaces[strings.ToLower(workspaceName)] {
		return failure("workspace_not_new")
	}
	// Only a schema/containment/GUI-identity validated report can enroll cleanup.
	d.workspaces = append(d.workspaces, report.Workspace)
	if err := report.requireSuccess(); err != nil {
		return err
	}
	phase.ChildPID, phase.Port = report.ChildPID, report.Port
	if mode == "graceful" {
		if *phase.ExitCode != 0 {
			return failure("graceful_exit_nonzero")
		}
	} else if err := d.forcedExit(ctx, launch, gui, report, phase); err != nil {
		return err
	}
	empty, err := eventually(ctx, d.options.Timeouts.Child, d.options.Timeouts.Poll, launch.Empty)
	if err != nil {
		return err
	}
	phase.AllOwnedStopped = empty
	if !empty {
		return failure("owned_processes_remain")
	}
	phase.OK = true
	return nil
}

func (d *driver) forcedExit(ctx context.Context, launch Launch, gui Process, report Report, phase *Phase) error {
	child, err := d.options.Platform.OpenProcess(report.ChildPID)
	if err != nil {
		return err
	}
	d.handles = append(d.handles, child) // Keep query/sync handle through the proof.
	for _, process := range []Process{gui, child} {
		member, err := launch.Contains(process)
		if err != nil {
			return err
		}
		if !member {
			return failure("process_not_owned")
		}
	}
	guiID, err := gui.Identity()
	if err != nil {
		return err
	}
	childID, err := child.Identity()
	if err != nil {
		return err
	}
	if guiID.PID != gui.PID() || child.PID() != report.ChildPID || childID.PID != report.ChildPID ||
		guiID.Created == 0 || childID.Created < guiID.Created || childID.ParentPID != gui.PID() ||
		!sameImage(guiID.Image, d.copied) || !sameImage(childID.Image, d.copied) {
		return failure("process_identity_invalid")
	}
	for index, process := range []Process{gui, child} {
		exited, err := process.Exited(0)
		if err != nil {
			return err
		}
		if exited {
			return failure("wait_process_not_live")
		}
		if index == 0 {
			phase.GUIAlive = true
		} else {
			phase.EngineAlive = true
		}
	}
	open, err := d.options.PortOpen(ctx, report.Port)
	if err != nil {
		return err
	}
	if !open {
		return failure("socks_not_listening")
	}
	if err := d.footprint(launch, gui.PID(), child.PID(), phase.ReportAfterMS); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// THE TEST: only the original GUI handle. No job/tree/helper termination,
	// handle closure, or safety-job action is allowed until assertions finish.
	if err := gui.Terminate(); err != nil {
		return err
	}
	phase.GUIOnlyTermination = true
	exited, err := d.waitExit(ctx, gui, d.options.Timeouts.GUI)
	if err != nil {
		return err
	}
	if !exited {
		return failure("gui_exit_timeout")
	}
	code, err := gui.ExitCode()
	if err != nil {
		return err
	}
	phase.ExitCode = &code
	phase.EngineStopped, err = d.waitExit(ctx, child, d.options.Timeouts.Child)
	if err != nil {
		return err
	}
	if !phase.EngineStopped {
		return failure("engine_survived_gui")
	}
	phase.PortClosed, err = eventually(ctx, d.options.Timeouts.Port, d.options.Timeouts.Poll, func() (bool, error) {
		open, err := d.options.PortOpen(ctx, report.Port)
		return !open, err
	})
	if err != nil {
		return err
	}
	if !phase.PortClosed {
		return failure("socks_port_still_open")
	}
	return nil
}

func (d *driver) footprint(launch Launch, gui, child int, duration float64) error {
	processes, err := launch.WorkingSets()
	if err != nil {
		return err
	}
	measurement := &Footprint{StartToReadyMS: duration, Processes: processes}
	seen := make(map[int]bool)
	for index := range processes {
		p := &processes[index]
		if p.PID <= 0 || seen[p.PID] || p.WorkingSetBytes == 0 || p.WorkingSetBytes > ^uint64(0)-measurement.OwnedWorkingSetBytes {
			return failure("working_set_invalid")
		}
		seen[p.PID] = true
		p.Role = "owned"
		if p.PID == gui {
			p.Role = "gui"
		} else if p.PID == child {
			p.Role = "engine"
		}
		measurement.OwnedWorkingSetBytes += p.WorkingSetBytes
	}
	if !seen[gui] || !seen[child] {
		return failure("working_set_incomplete")
	}
	sort.Slice(processes, func(i, j int) bool { return processes[i].PID < processes[j].PID })
	d.summary.Footprint = measurement
	return nil
}

func (d *driver) waitReport(ctx context.Context, name, mode string, stamp time.Time, gui Process) (Report, error) {
	var report Report
	ready, err := eventually(ctx, d.options.Timeouts.Report, d.options.Timeouts.Poll, func() (bool, error) {
		var err error
		report, err = d.files.readReport(name, mode, stamp)
		if !errors.Is(err, fs.ErrNotExist) {
			return err == nil, err
		}
		exited, err := gui.Exited(0)
		if err != nil {
			return false, err
		}
		if exited {
			return false, failure("report_missing")
		}
		return false, nil
	})
	if err != nil {
		return Report{}, err
	}
	if !ready {
		return Report{}, failure("report_timeout")
	}
	return report, nil
}

func (d *driver) waitExit(ctx context.Context, process Process, timeout time.Duration) (bool, error) {
	return eventually(ctx, timeout, d.options.Timeouts.Poll, func() (bool, error) { return process.Exited(0) })
}

func (d *driver) cleanup() {
	addError := func(code string) {
		d.summary.Cleanup.ErrorCodes = append(d.summary.Cleanup.ErrorCodes, code)
	}
	for index := len(d.launches) - 1; index >= 0; index-- {
		launch := d.launches[index]
		if !d.summary.OK {
			err := launch.TerminateJob()
			if err == nil {
				var empty bool
				empty, err = eventually(context.Background(), d.options.Timeouts.Cleanup, d.options.Timeouts.Poll, launch.Empty)
				if !empty && err == nil {
					err = failure("cleanup_timeout")
				}
			}
			if err != nil {
				addError("process_cleanup_failed")
			}
		}
		// KILL_ON_JOB_CLOSE remains a last resort, after failed-proof recording.
		if err := launch.Close(); err != nil {
			addError("handle_cleanup_failed")
		}
	}
	for index := len(d.handles) - 1; index >= 0; index-- {
		stopped, err := eventually(context.Background(), d.options.Timeouts.Cleanup, d.options.Timeouts.Poll,
			func() (bool, error) { return d.handles[index].Exited(0) })
		if err != nil || !stopped {
			addError("process_cleanup_failed")
		}
		if err := d.handles[index].Close(); err != nil {
			addError("handle_cleanup_failed")
		}
	}
	if d.files != nil {
		for _, path := range d.workspaces {
			if err := d.files.removeWorkspace(path); err != nil {
				addError("workspace_cleanup_failed")
			}
		}
	}
	if d.cwd != "" {
		if err := os.RemoveAll(d.cwd); err != nil {
			addError("working_directory_cleanup_failed")
		}
	}
	d.summary.Cleanup.OK = len(d.summary.Cleanup.ErrorCodes) == 0
	if !d.summary.Cleanup.OK {
		d.summary.OK = false
		if d.summary.ErrorCode == nil {
			code := "cleanup_failed"
			d.summary.ErrorCode = &code
		}
	}
}

func eventually(ctx context.Context, timeout, poll time.Duration, check func() (bool, error)) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		ready, err := check()
		if err != nil {
			return false, err
		}
		if ready {
			return true, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, nil
		}
		if poll <= 0 || poll > remaining {
			poll = remaining
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, ctx.Err()
		case <-timer.C:
		}
	}
}

// PortOpen probes only numeric IPv4 loopback. Refusal proves closure; timeouts,
// permission failures and cancellation must not masquerade as a closed port.
func PortOpen(ctx context.Context, port int) (bool, error) {
	if port < 1 || port > 65535 {
		return false, failure("port_invalid")
	}
	connection, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err == nil {
		_ = connection.Close()
		return true, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if errors.Is(err, syscall.ECONNREFUSED) || runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(10061)) {
		return false, nil
	}
	return false, failure("port_probe_failed")
}

func safeCode(err error) string {
	var controlled failure
	if errors.As(err, &controlled) {
		return string(controlled)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "interrupted"
	}
	return "driver_failed"
}

func contained(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && filepath.IsLocal(relative)
}

func sameImage(actual, expected string) bool {
	actualInfo, err := os.Stat(actual)
	if err != nil {
		return false
	}
	expectedInfo, err := os.Stat(expected)
	return err == nil && os.SameFile(actualInfo, expectedInfo)
}

func sourceRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", failure("source_root_invalid")
	}
	for path := cwd; ; path = filepath.Dir(path) {
		if _, err := os.Stat(filepath.Join(path, "tools", "go.mod")); err == nil {
			return path, nil
		}
		if filepath.Dir(path) == path {
			return cwd, nil
		}
	}
}
