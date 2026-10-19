package smoke

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const fakeGUI = 600000001
const fakeChild = 600000002

type fakePlatform struct {
	t                  *testing.T
	options            Options
	events             []string
	launches           []*fakeLaunch
	mutate             map[string]func(map[string]any)
	noReport           map[string]bool
	gracefulHangs      bool
	gracefulCode       uint32
	childSurvives      bool
	guiSurvives        bool
	portStaysOpen      bool
	noListener         bool
	foreignChild       bool
	wrongImage         bool
	wrongParent        bool
	wrongCreated       bool
	wrongHandlePID     bool
	childAlreadyDead   bool
	openFails          bool
	cleanupFails       bool
	closeFails         bool
	missingMemory      bool
	stale              bool
	beforeLaunch       func(mode string)
	afterReport        func(mode string)
	workingSetOverride []ProcessMemory
}

type fakeProcess struct {
	native *fakePlatform
	launch *fakeLaunch
	pid    int
	live   bool
	closed bool
	code   uint32
}

type fakeLaunch struct {
	native *fakePlatform
	gui    *fakeProcess
	child  *fakeProcess
	mode   string
	image  string
	closed bool
}

func newFake(t *testing.T) *fakePlatform {
	t.Helper()
	root := t.TempDir()
	exe := filepath.Join(root, "source.exe")
	if os.WriteFile(exe, []byte("synthetic executable fixture"), 0o600) != nil {
		t.Fatal("write fixture")
	}
	source := filepath.Join(root, "source")
	if os.Mkdir(source, 0o700) != nil {
		t.Fatal("create source")
	}
	fake := &fakePlatform{t: t, mutate: map[string]func(map[string]any){}, noReport: map[string]bool{}}
	fake.options = Options{Executable: exe, Output: filepath.Join(root, "out"), SourceRoot: source,
		TempDir: root, Platform: fake, PortOpen: fake.portOpen, Timeouts: Timeouts{Poll: time.Millisecond}}
	return fake
}

func (f *fakePlatform) Launch(argv []string, cwd string) (Launch, error) {
	f.t.Helper()
	if len(argv) != 3 || filepath.Base(argv[0]) != "WarpPocket.exe" || filepath.Base(filepath.Dir(argv[0])) != copyDirectory {
		f.t.Fatalf("not a single Unicode/spaces-path executable launch: %v", argv)
	}
	if contained(f.options.SourceRoot, cwd) {
		f.t.Fatal("cwd inside source")
	}
	if info, err := os.Stat(cwd); err != nil || !info.IsDir() {
		f.t.Fatal("owned cwd does not exist")
	}
	mode := "graceful"
	if argv[1] == "--smoke-wait" {
		mode = "wait"
	} else if argv[1] != "--smoke" {
		f.t.Fatal("unexpected launch option")
	}
	if _, err := os.Lstat(argv[2]); !errors.Is(err, os.ErrNotExist) {
		f.t.Fatal("stale report was not removed before launch")
	}
	if f.beforeLaunch != nil {
		f.beforeLaunch(mode)
	}
	f.events = append(f.events, "launch:"+mode, "cwd:"+cwd)
	launch := &fakeLaunch{native: f, mode: mode, image: argv[0]}
	launch.gui = &fakeProcess{native: f, launch: launch, pid: fakeGUI, live: mode == "wait" || f.gracefulHangs, code: f.gracefulCode}
	launch.child = &fakeProcess{native: f, launch: launch, pid: fakeChild, live: mode == "wait" && !f.childAlreadyDead}
	f.launches = append(f.launches, launch)
	workspace := filepath.Join(filepath.Dir(argv[2]), "runtime-"+mode)
	if os.MkdirAll(workspace, 0o700) != nil || os.WriteFile(filepath.Join(workspace, "owned.conf"), []byte("synthetic; never read by driver"), 0o600) != nil {
		f.t.Fatal("create workspace fixture")
	}
	if !f.noReport[mode] {
		data := reportData(mode, workspace, fakeGUI, fakeChild)
		if mutation := f.mutate[mode]; mutation != nil {
			mutation(data)
		}
		if os.WriteFile(argv[2], encodeReport(f.t, data), 0o600) != nil {
			f.t.Fatal("write report")
		}
		if f.stale && mode == "wait" {
			_ = os.Chtimes(argv[2], time.Unix(1, 0), time.Unix(1, 0))
		}
	}
	if f.afterReport != nil {
		f.afterReport(mode)
	}
	return launch, nil
}

func (f *fakePlatform) OpenProcess(pid int) (Process, error) {
	f.events = append(f.events, fmt.Sprintf("open:%d", pid))
	if f.openFails {
		return nil, errors.New("secret-token=never echo this OS error")
	}
	if pid != fakeChild {
		f.t.Fatal("driver attempted to reopen report GUI or foreign PID")
	}
	child := f.launches[len(f.launches)-1].child
	if f.wrongHandlePID {
		child.pid++
	}
	return child, nil
}

func (f *fakePlatform) portOpen(ctx context.Context, port int) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if port != 25344 {
		f.t.Fatal("unexpected port")
	}
	open := !f.noListener && (f.launches[len(f.launches)-1].child.live || f.portStaysOpen)
	f.events = append(f.events, fmt.Sprintf("port:%t", open))
	return open, nil
}

func (p *fakeProcess) PID() int { return p.pid }
func (p *fakeProcess) Exited(time.Duration) (bool, error) {
	if p.closed {
		p.native.t.Fatal("wait after retained handle was closed")
	}
	p.native.events = append(p.native.events, fmt.Sprintf("wait:%d:%t", p.pid, !p.live))
	return !p.live, nil
}
func (p *fakeProcess) ExitCode() (uint32, error) {
	if p.live {
		p.native.t.Fatal("exit code queried before exit")
	}
	return p.code, nil
}
func (p *fakeProcess) Identity() (Identity, error) {
	identity := Identity{PID: p.pid, Image: p.launch.image, Created: 100}
	if p == p.launch.child {
		identity.ParentPID, identity.Created = p.launch.gui.pid, 101
		if p.native.wrongParent {
			identity.ParentPID++
		}
		if p.native.wrongCreated {
			identity.Created = 99
		}
		if p.native.wrongImage {
			identity.Image = filepath.Join(p.native.options.Output, "foreign.exe")
		}
	}
	return identity, nil
}
func (p *fakeProcess) Terminate() error {
	p.native.events = append(p.native.events, fmt.Sprintf("terminate:%d", p.pid))
	if p != p.launch.gui {
		p.native.t.Fatal("driver terminated engine instead of GUI")
	}
	if !p.native.guiSurvives {
		p.live = false
		p.code = 1
	}
	if !p.native.childSurvives {
		p.launch.child.live = false
	}
	return nil
}
func (p *fakeProcess) Close() error {
	p.native.events = append(p.native.events, fmt.Sprintf("close:%d", p.pid))
	p.closed = true
	return nil
}

func (l *fakeLaunch) GUI() Process { return l.gui }
func (l *fakeLaunch) Contains(process Process) (bool, error) {
	l.native.events = append(l.native.events, fmt.Sprintf("contains:%d", process.PID()))
	return process == l.gui || process == l.child && !l.native.foreignChild, nil
}
func (l *fakeLaunch) Empty() (bool, error) {
	l.native.events = append(l.native.events, "empty:"+l.mode)
	return !l.gui.live && !l.child.live, nil
}
func (l *fakeLaunch) WorkingSets() ([]ProcessMemory, error) {
	l.native.events = append(l.native.events, "working-sets")
	if l.native.workingSetOverride != nil {
		return l.native.workingSetOverride, nil
	}
	processes := []ProcessMemory{{PID: l.gui.pid, WorkingSetBytes: 1000}}
	if !l.native.missingMemory {
		processes = append(processes, ProcessMemory{PID: l.child.pid, WorkingSetBytes: 2000})
	}
	return processes, nil
}
func (l *fakeLaunch) TerminateJob() error {
	// A durable failed summary must precede every emergency cleanup action.
	encoded, err := os.ReadFile(filepath.Join(l.native.options.Output, "summary.json"))
	if err != nil {
		l.native.t.Fatal("failure was not recorded before emergency cleanup")
	}
	var summary Summary
	if json.Unmarshal(encoded, &summary) != nil || summary.OK || summary.ErrorCode == nil {
		l.native.t.Fatal("safety teardown preceded failed-proof marking")
	}
	l.native.events = append(l.native.events, "emergency:"+l.mode)
	if l.native.cleanupFails {
		return errors.New("private-path cleanup failed")
	}
	l.gui.live, l.child.live = false, false
	return nil
}
func (l *fakeLaunch) Close() error {
	l.native.events = append(l.native.events, "close-job:"+l.mode)
	l.closed = true
	l.gui.live, l.child.live = false, false // Last-resort kill-on-close.
	_ = l.gui.Close()
	if l.native.closeFails {
		return errors.New("secret handle error")
	}
	return nil
}

func (f *fakePlatform) run(ctx context.Context) Summary {
	f.t.Helper()
	summary := Run(ctx, f.options)
	encoded, err := os.ReadFile(filepath.Join(f.options.Output, "summary.json"))
	if err != nil {
		f.t.Fatal(err)
	}
	var stored Summary
	if err := json.Unmarshal(encoded, &stored); err != nil || !reflect.DeepEqual(summary, stored) {
		f.t.Fatalf("on-disk and returned summaries differ: %s / %+v (%v)", encoded, summary, err)
	}
	if bytes.Contains(encoded, []byte("secret")) || bytes.Contains(encoded, []byte("private")) || bytes.Contains(encoded, []byte(f.options.Output)) {
		f.t.Fatalf("unsafe summary: %s", encoded)
	}
	for _, launch := range f.launches {
		if !launch.closed || !launch.gui.closed || launch.gui.live || launch.child.live {
			f.t.Fatal("owned launch not cleaned up")
		}
	}
	for _, event := range f.events {
		if strings.HasPrefix(event, "cwd:") {
			if _, err := os.Lstat(strings.TrimPrefix(event, "cwd:")); !errors.Is(err, os.ErrNotExist) {
				f.t.Fatal("owned cwd not cleaned up")
			}
		}
	}
	return summary
}

func summaryCode(t *testing.T, summary Summary, expected string) {
	t.Helper()
	if summary.OK || summary.ErrorCode == nil || *summary.ErrorCode != expected {
		encoded, _ := json.Marshal(summary)
		t.Fatalf("summary = %s, want failure %s", encoded, expected)
	}
}

func indexEvent(events []string, event string) int {
	for index, item := range events {
		if item == event {
			return index
		}
	}
	return -1
}

func TestDriverSuccessUsesExactPIDAndGUIOnlyProofBeforeClosingJob(t *testing.T) {
	fake := newFake(t)
	if os.MkdirAll(fake.options.Output, 0o700) != nil {
		t.Fatal("create out")
	}
	for _, name := range []string{"graceful.json", "wait.json", "summary.json"} {
		if os.WriteFile(filepath.Join(fake.options.Output, name), []byte("stale"), 0o600) != nil {
			t.Fatal("create stale file")
		}
	}
	summary := fake.run(context.Background())
	if !summary.OK || summary.ExitStatus() != 0 || !summary.Graceful.OK || !summary.ForcedKill.OK || !summary.Cleanup.OK {
		encoded, _ := json.Marshal(summary)
		t.Fatalf("unexpected failure: %s", encoded)
	}
	if summary.ForcedKill.PID != fakeGUI || !summary.ForcedKill.EngineStopped || !summary.ForcedKill.PortClosed || !summary.ForcedKill.GUIOnlyTermination {
		t.Fatal("ownership proof incomplete")
	}
	if summary.ExecutableBytes != int64(len("synthetic executable fixture")) || summary.Footprint == nil ||
		summary.Footprint.OwnedWorkingSetBytes != 3000 || summary.Footprint.StartToReadyMS <= 0 || len(summary.Footprint.Processes) != 2 {
		t.Fatalf("incomplete footprint: %+v", summary.Footprint)
	}
	if summary.Footprint.Processes[0].Role != "gui" || summary.Footprint.Processes[1].Role != "engine" {
		t.Fatal("working-set roles missing")
	}
	var terminated []string
	for _, event := range fake.events {
		if strings.HasPrefix(event, "terminate:") || strings.HasPrefix(event, "emergency:") {
			terminated = append(terminated, event)
		}
	}
	if !reflect.DeepEqual(terminated, []string{fmt.Sprintf("terminate:%d", fakeGUI)}) {
		t.Fatal("not a GUI-only termination", terminated)
	}
	for _, event := range []string{"working-sets", "port:false", "close-job:wait", fmt.Sprintf("close:%d", fakeChild)} {
		if indexEvent(fake.events, event) == -1 {
			t.Fatal("missing proof event", event)
		}
	}
	if indexEvent(fake.events, "working-sets") > indexEvent(fake.events, terminated[0]) ||
		indexEvent(fake.events, "port:false") > indexEvent(fake.events, "close-job:wait") ||
		indexEvent(fake.events, "port:false") > indexEvent(fake.events, fmt.Sprintf("close:%d", fakeChild)) {
		t.Fatal("job or retained child handle was closed before proof", fake.events)
	}
	for _, name := range []string{"runtime-graceful", "runtime-wait"} {
		if _, err := os.Stat(filepath.Join(fake.options.Output, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned workspace not cleaned up")
		}
	}
	if copied, err := os.ReadFile(filepath.Join(fake.options.Output, filepath.FromSlash(copyName))); err != nil || string(copied) != "synthetic executable fixture" {
		t.Fatal("copied executable was not preserved")
	}
}

// Windows temp paths can be short-name aliases, while the launch arguments use
// the canonical output root. A fake application must derive its workspace from
// the report path actually passed to it, just like the shipped application.
func TestDriverApplicationUsesCanonicalReportDirectory(t *testing.T) {
	fake := newFake(t)
	root := filepath.Dir(fake.options.Output)
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Skip("creating Windows symlinks requires Developer Mode or privilege")
	}
	fake.options.Output = filepath.Join(alias, "out")
	summary := fake.run(context.Background())
	if !summary.OK {
		encoded, _ := json.Marshal(summary)
		t.Fatalf("canonical launch/report directory diverged: %s", encoded)
	}
}

func TestDriverFailuresAreContainedButCannotBecomePassingProofs(t *testing.T) {
	tests := []struct {
		name, code string
		setup      func(*fakePlatform)
	}{
		{"graceful_timeout", "graceful_timeout", func(f *fakePlatform) { f.gracefulHangs = true; f.noReport["graceful"] = true }},
		{"missing_report", "report_missing", func(f *fakePlatform) { f.noReport["graceful"] = true }},
		{"wait_timeout", "report_timeout", func(f *fakePlatform) { f.noReport["wait"] = true }},
		{"stale", "report_stale", func(f *fakePlatform) { f.stale = true }},
		{"nonzero", "graceful_exit_nonzero", func(f *fakePlatform) { f.gracefulCode = 7 }},
		{"engine_survives", "engine_survived_gui", func(f *fakePlatform) { f.childSurvives = true }},
		{"gui_survives", "gui_exit_timeout", func(f *fakePlatform) { f.guiSurvives = true }},
		{"port_survives", "socks_port_still_open", func(f *fakePlatform) { f.portStaysOpen = true }},
		{"no_listener", "socks_not_listening", func(f *fakePlatform) { f.noListener = true }},
		{"foreign_child", "process_not_owned", func(f *fakePlatform) { f.foreignChild = true }},
		{"different_image", "process_identity_invalid", func(f *fakePlatform) { f.wrongImage = true }},
		{"different_parent", "process_identity_invalid", func(f *fakePlatform) { f.wrongParent = true }},
		{"older_child", "process_identity_invalid", func(f *fakePlatform) { f.wrongCreated = true }},
		{"different_handle_pid", "process_identity_invalid", func(f *fakePlatform) { f.wrongHandlePID = true }},
		{"dead_child", "wait_process_not_live", func(f *fakePlatform) { f.childAlreadyDead = true }},
		{"open_error", "driver_failed", func(f *fakePlatform) { f.openFails = true }},
		{"memory_missing", "working_set_incomplete", func(f *fakePlatform) { f.missingMemory = true }},
		{"memory_zero", "working_set_invalid", func(f *fakePlatform) { f.workingSetOverride = []ProcessMemory{{PID: fakeGUI}} }},
		{"memory_duplicate", "working_set_invalid", func(f *fakePlatform) {
			f.workingSetOverride = []ProcessMemory{{PID: fakeGUI, WorkingSetBytes: 1}, {PID: fakeGUI, WorkingSetBytes: 1}}
		}},
		{"memory_overflow", "working_set_invalid", func(f *fakePlatform) {
			f.workingSetOverride = []ProcessMemory{{PID: fakeGUI, WorkingSetBytes: ^uint64(0)}, {PID: fakeChild, WorkingSetBytes: 1}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := newFake(t)
			test.setup(fake)
			summary := fake.run(context.Background())
			summaryCode(t, summary, test.code)
			if indexEvent(fake.events, "emergency:"+fake.launches[len(fake.launches)-1].mode) < 0 {
				t.Fatal("failed proof did not trigger bounded emergency cleanup")
			}
			if summary.ForcedKill != nil && summary.ForcedKill.OK {
				t.Fatal("emergency cleanup falsely passed ownership proof")
			}
		})
	}
}

func TestReportCannotAuthorizeForeignGUIOrLeakApplicationErrors(t *testing.T) {
	tests := []struct {
		field string
		value any
		code  string
	}{
		{"pid", fakeGUI + 10, "process_identity_invalid"}, {"pid", os.Getpid(), "process_identity_invalid"},
		{"child_pid", fakeGUI, "process_identity_invalid"}, {"child_pid", os.Getpid(), "process_identity_invalid"},
		{"ok", false, "smoke_not_ok"}, {"error_code", "private-token=secret", "smoke_not_ok"},
		{"checks", map[string]bool{}, "required_checks_failed"}, {"pid", true, "report_schema_invalid"},
	}
	for _, test := range tests {
		t.Run(test.field+"/"+test.code, func(t *testing.T) {
			fake := newFake(t)
			fake.mutate["wait"] = func(data map[string]any) { data[test.field] = test.value }
			summaryCode(t, fake.run(context.Background()), test.code)
			if indexEvent(fake.events, fmt.Sprintf("terminate:%d", fakeGUI)) >= 0 {
				t.Fatal("invalid report authorized process termination")
			}
		})
	}
}

func TestCleanupFailuresPreserveProofFailureAndUseJobCloseFallback(t *testing.T) {
	fake := newFake(t)
	fake.childSurvives, fake.cleanupFails = true, true
	summary := fake.run(context.Background())
	summaryCode(t, summary, "engine_survived_gui")
	if summary.Cleanup.OK || len(summary.Cleanup.ErrorCodes) == 0 || !fake.launches[1].child.closed {
		t.Fatal("cleanup failure or retained handle not accounted for")
	}
	fake = newFake(t)
	fake.closeFails = true
	summary = fake.run(context.Background())
	summaryCode(t, summary, "cleanup_failed")
}

func TestCancellationIsBoundedAndDoesNotSkipCleanup(t *testing.T) {
	fake := newFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	fake.afterReport = func(mode string) {
		if mode == "wait" {
			cancel()
		}
	}
	summaryCode(t, fake.run(ctx), "interrupted")
	if indexEvent(fake.events, "emergency:wait") < 0 {
		t.Fatal("cancelled launch left owned processes")
	}
	fake = newFake(t)
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	summaryCode(t, fake.run(ctx), "interrupted")
	if len(fake.launches) != 0 {
		t.Fatal("cancelled driver launched")
	}
}

func TestWorkingDirectoryAndForeignWorkspaceSafety(t *testing.T) {
	fake := newFake(t)
	fake.options.SourceRoot = fake.options.TempDir
	summaryCode(t, fake.run(context.Background()), "working_directory_inside_source")
	if len(fake.launches) != 0 {
		t.Fatal("launched from source tree")
	}
	fake = newFake(t)
	foreign := t.TempDir()
	marker := filepath.Join(foreign, "must-survive")
	if os.WriteFile(marker, []byte("private"), 0o600) != nil {
		t.Fatal("write marker")
	}
	fake.mutate["wait"] = func(data map[string]any) { data["workspace"] = foreign }
	summaryCode(t, fake.run(context.Background()), "workspace_outside_output")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("foreign workspace was deleted")
	}
	fake = newFake(t)
	victim := filepath.Join(fake.options.Output, "runtime-preexisting")
	if os.MkdirAll(victim, 0o700) != nil || os.WriteFile(filepath.Join(victim, "keep"), []byte("foreign"), 0o600) != nil {
		t.Fatal("create existing runtime fixture")
	}
	canonicalVictim, err := filepath.EvalSymlinks(victim)
	if err != nil {
		t.Fatal(err)
	}
	fake.mutate["wait"] = func(data map[string]any) { data["workspace"] = canonicalVictim }
	summaryCode(t, fake.run(context.Background()), "workspace_not_new")
	if _, err := os.Stat(filepath.Join(victim, "keep")); err != nil {
		t.Fatal("preexisting in-output runtime directory was deleted")
	}
}

func TestDriverPortProbeFailureDoesNotProveClosure(t *testing.T) {
	fake := newFake(t)
	probes := 0
	fake.options.PortOpen = func(context.Context, int) (bool, error) {
		probes++
		if probes == 1 {
			return true, nil
		}
		return false, errors.New("private network error")
	}
	summary := fake.run(context.Background())
	summaryCode(t, summary, "driver_failed")
	if summary.ForcedKill.PortClosed {
		t.Fatal("probe error was counted as port closure")
	}
}

func TestPortOpenOnlyProbesLoopbackAndObservesClosure(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	open, err := PortOpen(context.Background(), port)
	if err != nil || !open {
		t.Fatal("loopback listener not observed", err)
	}
	if listener.Close() != nil {
		t.Fatal("close listener")
	}
	open, err = PortOpen(context.Background(), port)
	if err != nil || open {
		t.Fatal("closed listener not observed", err)
	}
	for _, port := range []int{-1, 0, 65536} {
		_, err := PortOpen(context.Background(), port)
		assertCode(t, err, "port_invalid")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = PortOpen(ctx, port)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("probe cancellation lost", err)
	}
}

func TestEventuallyTimeoutAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	checks := 0
	ready, err := eventually(ctx, time.Second, time.Millisecond, func() (bool, error) {
		checks++
		cancel()
		return false, nil
	})
	if ready || !errors.Is(err, context.Canceled) || checks != 1 {
		t.Fatal("polling ignored cancellation")
	}
	ready, err = eventually(context.Background(), 0, time.Millisecond, func() (bool, error) { return false, nil })
	if ready || err != nil {
		t.Fatal("zero timeout did not check exactly once")
	}
}
