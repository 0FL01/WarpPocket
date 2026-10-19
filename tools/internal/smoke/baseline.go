package smoke

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const baselineURL = "https://nightly.link/0FL01/WarpPocket/actions/runs/39265270853/WarpPocket-windows-x64.zip"
const baselineHash = "f81074866ca33a9eaeb362dfea751990a00ddb1dc092b475b73b6769d3a63f2d"
const baselineBytes = 29484399

type Comparison struct {
	BaselineCommit string    `json:"baseline_commit"`
	BaselineBytes  int64     `json:"baseline_executable_bytes"`
	CurrentBytes   int64     `json:"current_executable_bytes"`
	Baseline       Footprint `json:"baseline"`
	Current        Footprint `json:"current"`
	Note           string    `json:"note"`
}

func baselineExecutable(data []byte, expected string) ([]byte, error) {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(archive.File) != 1 || archive.File[0].Name != "WarpPocket.exe" || archive.File[0].UncompressedSize64 > 100<<20 {
		return nil, failure("baseline_archive")
	}
	f, err := archive.File[0].Open()
	if err != nil {
		return nil, failure("baseline_archive")
	}
	defer f.Close()
	executable, err := io.ReadAll(io.LimitReader(f, 100<<20+1))
	digest := sha256.Sum256(executable)
	if err != nil || len(executable) > 100<<20 || len(executable) < 2 || string(executable[:2]) != "MZ" || hex.EncodeToString(digest[:]) != expected {
		return nil, failure("baseline_digest")
	}
	return executable, nil
}

// CompareBaseline is a one-time migration measurement, not a release prerequisite
// forever: the pinned historical Actions artifact has a retention deadline.
// Both samples include every process in their owned job. Start-to-ready includes
// each application's actual smoke checks, which are intentionally not identical.
func CompareBaseline(ctx context.Context, currentSummary, output string) (comparison Comparison, result error) {
	platform, err := newNativePlatform()
	if err != nil {
		return comparison, err
	}
	currentData, err := os.ReadFile(currentSummary)
	var current Summary
	if err != nil || json.Unmarshal(currentData, &current) != nil || !current.OK || current.Footprint == nil {
		return comparison, failure("current_summary")
	}
	client := &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" || len(via) > 8 {
			return failure("baseline_redirect")
		}
		return nil
	}}
	request, _ := http.NewRequestWithContext(ctx, "GET", baselineURL, nil)
	response, err := client.Do(request)
	if err != nil {
		return comparison, failure("baseline_download")
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 100<<20+1))
	if err != nil || response.StatusCode != http.StatusOK || len(encoded) > 100<<20 {
		return comparison, failure("baseline_download")
	}
	executable, err := baselineExecutable(encoded, baselineHash)
	if err != nil || len(executable) != baselineBytes {
		return comparison, failure("baseline_digest")
	}
	parent, err := filepath.Abs(filepath.Dir(output))
	if err != nil || os.MkdirAll(parent, 0700) != nil {
		return comparison, failure("baseline_output")
	}
	work, err := os.MkdirTemp(parent, "baseline-")
	if err != nil {
		return comparison, failure("baseline_workspace")
	}
	defer os.RemoveAll(work)
	exe := filepath.Join(work, "WarpPocket.exe")
	if os.WriteFile(exe, executable, 0600) != nil {
		return comparison, failure("baseline_executable")
	}
	reportPath := filepath.Join(work, "wait.json")
	start := time.Now()
	launch, err := platform.Launch([]string{exe, "--smoke-wait", reportPath}, work)
	if err != nil {
		return comparison, err
	}
	defer func() {
		// This is benchmark containment, not a GUI-only crash proof. A teardown
		// failure cannot become a successful comparison.
		if result != nil {
			_ = launch.TerminateJob()
		}
		if err := launch.Close(); err != nil && result == nil {
			result = failure("baseline_cleanup")
		}
	}()
	var report map[string]json.RawMessage
	for {
		data, readErr := os.ReadFile(reportPath)
		if readErr == nil && len(data) <= MaxReportBytes && json.Unmarshal(data, &report) == nil {
			break
		}
		select {
		case <-ctx.Done():
			return comparison, failure("baseline_timeout")
		case <-time.After(50 * time.Millisecond):
		}
	}
	var version, pid, child, port int
	var ok bool
	var mode string
	var checks map[string]bool
	for name, target := range map[string]any{"schema_version": &version, "pid": &pid, "child_pid": &child, "port": &port, "mode": &mode, "ok": &ok, "checks": &checks} {
		if json.Unmarshal(report[name], target) != nil {
			return comparison, failure("baseline_report")
		}
	}
	if version != 1 || mode != "wait" || !ok || pid <= 0 || child <= 0 || pid == child || pid == launch.GUI().PID() || port < 1 || port > 65535 {
		return comparison, failure("baseline_report")
	}
	for _, name := range []string{"tk", "ui", "tls_bundle", "licenses", "wgcf_binary", "wireproxy_binary", "wgcf_help", "socks_started", "helper_alive"} {
		if !checks[name] {
			return comparison, failure("baseline_report")
		}
	}
	gui, err := platform.OpenProcess(pid)
	if err != nil {
		return comparison, err
	}
	defer gui.Close()
	engine, err := platform.OpenProcess(child)
	if err != nil {
		return comparison, err
	}
	defer engine.Close()
	for _, process := range []Process{gui, engine} {
		member, err := launch.Contains(process)
		if err != nil || !member {
			return comparison, failure("baseline_not_owned")
		}
	}
	guiIdentity, err := gui.Identity()
	if err != nil || guiIdentity.ParentPID != launch.GUI().PID() || !sameImage(guiIdentity.Image, exe) {
		return comparison, failure("baseline_identity")
	}
	engineIdentity, err := engine.Identity()
	if err != nil || engineIdentity.ParentPID != pid {
		return comparison, failure("baseline_identity")
	}
	processes, err := launch.WorkingSets()
	if err != nil {
		return comparison, failure("baseline_" + safeCode(err))
	}
	measurement, err := baselineFootprint(processes, pid, child, launch.GUI().PID(), time.Since(start))
	if err != nil {
		return comparison, err
	}
	if err := closeBaselineWindow(pid); err != nil {
		return comparison, err
	}
	for _, process := range []Process{gui, engine, launch.GUI()} {
		exited, err := process.Exited(30 * time.Second)
		if err != nil || !exited {
			return comparison, failure("baseline_cleanup")
		}
	}
	if empty, err := launch.Empty(); err != nil || !empty {
		return comparison, failure("baseline_cleanup")
	}
	comparison = Comparison{BaselineCommit: "b3239e85e8ffcc2ce1d4f9d3286922f6d1ac31ea", BaselineBytes: baselineBytes,
		CurrentBytes: current.ExecutableBytes, Baseline: measurement, Current: *current.Footprint,
		Note: "Single CI sample; total working set includes every owned process. Ready time includes different Tk/Gio smoke checks, including new native clipboard/picker checks; not a universal startup or memory guarantee."}
	data, _ := json.MarshalIndent(comparison, "", "  ")
	if os.WriteFile(output, data, 0600) != nil {
		return comparison, failure("baseline_output")
	}
	return comparison, nil
}

func baselineFootprint(processes []ProcessMemory, gui, engine, launcher int, elapsed time.Duration) (Footprint, error) {
	if gui <= 0 || engine <= 0 || launcher <= 0 || gui == engine || gui == launcher || engine == launcher {
		return Footprint{}, failure("baseline_working_set")
	}
	// WorkingSets verifies membership/liveness for every PID and takes a stable
	// snapshot of the entire owned job. A legacy console helper may also own a
	// conhost process: include its memory instead of assuming exactly three or
	// excluding auxiliary processes from the comparison. The new application's
	// separate exact GUI+engine crash proof is deliberately unchanged.
	want := map[int]string{gui: "gui", engine: "engine", launcher: "onefile_launcher"}
	seen := make(map[int]bool, len(processes))
	measurement := Footprint{StartToReadyMS: float64(elapsed.Microseconds()) / 1000, Processes: append([]ProcessMemory(nil), processes...)}
	for i := range measurement.Processes {
		p := &measurement.Processes[i]
		if p.PID <= 0 || seen[p.PID] || p.WorkingSetBytes == 0 || ^uint64(0)-measurement.OwnedWorkingSetBytes < p.WorkingSetBytes {
			return Footprint{}, failure("baseline_working_set")
		}
		seen[p.PID] = true
		measurement.OwnedWorkingSetBytes += p.WorkingSetBytes
		p.Role = want[p.PID]
		if p.Role == "" {
			p.Role = "runtime_auxiliary"
		}
	}
	for pid := range want {
		if !seen[pid] {
			return Footprint{}, failure("baseline_working_set")
		}
	}
	return measurement, nil
}
