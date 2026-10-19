package smoke

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testOutput(t *testing.T) *outputFiles {
	t.Helper()
	output, err := openOutput(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = output.root.Close() })
	return output
}

func TestReportFilesUseFilesystemMarkerAndRejectStaleSizeAndLinks(t *testing.T) {
	output := testOutput(t)
	stamp, err := output.filesystemTimestamp()
	if err != nil || stamp.IsZero() {
		t.Fatal("filesystem marker failed", err)
	}
	name := "wait.json"
	path := filepath.Join(output.path, name)
	encoded := encodeReport(t, reportData("wait", filepath.Join(output.path, "runtime-valid"), 123, 124))
	if err := output.root.WriteFile(name, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := output.readReport(name, "wait", stamp)
	if err != nil || report.requireSuccess() != nil {
		t.Fatalf("fresh report rejected: %v", err)
	}
	old := time.Unix(1, 0)
	if os.Chtimes(path, old, old) != nil {
		t.Fatal("set stale timestamp")
	}
	_, err = output.readReport(name, "wait", stamp)
	assertCode(t, err, "report_stale")
	if output.root.WriteFile(name, bytes.Repeat([]byte("x"), MaxReportBytes+1), 0o600) != nil {
		t.Fatal("write oversized report")
	}
	_, err = output.readReport(name, "wait", time.Time{})
	assertCode(t, err, "report_file_invalid")
	if output.root.Remove(name) != nil || output.root.Mkdir(name, 0o700) != nil {
		t.Fatal("directory fixture")
	}
	_, err = output.readReport(name, "wait", stamp)
	assertCode(t, err, "report_file_invalid")
	if output.root.Remove(name) != nil {
		t.Fatal("remove directory fixture")
	}
	_, err = output.readReport(name, "wait", stamp)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("missing report should be distinguishable")
	}
	outside := filepath.Join(t.TempDir(), "foreign.json")
	if os.WriteFile(outside, encoded, 0o600) != nil {
		t.Fatal("write external file")
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Skip("creating Windows symlinks requires Developer Mode or privilege")
	}
	_, err = output.readReport(name, "wait", stamp)
	assertCode(t, err, "report_file_invalid")
	if err := output.removeStale(name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("stale-link removal touched the foreign target")
	}
}

func TestWorkspaceContainmentAndCopiedExecutableProtection(t *testing.T) {
	output := testOutput(t)
	outside := t.TempDir()
	for _, path := range []string{"", "relative", "bad\x00path", output.path, outside,
		filepath.Join(output.path, "..", "foreign"), filepath.Join(output.path, copyDirectory),
		filepath.Join(output.path, "runtime-x", "nested"), filepath.Join(output.path, "runtime-"),
		filepath.Join(output.path, "runtime-x."), filepath.Join(output.path, "runtime-x:stream")} {
		if _, err := output.workspaceName(path); err == nil {
			t.Fatalf("unsafe workspace accepted: %q", path)
		}
	}
	if err := output.root.Mkdir(copyDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := output.root.WriteFile(copyName, []byte("exe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := output.removeWorkspace(filepath.Join(output.path, copyDirectory)); err == nil {
		t.Fatal("copied executable directory eligible for cleanup")
	}
	if err := output.root.MkdirAll("runtime-safe/sub", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := output.root.WriteFile("runtime-safe/sub/owned", []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(output.path, "runtime-safe")
	if err := output.removeWorkspace(workspace); err != nil {
		t.Fatal(err)
	}
	if err := output.removeWorkspace(workspace); err != nil {
		t.Fatal("repeated cleanup is not idempotent", err)
	}
	if _, err := output.root.Stat(copyName); err != nil {
		t.Fatal("copied EXE was removed")
	}
	marker := filepath.Join(outside, "must-survive")
	if err := os.WriteFile(marker, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, workspace); err != nil {
		t.Skip("creating Windows symlinks requires Developer Mode or privilege")
	}
	if err := output.removeWorkspace(workspace); err == nil {
		t.Fatal("replaced external workspace symlink accepted")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("foreign directory touched")
	}
}

func TestWorkspaceRemovalDoesNotFollowChildSymlinks(t *testing.T) {
	output := testOutput(t)
	if output.root.Mkdir("runtime-owned", 0o700) != nil {
		t.Fatal("create workspace")
	}
	foreign := t.TempDir()
	marker := filepath.Join(foreign, "keep")
	if os.WriteFile(marker, []byte("foreign"), 0o600) != nil {
		t.Fatal("create marker")
	}
	if err := os.Symlink(foreign, filepath.Join(output.path, "runtime-owned", "link")); err != nil {
		t.Skip("creating Windows symlinks requires Developer Mode or privilege")
	}
	if err := output.removeWorkspace(filepath.Join(output.path, "runtime-owned")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("workspace cleanup followed a child symlink")
	}
}

func TestCopyExecutableIsSingleAtomicArtifactAndDoesNotFollowOldLinks(t *testing.T) {
	output := testOutput(t)
	source := filepath.Join(t.TempDir(), "source.exe")
	if os.WriteFile(source, []byte("first"), 0o600) != nil {
		t.Fatal("create executable fixture")
	}
	path, size, err := output.copyExecutable(source)
	if err != nil || size != 5 || path != filepath.Join(output.path, filepath.FromSlash(copyName)) {
		t.Fatal("copy failed", err)
	}
	if os.WriteFile(source, []byte("replacement"), 0o600) != nil {
		t.Fatal("replace fixture")
	}
	if _, size, err := output.copyExecutable(source); err != nil || size != 11 {
		t.Fatal("repeat atomic copy failed", err)
	}
	if output.root.WriteFile(copyDirectory+"/foreign.dll", []byte("never delete me"), 0o600) != nil {
		t.Fatal("create extra file")
	}
	_, _, err = output.copyExecutable(source)
	assertCode(t, err, "executable_directory_not_single")
	if encoded, err := output.root.ReadFile(copyDirectory + "/foreign.dll"); err != nil || string(encoded) != "never delete me" {
		t.Fatal("single-file validation removed a foreign file")
	}
	if output.root.Remove(copyDirectory+"/foreign.dll") != nil || output.root.Remove(copyName) != nil {
		t.Fatal("prepare symlink test")
	}
	foreign := filepath.Join(t.TempDir(), "foreign.exe")
	if os.WriteFile(foreign, []byte("foreign"), 0o600) != nil {
		t.Fatal("write foreign fixture")
	}
	if err := os.Symlink(foreign, path); err != nil {
		t.Skip("creating Windows symlinks requires Developer Mode or privilege")
	}
	if _, _, err := output.copyExecutable(source); err != nil {
		t.Fatal("atomic replace of stale symlink failed", err)
	}
	if encoded, err := os.ReadFile(foreign); err != nil || string(encoded) != "foreign" {
		t.Fatal("copy followed and overwrote a foreign target")
	}
}
