package smoke

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCleanupWorkspaceAfterPickerChangesWorkingDirectory(t *testing.T) {
	workingDir := t.TempDir()
	t.Chdir(workingDir)
	workspace := filepath.Join(workingDir, "runtime")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "profile.conf"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workspace); err != nil {
		t.Fatal(err)
	}
	if err := cleanupWorkspace(workspace, workingDir); err != nil {
		t.Fatal(err)
	}
	got, err := os.Getwd()
	if err != nil || got != workingDir {
		t.Fatalf("working directory = %q, %v; want %q", got, err, workingDir)
	}
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Fatalf("workspace still exists: %v", err)
	}
}
