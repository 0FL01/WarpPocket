package application

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0FL01/WarpPocket/internal/storage"
)

func TestApplicationOwnsPersistentInstanceLockAndPreservesData(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Личные данные")
	a, err := New(root, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	if second, err := New(root, ""); err == nil {
		second.Close()
		t.Fatal("second application entered the same data directory")
	}
	profilePath := filepath.Join(a.Store.Paths.ProfileDir("primary"), "profile.conf")
	if err := storage.AtomicWrite(profilePath, []byte("private-fixture-not-read-by-close")); err != nil {
		t.Fatal(err)
	}
	a.Close()
	a.Close()
	data, err := os.ReadFile(profilePath)
	if err != nil || string(data) != "private-fixture-not-read-by-close" {
		t.Fatal("application close altered persistent profile data")
	}
	if _, err := os.Stat(filepath.Join(root, ".instance.lock")); err != nil {
		t.Fatal("persistent lock file was removed")
	}
	second, err := New(root, "")
	if err != nil {
		t.Fatalf("lock not released after close: %v", err)
	}
	second.Close()
}
