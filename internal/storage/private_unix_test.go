//go:build !windows

package storage

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func assertPrivate(t *testing.T, path string, directory bool) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	want := os.FileMode(0600)
	if directory {
		want = 0700
	}
	if info.Mode().Perm() != want {
		t.Errorf("private permission mismatch: %o != %o", info.Mode().Perm(), want)
	}
}

func TestLegacyFlockAndSymlinkRejection(t *testing.T) {
	store := testStore(t)
	path := filepath.Join(store.Paths.Root, ".instance.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if lock, err := AcquireLock(store.Paths.Root); err == nil || lock != nil {
		t.Fatal("independent legacy flock was ignored")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(store.Paths.Root, "target")
	if err := AtomicWrite(target, []byte("unchanged")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(store.Paths.Root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if PrivateFile(link) == nil || AtomicWrite(link, []byte("must fail")) == nil {
		t.Fatal("private writes followed a symlink")
	}
	if data, _ := os.ReadFile(target); string(data) != "unchanged" {
		t.Fatal("symlink target was modified")
	}
}
