//go:build windows

package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func assertPrivate(t *testing.T, path string, _ bool) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sddl := descriptor.String()
	if !strings.Contains(sddl, "D:P") || strings.Count(sddl, "(A;") != 1 || !strings.Contains(sddl, ";FA;;;"+user.User.Sid.String()+")") || strings.Contains(sddl, ";;;WD)") || strings.Contains(sddl, ";;;AU)") {
		t.Fatal("DACL is not protected current-user-only full access")
	}
}

func TestLegacyWindowsByteZeroLengthOneLock(t *testing.T) {
	store := testStore(t)
	path := filepath.Join(store.Paths.Root, ".instance.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		t.Fatal(err)
	}
	if lock, err := AcquireLock(store.Paths.Root); err == nil || lock != nil {
		t.Fatal("legacy msvcrt byte-zero length-one lock was ignored")
	}
	if err := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{}); err != nil {
		t.Fatal(err)
	}
	lock, err := AcquireLock(store.Paths.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	// Byte one must remain unlocked: Python only locks byte zero.
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{Offset: 1}); err != nil {
		t.Fatal("lock range exceeds legacy byte zero")
	}
	defer windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{Offset: 1})
}
