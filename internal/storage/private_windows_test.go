//go:build windows

package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SDDL's presentation uses aliases for well-known SIDs and can render the
// same mask with different abbreviations. Inspect the descriptor, not text.
// Exactly one explicit, object-applicable full-access ACE for this user is
// required; inherited/world/group grants and unprotected DACLs stay rejected.
func privateDACLReason(descriptor *windows.SECURITY_DESCRIPTOR, sid *windows.SID, directory bool) string {
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Sprintf("unprotected DACL: control=%#x error=%v", control, err)
	}
	acl, defaulted, err := descriptor.DACL()
	if err != nil || acl == nil || defaulted {
		return "missing or defaulted DACL"
	}
	if acl.AceCount != 1 {
		return fmt.Sprintf("unexpected ACE count: %d", acl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil || ace == nil {
		return "unreadable ACE"
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || uint32(ace.Mask) != 0x001f01ff || ace.Header.AceFlags&(windows.INHERIT_ONLY_ACE|windows.INHERITED_ACE) != 0 {
		return fmt.Sprintf("incorrect ACE: type=%d mask=%#x flags=%#x", ace.Header.AceType, ace.Mask, ace.Header.AceFlags)
	}
	if directory && ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
		return "directory ACE does not protect inherited children"
	}
	actualSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	match := actualSID.IsValid() && actualSID.Equals(sid)
	runtime.KeepAlive(descriptor)
	if !match {
		return "ACE is not for the current user"
	}
	return ""
}

func assertPrivate(t *testing.T, path string, directory bool) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if reason := privateDACLReason(descriptor, user.User.Sid, directory); reason != "" {
		t.Fatalf("DACL is not protected current-user-only full access: %s", reason)
	}
}

func TestPrivateDACLUsesSIDAndMaskSemantics(t *testing.T) {
	sid, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, sddl       string
		directory, valid bool
	}{
		{"well-known alias", "D:P(A;OICI;FA;;;SY)", true, true},
		{"literal SID", "D:P(A;OICI;FA;;;S-1-5-18)", true, true},
		{"file full access", "D:P(A;;FA;;;SY)", false, true},
		{"unprotected", "D:(A;OICI;FA;;;SY)", true, false},
		{"wrong user", "D:P(A;OICI;FA;;;AU)", true, false},
		{"extra grant", "D:P(A;OICI;FA;;;SY)(A;OICI;FR;;;WD)", true, false},
		{"read only", "D:P(A;OICI;FR;;;SY)", true, false},
		{"inherit only", "D:P(A;OICIIO;FA;;;SY)", true, false},
		{"directory lacks inheritance", "D:P(A;;FA;;;SY)", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			reason := privateDACLReason(descriptor, sid, tc.directory)
			if (reason == "") != tc.valid {
				t.Fatalf("unexpected privacy result: %s", reason)
			}
		})
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
