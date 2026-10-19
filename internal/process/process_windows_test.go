package process

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	processTestKernel = windows.NewLazySystemDLL("kernel32.dll")
	countHandlesProc  = processTestKernel.NewProc("GetProcessHandleCount")
	handleInfoProc    = processTestKernel.NewProc("GetHandleInformation")
	inJobProc         = processTestKernel.NewProc("IsProcessInJob")
)

func platformHelper(mode string, args []string) (int, bool) {
	if mode != "windows-inheritance" {
		return 0, false
	}
	stdin, err1 := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	stdout, err2 := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	stderr, err3 := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
	kind, err4 := windows.GetFileType(stdin)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || stdin != stdout || stdin != stderr || kind != windows.FILE_TYPE_CHAR {
		return 91, true
	}
	var inJob uint32
	ok, _, _ := inJobProc.Call(uintptr(windows.CurrentProcess()), 0, uintptr(unsafe.Pointer(&inJob)))
	runtime.KeepAlive(&inJob)
	if ok == 0 || inJob == 0 {
		return 92, true
	}
	foreign, err := strconv.ParseUint(args[1], 10, 64)
	if err != nil || windows.SetEvent(windows.Handle(foreign)) == nil {
		return 93, true
	}
	data, _ := json.Marshal(helperInfo{PID: os.Getpid(), Arg: "NUL-only"})
	if os.WriteFile(args[0], data, 0600) != nil {
		return 94, true
	}
	return 0, true
}

func ignoreTermination() {}

func running(pid int) bool {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	result, err := windows.WaitForSingleObject(handle, 0)
	return err == nil && result == uint32(windows.WAIT_TIMEOUT)
}

func emergencyKill(pid int) {
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err == nil {
		_ = windows.TerminateProcess(handle, 1)
		_ = windows.CloseHandle(handle)
	}
}

func resourceCount(t *testing.T) int {
	t.Helper()
	var count uint32
	ok, _, _ := countHandlesProc.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&count)))
	runtime.KeepAlive(&count)
	if ok == 0 {
		t.Fatal("cannot count native process handles")
	}
	return int(count)
}

func TestWindowsAtomicJobContainsLeaderAndInheritedDescendant(t *testing.T) {
	manager := testManager(t)
	directory := t.TempDir()
	childFile, parentFile := filepath.Join(directory, "child.json"), filepath.Join(directory, "parent.json")
	p := startHelper(t, manager, "tree", childFile, parentFile)
	child := waitInfo(t, childFile)
	waitInfo(t, parentFile)
	manager.mu.Lock()
	job := p.native.job
	var flags uint32
	ok, _, _ := handleInfoProc.Call(uintptr(job), uintptr(unsafe.Pointer(&flags)))
	runtime.KeepAlive(&flags)
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	var pin runtime.Pinner
	pin.Pin(&limits)
	limitErr := windows.QueryInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)), nil)
	runtime.KeepAlive(&limits)
	var list struct {
		Assigned uint32
		Count    uint32
		IDs      [8]uintptr
	}
	pin.Pin(&list)
	listErr := windows.QueryInformationJobObject(job, windows.JobObjectBasicProcessIdList,
		uintptr(unsafe.Pointer(&list)), uint32(unsafe.Sizeof(list)), nil)
	runtime.KeepAlive(&list)
	pin.Unpin()
	manager.mu.Unlock()
	if ok == 0 || flags&windows.HANDLE_FLAG_INHERIT != 0 || limitErr != nil || limits.BasicLimitInformation.LimitFlags&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 {
		t.Fatal("job is inheritable or does not enforce kill-on-close")
	}
	leaderFound, childFound := false, false
	for _, id := range list.IDs {
		leaderFound = leaderFound || id == uintptr(p.PID())
		childFound = childFound || id == uintptr(child.PID)
	}
	if listErr != nil || list.Assigned != 2 || list.Count != 2 || !leaderFound || !childFound {
		t.Fatal("atomic launch job did not contain the leader and inherited descendant")
	}
}

func TestWindowsOnlyNULHandlesAreInherited(t *testing.T) {
	manager := testManager(t)
	security := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	event, err := windows.CreateEvent(&security, 1, 0, nil)
	if err != nil {
		t.Fatal("cannot create unrelated inheritable event")
	}
	defer windows.CloseHandle(event)
	result := filepath.Join(t.TempDir(), "inheritance.json")
	p := startHelper(t, manager, "windows-inheritance", result, strconv.FormatUint(uint64(event), 10))
	if waitProcess(t, p) != 0 {
		t.Fatal("child did not have restricted NUL standard handles and an atomic job")
	}
	info, err := readInfo(result)
	if err != nil || info.Arg != "NUL-only" {
		t.Fatal("child could access an unrelated inheritable handle")
	}
	state, err := windows.WaitForSingleObject(event, 0)
	if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatal("child signaled an unrelated inheritable event")
	}
}

func TestWindowsFailedCleanupRetainsOwnershipForShutdownRetry(t *testing.T) {
	manager := testManager(t)
	ready := filepath.Join(t.TempDir(), "ready.json")
	p := startHelper(t, manager, "sleep", ready)
	waitInfo(t, ready)
	manager.mu.Lock()
	var duplicate windows.Handle
	err := windows.DuplicateHandle(windows.CurrentProcess(), p.native.process, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS)
	if err != nil {
		manager.mu.Unlock()
		t.Fatal("cannot duplicate test process handle")
	}
	_ = windows.CloseHandle(p.native.process)
	p.native.process = windows.InvalidHandle
	err = manager.stopLocked(p)
	_, stillOwned := manager.processes[p]
	p.native.process = duplicate
	manager.mu.Unlock()
	if err == nil || !stillOwned {
		t.Fatal("failed cleanup silently discarded ownership")
	}
	if manager.Shutdown() != nil {
		t.Fatal("shutdown could not retry retained cleanup")
	}
	waitProcess(t, p)
}

func TestWindowsJobKillsEntireTreeAfterOwnerCrash(t *testing.T) {
	directory := t.TempDir()
	childFile, parentFile := filepath.Join(directory, "child.json"), filepath.Join(directory, "parent.json")
	owner := exec.Command(self(t), helperMarker, "owner", "tree", childFile, parentFile)
	if err := owner.Start(); err != nil {
		t.Fatal("cannot launch crash-test owner")
	}
	var child, parent helperInfo
	defer func() {
		_ = owner.Process.Kill()
		_ = owner.Wait()
		for _, pid := range []int{child.PID, parent.PID} {
			if pid > 0 && running(pid) {
				emergencyKill(pid)
			}
		}
	}()
	child, parent = waitInfo(t, childFile), waitInfo(t, parentFile)
	if !listening(child.Port) {
		t.Fatal("crash-test descendant was not listening")
	}
	if owner.Process.Kill() != nil {
		t.Fatal("cannot crash owner")
	}
	_ = owner.Wait()
	if !eventually(8*time.Second, func() bool { return !running(child.PID) && !running(parent.PID) && !listening(child.Port) }) {
		t.Fatal("job tree or listener survived owner crash; verified before emergency cleanup")
	}
}

func TestWindowsNoUnmanagedFallbackForBadExecutable(t *testing.T) {
	manager := testManager(t)
	if p, err := manager.Start(context.Background(), []string{filepath.Join(t.TempDir(), "not-an-executable.exe")}, ""); err == nil || p != nil {
		t.Fatal("failed native launch used an unmanaged fallback")
	}
}
