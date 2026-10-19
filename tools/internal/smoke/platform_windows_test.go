//go:build windows && amd64

package smoke

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestNativeWindowsABISizes(t *testing.T) {
	for name, sizes := range map[string][2]uintptr{
		"STARTUPINFOW":                           {unsafe.Sizeof(syscall.StartupInfo{}), 104},
		"STARTUPINFOEXW":                         {unsafe.Sizeof(startupInfoEx{}), 112},
		"PROCESS_INFORMATION":                    {unsafe.Sizeof(syscall.ProcessInformation{}), 24},
		"JOBOBJECT_BASIC_LIMIT_INFORMATION":      {unsafe.Sizeof(jobBasicLimits{}), 64},
		"JOBOBJECT_EXTENDED_LIMIT_INFORMATION":   {unsafe.Sizeof(jobExtendedLimits{}), 144},
		"JOBOBJECT_BASIC_ACCOUNTING_INFORMATION": {unsafe.Sizeof(jobAccounting{}), 48},
		"PROCESS_MEMORY_COUNTERS":                {unsafe.Sizeof(processMemoryCounters{}), 72},
	} {
		if sizes[0] != sizes[1] {
			t.Errorf("%s size = %d, want %d", name, sizes[0], sizes[1])
		}
	}
	var startup startupInfoEx
	if unsafe.Offsetof(startup.AttributeList) != 104 {
		t.Fatal("STARTUPINFOEXW attribute-list offset is wrong")
	}
}

// The test binary doubles as a synthetic GUI and engine. The GUI owns an inner
// kill-on-close job; the test retains the outer safety job. No packaged app,
// real registration, WARP endpoint, or private profile is needed.
func TestNativeSmokeHelper(t *testing.T) {
	index := -1
	for position, argument := range os.Args {
		if argument == "--native-smoke-helper" {
			index = position
			break
		}
	}
	if index < 0 {
		return
	}
	if len(os.Args) <= index+1 {
		os.Exit(70)
	}
	for _, std := range []int{syscall.STD_INPUT_HANDLE, syscall.STD_OUTPUT_HANDLE, syscall.STD_ERROR_HANDLE} {
		handle, err := syscall.GetStdHandle(std)
		if err != nil {
			os.Exit(76)
		}
		kind, err := syscall.GetFileType(handle)
		if err != nil || kind != syscall.FILE_TYPE_CHAR {
			os.Exit(77)
		}
	}
	if os.Args[index+1] == "owner" {
		if len(os.Args) <= index+2 {
			os.Exit(71)
		}
		executable, err := os.Executable()
		if err != nil {
			os.Exit(72)
		}
		cwd, err := os.Getwd()
		if err != nil {
			os.Exit(73)
		}
		childReady := os.Args[index+2] + ".ready"
		launch, err := (windowsPlatform{}).Launch(nativeHelperArguments(executable, "child", childReady), cwd)
		if err != nil {
			os.Exit(74)
		}
		defer launch.Close()
		ready, err := eventually(context.Background(), 20*time.Second, 10*time.Millisecond, func() (bool, error) {
			data, err := os.ReadFile(childReady)
			if os.IsNotExist(err) {
				return false, nil
			}
			return bytes.Equal(data, []byte("ready")), err
		})
		if err != nil || !ready {
			os.Exit(78)
		}
		if writeNativeReady(os.Args[index+2], []byte(strconv.Itoa(launch.GUI().PID()))) != nil {
			os.Exit(75)
		}
	} else if len(os.Args) > index+2 {
		// ResumeThread returning is not evidence that the child has executed.
		// Publish readiness only after its Go runtime and NUL checks have run.
		if writeNativeReady(os.Args[index+2], []byte("ready")) != nil {
			os.Exit(79)
		}
	}
	for {
		time.Sleep(time.Hour)
	}
}

func writeNativeReady(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".native-ready-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = file.Write(data)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func nativeHelperArguments(executable, role string, extra ...string) []string {
	args := []string{executable, "-test.run=^TestNativeSmokeHelper$", "--", "--native-smoke-helper", role}
	return append(args, extra...)
}

func TestNativeWindowsGUIOnlyTerminationWithRetainedSafetyJob(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output := testOutput(t)
	executable, _, err = output.copyExecutable(executable)
	if err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	pidFile := filepath.Join(cwd, "engine.pid")
	platform := windowsPlatform{}
	launch, err := platform.Launch(nativeHelperArguments(executable, "owner", pidFile), cwd)
	if err != nil {
		t.Fatal("native suspended launch/job assignment failed:", err)
	}
	defer launch.Close()
	member, err := launch.Contains(launch.GUI())
	if err != nil || !member {
		t.Fatal("original GUI is not in safety job", err)
	}
	var flags uint32
	getHandleInfo := kernel32.NewProc("GetHandleInformation")
	result, _, _ := getHandleInfo.Call(uintptr(launch.(*windowsLaunch).job), uintptr(unsafe.Pointer(&flags)))
	if result == 0 || flags&syscall.HANDLE_FLAG_INHERIT != 0 {
		t.Fatal("safety job is inheritable or invalid")
	}
	var childPID int
	ready, err := eventually(context.Background(), 20*time.Second, 10*time.Millisecond, func() (bool, error) {
		encoded, err := os.ReadFile(pidFile)
		if os.IsNotExist(err) {
			// Observe the retained owner, not a PID reopened after failure. An
			// early helper exit must not become an opaque readiness timeout.
			exited, exitErr := launch.GUI().Exited(0)
			if exitErr != nil {
				return false, exitErr
			}
			if exited {
				code, codeErr := launch.GUI().ExitCode()
				return false, fmt.Errorf("synthetic owner exited before readiness: code=%d error=%v", code, codeErr)
			}
			return false, nil
		}
		if err != nil {
			return false, err
		}
		childPID, err = strconv.Atoi(string(encoded))
		return err == nil, err
	})
	if err != nil || !ready {
		exited, exitErr := launch.GUI().Exited(0)
		var exitCode uint32
		var codeErr error
		if exited {
			exitCode, codeErr = launch.GUI().ExitCode()
		}
		pids, jobErr := launch.(*windowsLaunch).processIDs()
		ack, ackErr := os.ReadFile(pidFile + ".ready")
		t.Fatalf("synthetic owner failed to launch nested-job engine: error=%v owner=%d exited=%t exit_error=%v exit_code=%d code_error=%v owned_pids=%v job_error=%v child_ack=%t ack_error=%v", err, launch.GUI().PID(), exited, exitErr, exitCode, codeErr, pids, jobErr, bytes.Equal(ack, []byte("ready")), ackErr)
	}
	child, err := platform.OpenProcess(childPID)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	member, err = launch.Contains(child)
	if err != nil || !member {
		t.Fatal("engine did not inherit the outer safety job", err)
	}
	guiID, err := launch.GUI().Identity()
	if err != nil {
		t.Fatal(err)
	}
	childID, err := child.Identity()
	if err != nil || childID.PID != childPID || childID.ParentPID != launch.GUI().PID() ||
		childID.Created < guiID.Created || !sameImage(childID.Image, executable) {
		t.Fatal("native child identity was not verified", err)
	}
	measurements, err := launch.WorkingSets()
	if err != nil || len(measurements) != 2 || measurements[0].WorkingSetBytes == 0 || measurements[1].WorkingSetBytes == 0 {
		var identities []Identity
		for _, measured := range measurements {
			process, openErr := platform.OpenProcess(measured.PID)
			if openErr != nil {
				t.Logf("owned PID %d identity unavailable: %v", measured.PID, openErr)
				continue
			}
			identity, identityErr := process.Identity()
			_ = process.Close()
			if identityErr != nil {
				t.Logf("owned PID %d identity unavailable: %v", measured.PID, identityErr)
				continue
			}
			identities = append(identities, identity)
		}
		t.Fatalf("job-wide native working sets not measured: gui=%d engine=%d measured=%+v identities=%+v error=%v", launch.GUI().PID(), childPID, measurements, identities, err)
	}
	if err := launch.GUI().Terminate(); err != nil {
		t.Fatal(err)
	}
	if exited, err := launch.GUI().Exited(10 * time.Second); err != nil || !exited {
		t.Fatal("GUI did not exit", err)
	}
	// No TerminateJob, engine Terminate, safety Close, or tree-kill occurred.
	if exited, err := child.Exited(10 * time.Second); err != nil || !exited {
		t.Fatal("engine survived GUI-only termination while safety job was open", err)
	}
	empty, err := eventually(context.Background(), 10*time.Second, 10*time.Millisecond, launch.Empty)
	if err != nil || !empty {
		t.Fatal("owned processes remain", err)
	}
	result, _, _ = getHandleInfo.Call(uintptr(launch.(*windowsLaunch).job), uintptr(unsafe.Pointer(&flags)))
	if result == 0 {
		t.Fatal("safety job was closed before GUI-only proof completed")
	}
}

func nativeHandleCount(t *testing.T) uint32 {
	t.Helper()
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	var count uint32
	result, _, _ := kernel32.NewProc("GetProcessHandleCount").Call(uintptr(current), uintptr(unsafe.Pointer(&count)))
	if result == 0 {
		t.Fatal("GetProcessHandleCount failed")
	}
	return count
}

func TestNativeWindowsHandleCleanupOnSuccessAndFailure(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	platform := windowsPlatform{}
	cwd := t.TempDir()
	warm, err := platform.Launch(nativeHelperArguments(executable, "child"), cwd)
	if err != nil {
		t.Fatal(err)
	}
	_ = warm.TerminateJob()
	_, _ = warm.GUI().Exited(10 * time.Second)
	_ = warm.Close()
	before := nativeHandleCount(t)
	for iteration := 0; iteration < 20; iteration++ {
		_, err := platform.Launch([]string{filepath.Join(cwd, "missing.exe"), "private-secret"}, cwd)
		assertCode(t, err, "process_create_failed")
	}
	for iteration := 0; iteration < 5; iteration++ {
		launch, err := platform.Launch(nativeHelperArguments(executable, "child"), cwd)
		if err != nil {
			t.Fatal(err)
		}
		if err := launch.TerminateJob(); err != nil {
			t.Fatal(err)
		}
		if exited, err := launch.GUI().Exited(10 * time.Second); err != nil || !exited {
			t.Fatal("cleanup failed", err)
		}
		if err := launch.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if after := nativeHandleCount(t); after > before+1 {
		t.Fatalf("process/job/NUL/attribute handles leaked: before=%d after=%d", before, after)
	}
}
