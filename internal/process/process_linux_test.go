package process

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func platformHelper(string, []string) (int, bool) { return 0, false }
func ignoreTermination()                          { signal.Ignore(syscall.SIGTERM) }

func running(pid int) bool {
	if unix.Kill(pid, 0) != nil {
		return false
	}
	// Container PID 1 need not reap orphan zombies promptly. They cannot
	// execute or listen; direct managed children are separately wait-reaped.
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	end := strings.LastIndexByte(string(data), ')')
	return end >= 0 && !strings.HasPrefix(string(data[end+1:]), " Z ")
}

func emergencyKill(pid int) { _ = unix.Kill(pid, unix.SIGKILL) }

func resourceCount(t *testing.T) int {
	t.Helper()
	files, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal("cannot count native file descriptors")
	}
	return len(files)
}

func TestSIGTERMResistantWorkerIsKilledAndReaped(t *testing.T) {
	manager := testManager(t)
	ready := filepath.Join(t.TempDir(), "resistant.json")
	p := startHelper(t, manager, "resistant", ready)
	waitInfo(t, ready)
	if err := manager.Stop(p); err != nil {
		t.Fatal(err)
	}
	if waitProcess(t, p) != -int(unix.SIGKILL) {
		t.Fatal("SIGTERM-resistant worker did not receive final group SIGKILL")
	}
	var status unix.WaitStatus
	if _, err := unix.Wait4(p.PID(), &status, unix.WNOHANG, nil); !errors.Is(err, unix.ECHILD) {
		t.Fatal("managed direct child was not reaped")
	}
}

func TestLeaderRemainsUnreapedUntilFinalGroupKill(t *testing.T) {
	manager := testManager(t)
	directory := t.TempDir()
	childFile, parentFile := filepath.Join(directory, "child.json"), filepath.Join(directory, "parent.json")
	p := startHelper(t, manager, "tree", childFile, parentFile)
	child := waitInfo(t, childFile)
	waitInfo(t, parentFile)
	finished := make(chan error, 1)
	go func() { finished <- manager.Stop(p) }()
	if !eventually(200*time.Millisecond, func() bool {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, p.PID(), &info, unix.WEXITED|unix.WNOWAIT|unix.WNOHANG, nil)
		return err == nil && info.Signo != 0
	}) {
		t.Fatal("leader was reaped before final group cleanup or did not terminate")
	}
	if !running(child.PID) {
		t.Fatal("resistant descendant did not receive its grace interval")
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if p.Wait(ctx) != nil || !eventually(time.Second, func() bool { return !running(child.PID) }) {
		t.Fatal("group was not killed before reaping")
	}
}
