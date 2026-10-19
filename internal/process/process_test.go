//go:build linux || windows

package process

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const helperMarker = "--warppocket-process-test"

type helperInfo struct {
	PID   int
	Port  int
	Stdin string
	CWD   string
	Arg   string
	Env   string
}

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == helperMarker {
		os.Exit(runHelper(os.Args[2], os.Args[3:]))
	}
	os.Exit(m.Run())
}

func runHelper(mode string, args []string) int {
	if code, handled := platformHelper(mode, args); handled {
		return code
	}
	writeInfo := func(path string, info helperInfo) bool {
		data, err := json.Marshal(info)
		return err == nil && os.WriteFile(path, data, 0600) == nil
	}
	switch mode {
	case "exit":
		code, _ := strconv.Atoi(args[0])
		return code
	case "stdio":
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			return 80
		}
		cwd, _ := os.Getwd()
		fmt.Fprintln(os.Stdout, "child output must never be captured")
		fmt.Fprintln(os.Stderr, "child error output must never be captured")
		if !writeInfo(args[0], helperInfo{PID: os.Getpid(), Stdin: string(input), CWD: cwd, Arg: args[1], Env: os.Getenv("WARPPOCKET_PROCESS_TEST")}) {
			return 81
		}
		return 7
	case "sleep", "resistant":
		if mode == "resistant" {
			ignoreTermination()
		}
		if !writeInfo(args[0], helperInfo{PID: os.Getpid()}) {
			return 82
		}
	case "listener":
		ignoreTermination()
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return 83
		}
		defer listener.Close()
		if !writeInfo(args[0], helperInfo{PID: os.Getpid(), Port: listener.Addr().(*net.TCPAddr).Port}) {
			return 84
		}
		for {
			connection, err := listener.Accept()
			if err != nil {
				return 85
			}
			_ = connection.Close()
		}
	case "tree", "orphan":
		executable, _ := os.Executable()
		child := exec.Command(executable, helperMarker, "listener", args[0])
		prepareTestDescendant(child)
		if child.Start() != nil {
			return 86
		}
		if !eventually(5*time.Second, func() bool { _, err := readInfo(args[0]); return err == nil }) {
			return 87
		}
		if !writeInfo(args[1], helperInfo{PID: os.Getpid()}) {
			return 88
		}
		if mode == "orphan" {
			return 12
		}
	case "owner":
		executable, _ := os.Executable()
		manager := NewManager()
		if _, err := manager.Start(context.Background(), append([]string{executable, helperMarker}, args...), ""); err != nil {
			return 89
		}
	default:
		return 90
	}
	for {
		time.Sleep(time.Second)
	}
}

func eventually(timeout time.Duration, predicate func() bool) bool {
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		if predicate() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return predicate()
}

func readInfo(path string) (helperInfo, error) {
	var info helperInfo
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &info)
	}
	return info, err
}

func waitInfo(t *testing.T, path string) helperInfo {
	t.Helper()
	var info helperInfo
	if !eventually(5*time.Second, func() bool {
		var err error
		info, err = readInfo(path)
		return err == nil && info.PID > 0
	}) {
		t.Fatal("test worker did not become ready")
	}
	return info
}

func self(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("cannot locate test executable")
	}
	return executable
}

func testManager(t *testing.T) *Manager {
	t.Helper()
	manager := NewManager()
	t.Cleanup(func() {
		if err := manager.Shutdown(); err != nil {
			t.Error(err)
		}
	})
	return manager
}

func startHelper(t *testing.T, manager *Manager, mode string, args ...string) *Process {
	t.Helper()
	p, err := manager.Start(context.Background(), append([]string{self(t), helperMarker, mode}, args...), "")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func waitProcess(t *testing.T, p *Process) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := p.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	code, ok := p.ExitCode()
	if !ok || p.Alive() {
		t.Fatal("completed process has no exit code or is still alive")
	}
	return code
}

func listening(port int) bool {
	connection, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func TestSilentStdioCWDInheritedEnvironmentAndLiteralArguments(t *testing.T) {
	manager := testManager(t)
	directory := t.TempDir()
	result := filepath.Join(directory, "result.json")
	literal := "literal ; & \" quoted \\ путь with spaces"
	t.Setenv("WARPPOCKET_PROCESS_TEST", "inherited-test-marker")
	p, err := manager.Start(context.Background(), []string{self(t), helperMarker, "stdio", result, literal}, directory)
	if err != nil {
		t.Fatal(err)
	}
	if p.PID() <= 0 || waitProcess(t, p) != 7 {
		t.Fatal("wrong PID or exit code")
	}
	info, err := readInfo(result)
	if err != nil || info.Stdin != "" || info.Arg != literal || info.CWD != directory || info.Env != "inherited-test-marker" {
		t.Fatal("stdio, working directory, inherited environment, or literal argv changed")
	}
	if err := manager.Stop(p); err != nil {
		t.Fatal(err)
	}
}

func TestStopEntireTreeAndReconnect(t *testing.T) {
	manager := testManager(t)
	directory := t.TempDir()
	childFile, parentFile := filepath.Join(directory, "child.json"), filepath.Join(directory, "parent.json")
	p := startHelper(t, manager, "tree", childFile, parentFile)
	child := waitInfo(t, childFile)
	parent := waitInfo(t, parentFile)
	if parent.PID != p.PID() || !listening(child.Port) {
		t.Fatal("test tree not listening")
	}
	for range 3 {
		if err := manager.Stop(p); err != nil {
			t.Fatal(err)
		}
	}
	waitProcess(t, p)
	if running(p.PID()) || !eventually(5*time.Second, func() bool { return !running(child.PID) && !listening(child.Port) }) {
		t.Fatal("owned tree survived stop")
	}
	if waitProcess(t, startHelper(t, manager, "exit", "0")) != 0 {
		t.Fatal("manager could not reconnect")
	}
}

func TestNaturalLeaderExitCleansDescendantsWithoutExplicitWait(t *testing.T) {
	manager := testManager(t)
	directory := t.TempDir()
	childFile, parentFile := filepath.Join(directory, "child.json"), filepath.Join(directory, "parent.json")
	p := startHelper(t, manager, "orphan", childFile, parentFile)
	child := waitInfo(t, childFile)
	if !eventually(8*time.Second, func() bool { _, done := p.ExitCode(); return done }) {
		t.Fatal("natural exit was not automatically reaped")
	}
	if waitProcess(t, p) != 12 || !eventually(5*time.Second, func() bool { return !running(child.PID) && !listening(child.Port) }) {
		t.Fatal("natural leader exit left its descendant alive")
	}
}

func TestWaitCancellationDoesNotStopAndStopInterruptsWait(t *testing.T) {
	manager := testManager(t)
	ready := filepath.Join(t.TempDir(), "ready.json")
	p := startHelper(t, manager, "sleep", ready)
	waitInfo(t, ready)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := p.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) || !p.Alive() {
		t.Fatal("waiting cancellation stopped the worker or was not reported")
	}
	waiting := make(chan error, 1)
	go func() { waiting <- p.Wait(context.Background()) }()
	if err := manager.Stop(p); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waiting:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("stop could not interrupt wait")
	}
}

func TestCancellationBeforeLaunchAndAfterOwnershipTransfer(t *testing.T) {
	manager := testManager(t)
	ready := filepath.Join(t.TempDir(), "ready.json")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, err := manager.Start(ctx, []string{self(t), helperMarker, "sleep", ready}, ""); p != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled launch was accepted")
	}
	if _, err := os.Stat(ready); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pre-canceled launch executed a child")
	}
	ctx, cancel = context.WithCancel(context.Background())
	p, err := manager.Start(ctx, []string{self(t), helperMarker, "sleep", ready}, "")
	if err != nil {
		t.Fatal(err)
	}
	waitInfo(t, ready)
	cancel()
	time.Sleep(50 * time.Millisecond)
	if !p.Alive() {
		t.Fatal("launch context retained ownership after a successful return")
	}
}

type cancelDuringLaunch struct {
	context.Context
	cancel context.CancelFunc
	ready  string
	checks atomic.Int32
}

func (c *cancelDuringLaunch) Err() error {
	if c.checks.Add(1) == 2 {
		_ = eventually(5*time.Second, func() bool { _, err := readInfo(c.ready); return err == nil })
		c.cancel()
	}
	return c.Context.Err()
}

func TestCancellationDuringRealNativeLaunchCleansCreatedChild(t *testing.T) {
	manager := testManager(t)
	ready := filepath.Join(t.TempDir(), "canceled.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	launch := &cancelDuringLaunch{Context: ctx, cancel: cancel, ready: ready}
	p, err := manager.Start(launch, []string{self(t), helperMarker, "sleep", ready}, "")
	if p != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("launch canceled after native creation was accepted")
	}
	info := waitInfo(t, ready)
	if running(info.PID) {
		t.Fatal("canceled launch left an executing child")
	}
	manager.mu.Lock()
	owned := len(manager.processes)
	manager.mu.Unlock()
	if owned != 0 || waitProcess(t, startHelper(t, manager, "exit", "0")) != 0 {
		t.Fatal("failed launch retained a reaped child or poisoned ownership")
	}
}

func TestInvalidAndFailedLaunchErrorsAreRedacted(t *testing.T) {
	manager := testManager(t)
	for _, args := range [][]string{nil, {}, {"relative-helper"}, {self(t), "invalid\x00argument"}} {
		if _, err := manager.Start(context.Background(), args, ""); !errors.Is(err, ErrArguments) {
			t.Fatal("invalid launch arguments accepted")
		}
	}
	secret := "private-config-secret"
	if _, err := manager.Start(context.Background(), []string{filepath.Join(t.TempDir(), secret), secret}, ""); err == nil || strings.Contains(fmt.Sprintf("%+v", err), secret) {
		t.Fatal("failed launch error was missing or exposed input")
	}
	if waitProcess(t, startHelper(t, manager, "exit", "0")) != 0 {
		t.Fatal("failed launch poisoned manager")
	}
}

func TestShutdownStopsTreeAndPermanentlyRejectsLaunches(t *testing.T) {
	manager := testManager(t)
	directory := t.TempDir()
	childFile, parentFile := filepath.Join(directory, "child.json"), filepath.Join(directory, "parent.json")
	p := startHelper(t, manager, "tree", childFile, parentFile)
	child := waitInfo(t, childFile)
	waitInfo(t, parentFile)
	for range 2 {
		if err := manager.Shutdown(); err != nil {
			t.Fatal(err)
		}
	}
	waitProcess(t, p)
	if !eventually(5*time.Second, func() bool { return !running(child.PID) && !listening(child.Port) }) {
		t.Fatal("shutdown left a descendant alive")
	}
	if _, err := manager.Start(context.Background(), []string{self(t), helperMarker, "exit", "0"}, ""); !errors.Is(err, ErrShutdown) {
		t.Fatal("shutdown manager accepted another launch")
	}
}

func TestLaunchShutdownOwnershipRace(t *testing.T) {
	executable := self(t)
	for range 4 {
		manager := testManager(t)
		barrier := make(chan struct{})
		var workers sync.WaitGroup
		var mu sync.Mutex
		var created []*Process
		var unexpected []error
		for index := range 4 {
			ready := filepath.Join(t.TempDir(), strconv.Itoa(index)+".json")
			workers.Go(func() {
				<-barrier
				p, err := manager.Start(context.Background(), []string{executable, helperMarker, "sleep", ready}, "")
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					created = append(created, p)
				} else if !errors.Is(err, ErrShutdown) {
					unexpected = append(unexpected, err)
				}
			})
		}
		close(barrier)
		if err := manager.Shutdown(); err != nil {
			t.Fatal(err)
		}
		workers.Wait()
		if len(unexpected) != 0 {
			t.Fatal("launch/shutdown race returned an unexpected error")
		}
		for _, p := range created {
			waitProcess(t, p)
			if running(p.PID()) {
				t.Fatal("launch racing shutdown escaped ownership")
			}
		}
	}
}

type transferBarrierContext struct {
	context.Context
	checks  atomic.Int32
	created chan struct{}
	release chan struct{}
}

func (c *transferBarrierContext) Err() error {
	if c.checks.Add(1) == 2 {
		close(c.created)
		<-c.release
	}
	return nil
}

func TestShutdownCannotMissChildCreatedDuringLaunch(t *testing.T) {
	manager := testManager(t)
	ctx := &transferBarrierContext{Context: context.Background(), created: make(chan struct{}), release: make(chan struct{})}
	type startResult struct {
		process *Process
		err     error
	}
	started := make(chan startResult, 1)
	executable, ready := self(t), filepath.Join(t.TempDir(), "ready.json")
	go func() {
		p, err := manager.Start(ctx, []string{executable, helperMarker, "sleep", ready}, "")
		started <- startResult{p, err}
	}()
	select {
	case <-ctx.created:
	case <-time.After(5 * time.Second):
		close(ctx.release)
		t.Fatal("native launch did not reach its ownership transfer barrier")
	}
	shutdown := make(chan error, 1)
	go func() { shutdown <- manager.Shutdown() }()
	select {
	case <-shutdown:
		close(ctx.release)
		t.Fatal("shutdown escaped ownership serialization during creation")
	case <-time.After(30 * time.Millisecond):
	}
	close(ctx.release)
	result := <-started
	if result.err != nil || result.process == nil {
		t.Fatal("serialized real native launch unexpectedly failed")
	}
	if err := <-shutdown; err != nil {
		t.Fatal(err)
	}
	waitProcess(t, result.process)
	if running(result.process.PID()) {
		t.Fatal("shutdown missed a child created concurrently with launch")
	}
}

func TestConcurrentStopAndWaitAreIdempotent(t *testing.T) {
	manager := testManager(t)
	ready := filepath.Join(t.TempDir(), "ready.json")
	p := startHelper(t, manager, "sleep", ready)
	waitInfo(t, ready)
	var stopping sync.WaitGroup
	for range 8 {
		stopping.Go(func() {
			if err := manager.Stop(p); err != nil {
				t.Error(err)
			}
			if err := p.Wait(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	stopping.Wait()
	waitProcess(t, p)
}

func TestDifferentManagerCannotStopProcess(t *testing.T) {
	manager, other := testManager(t), testManager(t)
	ready := filepath.Join(t.TempDir(), "ready.json")
	p := startHelper(t, manager, "sleep", ready)
	waitInfo(t, ready)
	if err := other.Stop(p); !errors.Is(err, ErrOwner) || !p.Alive() {
		t.Fatal("foreign manager stopped owned process")
	}
}

func TestNativeResourcesCloseAfterSuccessfulAndFailedLaunches(t *testing.T) {
	manager := testManager(t)
	waitProcess(t, startHelper(t, manager, "exit", "0")) // initialize lazy native/runtime resources
	before := resourceCount(t)
	for range 8 {
		if _, err := manager.Start(context.Background(), []string{filepath.Join(t.TempDir(), "missing-helper.exe")}, ""); err == nil {
			t.Fatal("missing executable launched")
		}
		p := startHelper(t, manager, "exit", "0")
		if waitProcess(t, p) != 0 || manager.Stop(p) != nil {
			t.Fatal("successful launch cleanup failed")
		}
	}
	if after := resourceCount(t); after > before+2 {
		t.Fatalf("native resources leaked: before=%d after=%d", before, after)
	}
}

func TestOwnerCrashKillsWorkerBeforeEmergencyCleanup(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "worker.json")
	owner := exec.Command(self(t), helperMarker, "owner", "sleep", ready)
	if err := owner.Start(); err != nil {
		t.Fatal("cannot launch crash-test owner")
	}
	var worker helperInfo
	defer func() {
		_ = owner.Process.Kill()
		_ = owner.Wait()
		if worker.PID > 0 && running(worker.PID) {
			emergencyKill(worker.PID)
		}
	}()
	worker = waitInfo(t, ready)
	if err := owner.Process.Kill(); err != nil {
		t.Fatal("cannot crash test owner")
	}
	_ = owner.Wait()
	if !eventually(5*time.Second, func() bool { return !running(worker.PID) }) {
		t.Fatal("worker survived owner crash; checked before emergency cleanup")
	}
}
