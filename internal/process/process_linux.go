package process

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type nativeProcess struct {
	process       *os.Process
	threadRelease chan struct{}
	threadDone    chan struct{}
}

func launchNative(args []string, cwd string) (*nativeProcess, error) {
	type result struct {
		process *nativeProcess
		err     error
	}
	created := make(chan result, 1)
	go func() {
		// Linux sends Pdeathsig when the creating OS thread dies, not just
		// when its process dies. Keep that thread alive for the worker's
		// complete lifetime; a short-lived Go goroutine is not sufficient.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		nul, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if err != nil {
			created <- result{err: ErrStart}
			return
		}
		child, err := os.StartProcess(args[0], args, &os.ProcAttr{
			Dir:   cwd,
			Env:   os.Environ(),
			Files: []*os.File{nul, nul, nul},
			Sys:   &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL},
		})
		_ = nul.Close()
		if err != nil {
			created <- result{err: ErrStart}
			return
		}
		native := &nativeProcess{process: child, threadRelease: make(chan struct{}), threadDone: make(chan struct{})}
		defer close(native.threadDone)
		created <- result{process: native}
		<-native.threadRelease
	}()
	r := <-created
	return r.process, r.err
}

func (p *nativeProcess) pid() int { return p.process.Pid }

func (p *nativeProcess) exited() (bool, error) {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, p.pid(), &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return info.Signo != 0, err
	}
}

func (p *nativeProcess) stop() (int, error) {
	// Do not call Process.Wait, Cmd.Wait, or waitpid before the final group
	// signal. An unreaped leader reserves its PID/PGID, even if it has exited.
	err := unix.Kill(-p.pid(), unix.SIGTERM)
	if err != nil && !errors.Is(err, unix.ESRCH) {
		return 0, ErrStop
	}
	if err == nil {
		// Descendants receive the full grace interval even when their leader
		// exits immediately or had already exited naturally.
		time.Sleep(300 * time.Millisecond)
	}
	if err := unix.Kill(-p.pid(), unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
		return 0, ErrStop
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		exited, err := p.exited()
		if err != nil {
			return 0, ErrStop
		}
		if exited {
			break
		}
		if time.Now().After(deadline) {
			return 0, ErrStop
		}
		time.Sleep(10 * time.Millisecond)
	}
	state, err := p.process.Wait()
	if err != nil {
		return 0, ErrStop
	}
	code := state.ExitCode()
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		code = -int(status.Signal())
	}
	close(p.threadRelease)
	<-p.threadDone
	return code, nil
}
