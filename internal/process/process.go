// Package process owns output-silent worker process trees. A successful Start
// transfers ownership to the caller, not to the launch context. Shutdown remains
// responsible for every process until its tree has been stopped and reaped.
package process

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// These errors deliberately contain no executable paths, arguments, environment
// values, operating-system error strings, or child output.
var (
	ErrArguments   = errors.New("Invalid managed process arguments.")
	ErrShutdown    = errors.New("The process manager has been shut down.")
	ErrStart       = errors.New("Unable to start the managed process.")
	ErrStop        = errors.New("Unable to stop the managed process tree.")
	ErrOwner       = errors.New("The process belongs to a different manager.")
	ErrUnsupported = errors.New("Managed processes are not supported on this platform.")
)

// Manager serializes creation, ownership transfer, cleanup, and permanent
// shutdown. Its zero value is usable, although NewManager is preferred.
type Manager struct {
	mu        sync.Mutex
	processes map[*Process]struct{}
	shutdown  bool
}

func NewManager() *Manager { return &Manager{processes: make(map[*Process]struct{})} }

// Process is an owned process tree, not just its leader. Never reap its leader
// externally: on POSIX the unreaped PID reserves the process-group identifier.
type Process struct {
	owner    *Manager
	pid      int
	native   *nativeProcess
	done     chan struct{}
	stopped  bool
	exitCode int
}

// Start launches an absolute executable without a shell or an environment
// override. Standard input, output and error are connected only to NUL.
// Cancellation observed before ownership transfer stops and reaps the child;
// cancellation after a successful return does not terminate it.
func (m *Manager) Start(ctx context.Context, args []string, cwd string) (*Process, error) {
	if ctx == nil || len(args) == 0 || !filepath.IsAbs(args[0]) || strings.ContainsRune(cwd, 0) {
		return nil, ErrArguments
	}
	args = append([]string(nil), args...)
	for _, arg := range args {
		if strings.ContainsRune(arg, 0) {
			return nil, ErrArguments
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shutdown {
		return nil, ErrShutdown
	}
	if err := ctx.Err(); err != nil {
		return nil, launchContextError(err)
	}
	native, err := launchNative(args, cwd)
	if err != nil {
		if errors.Is(err, ErrUnsupported) {
			return nil, ErrUnsupported
		}
		return nil, ErrStart
	}
	p := &Process{owner: m, pid: native.pid(), native: native, done: make(chan struct{})}
	if m.processes == nil {
		m.processes = make(map[*Process]struct{})
	}
	m.processes[p] = struct{}{}
	if err := ctx.Err(); err != nil {
		if m.stopLocked(p) != nil {
			// A failed cleanup stays owned so Shutdown can retry it.
			go p.monitor()
			return nil, ErrStop
		}
		return nil, launchContextError(err)
	}
	go p.monitor()
	return p, nil
}

// Do not return arbitrary errors supplied by a custom Context implementation.
func launchContextError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return context.Canceled
}

func (p *Process) PID() int {
	if p == nil {
		return 0
	}
	return p.pid
}

// Alive also notices a natural leader exit and cleans up remaining descendants.
func (p *Process) Alive() bool {
	if p == nil || p.owner == nil {
		return false
	}
	m := p.owner
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.stopped {
		return false
	}
	exited, err := p.native.exited()
	if err != nil {
		// Fail closed to callers, retaining ownership for cleanup retry.
		_ = m.stopLocked(p)
		return false
	}
	if exited {
		_ = m.stopLocked(p)
		return false
	}
	return true
}

// Wait waits for the entire owned tree to be cleaned up, without holding the
// ownership lock. A nonzero child exit is available through ExitCode, and is not
// itself a wait error. Canceling Wait never stops the process.
func (p *Process) Wait(ctx context.Context) error {
	if p == nil || p.owner == nil || ctx == nil {
		return ErrArguments
	}
	select {
	case <-p.done:
		return nil
	default:
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return launchContextError(ctx.Err())
	}
}

func (p *Process) ExitCode() (int, bool) {
	if p == nil || p.owner == nil {
		return 0, false
	}
	p.owner.mu.Lock()
	defer p.owner.mu.Unlock()
	return p.exitCode, p.stopped
}

func (p *Process) monitor() {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			_ = p.Alive()
		}
	}
}

// Stop is idempotent; it never signals a PID or job owned by another manager.
func (m *Manager) Stop(p *Process) error {
	if p == nil {
		return nil
	}
	if p.owner != m {
		return ErrOwner
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked(p)
}

func (m *Manager) stopLocked(p *Process) error {
	if p.stopped {
		return nil
	}
	code, err := p.native.stop()
	if err != nil {
		return ErrStop
	}
	p.exitCode = code
	p.stopped = true
	delete(m.processes, p)
	close(p.done)
	return nil
}

// Shutdown rejects all future starts, including starts racing this operation,
// and tries every owned process even if a previous cleanup fails. Another call
// retries failures rather than dropping ownership.
func (m *Manager) Shutdown() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shutdown = true
	var failed bool
	for p := range m.processes {
		if m.stopLocked(p) != nil {
			failed = true
		}
	}
	if failed {
		return ErrStop
	}
	return nil
}
