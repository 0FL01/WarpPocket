// Package backend starts the embedded engine in a second copy of the same
// executable. Private configuration files are the only secret-bearing input.
package backend

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/process"
	"github.com/0FL01/WarpPocket/internal/profile"
	"github.com/0FL01/WarpPocket/internal/storage"
)

const SOCKSPort = 25344

var runtimeDNS = [...]string{"83.220.169.155", "212.109.195.93", "194.87.196.13", "45.151.102.219", "9.9.9.9"}

type processManager interface {
	Start(context.Context, []string, string) (*process.Process, error)
	Stop(*process.Process) error
}

type Backend struct {
	paths      storage.Paths
	manager    processManager
	executable string
}

// New normally receives os.Executable from main; an explicit alternate
// executable is supported for offline process tests, never searched on PATH.
// Passing an empty executable also resolves the current executable.
func New(paths storage.Paths, manager *process.Manager, executable string) *Backend {
	if executable == "" {
		executable, _ = os.Executable()
	}
	b := &Backend{paths: paths, executable: executable}
	if manager != nil {
		b.manager = manager
	}
	return b
}

type Instance struct {
	Process  *process.Process
	Config   string
	Endpoint model.Endpoint
	Port     int
	Role     string

	// Cleanup uses these original values, not the mutable exported fields. A
	// caller cannot make Stop remove another instance's or a saved profile's file.
	owner        *Backend
	ownedProcess *process.Process
	ownedConfig  string
	mu           sync.Mutex
	processDone  bool
	configGone   bool
}

func (i *Instance) PID() int {
	if i == nil || i.Process == nil {
		return 0
	}
	return i.Process.PID()
}

// Start uses port 0 for a private ephemeral probe and 25344 for the primary
// loopback listener. It never kills or adopts an existing listener. The context
// covers preparation and the bounded SOCKS greeting, not the returned worker.
func (b *Backend) Start(ctx context.Context, p model.Profile, endpoint model.Endpoint, role string, port int) (*Instance, error) {
	if ctx == nil || b == nil || b.manager == nil || !model.ValidRole(role) || (port != 0 && port != SOCKSPort) {
		return nil, model.E("proxy_arguments_invalid", "Некорректные параметры сетевого компонента.")
	}
	if err := endpoint.Validate(); err != nil {
		return nil, model.E("endpoint_invalid", "Некорректный endpoint.")
	}
	if err := ctx.Err(); err != nil {
		return nil, contextError(err)
	}
	if !filepath.IsAbs(b.executable) || strings.TrimSpace(b.paths.Root) == "" {
		return nil, model.E("proxy_launch_failed", "Не удалось подготовить сетевой компонент.")
	}
	run, err := filepath.Abs(b.paths.Run())
	if err != nil || storage.PrivateDirectory(b.paths.Root) != nil || storage.PrivateDirectory(run) != nil {
		return nil, model.E("proxy_config_failed", "Не удалось подготовить личный файл сетевого компонента.")
	}
	// Clone all reference-valued fields. Neither DNS nor the endpoint override
	// changes the original imported/saved profile or its clamped identity.
	runtimeProfile := p.Clone()
	runtimeProfile.DNS = append([]string(nil), runtimeDNS[:]...)
	rendered, err := profile.Render(runtimeProfile, &endpoint)
	if err != nil {
		return nil, model.E("proxy_config_failed", "Не удалось подготовить профиль сетевого компонента.")
	}
	attempts := 1
	if port == 0 {
		attempts = 3
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, contextError(err)
		}
		instance, err, retry := b.startAttempt(ctx, run, rendered, endpoint, role, port)
		if err == nil {
			return instance, nil
		}
		if !retry || attempt == attempts-1 {
			return nil, err
		}
	}
	return nil, model.E("proxy_start_failed", "Не удалось запустить проверочный SOCKS5.")
}

func (b *Backend) startAttempt(ctx context.Context, run, rendered string, endpoint model.Endpoint, role string, port int) (*Instance, error, bool) {
	reservation, err := (&net.ListenConfig{Control: reservationControl}).Listen(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, contextError(err), false
		}
		if port == 0 {
			return nil, model.E("proxy_port_failed", "Не удалось подготовить порт SOCKS5."), false
		}
		return nil, model.E("port_busy", "Порт SOCKS5 занят другим приложением; чужой процесс не будет завершён."), false
	}
	chosenPort := reservation.Addr().(*net.TCPAddr).Port
	if reservation.Close() != nil {
		return nil, model.E("proxy_port_failed", "Не удалось подготовить порт SOCKS5."), false
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, model.E("proxy_config_failed", "Не удалось подготовить личный файл сетевого компонента."), false
	}
	config := filepath.Join(run, role+"-"+hex.EncodeToString(id[:])+".conf")
	content := fmt.Sprintf("%s\n[Socks5]\nBindAddress = 127.0.0.1:%d\n\n[Resolve]\nResolveStrategy = ipv4\n", rendered, chosenPort)
	instance := &Instance{Config: config, Endpoint: endpoint, Port: chosenPort, Role: role,
		owner: b, ownedConfig: config}
	if storage.AtomicWrite(config, []byte(content)) != nil {
		// AtomicWrite may report a directory-sync failure after replacement.
		// This exact fresh filename is ours even on that failure path.
		if cleanupErr := b.Stop(instance); cleanupErr != nil {
			return nil, cleanupErr, false
		}
		return nil, model.E("proxy_config_failed", "Не удалось записать личный файл сетевого компонента."), false
	}
	proc, err := b.manager.Start(ctx, []string{b.executable, "--engine", "--role", role, "--config", config}, run)
	instance.Process, instance.ownedProcess = proc, proc
	if err != nil || proc == nil {
		if cleanupErr := b.Stop(instance); cleanupErr != nil {
			return nil, cleanupErr, false
		}
		// Manager may retain a newly created tree after failed rollback while
		// returning no Process. Stop(nil) cannot prove that tree was cleaned up.
		if errors.Is(err, process.ErrStop) {
			return nil, cleanupError(), false
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, contextError(err), false
		}
		return nil, model.E("proxy_launch_failed", "Не удалось запустить сетевой компонент."), false
	}
	if err := awaitSOCKS(ctx, instance); err != nil {
		retry := model.Code(err) == "proxy_start_failed"
		if cleanupErr := b.Stop(instance); cleanupErr != nil {
			return nil, cleanupErr, false
		}
		return nil, err, retry
	}
	// Shutdown and natural exits clean up this instance even if its caller has
	// not yet consumed the successful result. No global runtime-directory clear.
	go func() {
		_ = proc.Wait(context.Background())
		_ = b.Stop(instance)
	}()
	return instance, nil, false
}

func awaitSOCKS(ctx context.Context, instance *Instance) error {
	startup, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(instance.Port))
	for {
		if err := ctx.Err(); err != nil {
			return contextError(err)
		}
		if !instance.ownedProcess.Alive() {
			return model.E("proxy_start_failed", "Сетевой компонент завершился при запуске.")
		}
		if startup.Err() != nil {
			return model.E("proxy_start_timeout", "SOCKS5 не запустился за отведённое время.")
		}
		connection, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(startup, "tcp4", address)
		if err == nil {
			deadline := time.Now().Add(200 * time.Millisecond)
			if end, ok := startup.Deadline(); ok && end.Before(deadline) {
				deadline = end
			}
			_ = connection.SetDeadline(deadline)
			interrupt := context.AfterFunc(startup, func() { _ = connection.Close() })
			_, writeErr := connection.Write([]byte{5, 1, 0})
			var response [2]byte
			_, readErr := io.ReadFull(connection, response[:])
			interrupt()
			_ = connection.Close()
			if writeErr == nil && readErr == nil && response == [2]byte{5, 0} {
				if err := ctx.Err(); err != nil {
					return contextError(err)
				}
				if instance.ownedProcess.Alive() {
					return nil
				}
				return model.E("proxy_start_failed", "Сетевой компонент завершился при запуске.")
			}
		}
		timer := time.NewTimer(30 * time.Millisecond)
		select {
		case <-startup.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

// Stop removes only the exact configuration allocated for this instance. It is
// idempotent and safe to race with automatic exit cleanup or another Stop.
func (b *Backend) Stop(instance *Instance) error {
	if instance == nil {
		return nil
	}
	if b == nil || instance.owner != b {
		return model.E("proxy_owner_invalid", "Сетевой компонент принадлежит другому владельцу.")
	}
	instance.mu.Lock()
	defer instance.mu.Unlock()
	var failed bool
	if !instance.processDone {
		if b.manager.Stop(instance.ownedProcess) != nil {
			failed = true
		} else {
			instance.processDone = true
		}
	}
	if !instance.configGone {
		err := os.Remove(instance.ownedConfig)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			failed = true
		} else {
			instance.configGone = true
		}
	}
	if failed {
		return cleanupError()
	}
	return nil
}

func cleanupError() error {
	return model.E("proxy_cleanup_failed", "Не удалось полностью освободить сетевой компонент.")
}

func contextError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return context.Canceled
}
