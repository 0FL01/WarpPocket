package backend_test

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0FL01/WarpPocket/internal/backend"
	"github.com/0FL01/WarpPocket/internal/controller"
	"github.com/0FL01/WarpPocket/internal/finder"
	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/process"
	"github.com/0FL01/WarpPocket/internal/storage"
)

// This external package shares backend's existing TestMain synthetic --engine
// dispatcher. It runs in the SAME test binary/group as the other fixed-25344
// tests, rather than racing them from another Go package or changing the port.
type preparedProfiles struct {
	p                  model.Profile
	prepares, reserved atomic.Int32
}

func (p *preparedProfiles) EnsureProfile(ctx context.Context, role string, consent bool) (model.Profile, error) {
	p.prepares.Add(1)
	if role != model.Primary || consent || ctx.Err() != nil {
		return model.Profile{}, model.E("profile_fixture", "Unexpected preparation.")
	}
	return p.p.Clone(), nil
}
func (p *preparedProfiles) EnsureReserved(ctx context.Context, role string) (model.Profile, error) {
	p.reserved.Add(1)
	if role != model.Primary || ctx.Err() != nil {
		return model.Profile{}, model.E("profile_fixture", "Unexpected preparation.")
	}
	return p.p.Clone(), nil
}

type ownedBackend struct {
	*backend.Backend
	mu         sync.Mutex
	instances  []*backend.Instance
	maxPrimary int
}

func (b *ownedBackend) Start(ctx context.Context, p model.Profile, endpoint model.Endpoint, role string, port int) (*backend.Instance, error) {
	i, err := b.Backend.Start(ctx, p, endpoint, role, port)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.instances = append(b.instances, i)
	primary := 0
	for _, instance := range b.instances {
		if instance.Role == model.Primary && instance.Process.Alive() {
			primary++
		}
	}
	b.maxPrimary = max(b.maxPrimary, primary)
	return i, nil
}
func (b *ownedBackend) current() *backend.Instance {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, i := range b.instances {
		if i.Role == model.Primary && i.Process.Alive() {
			return i
		}
	}
	return nil
}

func syntheticHealth(ctx context.Context, port int) (float64, error) {
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return 0, model.E("health_failed", "Synthetic SOCKS unavailable.")
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	_ = connection.SetDeadline(deadline)
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		return 0, model.E("health_failed", "Synthetic SOCKS unavailable.")
	}
	var greeting [2]byte
	if _, err := io.ReadFull(connection, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		return 0, model.E("health_failed", "Synthetic SOCKS unavailable.")
	}
	return 1, nil
}

func waitRecovery(t *testing.T, timeout time.Duration, predicate func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for {
		if predicate() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("native recovery condition timed out")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestControllerAutomaticallyReplacesOwnedNativePrimary(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	p := model.Profile{PrivateKey: key, PublicKey: key, Addresses: []string{"172.16.0.2/32"}, DNS: []string{"1.1.1.1"},
		Endpoint: model.Endpoint{Host: "127.0.0.1", Port: 9}, AllowedIPs: []string{"0.0.0.0/0"}, MTU: 1280, Reserved: &[3]byte{1, 2, 3}}
	profiles := &preparedProfiles{p: p}
	store, err := storage.New(storage.Paths{Root: filepath.Join(t.TempDir(), "Восстановление native")})
	if err != nil {
		t.Fatal(err)
	}
	manager := process.NewManager()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b := &ownedBackend{Backend: backend.New(store.Paths, manager, executable)}
	// A real process test, not virtual time: both the initial and recovered
	// worker must survive beyond their cancelled old trial deadline.
	const trialBudget = 2 * time.Second
	f := finder.New(b, syntheticHealth, finder.Options{Deadline: trialBudget})
	c := controller.New(store, profiles, b, f, manager, syntheticHealth, controller.Options{HealthInterval: 25 * time.Millisecond})
	t.Cleanup(func() {
		c.Close()
		if err := c.CloseError(); err != nil {
			t.Error(err)
		}
		if err := manager.Shutdown(); err != nil {
			t.Error(err)
		}
	})
	c.Connect(false)
	waitRecovery(t, 10*time.Second, func() bool { return c.Status().State == model.Connected && b.current() != nil })
	initial := b.current()
	initialPID := initial.PID()
	if initial.Port != 25344 {
		t.Fatal("primary used a different SOCKS port")
	}
	if err := manager.Stop(initial.Process); err != nil {
		t.Fatal(err)
	} // only this owned primary, never Controller.Disconnect
	waitRecovery(t, 10*time.Second, func() bool {
		i := b.current()
		s := c.Status()
		return i != nil && i != initial && i.PID() != initialPID && i.Port == 25344 && s.State == model.Connected && !s.Recovering && s.Endpoint == i.Endpoint
	})
	recovered := b.current()
	if err := func() error { _, err := syntheticHealth(context.Background(), 25344); return err }(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(trialBudget + 100*time.Millisecond)
	if !recovered.Process.Alive() || b.current() != recovered || c.Status().State != model.Connected || c.Status().Recovering {
		t.Fatal("old finder deadline killed the recovered native worker")
	}
	if profiles.prepares.Load() != 1 || profiles.reserved.Load() != 1 {
		t.Fatal("recovery re-entered profile/API preparation")
	}
	b.mu.Lock()
	maximum := b.maxPrimary
	all := append([]*backend.Instance(nil), b.instances...)
	b.mu.Unlock()
	if maximum != 1 {
		t.Fatal("native primary identities overlapped")
	}
	events := c.PollEvents()
	start, success := false, false
	for _, event := range events {
		start = start || event.Code == "recovery_started"
		success = success || event.Code == "recovered"
	}
	if !start || !success {
		t.Fatal("native test did not traverse recovery")
	}
	c.Close()
	for _, i := range all {
		if i.Process.Alive() {
			t.Fatal("owned native worker survived close")
		}
		if _, err := os.Stat(i.Config); !os.IsNotExist(err) {
			t.Fatal("private runtime config survived cleanup")
		}
	}
	configs, err := filepath.Glob(filepath.Join(store.Paths.Run(), "*.conf"))
	if err != nil || len(configs) != 0 {
		t.Fatal("runtime configuration cleanup failed")
	}
	connection, err := net.DialTimeout("tcp4", "127.0.0.1:25344", 200*time.Millisecond)
	if connection != nil {
		connection.Close()
	}
	if err == nil {
		t.Fatal("native SOCKS port remained open")
	}
}
