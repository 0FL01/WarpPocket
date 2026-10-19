//go:build network && linux

// Package acceptance contains explicitly opted-in tests of the shipped Go
// executable. It never registers an identity; all API methods are denied.
package acceptance

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0FL01/WarpPocket/internal/backend"
	"github.com/0FL01/WarpPocket/internal/controller"
	"github.com/0FL01/WarpPocket/internal/finder"
	"github.com/0FL01/WarpPocket/internal/health"
	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/process"
	"github.com/0FL01/WarpPocket/internal/profile"
	"github.com/0FL01/WarpPocket/internal/storage"
	"github.com/0FL01/WarpPocket/internal/trust"
	"golang.org/x/net/proxy"
)

type deniedAPI struct{ calls atomic.Int32 }

func (d *deniedAPI) Register(context.Context) (profile.Account, error) {
	d.calls.Add(1)
	return profile.Account{}, model.E("api_forbidden", "Registration is forbidden in acceptance.")
}
func (d *deniedAPI) Generate(context.Context, profile.Account) (model.Profile, error) {
	d.calls.Add(1)
	return model.Profile{}, model.E("api_forbidden", "API is forbidden in acceptance.")
}
func (d *deniedAPI) Reserved(context.Context, profile.Account) ([3]byte, error) {
	d.calls.Add(1)
	return [3]byte{}, model.E("api_forbidden", "API is forbidden in acceptance.")
}

type observed struct {
	*backend.Backend
	mu                   sync.Mutex
	instances            []*backend.Instance
	maximum              int
	maxPrimary, maxProbe int
}

// Connection keeps the actual application's 180-second candidate budget. Only
// the probe search is shortened for this opt-in observation, not the DNS or
// HTTPS health contracts (a short connection budget can cut off a valid trial).
type acceptanceFinder struct {
	*finder.Finder
	probe *finder.Finder
}

func (f acceptanceFinder) Search(ctx context.Context, p model.Profile, role string, cache model.Cache, explicit []model.Endpoint, progress finder.Progress) (finder.Outcome, error) {
	return f.probe.Search(ctx, p, role, cache, explicit, progress)
}

func (b *observed) Start(ctx context.Context, p model.Profile, e model.Endpoint, role string, port int) (*backend.Instance, error) {
	i, err := b.Backend.Start(ctx, p, e, role, port)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.instances = append(b.instances, i)
	n, primaries, probes := 0, 0, 0
	for _, instance := range b.instances {
		if instance.Process.Alive() {
			n++
			if instance.Role == model.Primary {
				primaries++
			} else if instance.Role == model.Probe {
				probes++
			}
		}
	}
	if n > b.maximum {
		b.maximum = n
	}
	b.maxPrimary = max(b.maxPrimary, primaries)
	b.maxProbe = max(b.maxProbe, probes)
	return i, nil
}

func (b *observed) workerCounts() (all, primary, probe int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.maximum, b.maxPrimary, b.maxProbe
}
func (b *observed) primary() *backend.Instance {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, i := range b.instances {
		if i.Port == backend.SOCKSPort && i.Process.Alive() {
			return i
		}
	}
	return nil
}

func await(t *testing.T, deadline time.Duration, check func() bool) {
	t.Helper()
	until := time.Now().Add(deadline)
	for time.Now().Before(until) {
		if check() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("acceptance deadline exceeded")
}

func TestExistingProfilesAutomaticRecovery(t *testing.T) {
	root, executable := os.Getenv("WARPPOCKET_E2E_DATA"), os.Getenv("WARPPOCKET_E2E_EXE")
	if root == "" || executable == "" {
		t.Skip("set explicit WARPPOCKET_E2E_DATA and WARPPOCKET_E2E_EXE to opt in")
	}
	if !filepath.IsAbs(root) || !filepath.IsAbs(executable) {
		t.Fatal("acceptance paths must be absolute")
	}
	lock, err := storage.AcquireLock(root)
	if err != nil {
		t.Fatal(model.SafeMessage(err))
	}
	defer lock.Close()
	store, err := storage.New(storage.Paths{Root: root})
	if err != nil {
		t.Fatal(model.SafeMessage(err))
	}
	api := &deniedAPI{}
	profiles := profile.NewService(store, api)
	before := map[string]string{}
	for _, role := range []string{model.Primary, model.Probe} {
		for _, name := range []string{"profile.conf", "account.toml"} {
			path := filepath.Join(store.Paths.ProfileDir(role), name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("existing private identity unavailable")
			}
			before[path] = string(data)
		}
		p, err := profiles.Load(role)
		if err != nil || p.Reserved == nil {
			t.Fatal("existing reserved profile unavailable")
		}
	}
	manager := process.NewManager()
	b := &observed{Backend: backend.New(store.Paths, manager, executable)}
	f := acceptanceFinder{Finder: finder.New(b, health.Check, finder.Options{}), probe: finder.New(b, health.Check, finder.Options{Deadline: 15 * time.Second})}
	c := controller.New(store, profiles, b, f, manager, health.Check, controller.Options{})
	report := map[string]any{"passed": false, "registration_allowed": false}
	defer func() {
		c.Close()
		_ = manager.Shutdown()
		unchanged := true
		for path, content := range before {
			now, err := os.ReadFile(path)
			unchanged = unchanged && err == nil && string(now) == content
		}
		if !unchanged {
			t.Error("private identity changed")
		}
		clean := c.CloseError() == nil
		for _, i := range b.instances {
			clean = clean && !i.Process.Alive()
		}
		configs, err := filepath.Glob(filepath.Join(store.Paths.Run(), "*.conf"))
		clean = clean && err == nil && len(configs) == 0
		conn, err := net.DialTimeout("tcp4", "127.0.0.1:25344", 200*time.Millisecond)
		if conn != nil {
			conn.Close()
		}
		clean = clean && err != nil
		if !clean {
			t.Error("owned worker/runtime/port cleanup failed")
		}
		if api.calls.Load() != 0 {
			t.Error("acceptance attempted a forbidden API call")
		}
		maximum, maxPrimary, maxProbe := b.workerCounts()
		if maximum > 2 || maxPrimary > 1 || maxProbe > 1 {
			t.Error("primary/probe identity workers overlapped")
		}
		report["profiles_unchanged"], report["cleanup_verified"], report["max_workers"] = unchanged, clean, maximum
		report["max_primary"], report["max_probe"] = maxPrimary, maxProbe
		report["passed"] = !t.Failed()
		data, _ := json.MarshalIndent(report, "", "  ")
		if storage.AtomicWrite(filepath.Join(root, "autorecovery-gate-2026-10-19.json"), data) != nil {
			t.Error("safe report write failed")
		}
		t.Log(string(data))
	}()
	c.Connect(false)
	await(t, 190*time.Second, func() bool { return c.Status().State != model.Connecting && !c.Status().Busy })
	if c.Status().State != model.Connected {
		t.Fatal("primary verification failed: " + c.Status().Code)
	}
	primary := b.primary()
	if primary == nil {
		t.Fatal("verified primary missing")
	}
	pid := primary.PID()
	report["primary_endpoint"] = primary.Endpoint.String()
	// Keep one verified HTTPS connection alive across the probe. Calling Check
	// for each packet would instead open fresh DNS/TLS connections and would not
	// prove that an existing primary stream survives worker churn.
	continuous, roundTrip, dialCount := continuousPrimary(t, primary.Port)
	defer continuous.CloseIdleConnections()
	if err := roundTrip(context.Background()); err != nil {
		t.Fatal("initial continuous primary HTTPS failed")
	}
	var requests, failures atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			err := roundTrip(ctx)
			if ctx.Err() != nil {
				return
			}
			requests.Add(1)
			if err != nil {
				failures.Add(1)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
	}()
	defer func() { cancel(); <-done }()
	started := time.Now()
	c.StartSearch(false)
	await(t, 25*time.Second, func() bool { return !c.Status().Searching })
	cancel()
	<-done
	report["primary_requests"], report["primary_failures"], report["search_seconds"] = requests.Load(), failures.Load(), time.Since(started).Seconds()
	report["primary_stream_connections"] = dialCount.Load()
	maximum, maxPrimary, maxProbe := b.workerCounts()
	if requests.Load() == 0 || failures.Load() != 0 || dialCount.Load() != 1 || maximum > 2 || maxPrimary > 1 || maxProbe > 1 {
		t.Fatal("probe disrupted primary traffic/ownership")
	}
	if b.primary() != primary || primary.PID() != pid || c.Status().State != model.Connected {
		t.Fatal("probe replaced the primary")
	}
	saved := false
	for _, event := range c.PollEvents() {
		if event.Type == "search_done" && event.Saved {
			saved = true
		}
	}
	if !saved {
		t.Fatal("successful probe result was not persisted")
	}
	report["primary_preserved"], report["probe_saved"] = true, true
	for _, host := range []string{"ya.ru", "vk.com"} {
		proveDirect(t, primary, host)
	}
	if _, err := health.Check(context.Background(), primary.Port); err != nil {
		t.Fatal("final WARP/independent HTTPS failed")
	}
	report["direct_host_socket_proof"], report["ip_only_stays_warp"] = true, true

	// Probe continuity and routing above deliberately precede the restart. A
	// worker's TCP sessions cannot migrate; prove a NEW verified primary instead
	// of accepting the stale Connected snapshot immediately after process exit.
	continuous.CloseIdleConnections()
	started = time.Now()
	if err := manager.Stop(primary.Process); err != nil {
		t.Fatal("could not stop the owned primary for recovery")
	}
	await(t, 250*time.Second, func() bool {
		next, status := b.primary(), c.Status()
		return next != nil && next != primary && next.PID() != pid && next.Port == backend.SOCKSPort &&
			status.State == model.Connected && !status.Recovering && status.Endpoint == next.Endpoint
	})
	recovered := b.primary()
	if recovered == nil || primary.Process.Alive() {
		t.Fatal("primary replacement was not exclusive")
	}
	if _, err := health.Check(context.Background(), recovered.Port); err != nil {
		t.Fatal("recovered WARP/independent HTTPS failed")
	}
	recoveryStarted, recoverySucceeded := false, false
	for _, event := range c.PollEvents() {
		recoveryStarted = recoveryStarted || event.Code == "recovery_started"
		recoverySucceeded = recoverySucceeded || event.Code == "recovered"
	}
	if !recoveryStarted || !recoverySucceeded {
		t.Fatal("the new primary did not traverse automatic recovery")
	}
	maximum, maxPrimary, maxProbe = b.workerCounts()
	if maximum > 2 || maxPrimary > 1 || maxProbe > 1 {
		t.Fatal("recovery exceeded identity worker limits")
	}
	report["automatic_recovery"], report["recovered_new_pid"], report["fixed_port_preserved"], report["recovered_https"] = true, true, true, true
	report["recovered_endpoint"], report["recovery_seconds"] = recovered.Endpoint.String(), time.Since(started).Seconds()
}

func continuousPrimary(t *testing.T, port int) (*http.Transport, func(context.Context) error, *atomic.Int32) {
	t.Helper()
	pool, err := trust.Pool()
	if err != nil {
		t.Fatal("embedded trust unavailable")
	}
	dial, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil, &net.Dialer{Timeout: 7 * time.Second})
	if err != nil {
		t.Fatal("explicit SOCKS client unavailable")
	}
	calls := &atomic.Int32{}
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 7 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		MaxConnsPerHost: 1, IdleConnTimeout: 90 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			calls.Add(1)
			return dial.(proxy.ContextDialer).DialContext(ctx, network, address)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(ctx context.Context) error {
		req, _ := http.NewRequestWithContext(ctx, "GET", health.TraceURL, nil)
		response, err := client.Do(req)
		if err != nil {
			return model.E("primary_stream_failed", "Primary HTTPS failed.")
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		if err != nil || len(data) > 16384 || response.StatusCode != 200 {
			return model.E("primary_stream_failed", "Invalid primary HTTPS response.")
		}
		count, valid := 0, false
		for _, line := range strings.Split(string(data), "\n") {
			key, value, _ := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
			if key == "warp" {
				count++
				valid = value == "on" || value == "plus"
			}
		}
		if count != 1 || !valid {
			return model.E("primary_stream_failed", "Primary stream is not WARP.")
		}
		return nil
	}
	return transport, request, calls
}

// This Linux opt-in proof inspects actual sockets owned by the engine rather
// than confusing an HTTP status, local proxy connection or synthetic dial with
// DIRECT transport. There are no system resolver calls.
func hostSockets(t *testing.T, pid int) map[string]string {
	t.Helper()
	owned := map[string]bool{}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatal("engine socket inspection unavailable")
	}
	for _, e := range entries {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, e.Name()))
		if err == nil && strings.HasPrefix(link, "socket:[") {
			owned[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
		}
	}
	result := map[string]string{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("kernel TCP table unavailable")
		}
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) < 10 || f[3] != "01" || !owned[f[9]] {
				continue
			}
			remote := strings.Split(f[2], ":")
			if len(remote) != 2 || remote[1] != "01BB" {
				continue
			}
			raw, err := hex.DecodeString(remote[0])
			if err != nil {
				t.Fatal("invalid kernel socket address")
			}
			for offset := 0; offset < len(raw); offset += 4 {
				raw[offset], raw[offset+3] = raw[offset+3], raw[offset]
				raw[offset+1], raw[offset+2] = raw[offset+2], raw[offset+1]
			}
			result[f[9]] = net.IP(raw).String()
		}
	}
	return result
}
func proveDirect(t *testing.T, primary *backend.Instance, host string) {
	t.Helper()
	dial, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(primary.Port)), nil, &net.Dialer{Timeout: 15 * time.Second})
	if err != nil {
		t.Fatal("SOCKS client setup failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	before := hostSockets(t, primary.PID())
	connection, err := dial.(proxy.ContextDialer).DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		// These are fixed public fixture hostnames and SOCKS protocol errors,
		// never account/config input or raw engine logs.
		t.Fatalf("DIRECT SOCKS connect to %s failed: %v", host, err)
	}
	defer connection.Close()
	after := hostSockets(t, primary.PID())
	target := ""
	for inode, ip := range after {
		if _, exists := before[inode]; !exists {
			if target != "" {
				t.Fatal("multiple new host connections")
			}
			target = ip
		}
	}
	if target == "" {
		t.Fatal("DIRECT did not create an engine-owned host TCP connection")
	}
	ipConnection, err := dial.(proxy.ContextDialer).DialContext(ctx, "tcp", net.JoinHostPort(target, "443"))
	if err != nil {
		t.Fatal("IP-only WARP connect failed")
	}
	defer ipConnection.Close()
	if len(hostSockets(t, primary.PID())) != len(after) {
		t.Fatal("IP-only request escaped WARP")
	}
	pool, err := trust.Pool()
	if err != nil {
		t.Fatal("embedded trust unavailable")
	}
	secure := tls.Client(connection, &tls.Config{ServerName: host, RootCAs: pool, MinVersion: tls.VersionTLS12})
	if secure.HandshakeContext(ctx) != nil {
		t.Fatal("DIRECT TLS verification failed")
	}
	_ = secure.SetDeadline(time.Now().Add(10 * time.Second))
	request, _ := http.NewRequest("HEAD", "https://"+host+"/", nil)
	if request.Write(secure) != nil {
		t.Fatal("DIRECT request failed")
	}
	line, err := bufio.NewReader(io.LimitReader(secure, 4096)).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/") {
		t.Fatal("DIRECT HTTPS response missing")
	}
}
