package backend

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/process"
	"github.com/0FL01/WarpPocket/internal/profile"
	"github.com/0FL01/WarpPocket/internal/storage"
)

type testWorkerControl struct {
	Mode         string
	FailAttempts int
}

type testWorkerLaunch struct {
	Args   []string
	PID    int
	Config string
	Port   int
}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "--engine" {
		os.Exit(runTestEngine())
	}
	os.Exit(m.Run())
}

// This injected same-EXE test engine uses synthetic loopback SOCKS only. Its
// test behavior is selected by a nonsecret fixture in cwd, never by extra engine
// arguments or an environment override in the backend API.
func runTestEngine() int {
	if len(os.Args) != 6 || os.Args[2] != "--role" || !model.ValidRole(os.Args[3]) || os.Args[4] != "--config" || !filepath.IsAbs(os.Args[5]) {
		return 70
	}
	cwd, _ := os.Getwd()
	if cwd != filepath.Dir(os.Args[5]) {
		return 71
	}
	config, err := os.ReadFile(os.Args[5])
	if err != nil {
		return 72
	}
	var address string
	for _, line := range strings.Split(string(config), "\n") {
		if strings.HasPrefix(line, "BindAddress = ") {
			address = strings.TrimPrefix(line, "BindAddress = ")
		}
	}
	host, rawPort, err := net.SplitHostPort(address)
	port, _ := strconv.Atoi(rawPort)
	if err != nil || host != "127.0.0.1" || port < 1 {
		return 73
	}
	var control testWorkerControl
	data, _ := os.ReadFile("worker-control.json")
	_ = json.Unmarshal(data, &control)
	previous, _ := os.ReadFile("worker-count")
	attempt, _ := strconv.Atoi(string(previous))
	attempt++
	_ = os.WriteFile("worker-count", []byte(strconv.Itoa(attempt)), 0600)
	launch, _ := json.Marshal(testWorkerLaunch{Args: os.Args, PID: os.Getpid(), Config: os.Args[5], Port: port})
	_ = os.WriteFile(fmt.Sprintf("worker-launch-%d.json", attempt), launch, 0600)
	if control.Mode == "exit" || attempt <= control.FailAttempts {
		return 12
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return 74
	}
	defer listener.Close()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return 75
		}
		if control.Mode == "exit-during-greeting" {
			var greeting [3]byte
			_, _ = io.ReadFull(connection, greeting[:])
			_ = connection.Close()
			return 13
		}
		go func() {
			defer connection.Close()
			var greeting [3]byte
			if _, err := io.ReadFull(connection, greeting[:]); err != nil {
				return
			}
			if control.Mode == "stall" {
				_, _ = io.Copy(io.Discard, connection)
				return
			}
			if control.Mode == "invalid" || greeting != [3]byte{5, 1, 0} {
				_, _ = connection.Write([]byte{5, 255})
				return
			}
			// The readiness gate must read the complete greeting, even when
			// TCP fragments its two-byte response.
			_, _ = connection.Write([]byte{5})
			time.Sleep(5 * time.Millisecond)
			_, _ = connection.Write([]byte{0})
		}()
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

func syntheticProfile() model.Profile {
	key := func(first byte) string {
		data := make([]byte, 32)
		for index := range data {
			data[index] = first + byte(index)
		}
		return base64.StdEncoding.EncodeToString(data)
	}
	return model.Profile{
		PrivateKey: key(0), Addresses: []string{"172.16.0.2/32", "2606:4700:110::1/128"},
		DNS: []string{"1.1.1.1", "2606:4700:4700::1111"}, PublicKey: key(32),
		Endpoint: model.Endpoint{Host: "127.0.0.1", Port: 9}, AllowedIPs: []string{"0.0.0.0/0", "::/0", "10.0.0.0/8"},
		MTU: 1420, Keepalive: 25, PresharedKey: key(64), Reserved: &[3]byte{7, 8, 9},
	}
}

func testBackend(t *testing.T, control testWorkerControl) (*Backend, storage.Paths, *process.Manager) {
	t.Helper()
	paths := storage.Paths{Root: filepath.Join(t.TempDir(), "WarpPocket путь with spaces")}
	if storage.PrivateDirectory(paths.Run()) != nil {
		t.Fatal("cannot create private test directory")
	}
	data, _ := json.Marshal(control)
	if err := os.WriteFile(filepath.Join(paths.Run(), "worker-control.json"), data, 0600); err != nil {
		t.Fatal("cannot write test control")
	}
	manager := process.NewManager()
	t.Cleanup(func() {
		if err := manager.Shutdown(); err != nil {
			t.Error(err)
		}
	})
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("cannot locate test executable")
	}
	return New(paths, manager, executable), paths, manager
}

func readLaunch(path string) (testWorkerLaunch, error) {
	var launch testWorkerLaunch
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &launch)
	}
	return launch, err
}

func waitLaunch(t *testing.T, paths storage.Paths, attempt int) testWorkerLaunch {
	t.Helper()
	var launch testWorkerLaunch
	if !eventually(5*time.Second, func() bool {
		var err error
		launch, err = readLaunch(filepath.Join(paths.Run(), fmt.Sprintf("worker-launch-%d.json", attempt)))
		return err == nil && launch.PID > 0
	}) {
		t.Fatal("synthetic test worker did not launch")
	}
	return launch
}

func runtimeConfigs(t *testing.T, paths storage.Paths) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(paths.Run(), "*.conf"))
	if err != nil {
		t.Fatal("cannot inspect test runtime configurations")
	}
	return files
}

func TestRuntimeDNSAndSameEXEArgumentsPreserveProfileAndIdentity(t *testing.T) {
	for _, role := range []string{model.Primary, model.Probe} {
		t.Run(role, func(t *testing.T) {
			backend, paths, _ := testBackend(t, testWorkerControl{})
			original := syntheticProfile()
			before := original.Clone()
			identity, _ := original.Identity()
			saved, err := profile.Render(original, nil)
			if err != nil {
				t.Fatal(err)
			}
			persisted, imported := filepath.Join(paths.Root, "profile.conf"), filepath.Join(paths.Root, "import.conf")
			for _, path := range []string{persisted, imported} {
				if storage.AtomicWrite(path, []byte(saved)) != nil {
					t.Fatal("cannot write synthetic profile fixture")
				}
			}
			endpoint := model.Endpoint{Host: "127.0.0.1", Port: 10}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			instance, err := backend.Start(ctx, original, endpoint, role, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = backend.Stop(instance) })
			config, err := os.ReadFile(instance.Config)
			if err != nil {
				t.Fatal("private runtime configuration missing")
			}
			expected := before.Clone()
			expected.DNS = []string{"83.220.169.155", "212.109.195.93", "194.87.196.13", "45.151.102.219", "9.9.9.9"}
			rendered, err := profile.Render(expected, &endpoint)
			if err != nil || string(config) != fmt.Sprintf("%s\n[Socks5]\nBindAddress = 127.0.0.1:%d\n\n[Resolve]\nResolveStrategy = ipv4\n", rendered, instance.Port) {
				t.Fatal("runtime config changed fields other than endpoint/DNS and loopback SOCKS sections")
			}
			afterIdentity, _ := original.Identity()
			if !reflect.DeepEqual(original, before) || identity != afterIdentity {
				t.Fatal("runtime override mutated the source profile or identity")
			}
			for _, path := range []string{persisted, imported} {
				data, err := os.ReadFile(path)
				if err != nil || string(data) != saved {
					t.Fatal("runtime start modified a saved/imported profile")
				}
			}
			launch := waitLaunch(t, paths, 1)
			if !reflect.DeepEqual(launch.Args, []string{backend.executable, "--engine", "--role", role, "--config", instance.Config}) || instance.PID() != launch.PID || instance.Endpoint != endpoint || instance.Role != role {
				t.Fatal("self-worker arguments or instance metadata are incorrect")
			}
			if strings.Contains(strings.Join(launch.Args, " "), original.PrivateKey) || strings.Contains(strings.Join(launch.Args, " "), original.PresharedKey) {
				t.Fatal("secret key reached process arguments")
			}
			if runtime.GOOS != "windows" {
				file, _ := os.Stat(instance.Config)
				directory, _ := os.Stat(paths.Run())
				if file.Mode().Perm() != 0600 || directory.Mode().Perm() != 0700 {
					t.Fatal("runtime configuration is not private")
				}
			}
			cancel()
			time.Sleep(50 * time.Millisecond)
			if !instance.Process.Alive() {
				t.Fatal("successful backend worker retained the launch context")
			}
			if backend.Stop(instance) != nil || backend.Stop(instance) != nil || len(runtimeConfigs(t, paths)) != 0 {
				t.Fatal("idempotent stop did not clean up the owned config")
			}
		})
	}
}

func TestFixedBusyPortDoesNotLaunchOrKillForeignListener(t *testing.T) {
	backend, paths, _ := testBackend(t, testWorkerControl{})
	listener, err := net.Listen("tcp4", "127.0.0.1:25344")
	if err != nil {
		t.Fatal("the fixed SOCKS test port must be available for this test")
	}
	defer listener.Close()
	instance, err := backend.Start(context.Background(), syntheticProfile(), syntheticProfile().Endpoint, model.Primary, SOCKSPort)
	if instance != nil || model.Code(err) != "port_busy" {
		t.Fatal("occupied primary port did not fail safely")
	}
	if _, err := os.Stat(filepath.Join(paths.Run(), "worker-count")); !errors.Is(err, os.ErrNotExist) || len(runtimeConfigs(t, paths)) != 0 {
		t.Fatal("occupied primary port launched a worker or wrote runtime config")
	}
	connection, err := net.DialTimeout("tcp4", "127.0.0.1:25344", time.Second)
	if err != nil {
		t.Fatal("foreign listener was disrupted")
	}
	_ = connection.Close()
}

func TestFixedPortReconnectAfterClosedSOCKSSession(t *testing.T) {
	backend, _, _ := testBackend(t, testWorkerControl{})
	for range 2 {
		instance, err := backend.Start(context.Background(), syntheticProfile(), syntheticProfile().Endpoint, model.Primary, SOCKSPort)
		if err != nil {
			t.Fatal(err)
		}
		connection, err := net.DialTimeout("tcp4", "127.0.0.1:25344", time.Second)
		if err != nil {
			t.Fatal("cannot connect to synthetic SOCKS listener")
		}
		_, _ = connection.Write([]byte{5, 1, 2})
		var response [2]byte
		_, err = io.ReadFull(connection, response[:])
		_ = connection.Close()
		if err != nil || response != [2]byte{5, 255} || backend.Stop(instance) != nil {
			t.Fatal("closed SOCKS session prevented reconnect cleanup")
		}
	}
}

func TestEphemeralRetriesExactlyThreeAndCleansFailedConfigs(t *testing.T) {
	for _, failures := range []int{2, 3} {
		t.Run(strconv.Itoa(failures), func(t *testing.T) {
			backend, paths, _ := testBackend(t, testWorkerControl{FailAttempts: failures})
			instance, err := backend.Start(context.Background(), syntheticProfile(), syntheticProfile().Endpoint, model.Probe, 0)
			if failures == 2 {
				if err != nil || instance == nil {
					t.Fatal("ephemeral worker did not retry two early exits")
				}
				if backend.Stop(instance) != nil {
					t.Fatal("cannot stop successful third attempt")
				}
			} else if instance != nil || model.Code(err) != "proxy_start_failed" {
				t.Fatal("three early exits did not fail safely")
			}
			data, _ := os.ReadFile(filepath.Join(paths.Run(), "worker-count"))
			if string(data) != "3" || len(runtimeConfigs(t, paths)) != 0 {
				t.Fatal("ephemeral retry count or per-attempt config cleanup is wrong")
			}
			seen := make(map[string]bool)
			for attempt := 1; attempt <= 3; attempt++ {
				launch := waitLaunch(t, paths, attempt)
				if seen[launch.Config] {
					t.Fatal("retry reused a private config filename")
				}
				seen[launch.Config] = true
			}
		})
	}
}

func TestFixedPortDoesNotRetryEarlyChildExit(t *testing.T) {
	backend, paths, _ := testBackend(t, testWorkerControl{Mode: "exit"})
	instance, err := backend.Start(context.Background(), syntheticProfile(), syntheticProfile().Endpoint, model.Primary, SOCKSPort)
	count, _ := os.ReadFile(filepath.Join(paths.Run(), "worker-count"))
	if instance != nil || model.Code(err) != "proxy_start_failed" || string(count) != "1" || len(runtimeConfigs(t, paths)) != 0 {
		t.Fatal("fixed listener retried or left a failed config")
	}
}

func TestStartupGreetingIsBoundedAndRejectsWrongAuthentication(t *testing.T) {
	for _, mode := range []string{"stall", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			backend, paths, _ := testBackend(t, testWorkerControl{Mode: mode})
			start := time.Now()
			instance, err := backend.Start(context.Background(), syntheticProfile(), syntheticProfile().Endpoint, model.Probe, 0)
			if instance != nil || model.Code(err) != "proxy_start_timeout" || time.Since(start) > 5*time.Second || len(runtimeConfigs(t, paths)) != 0 {
				t.Fatal("SOCKS startup did not enforce its greeting timeout and cleanup")
			}
		})
	}
}

func TestCancellationDuringStartupAndShutdownRacingStartup(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(strconv.FormatBool(shutdown), func(t *testing.T) {
			backend, paths, manager := testBackend(t, testWorkerControl{Mode: "stall"})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				instance, err := backend.Start(ctx, syntheticProfile(), syntheticProfile().Endpoint, model.Probe, 0)
				if instance != nil {
					_ = backend.Stop(instance)
					result <- errors.New("canceled startup returned a successful instance")
					return
				}
				result <- err
			}()
			waitLaunch(t, paths, 1)
			start := time.Now()
			if shutdown {
				if manager.Shutdown() != nil {
					t.Fatal("shutdown could not stop a starting worker")
				}
			} else {
				cancel()
			}
			select {
			case err := <-result:
				if err == nil || (!shutdown && !errors.Is(err, context.Canceled)) || time.Since(start) > 2*time.Second || len(runtimeConfigs(t, paths)) != 0 {
					t.Fatal("cancellation/shutdown did not promptly clean up an in-flight startup")
				}
			case <-time.After(4 * time.Second):
				t.Fatal("startup ignored cancellation or child exit")
			}
		})
	}
}

func TestChildExitDuringGreetingIsNotAStartupTimeout(t *testing.T) {
	backend, paths, _ := testBackend(t, testWorkerControl{Mode: "exit-during-greeting"})
	start := time.Now()
	instance, err := backend.Start(context.Background(), syntheticProfile(), syntheticProfile().Endpoint, model.Probe, 0)
	if instance != nil || model.Code(err) != "proxy_start_failed" || time.Since(start) > 3*time.Second || len(runtimeConfigs(t, paths)) != 0 {
		t.Fatal("child exit during greeting was not detected and cleaned up")
	}
}

func TestOnlyOwnedConfigIsRemovedAndStopIsConcurrentIdempotent(t *testing.T) {
	backend, paths, manager := testBackend(t, testWorkerControl{})
	foreign := filepath.Join(paths.Run(), "unrelated-private.conf")
	if storage.AtomicWrite(foreign, []byte("synthetic unrelated config")) != nil {
		t.Fatal("cannot write unrelated fixture")
	}
	first, err := backend.Start(context.Background(), syntheticProfile(), syntheticProfile().Endpoint, model.Primary, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := backend.Start(context.Background(), syntheticProfile(), syntheticProfile().Endpoint, model.Probe, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Stop(second) })
	owned := first.Config
	first.Config, first.Process = foreign, second.Process // public metadata is not cleanup authority
	var stopping sync.WaitGroup
	for range 8 {
		stopping.Go(func() {
			if err := backend.Stop(first); err != nil {
				t.Error(err)
			}
		})
	}
	stopping.Wait()
	if _, err := os.Stat(owned); !errors.Is(err, os.ErrNotExist) || !second.Process.Alive() {
		t.Fatal("stop did not use immutable ownership data")
	}
	if data, err := os.ReadFile(foreign); err != nil || string(data) != "synthetic unrelated config" {
		t.Fatal("disconnect cleared another runtime configuration")
	}
	if err := manager.Stop(second.Process); err != nil {
		t.Fatal(err)
	}
	if !eventually(2*time.Second, func() bool { _, err := os.Stat(second.Config); return errors.Is(err, os.ErrNotExist) }) {
		t.Fatal("automatic process exit cleanup did not remove its own config")
	}
	other := New(paths, manager, backend.executable)
	if err := other.Stop(first); model.Code(err) != "proxy_owner_invalid" {
		t.Fatal("foreign backend accepted an instance")
	}
}

func TestPreCanceledAndInvalidStartsDoNotCreateConfigs(t *testing.T) {
	backend, paths, _ := testBackend(t, testWorkerControl{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if instance, err := backend.Start(ctx, syntheticProfile(), syntheticProfile().Endpoint, model.Probe, 0); instance != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled startup was accepted")
	}
	for _, role := range []string{"../primary", "unknown"} {
		if _, err := backend.Start(context.Background(), syntheticProfile(), syntheticProfile().Endpoint, role, 0); model.Code(err) != "proxy_arguments_invalid" {
			t.Fatal("invalid role was accepted")
		}
	}
	if _, err := backend.Start(context.Background(), syntheticProfile(), syntheticProfile().Endpoint, model.Primary, 12345); model.Code(err) != "proxy_arguments_invalid" {
		t.Fatal("an arbitrary fixed listener port was accepted")
	}
	if len(runtimeConfigs(t, paths)) != 0 {
		t.Fatal("invalid/canceled startup created a runtime config")
	}
}

func TestLaunchAndPrivateConfigFailuresAreApplicationSafe(t *testing.T) {
	backend, paths, _ := testBackend(t, testWorkerControl{})
	secret := "synthetic-private-config-secret"
	backend.executable = filepath.Join(paths.Root, secret+".exe")
	if _, err := backend.Start(context.Background(), syntheticProfile(), syntheticProfile().Endpoint, model.Probe, 0); err == nil || strings.Contains(fmt.Sprintf("%+v", err), secret) || len(runtimeConfigs(t, paths)) != 0 {
		t.Fatal("failed launch exposed inputs or left a private config")
	}
	invalid := syntheticProfile()
	invalid.PrivateKey = secret
	if _, err := backend.Start(context.Background(), invalid, invalid.Endpoint, model.Probe, 0); err == nil || strings.Contains(fmt.Sprintf("%+v", err), secret) || len(runtimeConfigs(t, paths)) != 0 {
		t.Fatal("invalid profile exposed private input or created a config")
	}
}
