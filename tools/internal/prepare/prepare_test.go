package prepare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNativePreparationEnvironmentAndGates(t *testing.T) {
	root, p, calls := mockPreparation(t, "")
	result, err := p.prepare(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if result.Wireproxy != filepath.Join(root, "build", "deps", "wireproxy") || result.Wireguard != filepath.Join(root, "build", "deps", "wireguard-go") || result.Patch != supportedPatch {
		t.Fatalf("wrong result: %+v", result)
	}
	if len(*calls) != 5 {
		t.Fatalf("wrong commands: %+v", *calls)
	}
	for index, call := range *calls {
		if !isWithin(filepath.Join(root, "build", "deps"), call.Dir) || !strings.Contains(call.Dir, string(filepath.Separator)+".prepare-") {
			t.Fatalf("command ran outside isolated sources: %+v", call)
		}
		for key, want := range map[string]string{
			"CGO_ENABLED": "0", "GOFLAGS": "-mod=mod", "GOWORK": "off", "GOMODCACHE": filepath.Join(root, "build", "deps", ".gomodcache"),
		} {
			if got := envValue(call.Env, key); got != want {
				t.Errorf("command %d %s = %q, want %q", index, key, got, want)
			}
		}
		if index > 0 && (envValue(call.Env, "GOOS") != "linux" || envValue(call.Env, "GOARCH") != "amd64") {
			t.Errorf("command %d used cross target instead of native host", index)
		}
	}
	wantCommands := [][]string{
		{"go", "env", "GOHOSTOS", "GOHOSTARCH"},
		{"go", "mod", "download", "-json", wireguardModule + "@" + testPins(t).Wireguard.Version},
		{"go", "test", "./tun/netstack", "-run", "^TestWarpPocketDNS", "-count=1", "-v"},
		{"go", "test", ".", "./cmd/wireproxy", "-run", "^TestWarpPocketRouting", "-count=1", "-v"},
		{"go", "test", ".", "-run", "^TestWarpPocketJunk", "-count=1", "-v"},
	}
	for index, want := range wantCommands {
		if !reflect.DeepEqual((*calls)[index].Args, want) {
			t.Errorf("command %d = %v, want %v", index, (*calls)[index].Args, want)
		}
	}
	if filepath.Base((*calls)[2].Dir) != "wireguard-go" || filepath.Base((*calls)[3].Dir) != "wireproxy" || filepath.Base((*calls)[4].Dir) != "wireproxy" {
		t.Fatal("native gates ran in the wrong modules")
	}
	assertFile(t, filepath.Join(result.Wireguard, "tun", "netstack", "warppocket_dns.go"), mustPayload(t, "wireproxy_dns.go.txt"))
	assertFile(t, filepath.Join(result.Wireproxy, "cmd", "wireproxy", "warppocket_worker_test.go"), mustPayload(t, "wireproxy_worker_test.go.txt"))
	assertFile(t, filepath.Join(result.Wireproxy, "warppocket_junk.go"), mustPayload(t, "wireproxy_junk.go.txt"))
	assertFile(t, filepath.Join(result.Wireproxy, "warppocket_junk_test.go"), mustPayload(t, "wireproxy_junk_test.go.txt"))
	if _, err := p.prepare(context.Background(), root); err != nil {
		t.Fatalf("repeat preparation is not safe/idempotent: %v", err)
	}
	stages, err := filepath.Glob(filepath.Join(root, "build", "deps", ".prepare-*"))
	if err != nil || len(stages) != 0 {
		t.Fatalf("preparation left temporary sources: %v, %v", stages, err)
	}
}

func TestNativeGateFailureAbortsPublication(t *testing.T) {
	for _, gate := range []string{"native DNS tests", "native routing tests", "native junk tests"} {
		t.Run(gate, func(t *testing.T) {
			root, p, calls := mockPreparation(t, gate)
			deps := filepath.Join(root, "build", "deps")
			writeTree(t, deps, map[string]string{"wireproxy/marker": "old proxy", "wireguard-go/marker": "old guard", "unrelated/marker": "untouched"})
			if _, err := p.prepare(context.Background(), root); err == nil || !strings.Contains(err.Error(), gate) {
				t.Fatalf("native failure did not abort: %v", err)
			}
			assertFile(t, filepath.Join(deps, "wireproxy", "marker"), "old proxy")
			assertFile(t, filepath.Join(deps, "wireguard-go", "marker"), "old guard")
			assertFile(t, filepath.Join(deps, "unrelated", "marker"), "untouched")
			want := 3
			if gate == "native routing tests" {
				want = 4
			}
			if gate == "native junk tests" {
				want = 5
			}
			if len(*calls) != want {
				t.Fatalf("commands continued after failed gate: %v", *calls)
			}
			stages, _ := filepath.Glob(filepath.Join(deps, ".prepare-*"))
			if len(stages) != 0 {
				t.Fatalf("failed gate left source stage: %v", stages)
			}
		})
	}
}

func TestSourceHashFailurePrecedesExtractionAndCommands(t *testing.T) {
	root, p, calls := mockPreparation(t, "")
	p.download = func(context.Context, sourcePin) ([]byte, error) { return []byte("tampered"), nil }
	if _, err := p.prepare(context.Background(), root); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("unverified source was prepared: %v", err)
	}
	if len(*calls) != 0 {
		t.Fatal("commands executed before source integrity validation")
	}
	if _, err := os.Stat(filepath.Join(root, "build", "deps", "wireproxy")); !os.IsNotExist(err) {
		t.Fatal("unverified source was published")
	}
}

func TestFindRoot(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"vendor/wireproxy-build.json": testPinsJSON, "tools/cmd/prepare/marker": "fixture"})
	t.Chdir(filepath.Join(root, "tools", "cmd", "prepare"))
	got, err := findRoot("")
	if err != nil || got != root {
		t.Fatalf("auto-detected root = %q, %v; want %s", got, err, root)
	}
	got, err = findRoot("../../..")
	if err != nil || got != root {
		t.Fatalf("explicit root = %q, %v; want %s", got, err, root)
	}
	t.Chdir(t.TempDir())
	if _, err := findRoot(""); err == nil {
		t.Fatal("accepted a working directory outside a repository")
	}
}

func TestInvalidHostAndModuleReportsAbort(t *testing.T) {
	for _, mode := range []string{"host", "outside-cache", "wrong-version", "missing-sum", "module-error", "bad-json"} {
		t.Run(mode, func(t *testing.T) {
			root, p, _ := mockPreparation(t, "")
			originalRun := p.run
			p.run = func(ctx context.Context, call command) (commandResult, error) {
				result, err := originalRun(ctx, call)
				if call.Label == "go env host" && mode == "host" {
					result.Stdout = []byte("linux\n../escape\n")
				}
				if call.Label == "go mod download wireguard" {
					var module map[string]string
					if err := json.Unmarshal(result.Stdout, &module); err != nil {
						t.Fatal(err)
					}
					switch mode {
					case "outside-cache":
						module["Dir"] = t.TempDir()
					case "wrong-version":
						module["Version"] = "v0.0.0-wrong"
					case "missing-sum":
						module["Sum"] = ""
					case "module-error":
						module["Error"] = "download failed"
					}
					result.Stdout, _ = json.Marshal(module)
					if mode == "bad-json" {
						result.Stdout = []byte("not JSON")
					}
				}
				return result, err
			}
			if _, err := p.prepare(context.Background(), root); err == nil {
				t.Fatal("accepted invalid host/module report")
			}
		})
	}
}

func mockPreparation(t *testing.T, failGate string) (string, preparer, *[]command) {
	t.Helper()
	root := t.TempDir()
	proxyFiles, guardFiles := fixtureSources()
	archive := archiveFiles(t, proxyFiles)
	pins := testPins(t)
	pins.Wireproxy.SHA256 = fmt.Sprintf("%x", sha256.Sum256(archive))
	data, err := json.Marshal(pins)
	if err != nil {
		t.Fatal(err)
	}
	writeTree(t, root, map[string]string{"vendor/wireproxy-build.json": string(data)})
	var calls []command
	var output bytes.Buffer
	p := preparer{
		output:  &output,
		environ: []string{"GOOS=windows", "GOARCH=arm64", "CGO_ENABLED=1", "GOFLAGS=-mod=vendor", "GOWORK=/outside/go.work", "GOMODCACHE=/outside/cache"},
		download: func(ctx context.Context, pin sourcePin) ([]byte, error) {
			if pin != pins.Wireproxy {
				t.Fatal("download did not use repository pins")
			}
			return archive, nil
		},
		run: func(ctx context.Context, call command) (commandResult, error) {
			calls = append(calls, call)
			switch call.Label {
			case "go env host":
				return commandResult{Stdout: []byte("linux\namd64\n")}, nil
			case "go mod download wireguard":
				moduleDir := filepath.Join(envValue(call.Env, "GOMODCACHE"), "golang.zx2c4.com", "wireguard@"+pins.Wireguard.Version)
				writeTree(t, moduleDir, guardFiles)
				data, err := json.Marshal(map[string]string{
					"Path": wireguardModule, "Version": pins.Wireguard.Version, "Dir": moduleDir, "Sum": "h1:fixture", "GoModSum": "h1:fixture",
				})
				if err != nil {
					t.Fatal(err)
				}
				return commandResult{Stdout: data}, nil
			case "native DNS tests", "native routing tests", "native junk tests":
				if call.Label == failGate {
					return commandResult{Stdout: []byte("FAIL fixture gate\n")}, fmt.Errorf("%s failed: fixture failure", call.Label)
				}
				if _, err := os.Stat(filepath.Join(root, "build", "deps", "wireproxy", "warppocket_routing.go")); err == nil && len(calls) <= 5 {
					t.Fatal("sources published before native gates completed")
				}
				return commandResult{Stdout: []byte("PASS fixture gate\n")}, nil
			default:
				t.Fatalf("unexpected command: %+v", call)
				return commandResult{}, errors.New("unexpected command")
			}
		},
	}
	return root, p, &calls
}

func envValue(env []string, key string) string {
	for _, value := range env {
		if strings.HasPrefix(value, key+"=") {
			return strings.TrimPrefix(value, key+"=")
		}
	}
	return ""
}

func mustPayload(t *testing.T, name string) string {
	t.Helper()
	data, err := payloads.ReadFile("payload/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRunCommandCWDEnvironmentAndFailure(t *testing.T) {
	if os.Getenv("WARPP_CONFIG_PREPARE_HELPER") == "1" {
		if os.Getenv("WARPP_CONFIG_PREPARE_TIMEOUT") == "1" {
			time.Sleep(5 * time.Second)
		}
		cwd, err := os.Getwd()
		if err != nil {
			os.Exit(3)
		}
		fmt.Printf("cwd=%s\nvalue=%s\n", cwd, os.Getenv("WARPP_CONFIG_PREPARE_VALUE"))
		fmt.Fprintln(os.Stderr, "fixture stderr")
		os.Exit(7)
	}
	dir := t.TempDir()
	request := command{
		Args: []string{os.Args[0], "-test.run=^TestRunCommandCWDEnvironmentAndFailure$"}, Dir: dir,
		Env:     setEnv(os.Environ(), "WARPP_CONFIG_PREPARE_HELPER", "1", "WARPP_CONFIG_PREPARE_VALUE", "native"),
		Timeout: 5 * time.Second, Label: "helper test",
	}
	result, err := runCommand(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "helper test failed") || !strings.Contains(err.Error(), "fixture stderr") {
		t.Fatalf("command failure not reported: %v", err)
	}
	if string(result.Stdout) != "cwd="+dir+"\nvalue=native\n" {
		t.Fatalf("wrong command cwd/env: %q", result.Stdout)
	}
	request.Env = setEnv(request.Env, "WARPP_CONFIG_PREPARE_TIMEOUT", "1")
	request.Timeout = 30 * time.Millisecond
	if _, err := runCommand(context.Background(), request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("command timeout not enforced: %v", err)
	}
}
