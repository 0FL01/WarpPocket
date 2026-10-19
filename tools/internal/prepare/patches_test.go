package prepare

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each input includes every pinned anchor but no third-party build dependency.
// The real download plus native gates separately verify complete upstream trees.
func fixtureSources() (map[string]string, map[string]string) {
	trees := map[string]map[string]string{"proxy": {}, "guard": {}}
	for _, patch := range pinnedPatches() {
		var anchors []string
		for _, edit := range patch.edits {
			anchors = append(anchors, edit.old)
		}
		trees[patch.tree][patch.path] = strings.Join(anchors, "\n// fixture separator\n")
	}
	trees["proxy"]["go.mod"] = "module github.com/windtf/wireproxy\n\ngo 1.26.0\n\nrequire (\n\t" + wireguardModule + " v0.0.0-20250521234502-f333402bd9cb\n)\n"
	trees["guard"]["go.mod"] = "module " + wireguardModule + "\n\ngo 1.26.0\n"
	return trees["proxy"], trees["guard"]
}

func fixtureRoots(t *testing.T) (string, string) {
	t.Helper()
	parent := t.TempDir()
	proxy, guard := filepath.Join(parent, "wireproxy"), filepath.Join(parent, "wireguard-go")
	proxyFiles, guardFiles := fixtureSources()
	writeTree(t, proxy, proxyFiles)
	writeTree(t, guard, guardFiles)
	return proxy, guard
}

func TestExactOnceAnchors(t *testing.T) {
	for _, text := range []string{"missing", "anchor anchor"} {
		if _, err := replaceOnce(text, "anchor", "new", "fixture"); err == nil {
			t.Fatalf("accepted non-exact anchor: %q", text)
		}
	}
	if _, err := replaceOnce("text", "", "new", "empty"); err == nil {
		t.Fatal("accepted an empty anchor")
	}
	got, err := replaceOnce("before anchor after", "anchor", "new", "fixture")
	if err != nil || got != "before new after" {
		t.Fatalf("replacement = %q, %v", got, err)
	}
}

func TestEveryAnchorMissingOrDuplicatedAbortsBeforeWrites(t *testing.T) {
	for _, patch := range pinnedPatches() {
		for _, edit := range patch.edits {
			for _, mode := range []string{"missing", "duplicate"} {
				t.Run(patch.path+"/"+edit.label+"/"+mode, func(t *testing.T) {
					proxy, guard := fixtureRoots(t)
					root := proxy
					if patch.tree == "guard" {
						root = guard
					}
					path := filepath.Join(root, filepath.FromSlash(patch.path))
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					changed := strings.Replace(string(data), edit.old, "REMOVED ANCHOR", 1)
					if mode == "duplicate" {
						changed = string(data) + "\n" + edit.old
					}
					if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
						t.Fatal(err)
					}
					before := snapshotTree(t, filepath.Dir(proxy))
					if err := patchSources(proxy, guard, testPins(t)); err == nil || !strings.Contains(err.Error(), "anchor") {
						t.Fatalf("did not reject changed anchor: %v", err)
					}
					if after := snapshotTree(t, filepath.Dir(proxy)); before != after {
						t.Fatal("an invalid anchor caused writes before complete validation")
					}
				})
			}
		}
	}
}

func snapshotTree(t *testing.T, root string) string {
	t.Helper()
	var snapshot strings.Builder
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(&snapshot, "%s:%x\n", path, sha256.Sum256(data))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot.String()
}

func TestPayloadValidationAndInstallation(t *testing.T) {
	proxy, guard := fixtureRoots(t)
	if err := patchSources(proxy, guard, testPins(t)); err != nil {
		t.Fatal(err)
	}
	for _, spec := range sourcePayloads {
		root := proxy
		if spec.tree == "guard" {
			root = guard
		}
		want, err := payloads.ReadFile("payload/" + spec.name)
		if err != nil {
			t.Fatal(err)
		}
		assertFile(t, filepath.Join(root, filepath.FromSlash(spec.path)), string(want))
	}
	mod, err := os.ReadFile(filepath.Join(proxy, "go.mod"))
	if err != nil || !bytes.Contains(mod, []byte("replace "+wireguardModule+" => ../wireguard-go\n")) {
		t.Fatalf("missing sibling module replacement: %s, %v", mod, err)
	}
	main, err := os.ReadFile(filepath.Join(proxy, "cmd", "wireproxy", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(main, []byte("package worker\n")) || !bytes.Contains(main, []byte(workerRunNew)) {
		t.Fatal("worker package and Run entry were not installed")
	}
	for _, forbidden := range []string{"func main(", "argparse", "default_config_paths", "configFilePath", "exec.Command", "http.ListenAndServe", "LogLevelVerbose"} {
		if bytes.Contains(main, []byte(forbidden)) {
			t.Errorf("worker retains arbitrary CLI/service: %s", forbidden)
		}
	}
}

func TestInvalidPayloadsAbortBeforeWrites(t *testing.T) {
	for _, mode := range []string{"syntax", "package", "missing-function", "missing-payload", "existing-target"} {
		t.Run(mode, func(t *testing.T) {
			proxy, guard := fixtureRoots(t)
			if mode == "existing-target" {
				writeTree(t, proxy, map[string]string{"cmd/wireproxy/warppocket_worker_test.go": "user content"})
			}
			before := snapshotTree(t, filepath.Dir(proxy))
			read := func(name string) ([]byte, error) {
				if name != "payload/wireproxy_worker_test.go.txt" {
					return payloads.ReadFile(name)
				}
				switch mode {
				case "syntax":
					return []byte("not go source"), nil
				case "package":
					return []byte("package main\nfunc TestWarpPocketPolicyWorkerEntry() {}\n"), nil
				case "missing-function":
					return []byte("package worker_test\n"), nil
				case "missing-payload":
					return nil, os.ErrNotExist
				}
				return payloads.ReadFile(name)
			}
			if _, err := planPatches(proxy, guard, testPins(t), read); err == nil {
				t.Fatal("accepted invalid payload")
			}
			if after := snapshotTree(t, filepath.Dir(proxy)); before != after {
				t.Fatal("invalid payload changed sources")
			}
		})
	}
}

func TestGoModAnchorValidation(t *testing.T) {
	proxy, _ := fixtureSources()
	text := proxy["go.mod"]
	version := testPins(t).Wireguard.Version
	for _, bad := range []string{
		strings.Replace(text, "module github.com/windtf/wireproxy", "module wrong", 1),
		strings.Replace(text, version, "v0.0.0-wrong", 1),
		text + "\t" + wireguardModule + " " + version + "\n",
		text + "\nreplace " + wireguardModule + " => /outside\n",
		text + "\nreplace (\n" + wireguardModule + " => /outside\n)\n",
	} {
		if _, err := patchGoMod(bad, version); err == nil {
			t.Fatalf("accepted invalid go.mod: %s", bad)
		}
	}
}

func TestWorkerRunEntry(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "worker.go", "package worker\n"+workerRunNew, parser.AllErrors)
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Decls) != 1 {
		t.Fatal("worker entry must contain exactly one declaration")
	}
	entry, ok := file.Decls[0].(*ast.FuncDecl)
	if !ok || entry.Name.Name != "Run" || entry.Recv != nil || entry.Type.Results != nil || len(entry.Type.Params.List) != 1 {
		t.Fatal("worker must export only Run(configPath string)")
	}
	param := entry.Type.Params.List[0]
	if len(param.Names) != 1 || param.Names[0].Name != "configPath" || param.Type.(*ast.Ident).Name != "string" {
		t.Fatal("wrong fixed worker parameter")
	}
	ordered := []string{
		`lock("boot")`, `lock("read-config")`, `wireproxy.ParseConfig(configPath)`,
		`lockNetwork(conf.Routines, nil)`, `lock("ready", tlsFilePaths(conf.Routines)...)`,
		`wireproxy.StartWireguard(conf, device.LogLevelSilent)`, `go spawner.SpawnRoutine(tun)`,
		`tun.StartPingIPs()`, `<-ctx.Done()`,
	}
	position := 0
	for _, anchor := range ordered {
		index := strings.Index(workerRunNew[position:], anchor)
		if index < 0 {
			t.Fatalf("missing/out-of-order upstream stage: %s", anchor)
		}
		position += index + len(anchor)
	}
	if !strings.Contains(workerRunNew, "syscall.SIGTERM") || strings.Contains(workerRunNew, "os.Args") {
		t.Fatal("worker must stop on parent termination and have no arbitrary options")
	}
}

func TestPreservedPayloadDigests(t *testing.T) {
	// Digests of the pre-migration reference files for behavior that this
	// change does not touch.
	for name, want := range map[string]string{
		"wireproxy_dns.go.txt":      "e71b0d3e42890df7e1e0fe53d73dc4ba1b204512e02e118542991f9b524d2f9d",
		"wireproxy_dns_test.go.txt": "78772a3df9409301fead5b093c7fad58f3fe6463f7ad19a5e5dc248b3dfc2b93",
	} {
		data := mustPayload(t, name)
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(data))); got != want {
			t.Errorf("%s changed preserved logic: digest=%s, want=%s", name, got, want)
		}
	}
}

func TestWarpOnlySOCKSOptionsAndPreservedSandbox(t *testing.T) {
	proxy, guard := fixtureRoots(t)
	if err := patchSources(proxy, guard, testPins(t)); err != nil {
		t.Fatal(err)
	}
	routine, err := os.ReadFile(filepath.Join(proxy, "routine.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(routine, []byte(routingOptionsNew)) || !bytes.Contains(routine, []byte(resolveEntryNew)) {
		t.Fatal("generated SOCKS routine lacks the WARP-only options or hostname normalization")
	}
	for _, forbidden := range []string{"WithDialAndRequest", "newWarpPocketSOCKSRouter", "warpPocketDirectHost", "warpPocketDirectRoots"} {
		if bytes.Contains(routine, []byte(forbidden)) {
			t.Fatalf("split-routing reference survived in the SOCKS routine: %s", forbidden)
		}
	}
	main, err := os.ReadFile(filepath.Join(proxy, "cmd", "wireproxy", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(main, []byte(upstreamLockNetwork)) {
		t.Fatal("generated worker changed the pinned upstream network sandbox")
	}
	for _, forbidden := range []string{"warpPocketNetworkPolicy", "landlocksyscall", "AccessNetSet"} {
		if bytes.Contains(main, []byte(forbidden)) {
			t.Fatalf("relaxed network sandbox survived in the worker: %s", forbidden)
		}
	}
	for _, spec := range sourcePayloads {
		if strings.Contains(spec.name, "routing") || strings.Contains(spec.path, "routing") {
			t.Fatalf("routing payload is still generated: %s", spec.name)
		}
	}
}
