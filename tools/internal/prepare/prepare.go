// Package prepare installs isolated engine sources only after all pinned patches
// and native policy gates succeed. No application or WARP service is started.
package prepare

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	wireguardModule = "golang.zx2c4.com/wireguard"
	supportedPatch  = "reserved-support+ordered-dns+split-routing+handshake-junk"
	maxSourceBytes  = 20 * 1024 * 1024
)

// Result describes source directories, not shipped helper executables.
type Result struct {
	Wireproxy string `json:"wireproxy"`
	Wireguard string `json:"wireguard"`
	Patch     string `json:"patch"`
}

type preparer struct {
	run      runner
	download func(context.Context, sourcePin) ([]byte, error)
	output   io.Writer
	environ  []string
}

// Prepare locates the repository when root is empty. Downloads, cache and source
// copies stay under its ignored build/deps directory. Existing prepared sources
// remain untouched if fetching, patch validation or any native gate fails.
func Prepare(ctx context.Context, root string, output io.Writer) (Result, error) {
	if output == nil {
		output = io.Discard
	}
	p := preparer{run: runCommand, download: downloadSource, output: output, environ: os.Environ()}
	return p.prepare(ctx, root)
}

func findRoot(root string) (string, error) {
	if root != "" {
		return filepath.Abs(root)
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if info, err := os.Stat(filepath.Join(dir, "vendor", "wireproxy-build.json")); err == nil && info.Mode().IsRegular() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("cannot locate vendor/wireproxy-build.json; pass --root")
		}
		dir = parent
	}
}

func (p preparer) prepare(ctx context.Context, root string) (Result, error) {
	root, err := findRoot(root)
	if err != nil {
		return Result{}, err
	}
	pins, err := loadPins(root)
	if err != nil {
		return Result{}, err
	}
	deps := filepath.Join(root, "build", "deps")
	if err := ensureDirectory(filepath.Join(root, "build")); err != nil {
		return Result{}, err
	}
	if err := ensureDirectory(deps); err != nil {
		return Result{}, err
	}
	stage, err := os.MkdirTemp(deps, ".prepare-")
	if err != nil {
		return Result{}, fmt.Errorf("create source stage: %w", err)
	}
	defer os.RemoveAll(stage)
	proxy := filepath.Join(stage, "wireproxy")
	guard := filepath.Join(stage, "wireguard-go")
	archive, err := p.download(ctx, pins.Wireproxy)
	if err != nil {
		return Result{}, err
	}
	// Keep the integrity boundary here as well as in the HTTP downloader, so no
	// other source transport can bypass hash verification before extraction.
	if err := verifySource(archive, pins.Wireproxy.SHA256); err != nil {
		return Result{}, err
	}
	if err := extractSource(archive, pins.Wireproxy.Version, proxy); err != nil {
		return Result{}, err
	}
	// go mod download and all transitive native-test downloads use an isolated
	// cache. Neither patching nor downloading changes the user's global cache.
	cache := filepath.Join(deps, ".gomodcache")
	if err := ensureDirectory(cache); err != nil {
		return Result{}, err
	}
	env := setEnv(p.environ, "CGO_ENABLED", "0", "GOFLAGS", "-mod=mod", "GOWORK", "off", "GOMODCACHE", cache)
	host, err := p.run(ctx, command{Args: []string{"go", "env", "GOHOSTOS", "GOHOSTARCH"}, Dir: proxy, Env: env, Timeout: 30 * time.Second, Label: "go env host"})
	if err != nil {
		return Result{}, err
	}
	target := strings.Fields(string(host.Stdout))
	if len(target) != 2 || !validTarget(target[0]) || !validTarget(target[1]) {
		return Result{}, fmt.Errorf("go env did not report the native host target")
	}
	env = setEnv(env, "GOOS", target[0], "GOARCH", target[1])
	if err := p.copyWireguard(ctx, proxy, guard, cache, env, pins); err != nil {
		return Result{}, err
	}
	if err := patchSources(proxy, guard, pins); err != nil {
		return Result{}, err
	}
	if err := p.nativeGates(ctx, proxy, guard, env); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := installSources(deps, stage); err != nil {
		return Result{}, err
	}
	return Result{Wireproxy: filepath.Join(deps, "wireproxy"), Wireguard: filepath.Join(deps, "wireguard-go"), Patch: pins.Patch}, nil
}

func (p preparer) copyWireguard(ctx context.Context, proxy, guard, cache string, env []string, pins buildPins) error {
	result, err := p.run(ctx, command{
		Args: []string{"go", "mod", "download", "-json", wireguardModule + "@" + pins.Wireguard.Version},
		Dir:  proxy, Env: env, Timeout: 600 * time.Second, Label: "go mod download wireguard",
	})
	if err != nil {
		return err
	}
	var module struct {
		Path, Version, Dir, Sum, GoModSum, Error string
	}
	if err := json.Unmarshal(result.Stdout, &module); err != nil {
		return fmt.Errorf("parse go mod download output: %w", err)
	}
	if module.Error != "" || module.Path != wireguardModule || module.Version != pins.Wireguard.Version || module.Sum == "" || module.GoModSum == "" {
		return fmt.Errorf("go mod download did not report the verified pinned wireguard module")
	}
	if !filepath.IsAbs(module.Dir) || !isWithin(cache, module.Dir) {
		return fmt.Errorf("go mod download reported a directory outside the isolated module cache")
	}
	return copyModule(module.Dir, guard)
}

func (p preparer) nativeGates(ctx context.Context, proxy, guard string, env []string) error {
	for _, cmd := range []command{
		{Args: []string{"go", "test", "./tun/netstack", "-run", "^TestWarpPocketDNS", "-count=1", "-v"}, Dir: guard, Env: env, Timeout: 300 * time.Second, Label: "native DNS tests"},
		{Args: []string{"go", "test", ".", "./cmd/wireproxy", "-run", "^TestWarpPocketRouting", "-count=1", "-v"}, Dir: proxy, Env: env, Timeout: 300 * time.Second, Label: "native routing tests"},
		{Args: []string{"go", "test", ".", "-run", "^TestWarpPocketJunk", "-count=1", "-v"}, Dir: proxy, Env: env, Timeout: 300 * time.Second, Label: "native junk tests"},
	} {
		result, err := p.run(ctx, cmd)
		if _, writeErr := p.output.Write(result.Stdout); writeErr != nil {
			return fmt.Errorf("write native gate output: %w", writeErr)
		}
		if _, writeErr := p.output.Write(result.Stderr); writeErr != nil {
			return fmt.Errorf("write native gate output: %w", writeErr)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func validTarget(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
