// Package engine is the deliberately narrow self-worker entry point. It is
// called before Gio, instance locking or application persistence is initialized.
package engine

import (
	"encoding/hex"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/profile"
	worker "github.com/windtf/wireproxy/cmd/wireproxy"
)

// Validate accepts only the normalized private runtime format produced by our
// backend: one peer, one loopback SOCKS listener, and the fixed DNS/routing policy.
// Upstream CLI options, forwarding routines and extra listeners are not exposed.
func Validate(path, role string) error {
	fail := func() error {
		return model.E("engine_config_invalid", "Некорректная конфигурация сетевого процесса.")
	}
	if !model.ValidRole(role) || !filepath.IsAbs(path) {
		return fail()
	}
	name := filepath.Base(path)
	id, ok := strings.CutPrefix(name, role+"-")
	if !ok || !strings.HasSuffix(id, ".conf") {
		return fail()
	}
	decoded, err := hex.DecodeString(strings.TrimSuffix(id, ".conf"))
	if err != nil || len(decoded) != 16 {
		return fail()
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
		return fail()
	}
	file, err := os.Open(path)
	if err != nil {
		return fail()
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(content) > 65536 {
		return fail()
	}
	base, rest, ok := strings.Cut(string(content), "\n[Socks5]\nBindAddress = ")
	if !ok {
		return fail()
	}
	address, tail, ok := strings.Cut(rest, "\n")
	if !ok || tail != "\n[Resolve]\nResolveStrategy = ipv4\n" {
		return fail()
	}
	host, rawPort, err := net.SplitHostPort(address)
	port, portErr := strconv.Atoi(rawPort)
	if err != nil || portErr != nil || host != "127.0.0.1" || port < 1 || port > 65535 {
		return fail()
	}
	p, err := profile.Parse([]byte(base))
	if err != nil || strings.Join(p.DNS, ",") != "83.220.169.155,212.109.195.93,194.87.196.13,45.151.102.219,9.9.9.9" {
		return fail()
	}
	return nil
}

func Run(path, role string) error {
	if err := Validate(path, role); err != nil {
		return err
	}
	// The parent also redirects every inherited standard handle to NUL. Keep
	// upstream fatal errors private even when a worker is invoked manually.
	log.SetOutput(io.Discard)
	worker.Run(path)
	return nil
}
