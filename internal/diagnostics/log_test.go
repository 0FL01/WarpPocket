package diagnostics

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/storage"
)

func testLogger(t *testing.T) (*Logger, storage.Paths) {
	t.Helper()
	store, err := storage.New(storage.Paths{Root: filepath.Join(t.TempDir(), "data")})
	if err != nil {
		t.Fatal(err)
	}
	return New(store.Paths), store.Paths
}

func readLog(t *testing.T, path string) []map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(data, []byte("\n")) {
		t.Fatal("diagnostics must contain newline-terminated JSON records")
	}
	var entries []map[string]string
	for _, line := range bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
		var entry map[string]string
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	return entries
}

func assertPrivateLog(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatal("diagnostic log is not a regular file")
	}
	// Windows DACL details are tested by storage; use its existing privacy API
	// rather than treating Unix permission bits as an ACL assertion there.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("diagnostic permissions = %o, want 600", info.Mode().Perm())
	}
	if err := storage.PrivateFile(path); err != nil {
		t.Fatal(err)
	}
}

func TestLoggerClosedAllowlistAndExistingFormat(t *testing.T) {
	l, paths := testLogger(t)
	codes := []string{
		"connected", "disconnected", "connection_lost", "proxy_exited", "recovered",
		"health_failed", "health_timeout", "health_tls", "warp_not_enabled", "external_unavailable", "health_response_large", "health_setup_failed", "proxy_cleanup_failed",
	}
	endpoint := model.Endpoint{Host: "188.114.96.1", Port: 4500}
	started := time.Now().UTC()
	for _, code := range codes {
		if code == "disconnected" {
			l.Event(code, model.Endpoint{})
		} else {
			l.Event(code, endpoint)
		}
	}
	finished := time.Now().UTC()
	entries := readLog(t, l.path)
	if len(entries) != len(codes) || l.path != filepath.Join(paths.Logs(), "diagnostics.log") {
		t.Fatal("diagnostic allowlist or established path changed")
	}
	for n, entry := range entries {
		stamp, err := time.Parse(time.RFC3339Nano, entry["time"])
		if err != nil || !strings.HasSuffix(entry["time"], "Z") || stamp.Before(started) || stamp.After(finished) {
			t.Fatal("diagnostic timestamp is not current RFC3339Nano UTC")
		}
		if entry["code"] != codes[n] {
			t.Fatal("diagnostic order or code changed")
		}
		if codes[n] == "disconnected" {
			if len(entry) != 2 || entry["endpoint"] != "" {
				t.Fatal("empty endpoint was not omitted")
			}
		} else if len(entry) != 3 || entry["endpoint"] != endpoint.String() {
			t.Fatal("diagnostics changed the endpoint format or added fields")
		}
	}
	assertPrivateLog(t, l.path)
	ipv6 := model.Endpoint{Host: "2606:4700:d0::a29f:c001", Port: 2408}
	l.Event("recovered", ipv6)
	entries = readLog(t, l.path)
	if entries[len(entries)-1]["endpoint"] != "[2606:4700:d0::a29f:c001]:2408" {
		t.Fatal("IPv6 endpoint formatting changed")
	}
}

func TestLoggerRejectsArbitraryTextAndInvalidEndpoints(t *testing.T) {
	l, _ := testLogger(t)
	valid := model.Endpoint{Host: "188.114.96.1", Port: 4500}
	for _, code := range []string{
		"", "cancelled", "timeout", "internal_error", "health_arbitrary", "recovery_started",
		"health_timeout: Synthetic private exception", "connected\nPrivateKey=synthetic", "--config private.conf",
	} {
		l.Event(code, valid)
	}
	for _, endpoint := range []model.Endpoint{
		{Host: "188.114.96.1", Port: 0}, {Host: "188.114.96.1", Port: 65536},
		{Host: "https://private.invalid/path", Port: 443}, {Host: "host\nPrivateKey=synthetic", Port: 443},
		{Host: "../private.conf", Port: 443}, {Host: strings.Repeat("a", 254), Port: 443},
	} {
		l.Event("health_timeout", endpoint)
	}
	if _, err := os.Lstat(l.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected diagnostic input created or modified a log")
	}
	l.Event("health_failed", valid)
	entries := readLog(t, l.path)
	if len(entries) != 1 || entries[0]["code"] != "health_failed" {
		t.Fatal("rejected diagnostics escaped the closed allowlist")
	}
}

func TestLoggerRotationRetainsOnlyThreeBoundedPrivateFiles(t *testing.T) {
	l, paths := testLogger(t)
	const limit = 1 << 20
	const maxRecord = 512 // Includes the longest valid endpoint and fixed code.
	endpoint := model.Endpoint{Host: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), Port: 65535}
	var previous []byte
	for n := range 5 {
		// Seed just below the existing pre-append threshold, without performing
		// thousands of private-file operations to fill each 1 MiB generation.
		seed := bytes.Repeat([]byte{byte('a' + n)}, limit-1)
		if err := storage.AtomicWrite(l.path, seed); err != nil {
			t.Fatal(err)
		}
		l.Event("health_response_large", endpoint)
		full, err := os.ReadFile(l.path)
		if err != nil || len(full) < limit || len(full) > limit+maxRecord || !bytes.HasPrefix(full, seed) {
			t.Fatal("logger changed its pre-append threshold or exceeded one bounded record")
		}
		if n == 0 {
			if _, err := os.Lstat(l.path + ".1"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("logger rotated before reaching its established threshold")
			}
		}
		l.Event("recovered", endpoint)
		archive, err := os.ReadFile(l.path + ".1")
		if err != nil || !bytes.Equal(archive, full) {
			t.Fatal("rotation did not preserve the previous generation")
		}
		if n > 0 {
			archive, err = os.ReadFile(l.path + ".2")
			if err != nil || !bytes.Equal(archive, previous) {
				t.Fatal("rotation did not replace the oldest generation in order")
			}
		}
		previous = full
		entries := readLog(t, l.path)
		if len(entries) != 1 || entries[0]["code"] != "recovered" {
			t.Fatal("rotation lost the event that opened the new generation")
		}
		files, err := os.ReadDir(paths.Logs())
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"diagnostics.log", "diagnostics.log.1"}
		if n > 0 {
			want = append(want, "diagnostics.log.2")
		}
		var names []string
		var total int64
		for _, file := range files {
			names = append(names, file.Name())
			path := filepath.Join(paths.Logs(), file.Name())
			assertPrivateLog(t, path)
			info, err := file.Info()
			if err != nil || info.Size() > limit+maxRecord {
				t.Fatal("diagnostic generation is not bounded")
			}
			total += info.Size()
		}
		if !slices.Equal(names, want) || total > 3*(limit+maxRecord) {
			t.Fatal("diagnostics retained more than the existing three bounded files")
		}
	}
}

func TestLoggerConcurrentEventsStaySeparate(t *testing.T) {
	l, _ := testLogger(t)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() { l.Event("health_timeout", model.Endpoint{Host: "188.114.96.1", Port: 4500}) })
	}
	wg.Wait()
	entries := readLog(t, l.path)
	if len(entries) != 32 {
		t.Fatal("concurrent diagnostic records were lost or interleaved")
	}
	for _, entry := range entries {
		if len(entry) != 3 || entry["code"] != "health_timeout" || entry["endpoint"] != "188.114.96.1:4500" {
			t.Fatal("concurrent diagnostic event was malformed")
		}
	}
	assertPrivateLog(t, l.path)
}

func TestLoggerRejectsNonRegularLogPaths(t *testing.T) {
	for _, kind := range []string{"directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			l, paths := testLogger(t)
			var target string
			if kind == "directory" {
				if err := storage.PrivateDirectory(l.path); err != nil {
					t.Fatal(err)
				}
			} else {
				target = filepath.Join(paths.Root, "synthetic-target")
				if err := storage.AtomicWrite(target, []byte("unchanged")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, l.path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			l.Event("health_timeout", model.Endpoint{})
			if target != "" {
				data, err := os.ReadFile(target)
				if err != nil || string(data) != "unchanged" {
					t.Fatal("logger followed a nonregular path")
				}
			}
			if _, err := os.Lstat(l.path + ".1"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("logger rotated a nonregular path")
			}
		})
	}
}
