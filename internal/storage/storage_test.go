package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0FL01/WarpPocket/internal/model"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(Paths{Root: filepath.Join(t.TempDir(), "Личные данные с пробелами")})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testResult(role string) model.CheckResult {
	return model.CheckResult{Endpoint: model.Endpoint{Host: "engage.cloudflareclient.com", Port: 2408}, LatencyMS: 42.5, VerifiedAt: time.Date(2026, 10, 19, 10, 11, 12, 123456000, time.FixedZone("fixture", 3*3600)), Role: role}
}

func TestDefaultPathsAndPrivateDirectories(t *testing.T) {
	base := filepath.Join(t.TempDir(), "данные")
	if runtime.GOOS == "windows" {
		t.Setenv("LOCALAPPDATA", base)
	} else {
		t.Setenv("XDG_DATA_HOME", base)
	}
	paths, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	name := "warppocket"
	if runtime.GOOS == "windows" {
		name = "WarpPocket"
	}
	if paths.Root != filepath.Join(base, name) {
		t.Fatal("legacy data directory changed")
	}
	store, err := New(paths)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.Root, filepath.Join(paths.Root, "profiles"), paths.ProfileDir(model.Primary), paths.ProfileDir(model.Probe), store.Paths.Run(), store.Paths.Logs()} {
		assertPrivate(t, path, true)
	}
}

func TestAtomicWriteReplacementPrivacyAndFailure(t *testing.T) {
	store := testStore(t)
	path := filepath.Join(store.Paths.ProfileDir(model.Primary), "profile.conf")
	for _, data := range []string{"old synthetic content", "new synthetic content"} {
		if err := AtomicWrite(path, []byte(data)); err != nil {
			t.Fatal(err)
		}
		assertPrivate(t, path, false)
		if got, _ := os.ReadFile(path); string(got) != data {
			t.Fatal("atomic replacement failed")
		}
	}
	err := atomicWrite(path, []byte("must not replace"), func(string, string) error { return os.ErrPermission })
	if model.Code(err) != "storage_write_failed" {
		t.Fatalf("unexpected safe error: %s", model.Code(err))
	}
	if got, _ := os.ReadFile(path); string(got) != "new synthetic content" {
		t.Fatal("failed replacement destroyed previous data")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 || entries[0].Name() != "profile.conf" {
		t.Fatal("failed replacement left a temporary private file")
	}
	if err := AtomicWrite(filepath.Dir(path), []byte("not a regular file")); err == nil {
		t.Fatal("directory replacement accepted")
	}
}

func TestCacheSchemaOneRoundTripAndTruncation(t *testing.T) {
	store := testStore(t)
	primary, probe := testResult(model.Primary), testResult(model.Probe)
	cache := model.Cache{LastGood: &primary, Preferred: &probe, Fallbacks: []model.CheckResult{primary, probe, primary, probe}}
	if err := store.SaveCache(cache); err != nil {
		t.Fatal(err)
	}
	assertPrivate(t, store.Paths.Settings(), false)
	loaded, err := store.LoadCache()
	if err != nil || loaded.LastGood == nil || loaded.Preferred == nil || len(loaded.Fallbacks) != 3 || !loaded.LastGood.VerifiedAt.Equal(primary.VerifiedAt) {
		t.Fatalf("schema one round trip failed: %s", model.Code(err))
	}
	data, _ := os.ReadFile(store.Paths.Settings())
	var wire map[string]json.RawMessage
	if json.Unmarshal(data, &wire) != nil || string(wire["schema_version"]) != "1" || len(wire) != 4 {
		t.Fatal("legacy schema changed")
	}
	if err := store.SaveCache(model.Cache{}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(store.Paths.Settings())
	if !bytes.Contains(data, []byte(`"fallbacks": []`)) {
		t.Fatal("fallbacks must be an array, never null")
	}
}

func TestLegacySchemaOneFixture(t *testing.T) {
	store := testStore(t)
	fixture := `{"schema_version":1,"last_good":{"endpoint":{"host":"ENGAGE.CloudflareClient.com.","port":2408},"latency_ms":32,"verified_at":"2026-10-19T10:11:12.123456+03:00","role":"primary"},"preferred":null,"fallbacks":[]}`
	if err := AtomicWrite(store.Paths.Settings(), []byte(fixture)); err != nil {
		t.Fatal(err)
	}
	cache, err := store.LoadCache()
	if err != nil || cache.LastGood == nil || cache.LastGood.Endpoint.Host != "engage.cloudflareclient.com" || cache.LastGood.LatencyMS != 32 {
		t.Fatalf("legacy cache rejected: %s", model.Code(err))
	}
}

func TestUnknownSchemaIsReadOnlyEvenWithoutLoad(t *testing.T) {
	for _, version := range []string{"2", "true", "1.0", "null", `"1"`} {
		t.Run(version, func(t *testing.T) {
			store := testStore(t)
			original := []byte(`{"schema_version":` + version + `,"future":"preserve exactly"}`)
			if err := AtomicWrite(store.Paths.Settings(), original); err != nil {
				t.Fatal(err)
			}
			if model.Code(store.SaveCache(model.Cache{})) != "cache_read_only" {
				t.Fatal("save without load overwrote unknown schema")
			}
			cache, err := store.LoadCache()
			if model.Code(err) != "cache_schema_unknown" || cache.LastGood != nil || len(cache.Fallbacks) != 0 {
				t.Fatal("unknown schema was used")
			}
			second, err := New(store.Paths)
			if err != nil || model.Code(second.SaveCache(model.Cache{})) != "cache_read_only" {
				t.Fatal("same-root Store bypassed read-only state")
			}
			got, _ := os.ReadFile(store.Paths.Settings())
			if !bytes.Equal(got, original) {
				t.Fatal("unknown schema changed")
			}
		})
	}
}

func TestCorruptCacheQuarantineNeverTouchesProfiles(t *testing.T) {
	result, _ := json.Marshal(testResult(model.Primary))
	for name, data := range map[string][]byte{
		"broken JSON":          []byte("{bad"),
		"non object":           []byte("[]"),
		"oversize":             bytes.Repeat([]byte("x"), maxCacheSize+1),
		"invalid UTF8":         {0xff},
		"null fallback":        []byte(`{"schema_version":1,"fallbacks":null}`),
		"negative latency":     []byte(`{"schema_version":1,"last_good":` + strings.Replace(string(result), "42.5", "-1", 1) + `}`),
		"boolean latency":      []byte(`{"schema_version":1,"last_good":` + strings.Replace(string(result), "42.5", "true", 1) + `}`),
		"missing timezone":     []byte(`{"schema_version":1,"last_good":` + strings.Replace(string(result), "+03:00", "", 1) + `}`),
		"invalid role":         []byte(`{"schema_version":1,"last_good":` + strings.Replace(string(result), `"primary"`, `"other"`, 1) + `}`),
		"float port":           []byte(`{"schema_version":1,"last_good":` + strings.Replace(string(result), "2408", "2408.0", 1) + `}`),
		"extra endpoint field": []byte(`{"schema_version":1,"last_good":` + strings.Replace(string(result), `"port":2408`, `"port":2408,"unknown":true`, 1) + `}`),
		"missing latency":      []byte(`{"schema_version":1,"last_good":` + strings.Replace(string(result), `"latency_ms":42.5,`, "", 1) + `}`),
		"too many fallbacks":   []byte(`{"schema_version":1,"fallbacks":[` + strings.TrimSuffix(strings.Repeat(string(result)+",", 4), ",") + `]}`),
	} {
		t.Run(name, func(t *testing.T) {
			store := testStore(t)
			profile := filepath.Join(store.Paths.ProfileDir(model.Primary), "profile.conf")
			if err := AtomicWrite(profile, []byte("synthetic profile sentinel")); err != nil {
				t.Fatal(err)
			}
			if err := AtomicWrite(store.Paths.Settings(), data); err != nil {
				t.Fatal(err)
			}
			cache, err := store.LoadCache()
			if model.Code(err) != "cache_corrupt" || cache.LastGood != nil {
				t.Fatalf("corruption not rejected: %s", model.Code(err))
			}
			quarantines, _ := filepath.Glob(filepath.Join(store.Paths.Root, "settings.corrupt.*.json"))
			if len(quarantines) != 1 {
				t.Fatal("corrupt cache not quarantined")
			}
			assertPrivate(t, quarantines[0], false)
			if got, _ := os.ReadFile(profile); string(got) != "synthetic profile sentinel" {
				t.Fatal("profile was modified while recovering cache")
			}
			if err := store.SaveCache(model.Cache{}); err != nil {
				t.Fatal("quarantined cache should allow a fresh schema-one save")
			}
		})
	}
}

func TestCacheRejectsUnsafeWritesAndConcurrentUpdates(t *testing.T) {
	store := testStore(t)
	for _, latency := range []float64{-1, math.Inf(1), math.NaN()} {
		result := testResult(model.Primary)
		result.LatencyMS = latency
		if model.Code(store.SaveCache(model.Cache{LastGood: &result})) != "cache_write_failed" {
			t.Fatal("unsafe latency persisted")
		}
	}
	var group sync.WaitGroup
	for range 24 {
		group.Go(func() {
			if err := store.UpdateCache(func(cache model.Cache) model.Cache {
				if cache.LastGood == nil {
					result := testResult(model.Primary)
					result.LatencyMS = 0
					cache.LastGood = &result
				}
				cache.LastGood.LatencyMS++
				return cache
			}); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	cache, err := store.LoadCache()
	if err != nil || cache.LastGood == nil || cache.LastGood.LatencyMS != 24 {
		t.Fatal("concurrent cache updates were lost")
	}
}

func TestClearRuntimeOnlyRemovesConfigFiles(t *testing.T) {
	store := testStore(t)
	for _, name := range []string{"primary.conf", "probe.conf", "keep.txt"} {
		if err := AtomicWrite(filepath.Join(store.Paths.Run(), name), []byte("synthetic")); err != nil {
			t.Fatal(err)
		}
	}
	directory := filepath.Join(store.Paths.Run(), "keep.conf")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearRuntime(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(store.Paths.Run())
	if len(entries) != 2 {
		t.Fatal("runtime cleanup removed unrelated data or left config files")
	}
}

func TestInstanceLockPersistentAndCrossProcess(t *testing.T) {
	store := testStore(t)
	lock, err := AcquireLock(store.Paths.Root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	path := filepath.Join(store.Paths.Root, ".instance.lock")
	assertPrivate(t, path, false)
	before, _ := os.Stat(path)
	if second, err := AcquireLock(store.Paths.Root); second != nil || model.Code(err) != "already_running" {
		t.Fatal("second instance acquired lock")
	}
	command := exec.Command(os.Args[0], "-test.run=^TestLockSubprocessHelper$")
	command.Env = append(os.Environ(), "WARPPOCKET_TEST_LOCK_ROOT="+store.Paths.Root, "WARPPOCKET_TEST_LOCK_MODE=blocked")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("cross-process lock failed: %v (%s)", err, output)
	}
	if err := lock.Close(); err != nil || lock.Close() != nil {
		t.Fatal("lock close must be idempotent")
	}
	after, _ := os.Stat(path)
	if before == nil || after == nil || !os.SameFile(before, after) {
		t.Fatal("lock file was unlinked/replaced")
	}
	command = exec.Command(os.Args[0], "-test.run=^TestLockSubprocessHelper$")
	command.Env = append(os.Environ(), "WARPPOCKET_TEST_LOCK_ROOT="+store.Paths.Root, "WARPPOCKET_TEST_LOCK_MODE=exit-with-lock")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("lock helper failed: %v (%s)", err, output)
	}
	reopened, err := AcquireLock(store.Paths.Root)
	if err != nil {
		t.Fatal("process exit did not release lock")
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLockSubprocessHelper(t *testing.T) {
	root := os.Getenv("WARPPOCKET_TEST_LOCK_ROOT")
	if root == "" {
		return
	}
	lock, err := AcquireLock(root)
	if os.Getenv("WARPPOCKET_TEST_LOCK_MODE") == "blocked" {
		if lock != nil || model.Code(err) != "already_running" {
			t.Fatal("legacy byte-range/flock lock was not respected")
		}
	} else if err != nil || lock == nil {
		t.Fatal("unlocked persistent file could not be acquired")
	}
	// Deliberately do not Close: the kernel must release it at process exit.
}

func TestStorageErrorsNeverContainInput(t *testing.T) {
	store := testStore(t)
	path := filepath.Join(store.Paths.Root, "SECRET-fixture", "path")
	if err := os.WriteFile(filepath.Join(store.Paths.Root, "SECRET-fixture"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{PrivateDirectory(path), PrivateFile(path), AtomicWrite(path, nil)} {
		if err == nil || strings.Contains(fmt.Sprint(err), "SECRET") || strings.Contains(fmt.Sprint(err), store.Paths.Root) {
			t.Fatal("raw filesystem error was exposed")
		}
	}
}
