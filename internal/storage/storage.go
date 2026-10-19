// Package storage owns private, backward-compatible application persistence.
package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/0FL01/WarpPocket/internal/model"
)

const maxCacheSize = 65536

type Paths struct{ Root string }

func DefaultPaths() (Paths, error) {
	if runtime.GOOS == "windows" {
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return Paths{Root: filepath.Join(base, "WarpPocket")}, nil
		}
		return Paths{}, model.E("storage_unavailable", "Не удалось найти каталог данных приложения.")
	}
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Paths{}, model.E("storage_unavailable", "Не удалось найти каталог данных приложения.")
		}
		base = filepath.Join(home, ".local", "share")
	}
	return Paths{Root: filepath.Join(base, "warppocket")}, nil
}

func (p Paths) Run() string                   { return filepath.Join(p.Root, "run") }
func (p Paths) Settings() string              { return filepath.Join(p.Root, "settings.json") }
func (p Paths) Logs() string                  { return filepath.Join(p.Root, "logs") }
func (p Paths) ProfileDir(role string) string { return filepath.Join(p.Root, "profiles", role) }

type rootState struct {
	cacheMu   sync.Mutex
	profileMu sync.Mutex
	readOnly  bool
}

var roots sync.Map // canonical root -> *rootState; shared by Stores in this process

type Store struct {
	Paths Paths
	state *rootState
}

func New(paths Paths) (*Store, error) {
	if strings.TrimSpace(paths.Root) == "" {
		return nil, model.E("storage_unavailable", "Каталог данных приложения недоступен.")
	}
	root, err := filepath.Abs(paths.Root)
	if err != nil {
		return nil, model.E("storage_unavailable", "Каталог данных приложения недоступен.")
	}
	paths.Root = filepath.Clean(root)
	for _, path := range []string{paths.Root, filepath.Join(paths.Root, "profiles"), paths.ProfileDir(model.Primary), paths.ProfileDir(model.Probe), paths.Run(), paths.Logs()} {
		if err := PrivateDirectory(path); err != nil {
			return nil, err
		}
	}
	key := paths.Root
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	state, _ := roots.LoadOrStore(key, &rootState{})
	return &Store{Paths: paths, state: state.(*rootState)}, nil
}

// WithProfilesLock serializes complete identity transactions, including API calls,
// across Services sharing this root. The application also holds AcquireLock for
// cross-process exclusion. fn must not recursively acquire the profile lock.
func (s *Store) WithProfilesLock(fn func() error) error {
	s.state.profileMu.Lock()
	defer s.state.profileMu.Unlock()
	return fn()
}

func (s *Store) LoadCache() (model.Cache, error) {
	s.state.cacheMu.Lock()
	defer s.state.cacheMu.Unlock()
	return s.loadCache()
}

func (s *Store) loadCache() (model.Cache, error) {
	content, err := readBounded(s.Paths.Settings(), maxCacheSize)
	if errors.Is(err, os.ErrNotExist) {
		return model.Cache{}, nil
	}
	if err != nil && !errors.Is(err, errInvalidFile) {
		s.state.readOnly = true
		return model.Cache{}, model.E("cache_read_failed", "Не удалось прочитать кеш; существующий файл сохранён.")
	}
	var data map[string]json.RawMessage
	if err == nil && utf8.Valid(content) && json.Unmarshal(content, &data) == nil && data != nil {
		if !bytes.Equal(bytes.TrimSpace(data["schema_version"]), []byte("1")) {
			s.state.readOnly = true
			return model.Cache{}, model.E("cache_schema_unknown", "Неизвестная версия кеша; существующий файл сохранён без изменений.")
		}
		if cache, valid := decodeCache(data); valid {
			return cache, nil
		}
	}
	// Quarantine only this settings file; never migrate or touch private identities.
	stamp := time.Now().UTC().Format("20060102T150405.000000000")
	quarantine := filepath.Join(s.Paths.Root, "settings.corrupt."+stamp+".json")
	if info, statErr := os.Lstat(s.Paths.Settings()); statErr != nil || !info.Mode().IsRegular() {
		s.state.readOnly = true
	} else if PrivateFile(s.Paths.Settings()) != nil || replaceFile(s.Paths.Settings(), quarantine) != nil {
		s.state.readOnly = true
	}
	return model.Cache{}, model.E("cache_corrupt", "Повреждённый кеш не использован; профили сохранены.")
}

func decodeCache(data map[string]json.RawMessage) (model.Cache, bool) {
	var cache model.Cache
	for name, target := range map[string]**model.CheckResult{"last_good": &cache.LastGood, "preferred": &cache.Preferred} {
		raw := data[name]
		if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}
		result, ok := decodeResult(raw)
		if !ok {
			return model.Cache{}, false
		}
		*target = &result
	}
	if raw, present := data["fallbacks"]; present {
		var list []json.RawMessage
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &list) != nil || len(list) > 3 {
			return model.Cache{}, false
		}
		for _, item := range list {
			result, ok := decodeResult(item)
			if !ok {
				return model.Cache{}, false
			}
			cache.Fallbacks = append(cache.Fallbacks, result)
		}
	}
	return cache, true
}

func decodeResult(raw []byte) (model.CheckResult, bool) {
	var fields map[string]json.RawMessage
	var endpointFields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || json.Unmarshal(fields["endpoint"], &endpointFields) != nil || len(endpointFields) != 2 || endpointFields["host"] == nil || endpointFields["port"] == nil {
		return model.CheckResult{}, false
	}
	var wire struct {
		Endpoint *struct {
			Host *string `json:"host"`
			Port *int    `json:"port"`
		} `json:"endpoint"`
		Latency *float64 `json:"latency_ms"`
		Stamp   *string  `json:"verified_at"`
		Role    *string  `json:"role"`
	}
	if json.Unmarshal(raw, &wire) != nil || wire.Endpoint == nil || wire.Endpoint.Host == nil || wire.Endpoint.Port == nil || wire.Latency == nil || wire.Stamp == nil || wire.Role == nil {
		return model.CheckResult{}, false
	}
	endpoint, err := model.NewEndpoint(*wire.Endpoint.Host, *wire.Endpoint.Port)
	if err != nil || math.IsNaN(*wire.Latency) || math.IsInf(*wire.Latency, 0) || *wire.Latency < 0 || !model.ValidRole(*wire.Role) {
		return model.CheckResult{}, false
	}
	stamp, err := time.Parse(time.RFC3339Nano, *wire.Stamp)
	if err != nil {
		// datetime.isoformat's space-separated form is also valid legacy input.
		stamp, err = time.Parse("2006-01-02 15:04:05.999999999Z07:00", *wire.Stamp)
	}
	if err != nil {
		return model.CheckResult{}, false
	}
	return model.CheckResult{Endpoint: endpoint, LatencyMS: *wire.Latency, VerifiedAt: stamp, Role: *wire.Role}, true
}

func (s *Store) SaveCache(cache model.Cache) error {
	s.state.cacheMu.Lock()
	defer s.state.cacheMu.Unlock()
	// Inspect even when LoadCache was never called: an unknown schema must never
	// be overwritten by a fresh application session.
	_, _ = s.loadCache()
	return s.saveCache(cache)
}

// UpdateCache performs a load/modify/save without losing concurrent updates.
// A recoverable corrupt-cache warning is superseded by the successful new save.
func (s *Store) UpdateCache(update func(model.Cache) model.Cache) error {
	s.state.cacheMu.Lock()
	defer s.state.cacheMu.Unlock()
	cache, _ := s.loadCache()
	return s.saveCache(update(cache.Clone()))
}

func (s *Store) saveCache(cache model.Cache) error {
	if s.state.readOnly {
		return model.E("cache_read_only", "Кеш недоступен для записи; существующий файл сохранён.")
	}
	cache = cache.Clone()
	if len(cache.Fallbacks) > 3 {
		cache.Fallbacks = cache.Fallbacks[:3]
	}
	if cache.Fallbacks == nil {
		cache.Fallbacks = []model.CheckResult{}
	}
	for _, result := range appendResults(cache) {
		if result.Endpoint.Validate() != nil || math.IsNaN(result.LatencyMS) || math.IsInf(result.LatencyMS, 0) || result.LatencyMS < 0 || !model.ValidRole(result.Role) {
			return model.E("cache_write_failed", "Не удалось сохранить стратегии; текущее подключение не изменено.")
		}
	}
	content, err := json.MarshalIndent(struct {
		Schema int `json:"schema_version"`
		model.Cache
	}{1, cache}, "", "  ")
	if err != nil || len(content) > maxCacheSize {
		return model.E("cache_write_failed", "Не удалось сохранить стратегии; текущее подключение не изменено.")
	}
	if err := AtomicWrite(s.Paths.Settings(), content); err != nil {
		return model.E("cache_write_failed", "Не удалось сохранить стратегии; текущее подключение не изменено.")
	}
	return nil
}

func appendResults(cache model.Cache) []model.CheckResult {
	results := append([]model.CheckResult(nil), cache.Fallbacks...)
	if cache.LastGood != nil {
		results = append(results, *cache.LastGood)
	}
	if cache.Preferred != nil {
		results = append(results, *cache.Preferred)
	}
	return results
}

// ClearRuntime must only be called while holding this root's instance lock.
// Non-config files and directories are deliberately left alone.
func (s *Store) ClearRuntime() error {
	entries, err := os.ReadDir(s.Paths.Run())
	if err != nil {
		return model.E("runtime_cleanup_failed", "Не удалось очистить временные конфигурации.")
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
			if err := os.Remove(filepath.Join(s.Paths.Run(), entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return model.E("runtime_cleanup_failed", "Не удалось очистить временные конфигурации.")
			}
		}
	}
	return nil
}

var errInvalidFile = errors.New("invalid private file")

func readBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errInvalidFile
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err == nil && int64(len(content)) > limit {
		err = errInvalidFile
	}
	return content, err
}
