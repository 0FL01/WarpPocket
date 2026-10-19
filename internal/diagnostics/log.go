// Package diagnostics writes only application-owned, bounded, nonsecret events.
package diagnostics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/storage"
)

type Logger struct {
	mu   sync.Mutex
	path string
}

func New(paths storage.Paths) *Logger {
	return &Logger{path: filepath.Join(paths.Logs(), "diagnostics.log")}
}

func (l *Logger) Event(code string, endpoint model.Endpoint) {
	// Do not accept arbitrary exception text, argv, profile objects or tokens.
	if code != "connected" && code != "disconnected" && code != "connection_lost" {
		return
	}
	if endpoint.Host != "" && endpoint.Validate() != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if info, err := os.Lstat(l.path); err == nil {
		if !info.Mode().IsRegular() {
			return
		}
		if info.Size() >= 1<<20 {
			_ = os.Remove(l.path + ".2")
			_ = os.Rename(l.path+".1", l.path+".2")
			if os.Rename(l.path, l.path+".1") != nil {
				return
			}
		}
	}
	file, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer file.Close()
	if storage.PrivateFile(l.path) != nil {
		return
	}
	_ = json.NewEncoder(file).Encode(struct {
		Time     string `json:"time"`
		Code     string `json:"code"`
		Endpoint string `json:"endpoint,omitempty"`
	}{time.Now().UTC().Format(time.RFC3339Nano), code, endpointString(endpoint)})
}

func endpointString(endpoint model.Endpoint) string {
	if endpoint.Host == "" {
		return ""
	}
	return endpoint.String()
}
