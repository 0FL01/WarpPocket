package storage

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/0FL01/WarpPocket/internal/model"
)

// Lock interoperates with the legacy persistent .instance.lock. Never unlink it:
// another process may already have opened the same inode while waiting.
type Lock struct {
	mu   sync.Mutex
	file *os.File
}

func AcquireLock(root string) (*Lock, error) {
	if root == "" || PrivateDirectory(root) != nil {
		return nil, model.E("instance_lock_failed", "Не удалось открыть блокировку приложения.")
	}
	path := filepath.Join(root, ".instance.lock")
	file, err := openLock(path)
	if err != nil {
		return nil, model.E("instance_lock_failed", "Не удалось открыть блокировку приложения.")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || PrivateFile(path) != nil {
		file.Close()
		return nil, model.E("instance_lock_failed", "Не удалось защитить блокировку приложения.")
	}
	if err := lockFile(file); err != nil {
		file.Close()
		return nil, model.E("already_running", "WarpPocket уже запущен для этого каталога данных.")
	}
	if info.Size() == 0 {
		if _, err := file.WriteAt([]byte{0}, 0); err != nil {
			unlockFile(file)
			file.Close()
			return nil, model.E("instance_lock_failed", "Не удалось подготовить блокировку приложения.")
		}
	}
	return &Lock{file: file}, nil
}

func (l *Lock) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	unlockErr := unlockFile(l.file)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil || closeErr != nil {
		return model.E("instance_lock_failed", "Не удалось освободить блокировку приложения.")
	}
	return nil
}
