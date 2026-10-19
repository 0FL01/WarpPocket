package storage

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/0FL01/WarpPocket/internal/model"
)

func PrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return privateError()
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return privateError()
	}
	if err := setPrivate(path, true); err != nil {
		return privateError()
	}
	return nil
}

func PrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return privateError()
	}
	if err := setPrivate(path, false); err != nil {
		return privateError()
	}
	return nil
}

func privateError() error {
	return model.E("private_storage_failed", "Не удалось защитить личные файлы приложения.")
}

// AtomicWrite protects the temporary inode before writing secrets and replaces
// existing files atomically on both Unix and Windows. A failed replacement leaves
// the previous file intact and removes the temporary file.
func AtomicWrite(path string, content []byte) error {
	return atomicWrite(path, content, replaceFile)
}

func atomicWrite(path string, content []byte, replace func(string, string) error) error {
	fail := func() error {
		return model.E("storage_write_failed", "Не удалось безопасно сохранить файл приложения.")
	}
	parent := filepath.Dir(path)
	if err := PrivateDirectory(parent); err != nil {
		return fail()
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fail()
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail()
	}
	file, err := os.CreateTemp(parent, "."+filepath.Base(path)+".")
	if err != nil {
		return fail()
	}
	name := file.Name()
	defer os.Remove(name)
	defer file.Close()
	if PrivateFile(name) != nil {
		return fail()
	}
	if _, err := file.Write(content); err != nil {
		return fail()
	}
	if file.Sync() != nil || file.Close() != nil {
		return fail()
	}
	if err := replace(name, path); err != nil {
		return fail()
	}
	if err := syncDirectory(parent); err != nil {
		return fail()
	}
	return nil
}
