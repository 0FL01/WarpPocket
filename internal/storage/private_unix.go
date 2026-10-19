//go:build !windows

package storage

import "os"

func setPrivate(path string, directory bool) error {
	if directory {
		return os.Chmod(path, 0700)
	}
	return os.Chmod(path, 0600)
}

func replaceFile(source, destination string) error { return os.Rename(source, destination) }

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
