package prepare

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func ensureDirectory(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing non-directory source location: %s", dir)
	}
	return nil
}

func isWithin(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func extractSource(archive []byte, version, destination string) (err error) {
	if err := os.Mkdir(destination, 0o700); err != nil {
		return fmt.Errorf("create isolated source directory: %w", err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(destination)
		}
	}()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return fmt.Errorf("invalid wireproxy source gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	base := "wireproxy-" + version
	seen := make(map[string]bool)
	var total int64
	for count := 0; ; count++ {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid wireproxy source tar: %w", err)
		}
		if count >= 10000 {
			return fmt.Errorf("source archive has too many members")
		}
		// GitHub's git archive starts with a global PAX commit comment, which
		// archive/tar exposes while Python's tarfile treats it as metadata.
		// Accept only that inert first header, never global path/link overrides.
		if header.Typeflag == tar.TypeXGlobalHeader && count == 0 && header.Name == "pax_global_header" && len(header.PAXRecords) == 1 && validCommitComment(header.PAXRecords["comment"]) {
			continue
		}
		name := strings.TrimSuffix(header.Name, "/")
		parts := strings.Split(name, "/")
		if parts[0] != base || strings.ContainsAny(name, "\\:\x00") {
			return fmt.Errorf("unexpected archive member: %q", header.Name)
		}
		for _, part := range parts {
			if part == "" || part == "." || part == ".." {
				return fmt.Errorf("unsafe archive member: %q", header.Name)
			}
		}
		if seen[name] {
			return fmt.Errorf("duplicate archive member: %q", header.Name)
		}
		seen[name] = true
		for key := range header.PAXRecords {
			if strings.HasPrefix(key, "GNU.sparse") {
				return fmt.Errorf("unsupported sparse archive member: %q", header.Name)
			}
		}
		if header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg {
			return fmt.Errorf("unsupported archive member: %q", header.Name)
		}
		if len(parts) == 1 {
			if header.Typeflag != tar.TypeDir {
				return fmt.Errorf("archive root must be a directory")
			}
			continue
		}
		target := filepath.Join(append([]string{destination}, parts[1:]...)...)
		if !isWithin(destination, target) {
			return fmt.Errorf("archive member escaped extraction directory")
		}
		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if header.Size <= 0 || header.Size > maxSourceBytes || total+header.Size > maxSourceBytes {
			return fmt.Errorf("empty or oversized archive member: %q", header.Name)
		}
		total += header.Size
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		n, copyErr := io.CopyN(file, tr, header.Size)
		closeErr := file.Close()
		if copyErr != nil || n != header.Size {
			return fmt.Errorf("truncated archive member %q: %w", header.Name, copyErr)
		}
		if closeErr != nil {
			return closeErr
		}
	}
	// Reading the gzip trailer checks its CRC even though tar stops at its own
	// end markers. Do not permit an unbounded decompressed trailer either.
	if n, err := io.Copy(io.Discard, io.LimitReader(gz, maxSourceBytes+1)); err != nil || n > maxSourceBytes {
		return fmt.Errorf("invalid or oversized gzip trailer: %v", err)
	}
	if total == 0 {
		return fmt.Errorf("source archive contains no files")
	}
	return nil
}

func validCommitComment(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func copyModule(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("invalid downloaded module directory: %s", source)
	}
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		if entry.IsDir() {
			return os.Mkdir(target, 0o700)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported file in module copy: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
}

// installSources swaps only the two owned dependency directories, never build/
// or another workstream's outputs. Roll back both on any failed rename.
func installSources(deps, stage string) error {
	names := []string{"wireproxy", "wireguard-go"}
	backups := make(map[string]bool)
	installed := make(map[string]bool)
	rollback := func() error {
		var failures []string
		for _, name := range names {
			target := filepath.Join(deps, name)
			if installed[name] {
				if err := os.Rename(target, filepath.Join(stage, name)); err != nil {
					failures = append(failures, err.Error())
					continue
				}
			}
			if backups[name] {
				if err := os.Rename(filepath.Join(stage, "old-"+name), target); err != nil {
					failures = append(failures, err.Error())
				}
			}
		}
		if len(failures) != 0 {
			return fmt.Errorf("source rollback failed: %s", strings.Join(failures, "; "))
		}
		return nil
	}
	for _, name := range names {
		target := filepath.Join(deps, name)
		if info, err := os.Lstat(target); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				_ = rollback()
				return fmt.Errorf("refusing to replace non-directory dependency: %s", target)
			}
			if err := os.Rename(target, filepath.Join(stage, "old-"+name)); err != nil {
				return fmt.Errorf("back up sources: %w (rollback: %v)", err, rollback())
			}
			backups[name] = true
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect sources: %w (rollback: %v)", err, rollback())
		}
		if err := os.Rename(filepath.Join(stage, name), target); err != nil {
			return fmt.Errorf("install sources: %w (rollback: %v)", err, rollback())
		}
		installed[name] = true
	}
	return nil
}
