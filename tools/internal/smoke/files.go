package smoke

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const copyDirectory = "Копия WarpPocket"
const copyName = copyDirectory + "/WarpPocket.exe"

type outputFiles struct {
	root *os.Root
	path string
}

func openOutput(path string) (*outputFiles, error) {
	if path == "" || strings.ContainsRune(path, 0) {
		return nil, failure("output_invalid")
	}
	absolute, err := filepath.Abs(path)
	if err != nil || os.MkdirAll(absolute, 0o700) != nil {
		return nil, failure("output_open_failed")
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, failure("output_open_failed")
	}
	root, err := os.OpenRoot(canonical)
	if err != nil {
		return nil, failure("output_open_failed")
	}
	return &outputFiles{root: root, path: canonical}, nil
}

func (o *outputFiles) removeStale(name string) error {
	info, err := o.root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || info.IsDir() {
		return failure("stale_file_remove_failed")
	}
	if o.root.Remove(name) != nil {
		return failure("stale_file_remove_failed")
	}
	return nil
}

func (o *outputFiles) temporary(prefix string) (*os.File, string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, "", failure("temporary_file_failed")
	}
	name := prefix + hex.EncodeToString(random[:]) + ".tmp"
	file, err := o.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, "", failure("temporary_file_failed")
	}
	return file, name, nil
}

func (o *outputFiles) filesystemTimestamp() (time.Time, error) {
	// Compare two timestamps supplied by the same filesystem, not NTFS metadata
	// against GetSystemTimePreciseAsFileTime (which can be ahead of metadata).
	file, name, err := o.temporary(".launch-")
	if err != nil {
		return time.Time{}, err
	}
	defer o.root.Remove(name)
	if file.Close() != nil {
		return time.Time{}, failure("timestamp_marker_failed")
	}
	info, err := o.root.Stat(name)
	if err != nil {
		return time.Time{}, failure("timestamp_marker_failed")
	}
	return info.ModTime(), nil
}

func (o *outputFiles) copyExecutable(path string) (string, int64, error) {
	input, err := os.Open(path)
	if err != nil {
		return "", 0, failure("executable_open_failed")
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return "", 0, failure("executable_invalid")
	}
	if err := o.root.Mkdir(copyDirectory, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", 0, failure("executable_copy_failed")
	}
	directory, err := o.root.Lstat(copyDirectory)
	if err != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 {
		return "", 0, failure("executable_copy_failed")
	}
	copyRoot, err := o.root.OpenRoot(copyDirectory)
	if err != nil {
		return "", 0, failure("executable_copy_failed")
	}
	contents, err := copyRoot.Open(".")
	_ = copyRoot.Close()
	if err != nil {
		return "", 0, failure("executable_copy_failed")
	}
	entries, readErr := contents.ReadDir(2)
	_ = contents.Close()
	if readErr != nil && readErr != io.EOF || len(entries) > 1 || len(entries) == 1 && entries[0].Name() != "WarpPocket.exe" {
		return "", 0, failure("executable_directory_not_single")
	}
	// Rename, rather than truncate an existing path: a stale symlink or hardlink
	// must not cause writing to some unrelated executable.
	temporary, name, err := o.temporary(copyDirectory + "/.copy-")
	if err != nil {
		return "", 0, err
	}
	defer o.root.Remove(name)
	written, copyErr := io.Copy(temporary, input)
	if err := temporary.Sync(); copyErr == nil {
		copyErr = err
	}
	if err := temporary.Close(); copyErr == nil {
		copyErr = err
	}
	if copyErr != nil || written != info.Size() || o.root.Rename(name, copyName) != nil {
		return "", 0, failure("executable_copy_failed")
	}
	return filepath.Join(o.path, filepath.FromSlash(copyName)), written, nil
}

func (o *outputFiles) readReport(name, mode string, notBefore time.Time) (Report, error) {
	var zero Report
	before, err := o.root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return zero, fs.ErrNotExist
	}
	if err != nil || !before.Mode().IsRegular() {
		return zero, failure("report_file_invalid")
	}
	file, err := o.root.Open(name)
	if err != nil {
		return zero, failure("report_file_invalid")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) || info.Size() > MaxReportBytes {
		return zero, failure("report_file_invalid")
	}
	if info.ModTime().Before(notBefore) {
		return zero, failure("report_stale")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, MaxReportBytes+1))
	if err != nil || len(encoded) > MaxReportBytes {
		return zero, failure("report_file_invalid")
	}
	report, err := ParseReport(encoded, mode)
	if err != nil {
		return zero, err
	}
	if _, err = o.workspaceName(report.Workspace); err != nil {
		return zero, err
	}
	return report, nil
}

func (o *outputFiles) workspaceName(path string) (string, error) {
	if path == "" || strings.ContainsRune(path, 0) || !filepath.IsAbs(path) {
		return "", failure("workspace_invalid")
	}
	relative, err := filepath.Rel(o.path, filepath.Clean(path))
	if err != nil || !filepath.IsLocal(relative) || relative == "." || filepath.Dir(relative) != "." {
		return "", failure("workspace_outside_output")
	}
	// Only the application's disposable runtime-* child is eligible for cleanup.
	// In particular, no report can authorize removing out or the copied EXE.
	if !strings.HasPrefix(relative, "runtime-") || len(relative) <= len("runtime-") || len(relative) > 160 {
		return "", failure("workspace_invalid")
	}
	for _, char := range strings.TrimPrefix(relative, "runtime-") {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return "", failure("workspace_invalid")
		}
	}
	info, err := o.root.Lstat(relative)
	if errors.Is(err, fs.ErrNotExist) {
		return relative, nil // A graceful application may already have removed it.
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", failure("workspace_cleanup_unsafe")
	}
	return relative, nil
}

func (o *outputFiles) removeWorkspace(path string) error {
	name, err := o.workspaceName(path) // Revalidate immediately before deletion.
	if err != nil {
		return err
	}
	// Root provides traversal-resistant containment, including symlink/junction
	// swaps while walking a directory. RemoveAll never follows links in children.
	if o.root.RemoveAll(name) != nil {
		return failure("workspace_cleanup_failed")
	}
	return nil
}

func (o *outputFiles) runtimeNames() (map[string]bool, error) {
	directory, err := o.root.Open(".")
	if err != nil {
		return nil, failure("workspace_snapshot_failed")
	}
	defer directory.Close()
	entries, err := directory.ReadDir(10001)
	if err != nil && err != io.EOF || len(entries) > 10000 {
		return nil, failure("workspace_snapshot_failed")
	}
	names := make(map[string]bool)
	for _, entry := range entries {
		names[strings.ToLower(entry.Name())] = true
	}
	return names, nil
}

func (o *outputFiles) writeSummary(summary Summary) error {
	file, name, err := o.temporary(".summary-")
	if err != nil {
		return failure("summary_write_failed")
	}
	defer o.root.Remove(name)
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(summary)
	if syncErr := file.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil || o.root.Rename(name, "summary.json") != nil {
		return failure("summary_write_failed")
	}
	return nil
}
