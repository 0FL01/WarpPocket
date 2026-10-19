package prepare

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type archiveEntry struct {
	header tar.Header
	data   string
}

func makeArchive(t *testing.T, entries ...archiveEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		header := entry.header
		if header.Mode == 0 && header.Typeflag != tar.TypeXGlobalHeader {
			header.Mode = 0o777
		}
		if header.Typeflag == 0 {
			header.Typeflag = tar.TypeReg
		}
		if header.Size == 0 {
			header.Size = int64(len(entry.data))
		}
		if err := tw.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(entry.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func archiveFiles(t *testing.T, files map[string]string) []byte {
	t.Helper()
	keys := make([]string, 0, len(files))
	for path := range files {
		keys = append(keys, path)
	}
	sort.Strings(keys)
	entries := []archiveEntry{{header: tar.Header{Name: "wireproxy-1.1.3/", Typeflag: tar.TypeDir}}}
	for _, path := range keys {
		entries = append(entries, archiveEntry{header: tar.Header{Name: "wireproxy-1.1.3/" + path}, data: files[path]})
	}
	return makeArchive(t, entries...)
}

func TestExtractSource(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "source")
	archive := archiveFiles(t, map[string]string{"go.mod": "module fixture\n", "cmd/wireproxy/main.go": "package main\n"})
	if err := extractSource(archive, "1.1.3", destination); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(destination, "cmd", "wireproxy", "main.go"))
	if err != nil || string(got) != "package main\n" {
		t.Fatalf("source = %q, %v", got, err)
	}
	if err := extractSource(archive, "1.1.3", destination); err == nil {
		t.Fatal("extracted into an existing directory")
	}
}

func TestGitHubGlobalPAXComment(t *testing.T) {
	for _, test := range []struct {
		name    string
		records map[string]string
		valid   bool
	}{
		{"commit-comment", map[string]string{"comment": strings.Repeat("a", 40)}, true},
		{"unrecognized-comment", map[string]string{"comment": "unexpected"}, false},
		{"global-path-override", map[string]string{"path": "../escape", "comment": strings.Repeat("a", 40)}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			archive := makeArchive(t,
				archiveEntry{header: tar.Header{Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader, PAXRecords: test.records}},
				archiveEntry{header: tar.Header{Name: "wireproxy-1.1.3/go.mod"}, data: "module fixture\n"},
			)
			err := extractSource(archive, "1.1.3", filepath.Join(t.TempDir(), "source"))
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v: %v", test.valid, err)
			}
		})
	}
}

func TestMaliciousArchives(t *testing.T) {
	regular := archiveEntry{header: tar.Header{Name: "wireproxy-1.1.3/file"}, data: "payload"}
	for _, test := range []struct {
		name    string
		entries []archiveEntry
	}{
		{"parent", []archiveEntry{{header: tar.Header{Name: "wireproxy-1.1.3/../escape"}, data: "bad"}}},
		{"absolute", []archiveEntry{{header: tar.Header{Name: "/wireproxy-1.1.3/escape"}, data: "bad"}}},
		{"wrong-root", []archiveEntry{{header: tar.Header{Name: "other-1.1.3/file"}, data: "bad"}}},
		{"backslash", []archiveEntry{{header: tar.Header{Name: "wireproxy-1.1.3/..\\escape"}, data: "bad"}}},
		{"drive", []archiveEntry{{header: tar.Header{Name: "wireproxy-1.1.3/C:/escape"}, data: "bad"}}},
		{"empty-component", []archiveEntry{{header: tar.Header{Name: "wireproxy-1.1.3/a//b"}, data: "bad"}}},
		{"dot-component", []archiveEntry{{header: tar.Header{Name: "wireproxy-1.1.3/a/./b"}, data: "bad"}}},
		{"symlink", []archiveEntry{{header: tar.Header{Name: "wireproxy-1.1.3/link", Typeflag: tar.TypeSymlink, Linkname: "../outside"}}}},
		{"hardlink", []archiveEntry{regular, {header: tar.Header{Name: "wireproxy-1.1.3/link", Typeflag: tar.TypeLink, Linkname: "wireproxy-1.1.3/file"}}}},
		{"device", []archiveEntry{{header: tar.Header{Name: "wireproxy-1.1.3/device", Typeflag: tar.TypeChar}}}},
		{"fifo", []archiveEntry{{header: tar.Header{Name: "wireproxy-1.1.3/fifo", Typeflag: tar.TypeFifo}}}},
		{"duplicate-file", []archiveEntry{regular, regular}},
		{"duplicate-directory", []archiveEntry{{header: tar.Header{Name: "wireproxy-1.1.3/", Typeflag: tar.TypeDir}}, {header: tar.Header{Name: "wireproxy-1.1.3/", Typeflag: tar.TypeDir}}, regular}},
		{"root-file", []archiveEntry{{header: tar.Header{Name: "wireproxy-1.1.3"}, data: "bad"}}},
		{"empty-file", []archiveEntry{{header: tar.Header{Name: "wireproxy-1.1.3/file"}}}},
		{"no-files", nil},
		{"file-as-parent", []archiveEntry{regular, {header: tar.Header{Name: "wireproxy-1.1.3/file/child"}, data: "bad"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			destination := filepath.Join(parent, "source")
			if err := extractSource(makeArchive(t, test.entries...), "1.1.3", destination); err == nil {
				t.Fatal("accepted malicious archive")
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatalf("failed extraction left a partial tree: %v", err)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("archive wrote outside extraction root: %v, %v", entries, err)
			}
		})
	}
	archive := makeArchive(t, regular)
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"invalid-gzip", []byte("not a tar.gz")},
		{"truncated-gzip", archive[:len(archive)-4]},
		{"corrupt-gzip-checksum", append(append([]byte(nil), archive[:len(archive)-8]...), make([]byte, 8)...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := extractSource(test.data, "1.1.3", filepath.Join(t.TempDir(), "source")); err == nil {
				t.Fatal("accepted corrupt archive")
			}
		})
	}
}

func TestCopyModuleDoesNotModifySource(t *testing.T) {
	source := t.TempDir()
	writeTree(t, source, map[string]string{"go.mod": "module fixture\n", "nested/source.go": "package fixture\n"})
	destination := filepath.Join(t.TempDir(), "module")
	if err := copyModule(source, destination); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, "go.mod"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(source, "go.mod"), "module fixture\n")
	if err := os.Symlink("go.mod", filepath.Join(source, "link")); err != nil {
		t.Fatal(err)
	}
	if err := copyModule(source, filepath.Join(t.TempDir(), "module")); err == nil {
		t.Fatal("accepted a module symlink")
	}
}

func TestInstallSources(t *testing.T) {
	deps, stage := t.TempDir(), t.TempDir()
	writeTree(t, deps, map[string]string{"wireproxy/marker": "old proxy", "wireguard-go/marker": "old guard", "unrelated/marker": "untouched"})
	writeTree(t, stage, map[string]string{"wireproxy/marker": "new proxy", "wireguard-go/marker": "new guard"})
	if err := installSources(deps, stage); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(deps, "wireproxy", "marker"), "new proxy")
	assertFile(t, filepath.Join(deps, "wireguard-go", "marker"), "new guard")
	assertFile(t, filepath.Join(deps, "unrelated", "marker"), "untouched")
	assertFile(t, filepath.Join(stage, "old-wireproxy", "marker"), "old proxy")
	assertFile(t, filepath.Join(stage, "old-wireguard-go", "marker"), "old guard")
}

func TestInstallSourcesRollback(t *testing.T) {
	for _, failure := range []string{"missing-guard-stage", "symlink-guard-target"} {
		t.Run(failure, func(t *testing.T) {
			deps, stage := t.TempDir(), t.TempDir()
			writeTree(t, deps, map[string]string{"wireproxy/marker": "old proxy", "unrelated/marker": "untouched"})
			writeTree(t, stage, map[string]string{"wireproxy/marker": "new proxy"})
			if failure == "missing-guard-stage" {
				writeTree(t, deps, map[string]string{"wireguard-go/marker": "old guard"})
			} else {
				if err := os.Symlink(t.TempDir(), filepath.Join(deps, "wireguard-go")); err != nil {
					t.Fatal(err)
				}
			}
			if err := installSources(deps, stage); err == nil {
				t.Fatal("installed incomplete or unsafe sources")
			}
			assertFile(t, filepath.Join(deps, "wireproxy", "marker"), "old proxy")
			assertFile(t, filepath.Join(deps, "unrelated", "marker"), "untouched")
			if failure == "missing-guard-stage" {
				assertFile(t, filepath.Join(deps, "wireguard-go", "marker"), "old guard")
			}
		})
	}
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, data := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != want {
		t.Fatalf("%s = %.200q, %v; want %.200q", path, data, err, want)
	}
}

func TestDependencyDirectoryRejectsSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), path); err != nil {
		t.Fatal(err)
	}
	if err := ensureDirectory(path); err == nil || !strings.Contains(err.Error(), "non-directory") {
		t.Fatalf("accepted a dependency symlink: %v", err)
	}
}
