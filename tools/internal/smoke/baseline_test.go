package smoke

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestPinnedBaselineArchive(t *testing.T) {
	archive := func(name string, contents []byte) []byte {
		var out bytes.Buffer
		writer := zip.NewWriter(&out)
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		entry.Write(contents)
		writer.Close()
		return out.Bytes()
	}
	executable := []byte("MZ synthetic pinned binary")
	expected := fmt.Sprintf("%x", sha256.Sum256(executable))
	for _, tc := range []struct {
		name string
		data []byte
		hash string
		ok   bool
	}{
		{"valid", archive("WarpPocket.exe", executable), expected, true},
		{"digest", archive("WarpPocket.exe", executable), "bad", false},
		{"path", archive("../WarpPocket.exe", executable), expected, false},
		{"not_exe", archive("WarpPocket.exe", []byte("not an EXE")), "", false},
		{"not_zip", []byte("not a ZIP"), expected, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := baselineExecutable(tc.data, tc.hash)
			if (err == nil) != tc.ok || (tc.ok && !bytes.Equal(got, executable)) {
				t.Fatalf("baseline accepted=%v, expected=%v", err == nil, tc.ok)
			}
		})
	}
}
