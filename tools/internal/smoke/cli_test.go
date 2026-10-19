package smoke

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCLIHelpAndInvalidArgumentsAreSafe(t *testing.T) {
	for _, args := range [][]string{{}, {"--unknown=private-secret"}, {"--exe"}, {"--exe", "x", "--out", "x", "private-secret"}} {
		var stdout, stderr bytes.Buffer
		if Main(context.Background(), args, &stdout, &stderr) != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalid_arguments") {
			t.Fatalf("invalid arguments accepted: %q", args)
		}
		if strings.Contains(stderr.String(), "private-secret") {
			t.Fatal("raw flag error leaked caller input")
		}
	}
	var stdout, stderr bytes.Buffer
	if Main(context.Background(), []string{"--help"}, &stdout, &stderr) != 0 || !strings.Contains(stdout.String(), "--exe") || stderr.Len() != 0 {
		t.Fatal("help failed")
	}
}

func TestNativeUnsupportedPlatformProducesSafeSummary(t *testing.T) {
	if runtime.GOOS == "windows" && runtime.GOARCH == "amd64" {
		t.Skip("this assertion concerns unsupported native platforms only")
	}
	out := filepath.Join(t.TempDir(), "out")
	var stdout, stderr bytes.Buffer
	status := Main(context.Background(), []string{"--exe", "private-secret-missing.exe", "--out", out}, &stdout, &stderr)
	if status != 2 || stderr.Len() != 0 {
		t.Fatal("unsupported platform did not return the documented exit status")
	}
	var summary Summary
	if json.Unmarshal(stdout.Bytes(), &summary) != nil || summary.OK || summary.ErrorCode == nil || summary.Cleanup.OK != true {
		t.Fatal("unsupported result is not a valid safe summary")
	}
	if strings.Contains(stdout.String(), "private-secret") {
		t.Fatal("unsupported error leaked executable path")
	}
	if _, err := os.Stat(filepath.Join(out, "summary.json")); err != nil {
		t.Fatal("unsupported result was not persisted")
	}
}
