package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCLIRejectsArbitraryOptions(t *testing.T) {
	for _, args := range [][]string{{"--url", "https://attacker.example"}, {"positional"}, {"--root"}} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("args %v: code=%d stdout=%s stderr=%s", args, code, &stdout, &stderr)
		}
	}
}

func TestCLIFailureDoesNotReportSuccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--root", t.TempDir()}, &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "Source preparation failed") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, &stdout, &stderr)
	}
}
