package main

import (
	"strings"
	"testing"
)

func TestModesAreExclusiveBeforeGUIOrWorkerStartup(t *testing.T) {
	for _, args := range [][]string{
		{"--smoke", "first", "--smoke-wait", "second"},
		{"--data-dir", "data", "--smoke", "report"},
		{"--data-dir", "data", "--smoke-wait", "report"},
		{"--engine"}, {"--engine", "--role", "primary"},
		{"--engine", "--role", "primary", "--config", "file", "--smoke", "report"},
		{"--engine", "--role", "primary", "--config", "file", "--data-dir", "data"},
		{"--role", "primary"}, {"--config", "file"}, {"unexpected"}, {"--daemon"},
	} {
		if _, err := parse(args); err == nil {
			t.Fatalf("accepted ambiguous/unsupported mode: %v", args)
		}
	}
	for _, args := range [][]string{nil, {"--data-dir", "data"}, {"--smoke", "report"}, {"--smoke-wait", "report"}, {"--engine", "--role", "probe", "--config", "private path"}} {
		if _, err := parse(args); err != nil {
			t.Fatalf("rejected supported mode %v: %v", args, err)
		}
	}
	if _, err := parse([]string{"--secret=never-echo-this"}); err == nil || strings.Contains(err.Error(), "never-echo-this") {
		t.Fatal("CLI validation leaked unrecognized input or accepted it")
	}
}
