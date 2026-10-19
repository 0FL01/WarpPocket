package prepare

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type command struct {
	Args    []string
	Dir     string
	Env     []string
	Timeout time.Duration
	Label   string
}

type commandResult struct {
	Stdout, Stderr []byte
}

type runner func(context.Context, command) (commandResult, error)

func runCommand(ctx context.Context, request command) (commandResult, error) {
	ctx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, request.Args[0], request.Args[1:]...)
	cmd.Dir, cmd.Env = request.Dir, request.Env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	result := commandResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err != nil {
		if ctx.Err() != nil {
			return result, fmt.Errorf("%s stopped: %w", request.Label, ctx.Err())
		}
		tail := strings.TrimSpace(stderr.String())
		if tail == "" {
			tail = strings.TrimSpace(stdout.String())
		}
		if len(tail) > 1500 {
			tail = tail[len(tail)-1500:]
		}
		return result, fmt.Errorf("%s failed: %w: %s", request.Label, err, tail)
	}
	return result, nil
}

func setEnv(env []string, changes ...string) []string {
	result := make([]string, 0, len(env)+len(changes)/2)
	for _, item := range env {
		key, _, _ := strings.Cut(item, "=")
		replaced := false
		for i := 0; i < len(changes); i += 2 {
			if strings.EqualFold(key, changes[i]) {
				replaced = true
				break
			}
		}
		if !replaced {
			result = append(result, item)
		}
	}
	for i := 0; i < len(changes); i += 2 {
		result = append(result, changes[i]+"="+changes[i+1])
	}
	return result
}
