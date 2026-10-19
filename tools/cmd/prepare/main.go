// Command prepare installs the pinned, patched engine sources. It does not build
// an upstream wireproxy executable: the application imports its worker package.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/0FL01/WarpPocket/tools/internal/prepare"
)

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "repository root (default: locate vendor/wireproxy-build.json above the working directory)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "prepare: unexpected positional arguments")
		return 2
	}
	result, err := prepare.Prepare(ctx, *root, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "Source preparation failed: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintf(stderr, "prepare: write result: %v\n", err)
		return 1
	}
	return 0
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
