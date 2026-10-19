package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/0FL01/WarpPocket/tools/internal/smoke"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(smoke.Main(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
