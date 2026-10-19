package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/0FL01/WarpPocket/tools/internal/smoke"
)

func main() {
	current := flag.String("current-report", "", "verified Go smoke summary")
	output := flag.String("out", "", "safe comparison JSON")
	flag.Parse()
	if *current == "" || *output == "" || flag.NArg() != 0 {
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	comparison, err := smoke.CompareBaseline(ctx, *current, *output)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Footprint comparison failed:", err)
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(comparison)
}
