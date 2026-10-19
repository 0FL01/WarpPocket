package main

import (
	"github.com/0FL01/WarpPocket/tools/internal/release"
	"os"
)

func main() { os.Exit(release.Main(os.Args[1:], os.Getenv, os.Stdout, os.Stderr)) }
