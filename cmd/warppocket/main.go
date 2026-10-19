package main

import (
	"flag"
	"io"
	"os"

	"gioui.org/app"
	"github.com/0FL01/WarpPocket/internal/application"
	"github.com/0FL01/WarpPocket/internal/engine"
	"github.com/0FL01/WarpPocket/internal/resources"
	"github.com/0FL01/WarpPocket/internal/smoke"
	"github.com/0FL01/WarpPocket/internal/ui"
)

func main() {
	flags := flag.NewFlagSet("WarpPocket", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	engineMode := flags.Bool("engine", false, "private self-worker mode")
	role := flags.String("role", "", "private worker role")
	config := flags.String("config", "", "private normalized runtime config")
	dataDir := flags.String("data-dir", "", "private data directory")
	report := flags.String("smoke", "", "offline GUI/engine smoke report")
	waitReport := flags.String("smoke-wait", "", "offline GUI crash-test ready report")
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	if *engineMode {
		// Self-workers never initialize a window or take the GUI instance lock.
		if *dataDir != "" || *report != "" || *waitReport != "" || *config == "" || *role == "" {
			os.Exit(2)
		}
		if engine.Run(*config, *role) != nil {
			os.Exit(1)
		}
		return
	}
	if *role != "" || *config != "" || *report != "" && *waitReport != "" || *dataDir != "" && (*report != "" || *waitReport != "") {
		os.Exit(2)
	}
	go func() {
		os.Exit(run(*dataDir, *report, *waitReport))
	}()
	app.Main()
}

// All cleanup defers run before the process exits, after Gio's main loop ends.
func run(dataDir, report, waitReport string) int {
	if report != "" || waitReport != "" {
		wait := waitReport != ""
		if wait {
			report = waitReport
		}
		if smoke.Run(report, wait) != nil {
			return 1
		}
		return 0
	}
	a, err := application.New(dataDir, "")
	if err != nil {
		_ = ui.ShowError(err)
		return 1
	}
	defer a.Close()
	err = ui.Run(a.Controller, ui.Options{Diagnostics: a.Diagnostics, Licenses: resources.Licenses, Import: a.Import})
	if err != nil || a.Controller.CloseError() != nil {
		return 1
	}
	return 0
}
