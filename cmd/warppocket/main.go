package main

import (
	"flag"
	"io"
	"os"

	"gioui.org/app"
	"github.com/0FL01/WarpPocket/internal/application"
	"github.com/0FL01/WarpPocket/internal/engine"
	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/resources"
	"github.com/0FL01/WarpPocket/internal/smoke"
	"github.com/0FL01/WarpPocket/internal/ui"
)

type options struct {
	engine                                    bool
	role, config, dataDir, report, waitReport string
}

func parse(args []string) (options, error) {
	flags := flag.NewFlagSet("WarpPocket", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	engineMode := flags.Bool("engine", false, "private self-worker mode")
	role := flags.String("role", "", "private worker role")
	config := flags.String("config", "", "private normalized runtime config")
	dataDir := flags.String("data-dir", "", "private data directory")
	report := flags.String("smoke", "", "offline GUI/engine smoke report")
	waitReport := flags.String("smoke-wait", "", "offline GUI crash-test ready report")
	invalid := func() (options, error) {
		return options{}, model.E("invalid_options", "Недопустимые параметры запуска.")
	}
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return invalid()
	}
	if *engineMode {
		// Self-workers never initialize a window or take the GUI instance lock.
		if *dataDir != "" || *report != "" || *waitReport != "" || *config == "" || *role == "" {
			return invalid()
		}
	} else if *role != "" || *config != "" || *report != "" && *waitReport != "" || *dataDir != "" && (*report != "" || *waitReport != "") {
		return invalid()
	}
	return options{*engineMode, *role, *config, *dataDir, *report, *waitReport}, nil
}

func main() {
	o, err := parse(os.Args[1:])
	if err != nil {
		os.Exit(2)
	}
	if o.engine {
		// Fixed worker dispatch precedes app.Main, GUI locks and window creation.
		if engine.Run(o.config, o.role) != nil {
			os.Exit(1)
		}
		return
	}
	go func() {
		os.Exit(run(o.dataDir, o.report, o.waitReport))
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
