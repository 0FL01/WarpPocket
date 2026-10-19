package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"gioui.org/app"
	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/ui"
)

// Bootstrap controller exists only for the early native-render acceptance gate.
// Normal application wiring is added after this gate, never released as a demo.
type frameController struct{ sync.Mutex }

func (*frameController) Status() model.Snapshot    { return model.Snapshot{State: model.Disconnected} }
func (*frameController) PollEvents() []model.Event { return nil }
func (*frameController) Connect(bool)              {}
func (*frameController) Disconnect()               {}
func (*frameController) StartSearch(bool)          {}
func (*frameController) CancelSearch()             {}
func (*frameController) Close()                    {}

func main() {
	if len(os.Args) != 3 || os.Args[1] != "--ui-smoke" {
		fmt.Fprintln(os.Stderr, "Go migration bootstrap: --ui-smoke REPORT is required.")
		return
	}
	report := os.Args[2]
	go func() {
		frames := 0
		err := ui.Run(&frameController{}, ui.Options{Title: "WarpPocket — Gio acceptance", OnFrame: func(info ui.FrameInfo) bool { frames = info.Count; return frames >= 3 }})
		data, _ := json.MarshalIndent(map[string]any{"gio_frame": frames >= 3 && err == nil, "frames": frames, "pid": os.Getpid()}, "", "  ")
		writeErr := os.WriteFile(report, data, 0600)
		if err != nil || writeErr != nil || frames < 3 {
			os.Exit(1)
		}
		os.Exit(0)
	}()
	app.Main()
}
