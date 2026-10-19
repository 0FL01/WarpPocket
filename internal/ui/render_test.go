//go:build guirender

package ui

import (
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gioui.org/gpu/headless"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"github.com/0FL01/WarpPocket/internal/model"
)

// This gate is explicitly enabled in graphical CI. Failure to initialize or
// render is a failure, not a skip or a replacement by a browser mock.
func TestRenderedCrayonStatesAndDPI(t *testing.T) {
	for _, scale := range []float32{1, 1.25, 1.5} {
		for _, state := range []string{"disconnected", "connecting", "connected", "searching", "error", "menu", "consent"} {
			t.Run(fmt.Sprintf("%s-%g", state, scale), func(t *testing.T) {
				c := &testController{state: model.Snapshot{State: model.State(state)}}
				if state == "searching" {
					c.state.State = model.Connected
					c.state.Searching = true
				}
				if state == "menu" || state == "consent" {
					c.state.State = model.Disconnected
				}
				if c.state.State == model.Connected {
					c.state.Endpoint = model.Endpoint{Host: "188.114.97.1", Port: 4500}
					c.state.LatencyMS = 414
				}
				if state == "error" {
					c.state.Message = "Не удалось проверить соединение. Попробуйте снова."
				}
				v := NewView(c, nil, "Лицензии")
				v.Update()
				v.completed, v.limit, v.found = 12, 30, 1
				v.menuOpen = state == "menu"
				if state == "consent" {
					v.consent = model.Primary
				}
				size := image.Pt(int(442*scale), int(700*scale))
				w, err := headless.NewWindow(size.X, size.Y)
				if err != nil {
					t.Fatal(err)
				}
				defer w.Release()
				var ops op.Ops
				gtx := layout.Context{Ops: &ops, Metric: unit.Metric{PxPerDp: scale, PxPerSp: scale}, Constraints: layout.Exact(size), Now: time.Unix(100, 0)}
				v.Layout(gtx)
				if err := w.Frame(&ops); err != nil {
					t.Fatal(err)
				}
				img := image.NewRGBA(image.Rectangle{Max: size})
				if err := w.Screenshot(img); err != nil {
					t.Fatal(err)
				}
				inkPixels := 0
				for y := 0; y < size.Y; y++ {
					for x := 0; x < size.X; x++ {
						p := img.RGBAAt(x, y)
						if p.R < 150 && p.G < 150 && p.B < 150 && p.A > 0 {
							inkPixels++
						}
					}
				}
				if inkPixels < 500 {
					t.Fatal("native frame is blank")
				}
				if out := os.Getenv("WARPPOCKET_SCREENSHOTS"); out != "" {
					if err := os.MkdirAll(out, 0700); err != nil {
						t.Fatal(err)
					}
					file, err := os.Create(filepath.Join(out, fmt.Sprintf("%s-%g.png", state, scale)))
					if err != nil {
						t.Fatal(err)
					}
					if err := png.Encode(file, img); err != nil {
						file.Close()
						t.Fatal(err)
					}
					if err := file.Close(); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
