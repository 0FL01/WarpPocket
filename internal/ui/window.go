package ui

import (
	"errors"
	"io"
	"time"

	"gioui.org/app"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/x/explorer"
	"github.com/0FL01/WarpPocket/internal/model"
)

type FrameInfo struct {
	Count, Width, Height int
	PxPerDp              float32
	NativeChecks         bool
}
type Options struct {
	Title       string
	Diagnostics func() string
	Licenses    string
	Import      func(data []byte, role string) error
	// Explicit offline-smoke probes, never enabled for normal user windows.
	NativeChecks, CloseWithPicker bool
	// OnFrame runs in the event loop AFTER a real native frame submission.
	// Returning true requests the same asynchronous close as the OS close action.
	OnFrame func(FrameInfo) bool
}
type dialogResult struct {
	data []byte
	role string
	err  error
}

func Run(controller Controller, options Options) error {
	w := new(app.Window)
	title := options.Title
	if title == "" {
		title = "WarpPocket"
	}
	w.Option(app.Title(title), app.Size(442, 620), app.MinSize(380, 420))
	v := NewView(controller, options.Diagnostics, options.Licenses)
	expl := explorer.NewExplorer(w)
	var probe *nativeProbe
	if options.NativeChecks {
		probe = newNativeProbe(options.CloseWithPicker)
		defer probe.cancel()
	}
	results := make(chan dialogResult, 1)
	closed := make(chan struct{})
	stopTick := make(chan struct{})
	defer close(stopTick)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopTick:
				return
			case <-ticker.C:
				w.Invalidate()
			}
		}
	}()
	startClose := func() {
		if v.closing {
			return
		}
		v.closing = true
		v.consent = ""
		v.info = ""
		v.menuOpen = false
		go func() { controller.Close(); close(closed); w.Invalidate() }()
	}
	var ops op.Ops
	frames := 0
	for {
		e := w.Event()
		expl.ListenEvents(e)
		switch event := e.(type) {
		case *app.ClosingEvent:
			startClose()
			if probe != nil {
				probe.closing(v.dialogBusy)
			}
			select {
			case <-closed:
				if v.dialogBusy {
					event.Abort()
				}
			default:
				event.Abort()
			}
		case app.DestroyEvent:
			controller.Close()
			if probe != nil && probe.err != nil {
				return probe.err
			}
			return event.Err
		case app.FrameEvent:
			select {
			case result := <-results:
				v.dialogBusy = false
				if probe != nil {
					probe.pickerCancelled = errors.Is(result.err, explorer.ErrUserDecline)
				}
				if !v.closing {
					if result.err != nil {
						if !errors.Is(result.err, explorer.ErrUserDecline) {
							v.notice = model.SafeMessage(result.err)
						}
					} else if options.Import != nil {
						// Import is a bounded local operation; file selection happens on
						// a worker. Networking never runs in this callback.
						if err := options.Import(result.data, result.role); err != nil {
							v.notice = model.SafeMessage(err)
						} else {
							v.notice = "Профиль сохранён и будет использован при подключении."
						}
					}
				}
			default:
			}
			v.Update()
			gtx := app.NewContext(&ops, event)
			if probe != nil {
				probe.frame(gtx, v)
			}
			v.Layout(gtx)
			event.Frame(gtx.Ops)
			frames++
			if options.OnFrame != nil && options.OnFrame(FrameInfo{Count: frames, Width: event.Size.X, Height: event.Size.Y, PxPerDp: event.Metric.PxPerDp, NativeChecks: probe != nil && probe.ready()}) {
				startClose()
			}
			if probe != nil && probe.err != nil {
				startClose()
			}
			if probe != nil && probe.pickerSeen && probe.closeWithPicker && !probe.closeSent {
				probe.closeSent = true
				w.Perform(system.ActionClose)
			}
			if v.importRequest != "" && !v.dialogBusy && !v.closing {
				role := v.importRequest
				v.importRequest = ""
				v.dialogBusy = true
				if probe != nil {
					probe.startPicker()
				}
				go func() {
					f, err := expl.ChooseFile(".conf")
					var data []byte
					if err == nil {
						data, err = io.ReadAll(io.LimitReader(f, 65537))
						f.Close()
						if len(data) > 65536 {
							err = model.E("profile_invalid", "Профиль слишком большой.")
						}
					}
					results <- dialogResult{data, role, err}
					w.Invalidate()
				}()
			}
			if v.closing && !v.dialogBusy {
				select {
				case <-closed:
					w.Perform(system.ActionClose)
				default:
				}
			}
		}
	}
}

// These names are checked at compile time; the drawing layer uses logical dp/sp.
var _ layout.Widget = doodle
var _ unit.Dp = 442
