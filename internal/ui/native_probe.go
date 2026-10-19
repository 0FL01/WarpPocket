package ui

import (
	"context"
	"io"
	"time"

	"gioui.org/io/clipboard"
	"gioui.org/io/event"
	"gioui.org/io/transfer"
	"gioui.org/layout"
	"github.com/0FL01/WarpPocket/internal/model"
)

// nativeProbe is used only by the explicit offline smoke mode. It exercises the
// real copy action and native picker, never reads an existing clipboard value
// or imports a user file. All widget/probe state stays on the window loop.
type nativeProbe struct {
	closeWithPicker                     bool
	profilePath                         string
	imported                            bool
	frames                              int
	clipboardOK, readSent               bool
	pickerRequested, pickerCancelled    bool
	pickerSeen, closeSent, closeAborted bool
	cancelDone                          bool
	seen                                chan struct{}
	allowCancel                         chan struct{}
	result                              chan error
	ctx                                 context.Context
	cancel                              context.CancelFunc
	err                                 error
}

func newNativeProbe(closeWithPicker bool, profilePath string) *nativeProbe {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	p := &nativeProbe{closeWithPicker: closeWithPicker, profilePath: profilePath, ctx: ctx, cancel: cancel,
		seen: make(chan struct{}, 1), allowCancel: make(chan struct{}), result: make(chan error, 1)}
	if !closeWithPicker {
		close(p.allowCancel)
	}
	return p
}

func (p *nativeProbe) frame(gtx layout.Context, v *View) {
	p.frames++
	event.Op(gtx.Ops, p)
	for {
		e, ok := gtx.Event(transfer.TargetFilter{Target: p, Type: "application/text"})
		if !ok {
			break
		}
		if data, ok := e.(transfer.DataEvent); ok {
			stream := data.Open()
			value, err := io.ReadAll(io.LimitReader(stream, 128))
			stream.Close()
			p.clipboardOK = err == nil && string(value) == SOCKSAddress
			if !p.clipboardOK {
				p.err = model.E("native_clipboard", "Не выполнена проверка буфера обмена.")
			}
		}
	}
	if p.frames == 1 {
		v.copy.Click()
	} else if p.frames >= 3 && !p.readSent {
		p.readSent = true
		gtx.Execute(clipboard.ReadCmd{Tag: p})
	}
	if p.clipboardOK && !p.pickerRequested {
		p.pickerRequested = true
		v.importRequest = model.Primary
	}
	select {
	case <-p.seen:
		p.pickerSeen = true
	default:
	}
	select {
	case err := <-p.result:
		p.cancelDone = true
		if err != nil {
			p.err = err
		}
	default:
	}
	if p.ctx.Err() != nil && p.err == nil && !p.ready() {
		p.err = model.E("native_ui_timeout", "Истекло время проверки нативного интерфейса.")
	}
}

func (p *nativeProbe) startPicker() {
	path, allow := "", (<-chan struct{})(p.allowCancel)
	if !p.imported {
		path = p.profilePath
		ready := make(chan struct{})
		close(ready)
		allow = ready
	}
	ctx, seen, result := p.ctx, p.seen, p.result
	go func() { result <- completeNativePicker(ctx, seen, allow, path) }()
}

func (p *nativeProbe) importedFile() {
	p.imported = true
	p.pickerRequested, p.pickerSeen, p.cancelDone, p.pickerCancelled = false, false, false, false
	p.seen, p.result = make(chan struct{}, 1), make(chan error, 1)
}

func (p *nativeProbe) closing(pickerBusy bool) {
	if p.closeWithPicker && p.imported && pickerBusy && !p.closeAborted {
		p.closeAborted = true
		close(p.allowCancel)
	}
}

func (p *nativeProbe) ready() bool {
	return p.clipboardOK && p.imported && p.pickerCancelled && p.cancelDone && p.err == nil && (!p.closeWithPicker || p.closeAborted)
}

// Only fixed stages/safe error codes leave the probe; clipboard contents,
// selected paths and profile data are never included in smoke diagnostics.
func (p *nativeProbe) stage() string {
	switch {
	case p.err != nil:
		return model.Code(p.err)
	case !p.clipboardOK:
		if p.readSent {
			return "clipboard_wait"
		}
		return "clipboard_write"
	case !p.imported:
		if p.pickerSeen {
			return "import_result"
		}
		return "import_dialog"
	case !p.pickerRequested:
		return "cancel_start"
	case !p.pickerSeen:
		return "cancel_dialog"
	case p.closeWithPicker && !p.closeAborted:
		return "closing_event"
	case !p.pickerCancelled:
		return "cancel_result"
	case !p.cancelDone:
		return "cancel_ack"
	default:
		return "complete"
	}
}
