package ui

import (
	"image"
	"io"
	"strings"
	"testing"

	"gioui.org/io/transfer"
	"gioui.org/layout"
	"gioui.org/unit"
	"github.com/0FL01/WarpPocket/internal/model"
)

func TestNativeProbeClipboardCommandsUseTheActualCopyAction(t *testing.T) {
	p := newNativeProbe(false, "synthetic.conf")
	defer p.cancel()
	f := newUIFrame(&testController{state: model.Snapshot{State: model.Disconnected}})
	frame := func() {
		f.ops.Reset()
		f.view.Update()
		gtx := layout.Context{Ops: &f.ops, Source: f.router.Source(), Now: f.now,
			Metric: unit.Metric{PxPerDp: 1, PxPerSp: 1}, Constraints: layout.Exact(image.Pt(442, 620))}
		p.frame(gtx, f.view)
		f.view.Layout(gtx)
		f.router.Frame(&f.ops)
	}
	frame()
	mime, content, copied := f.router.WriteClipboard()
	if !copied || mime != "application/text" || string(content) != SOCKSAddress {
		t.Fatal("native probe did not execute the actual Copy action")
	}
	frame()
	frame()
	if !f.router.ClipboardRequested() || p.clipboardOK || p.pickerRequested {
		t.Fatal("native probe skipped the asynchronous clipboard acknowledgement")
	}
	f.router.Queue(transfer.DataEvent{Type: "application/text", Open: func() io.ReadCloser {
		return io.NopCloser(strings.NewReader(SOCKSAddress))
	}})
	frame()
	if !p.clipboardOK || !p.pickerRequested || f.view.importRequest != model.Primary || p.ready() {
		t.Fatal("clipboard acknowledgement did not lead to the real import action")
	}
}

func TestNativeProbeKeepsTheFirstFailureAfterItsDeadline(t *testing.T) {
	p := newNativeProbe(false, "synthetic.conf")
	p.err = model.E("native_filename_verify", "Проверочный путь не подтверждён.")
	p.cancel()
	f := newUIFrame(&testController{state: model.Snapshot{State: model.Disconnected}})
	gtx := layout.Context{Ops: &f.ops, Source: f.router.Source(), Now: f.now,
		Metric: unit.Metric{PxPerDp: 1, PxPerSp: 1}, Constraints: layout.Exact(image.Pt(442, 620))}
	p.frame(gtx, f.view)
	if model.Code(p.err) != "native_filename_verify" {
		t.Fatal("probe deadline replaced the diagnosed failure")
	}
}

func TestNativeProbeRequiresImportAndSafePickerClose(t *testing.T) {
	for _, closeWithPicker := range []bool{false, true} {
		p := newNativeProbe(closeWithPicker, "synthetic.conf")
		p.clipboardOK = true
		p.pickerCancelled, p.cancelDone = true, true
		if p.ready() {
			t.Fatal("clipboard/cancel alone masqueraded as a successful import")
		}
		p.closing(true)
		if p.closeAborted {
			t.Fatal("shutdown probe fired before the import round-trip")
		}
		p.importedFile()
		if p.ready() || p.cancelDone || p.pickerCancelled {
			t.Fatal("first picker completion completed the second picker check")
		}
		p.pickerCancelled, p.cancelDone = true, true
		if closeWithPicker {
			if p.ready() {
				t.Fatal("graceful picker check did not require an actual aborted close")
			}
			p.closing(true)
			p.closing(true) // idempotent, must not close the channel twice.
		}
		if !p.ready() {
			t.Fatal("completed native probe was not ready")
		}
		p.cancel()
	}
}

func TestNativeProbeDiagnosticStagesRemainDistinct(t *testing.T) {
	p := newNativeProbe(true, "private-path-not-in-diagnostics.conf")
	defer p.cancel()
	if p.stage() != "clipboard_write" {
		t.Fatal(p.stage())
	}
	p.readSent = true
	if p.stage() != "clipboard_wait" {
		t.Fatal(p.stage())
	}
	p.clipboardOK, p.pickerRequested = true, true
	if p.stage() != "import_dialog" {
		t.Fatal(p.stage())
	}
	p.pickerSeen = true
	if p.stage() != "import_result" {
		t.Fatal(p.stage())
	}
	p.importedFile()
	if p.stage() != "cancel_start" {
		t.Fatal(p.stage())
	}
	p.pickerRequested, p.pickerSeen = true, true
	if p.stage() != "closing_event" {
		t.Fatal(p.stage())
	}
	p.closing(true)
	p.pickerCancelled, p.cancelDone = true, true
	if p.stage() != "complete" || !p.ready() {
		t.Fatal(p.stage())
	}
}
