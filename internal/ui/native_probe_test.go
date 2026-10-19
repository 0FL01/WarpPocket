package ui

import "testing"

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
