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
