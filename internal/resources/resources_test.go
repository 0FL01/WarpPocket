package resources

import "testing"

func TestEmbeddedNotices(t *testing.T) {
	if !Ready() || len(Licenses) < 50000 {
		t.Fatal("missing embedded dependency notices")
	}
}
