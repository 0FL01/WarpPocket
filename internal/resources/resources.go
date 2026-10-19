// Package resources contains notices delivered inside the executable, not
// files extracted beside the application or in a temporary runtime directory.
package resources

import (
	_ "embed"
	"strings"
)

//go:embed licenses.txt
var Licenses string

func Ready() bool {
	for _, component := range []string{"gioui.org@v0.10.3", "gioui.org/x@v0.10.3", "wireproxy@v1.1.3", "wireguard@", "Mozilla CA bundle", "Go Regular, Bold and Mono"} {
		if !strings.Contains(Licenses, component) {
			return false
		}
	}
	return true
}
