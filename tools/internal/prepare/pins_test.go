package prepare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testPinsJSON = `{
	"schema_version": 1,
	"wireproxy": {
		"version": "1.1.3",
		"url": "https://github.com/windtf/wireproxy/archive/refs/tags/v1.1.3.tar.gz",
		"sha256": "b62e925d9efe402a14c6501dfa56137c49ece6a5be264095295d2565d747b1c7"
	},
	"wireguard": {
		"module": "golang.zx2c4.com/wireguard",
		"version": "v0.0.0-20250521234502-f333402bd9cb"
	},
	"patch": "reserved-support+ordered-dns+handshake-junk"
}`

func testPins(t *testing.T) buildPins {
	t.Helper()
	pins, err := parsePins([]byte(testPinsJSON))
	if err != nil {
		t.Fatal(err)
	}
	return pins
}

func TestPins(t *testing.T) {
	pins := testPins(t)
	if pins.Wireguard.Module != wireguardModule || pins.Patch != supportedPatch {
		t.Fatalf("wrong pins: %+v", pins)
	}
	for _, test := range []struct{ name, old, new string }{
		{"schema", `"schema_version": 1`, `"schema_version": 2`},
		{"schema-type", `"schema_version": 1`, `"schema_version": true`},
		{"version", `"version": "1.1.3"`, `"version": "../escape"`},
		{"version-type", `"version": "1.1.3"`, `"version": 113`},
		{"http", `https://github.com/`, `http://github.com/`},
		{"host", `https://github.com/`, `https://github.example/`},
		{"user-info", `https://github.com/`, `https://user@github.com/`},
		{"query", `v1.1.3.tar.gz"`, `v1.1.3.tar.gz?x=1"`},
		{"fragment", `v1.1.3.tar.gz"`, `v1.1.3.tar.gz#x"`},
		{"digest", pins.Wireproxy.SHA256, strings.Repeat("G", 64)},
		{"digest-length", pins.Wireproxy.SHA256, "abc"},
		{"module", wireguardModule, "attacker.example/wireguard"},
		{"module-version", pins.Wireguard.Version, "latest"},
		{"module-version-traversal", pins.Wireguard.Version, "v0.0.0-../../escape"},
		{"patch", supportedPatch, "unreviewed-patch"},
		{"unknown-field", `"schema_version": 1`, `"unexpected": 1, "schema_version": 1`},
		{"missing-wireproxy", `"wireproxy": {`, `"wireproxy": null, "wireproxy-invalid": {`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parsePins([]byte(strings.Replace(testPinsJSON, test.old, test.new, 1))); err == nil {
				t.Fatal("accepted invalid pins")
			}
		})
	}
	for _, data := range []string{"null", "[]", "{", testPinsJSON + " {}", strings.Repeat(" ", 65537)} {
		if _, err := parsePins([]byte(data)); err == nil {
			t.Fatalf("accepted malformed/trailing/oversized pins: %.40q", data)
		}
	}
}

func TestSourceHash(t *testing.T) {
	data := []byte("pinned source fixture")
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	if err := verifySource(data, digest); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		data   []byte
		digest string
	}{
		{"changed-source", []byte("changed"), digest},
		{"empty-source", nil, digest},
		{"oversized-source", make([]byte, maxSourceBytes+1), digest},
		{"bad-digest", data, "xyz"},
		{"short-digest", data, "01"},
		{"uppercase-digest", data, strings.ToUpper(digest)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := verifySource(test.data, test.digest); err == nil {
				t.Fatal("accepted unverified source")
			}
		})
	}
}

func TestHTTPSDownload(t *testing.T) {
	data := []byte("pinned HTTPS fixture")
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	for _, mode := range []string{"valid", "wrong-hash", "empty", "status", "oversized-header", "oversized-stream", "redirect-http", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "empty":
					return
				case "status":
					w.WriteHeader(http.StatusForbidden)
					return
				case "oversized-header":
					w.Header().Set("Content-Length", fmt.Sprint(maxSourceBytes+1))
					return
				case "oversized-stream":
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					_, _ = w.Write(make([]byte, maxSourceBytes+1))
					return
				case "redirect-http":
					http.Redirect(w, r, "http://127.0.0.1/", http.StatusFound)
					return
				}
				_, _ = w.Write(data)
			}))
			defer server.Close()
			client := server.Client()
			client.CheckRedirect = sourceHTTPClient().CheckRedirect
			pin := sourcePin{URL: server.URL, SHA256: digest}
			if mode == "wrong-hash" {
				pin.SHA256 = strings.Repeat("0", 64)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			got, err := fetchSource(ctx, client, pin)
			if mode == "valid" {
				if err != nil || !bytes.Equal(got, data) {
					t.Fatalf("download = %q, %v", got, err)
				}
			} else if err == nil {
				t.Fatal("accepted unsafe download")
			}
		})
	}
	if _, err := fetchSource(context.Background(), http.DefaultClient, sourcePin{URL: "http://127.0.0.1/"}); err == nil {
		t.Fatal("accepted plain HTTP")
	}
}
