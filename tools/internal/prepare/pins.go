package prepare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

type sourcePin struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

type buildPins struct {
	SchemaVersion int       `json:"schema_version"`
	Wireproxy     sourcePin `json:"wireproxy"`
	Wireguard     struct {
		Module  string `json:"module"`
		Version string `json:"version"`
	} `json:"wireguard"`
	Patch string `json:"patch"`
}

var (
	sourceVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	moduleVersionPattern = regexp.MustCompile(`^v0\.0\.0-[0-9]{14}-[0-9a-f]{12}$`)
	digestPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func loadPins(root string) (buildPins, error) {
	data, err := os.ReadFile(filepath.Join(root, "vendor", "wireproxy-build.json"))
	if err != nil {
		return buildPins{}, fmt.Errorf("read wireproxy build pins: %w", err)
	}
	return parsePins(data)
}

func parsePins(data []byte) (buildPins, error) {
	var pins buildPins
	if len(data) > 64*1024 {
		return pins, fmt.Errorf("wireproxy build pins exceed the size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pins); err != nil {
		return pins, fmt.Errorf("parse wireproxy build pins: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return pins, fmt.Errorf("wireproxy build pins must contain exactly one JSON object")
	}
	if pins.SchemaVersion != 1 {
		return pins, fmt.Errorf("unsupported wireproxy build pin schema")
	}
	if !sourceVersionPattern.MatchString(pins.Wireproxy.Version) {
		return pins, fmt.Errorf("wireproxy source pin must have a numeric release version")
	}
	expected := "https://github.com/windtf/wireproxy/archive/refs/tags/v" + pins.Wireproxy.Version + ".tar.gz"
	if pins.Wireproxy.URL != expected {
		return pins, fmt.Errorf("wireproxy source pin must be %s", expected)
	}
	if !digestPattern.MatchString(pins.Wireproxy.SHA256) {
		return pins, fmt.Errorf("wireproxy source SHA-256 must be 64 lowercase hex digits")
	}
	if pins.Wireguard.Module != wireguardModule || !moduleVersionPattern.MatchString(pins.Wireguard.Version) {
		return pins, fmt.Errorf("wireguard source pin must name %s at a pinned pseudo-version", wireguardModule)
	}
	if pins.Patch != supportedPatch {
		return pins, fmt.Errorf("unsupported wireproxy patch pin: %q", pins.Patch)
	}
	return pins, nil
}

func downloadSource(ctx context.Context, pin sourcePin) ([]byte, error) {
	return fetchSource(ctx, sourceHTTPClient(), pin)
}

func sourceHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing a non-HTTPS source redirect")
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many source redirects")
			}
			return nil
		},
	}
}

func fetchSource(ctx context.Context, client *http.Client, pin sourcePin) ([]byte, error) {
	parsed, err := url.Parse(pin.URL)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil {
		return nil, fmt.Errorf("source download requires an HTTPS URL without credentials")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pin.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("create source request: %w", err)
	}
	request.Header.Set("User-Agent", "WarpPocket-prepare/1")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("wireproxy source download failed: %w", err)
	}
	defer response.Body.Close()
	if response.Request == nil || response.Request.URL.Scheme != "https" {
		return nil, fmt.Errorf("refusing a non-HTTPS wireproxy source response")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wireproxy source download returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxSourceBytes {
		return nil, fmt.Errorf("wireproxy source exceeds the size limit")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxSourceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read wireproxy source: %w", err)
	}
	if err := verifySource(data, pin.SHA256); err != nil {
		return nil, err
	}
	return data, nil
}

func verifySource(data []byte, expected string) error {
	if len(data) == 0 || len(data) > maxSourceBytes {
		return fmt.Errorf("wireproxy source archive is empty or exceeds the size limit")
	}
	want, err := hex.DecodeString(expected)
	if err != nil || len(want) != sha256.Size || !digestPattern.MatchString(expected) {
		return fmt.Errorf("invalid wireproxy source SHA-256 pin")
	}
	got := sha256.Sum256(data)
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return fmt.Errorf("wireproxy source SHA-256 mismatch; refusing to prepare")
	}
	return nil
}
