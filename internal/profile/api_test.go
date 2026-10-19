package profile

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0FL01/WarpPocket/internal/model"
	utls "github.com/refraction-networking/utls"
)

func tlsClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client := newClient(server.URL, roots)
	t.Cleanup(client.CloseIdleConnections)
	return client, server
}

func apiFixture(clientID string, enabled bool) map[string]any {
	return map[string]any{"config": map[string]any{
		"client_id": clientID, "warp_enabled": enabled,
		"interface": map[string]any{"addresses": map[string]any{"v4": "172.16.0.2", "v6": "2606:4700:110::1"}},
		"peers":     []any{map[string]any{"public_key": fixtureKey(32), "endpoint": map[string]any{"host": "engage.cloudflareclient.com:2408", "v4": "192.0.2.1", "ports": []int{500}}}},
	}}
}

func writeJSON(t *testing.T, writer http.ResponseWriter, data any) {
	t.Helper()
	// Cloudflare sometimes labels its JSON as text/plain; decoding is bounded
	// and structural, not dependent on a misleading Content-Type.
	writer.Header().Set("Content-Type", "text/plain")
	if err := json.NewEncoder(writer).Encode(data); err != nil {
		t.Error(err)
	}
}

func TestNativeAPIAndroidRequestsPerAccountAuthAndNormalizedGeneration(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	var registeredPublic string
	client, _ := tlsClient(t, func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		methods = append(methods, request.Method)
		mu.Unlock()
		if request.Header.Get("User-Agent") != "1.1.1.1/6.38.9-5641 (Android 16.0.0)" || request.Header.Get("CF-Client-Version") != "a-6.38.9-5641" || request.Header.Get("Connection") != "Keep-Alive" || request.Header.Get("Accept") != "" {
			t.Error("pinned Android headers changed")
		}
		if request.TLS == nil || request.TLS.Version != tls.VersionTLS12 || request.Proto != "HTTP/1.1" {
			t.Error("API did not use TLS 1.2 and HTTP/1.1")
		}
		if request.Method == http.MethodPost {
			if request.URL.Path != "/v0a5641/reg" || request.Header.Get("Authorization") != "" || request.Header.Get("Content-Type") != "application/json; charset=UTF-8" {
				t.Error("registration request routing/auth/content type changed")
			}
			var body map[string]string
			if json.NewDecoder(request.Body).Decode(&body) != nil || len(body) != 10 {
				t.Error("invalid registration request shape")
			}
			for key, expected := range map[string]string{"fcm_token": "", "install_id": "", "locale": "en_US", "model": "PC", "serial_number": "", "os_version": "16.0.0", "key_type": "curve25519", "tunnel_type": "wireguard"} {
				if value, present := body[key]; !present || value != expected {
					t.Errorf("registration field %s differs from wgcf 2.3.1", key)
				}
			}
			if _, err := time.Parse(time.RFC3339Nano, body["tos"]); err != nil {
				t.Error("registration consent timestamp missing")
			}
			registeredPublic = body["key"]
			writeJSON(t, writer, map[string]any{"id": "synthetic-device", "token": "synthetic-token", "account": map[string]string{"license": "synthetic-license"}})
			return
		}
		if request.URL.Path == "/v0a5641/reg/second-device" {
			if request.Header.Get("Authorization") != "Bearer second-token" {
				t.Error("first account token leaked into second account request")
			}
			writeJSON(t, writer, apiFixture("AQID", true))
			return
		}
		if request.URL.Path != "/v0a5641/reg/synthetic-device" || request.Header.Get("Authorization") != "Bearer synthetic-token" {
			t.Error("request did not use its own account token")
		}
		if request.Method == http.MethodPatch {
			var patch map[string]bool
			if json.NewDecoder(request.Body).Decode(&patch) != nil || !patch["warp_enabled"] || len(patch) != 1 || request.Header.Get("Content-Type") != "application/json; charset=UTF-8" {
				t.Error("WARP enabling PATCH changed")
			}
			writeJSON(t, writer, map[string]any{"config": map[string]string{"client_id": "CgsM"}})
			return
		}
		writeJSON(t, writer, apiFixture("BwgJ", false))
	})
	account, err := client.Register(context.Background())
	if err != nil || account.DeviceID != "synthetic-device" || account.AccessToken != "synthetic-token" || account.LicenseKey != "synthetic-license" {
		t.Fatalf("mock registration failed: %s", model.Code(err))
	}
	privateBytes, _ := base64.StdEncoding.DecodeString(account.PrivateKey)
	if privateBytes[0]&7 != 0 || privateBytes[31]&0x80 != 0 || privateBytes[31]&0x40 == 0 {
		t.Fatal("registered private key was not clamped")
	}
	private, _ := ecdh.X25519().NewPrivateKey(privateBytes)
	if registeredPublic != base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()) {
		t.Fatal("registration public key does not match persisted private key")
	}
	profile, err := client.Generate(context.Background(), account)
	if err != nil || profile.PrivateKey != account.PrivateKey || profile.Reserved == nil || *profile.Reserved != [3]byte{10, 11, 12} || profile.Endpoint.String() != "engage.cloudflareclient.com:2408" || profile.Keepalive != 25 || profile.MTU != 1280 || len(profile.DNS) != 4 || !reflect.DeepEqual(profile.Addresses, []string{"172.16.0.2/32", "2606:4700:110::1/128"}) {
		t.Fatalf("native generated profile differs: %s", model.Code(err))
	}
	second := account
	second.DeviceID, second.AccessToken = "second-device", "second-token"
	if reserved, err := client.Reserved(context.Background(), second); err != nil || reserved != [3]byte{1, 2, 3} {
		t.Fatal("second account Reserved fetch failed")
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(methods, []string{"POST", "GET", "PATCH", "GET"}) {
		t.Fatal("unexpected API calls/repeated registration")
	}
}

func TestNativeAPIEndpointAddressAndPeerExtraction(t *testing.T) {
	for _, test := range []struct {
		name     string
		endpoint map[string]any
		want     string
	}{
		{"host precedence", map[string]any{"host": "example.com:8443", "v4": "192.0.2.1", "ports": []int{500}}, "example.com:8443"},
		{"v4 embedded port replaced", map[string]any{"v4": "192.0.2.1:999", "ports": []int{500}}, "192.0.2.1:500"},
		{"v4 default port", map[string]any{"v4": "192.0.2.1"}, "192.0.2.1:2408"},
		{"v6 fallback", map[string]any{"v6": "2606:4700:d0::a29f:c001", "ports": []int{4500}}, "[2606:4700:d0::a29f:c001]:4500"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _ := tlsClient(t, func(writer http.ResponseWriter, _ *http.Request) {
				body := apiFixture("AAAA", true)
				config := body["config"].(map[string]any)
				config["peers"].([]any)[0].(map[string]any)["endpoint"] = test.endpoint
				writeJSON(t, writer, body)
			})
			profile, err := client.Generate(context.Background(), fixtureAccount(0))
			if err != nil || profile.Endpoint.String() != test.want || profile.Reserved == nil || *profile.Reserved != [3]byte{} {
				t.Fatalf("endpoint extraction failed: %s", model.Code(err))
			}
		})
	}
	for _, mode := range []string{"no peers", "bad public key", "no v4", "scoped address", "bad client id", "bad endpoint", "bad port"} {
		t.Run(mode, func(t *testing.T) {
			client, _ := tlsClient(t, func(writer http.ResponseWriter, _ *http.Request) {
				body := apiFixture("BwgJ", true)
				config := body["config"].(map[string]any)
				switch mode {
				case "no peers":
					config["peers"] = []any{}
				case "bad public key":
					config["peers"].([]any)[0].(map[string]any)["public_key"] = "synthetic-invalid"
				case "no v4":
					config["interface"].(map[string]any)["addresses"].(map[string]any)["v4"] = ""
				case "scoped address":
					config["interface"].(map[string]any)["addresses"].(map[string]any)["v6"] = "fe80::1%scope"
				case "bad client id":
					config["client_id"] = "AA=="
				case "bad endpoint":
					config["peers"].([]any)[0].(map[string]any)["endpoint"] = map[string]string{"host": "example.com"}
				case "bad port":
					config["peers"].([]any)[0].(map[string]any)["endpoint"] = map[string]any{"v4": "192.0.2.1", "ports": []int{0}}
				}
				writeJSON(t, writer, body)
			})
			if _, err := client.Generate(context.Background(), fixtureAccount(0)); model.Code(err) != "generation_failed" {
				t.Fatal("malformed API configuration was not rejected safely")
			}
		})
	}
}

func TestNativeAPIGenerationDefaultsNewProfileKeepaliveTo25(t *testing.T) {
	var gets atomic.Int32
	client, _ := tlsClient(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Error("new-profile fixture unexpectedly registered or patched an account")
		}
		gets.Add(1)
		writeJSON(t, writer, apiFixture("BwgJ", true))
	})
	p, err := client.Generate(context.Background(), fixtureAccount(0))
	if err != nil || p.Keepalive != 25 || gets.Load() != 1 {
		t.Fatal("native generation did not apply the new-profile-only keepalive default")
	}
	text, err := Render(p, nil)
	if err != nil || !strings.Contains(text, "\nPersistentKeepalive = 25\n") || mustParse(t, text).Keepalive != 25 {
		t.Fatal("new profile's keepalive was not preserved through render/parse")
	}
}

func TestNativeAPIBoundedResponsesNoRedirectNoEnvironmentProxy(t *testing.T) {
	var proxyCalls, redirectCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxyCalls.Add(1) }))
	t.Cleanup(proxy.Close)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirectCalls.Add(1) }))
	t.Cleanup(redirect.Close)
	for _, mode := range []string{"ok", "redirect", "status error", "oversize length", "oversize streamed", "invalid JSON", "invalid UTF8", "wrong client id", "missing config"} {
		t.Run(mode, func(t *testing.T) {
			client, _ := tlsClient(t, func(writer http.ResponseWriter, request *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(writer, request, redirect.URL+"/synthetic-private-path", http.StatusFound)
				case "status error":
					writer.WriteHeader(http.StatusForbidden)
					_, _ = io.WriteString(writer, "synthetic-token-and-private-key")
				case "oversize length":
					writer.Header().Set("Content-Length", "40961")
					_, _ = io.WriteString(writer, strings.Repeat("x", maxAPIResponse+1))
				case "oversize streamed":
					writer.WriteHeader(http.StatusOK)
					writer.(http.Flusher).Flush()
					_, _ = io.WriteString(writer, strings.Repeat("x", maxAPIResponse+1))
				case "invalid JSON":
					_, _ = io.WriteString(writer, `{"config":`)
				case "invalid UTF8":
					_, _ = writer.Write([]byte{'{', '"', 0xff, '"', ':', '1', '}'})
				case "wrong client id":
					writeJSON(t, writer, apiFixture("AQI=", true))
				case "missing config":
					writeJSON(t, writer, map[string]string{"message": "synthetic-token-and-private-key"})
				default:
					writeJSON(t, writer, apiFixture("BwgJ", true))
				}
			})
			reserved, err := client.Reserved(context.Background(), fixtureAccount(0))
			if mode == "ok" {
				if err != nil || reserved != [3]byte{7, 8, 9} {
					t.Fatal("verified direct request failed")
				}
			} else if model.Code(err) != "reserved_unavailable" || strings.Contains(err.Error(), "synthetic") {
				t.Fatal("malformed response/redirect exposed unsafe error")
			}
		})
	}
	if proxyCalls.Load() != 0 || redirectCalls.Load() != 0 {
		t.Fatal("API used an environment proxy or followed a redirect")
	}
	transport := newTransport(nil)
	if transport.Proxy != nil || transport.ForceAttemptHTTP2 || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.TLSClientConfig.MaxVersion != tls.VersionTLS12 {
		t.Fatal("verified direct TLS policy changed")
	}
}

func TestNativeAPIVerifiesCertificatesAndCancelsResponseReads(t *testing.T) {
	var calls atomic.Int32
	_, server := tlsClient(t, func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		writeJSON(t, writer, apiFixture("BwgJ", true))
	})
	untrusted := newClient(server.URL, x509.NewCertPool())
	t.Cleanup(untrusted.CloseIdleConnections)
	if _, err := untrusted.Reserved(context.Background(), fixtureAccount(0)); model.Code(err) != "reserved_unavailable" || calls.Load() != 0 {
		t.Fatal("API accepted an untrusted TLS certificate")
	}
	started := make(chan struct{})
	client, _ := tlsClient(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		close(started)
		<-request.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := client.Reserved(ctx, fixtureAccount(0)); finished <- err }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("mock request did not start")
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled body read did not preserve cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("body read did not stop promptly after cancellation")
	}
}

func TestNativeAPIWarpEnableLegacyFallbackAndTopLevelFlag(t *testing.T) {
	for _, mode := range []string{"patch fails", "top-level false", "already enabled"} {
		t.Run(mode, func(t *testing.T) {
			var patches atomic.Int32
			client, _ := tlsClient(t, func(writer http.ResponseWriter, request *http.Request) {
				if request.Method == http.MethodPatch {
					patches.Add(1)
					if mode == "patch fails" {
						writer.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					writeJSON(t, writer, map[string]any{"config": map[string]string{"client_id": "CgsM"}})
					return
				}
				body := apiFixture("BwgJ", mode != "patch fails")
				if mode == "top-level false" {
					body["warp_enabled"] = false
				}
				writeJSON(t, writer, body)
			})
			reserved, err := client.Reserved(context.Background(), fixtureAccount(0))
			want := [3]byte{7, 8, 9}
			if mode == "top-level false" {
				want = [3]byte{10, 11, 12}
			}
			if err != nil || reserved != want || (mode == "already enabled" && patches.Load() != 0) || (mode != "already enabled" && patches.Load() != 1) {
				t.Fatal("legacy WARP enabling behavior changed")
			}
		})
	}
}

type recordingListener struct {
	net.Listener
	hellos chan []byte
}

func (listener recordingListener) Accept() (net.Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &recordingConn{Conn: conn, hellos: listener.hellos}, nil
}

type recordingConn struct {
	net.Conn
	hellos chan []byte
	data   []byte
	sent   bool
}

func (conn *recordingConn) Read(buffer []byte) (int, error) {
	n, err := conn.Conn.Read(buffer)
	if !conn.sent {
		conn.data = append(conn.data, buffer[:n]...)
		if len(conn.data) >= 5 {
			length := 5 + int(binary.BigEndian.Uint16(conn.data[3:5]))
			if len(conn.data) >= length {
				conn.hellos <- bytes.Clone(conn.data[:length])
				conn.sent = true
				conn.data = nil
			}
		}
	}
	return n, err
}

func parseHello(t *testing.T, data []byte) (session []byte, ciphers, extensions []uint16, ticket []byte) {
	t.Helper()
	if len(data) < 44 || data[0] != 22 || data[5] != 1 || binary.BigEndian.Uint16(data[9:11]) != tls.VersionTLS12 {
		t.Fatal("invalid TLS 1.2 ClientHello capture")
	}
	index := 43
	length := int(data[index])
	index++
	session = data[index : index+length]
	index += length
	length = int(binary.BigEndian.Uint16(data[index:]))
	index += 2
	for end := index + length; index < end; index += 2 {
		ciphers = append(ciphers, binary.BigEndian.Uint16(data[index:]))
	}
	length = int(data[index])
	index += 1 + length
	length = int(binary.BigEndian.Uint16(data[index:]))
	index += 2
	for end := index + length; index < end; {
		kind := binary.BigEndian.Uint16(data[index:])
		size := int(binary.BigEndian.Uint16(data[index+2:]))
		index += 4
		extensions = append(extensions, kind)
		if kind == 35 {
			ticket = data[index : index+size]
		}
		index += size
	}
	return
}

func TestConscryptClientHelloWireShapeAndSessionResumption(t *testing.T) {
	hellos := make(chan []byte, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Connection", "close")
		writeJSON(t, writer, apiFixture("BwgJ", true))
	}))
	server.Listener = recordingListener{Listener: server.Listener, hellos: hellos}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client := newClient(server.URL, roots)
	t.Cleanup(client.CloseIdleConnections)
	for attempt := range 2 {
		if _, err := client.Reserved(context.Background(), fixtureAccount(0)); err != nil {
			t.Fatal(err)
		}
		var captured []byte
		select {
		case captured = <-hellos:
		case <-time.After(time.Second):
			t.Fatal("ClientHello not captured")
		}
		session, ciphers, extensions, ticket := parseHello(t, captured)
		if !reflect.DeepEqual(ciphers, []uint16{utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}) {
			t.Fatal("Conscrypt cipher suite order changed")
		}
		// IP-literal loopback omits SNI; production DNS hosts include extension 0.
		wantExtensions := []uint16{23, 65281, 10, 11, 35, 16, 5, 13}
		if len(extensions) > 0 && extensions[len(extensions)-1] == 21 {
			extensions = extensions[:len(extensions)-1] // BoringSSL conditional padding
		}
		if !reflect.DeepEqual(extensions, wantExtensions) {
			t.Fatalf("Conscrypt extension order changed: %v", extensions)
		}
		if (attempt == 0 && (len(session) != 0 || len(ticket) != 0)) || (attempt == 1 && (len(session) != 32 || len(ticket) == 0)) {
			t.Fatal("fresh/resumed Conscrypt session ID behavior changed")
		}
	}
}

func TestConscryptPresetIncludesPinnedCurvesALPNAndSignatureOrder(t *testing.T) {
	spec := clientHelloSpec()
	if spec.TLSVersMin != utls.VersionTLS12 || spec.TLSVersMax != utls.VersionTLS12 || !reflect.DeepEqual(spec.CompressionMethods, []uint8{0}) {
		t.Fatal("Conscrypt version/compression changed")
	}
	var names []string
	for _, extension := range spec.Extensions {
		names = append(names, fmt.Sprintf("%T", extension))
	}
	wantNames := []string{"*tls.SNIExtension", "*tls.ExtendedMasterSecretExtension", "*tls.RenegotiationInfoExtension", "*tls.SupportedCurvesExtension", "*tls.SupportedPointsExtension", "*tls.SessionTicketExtension", "*tls.ALPNExtension", "*tls.StatusRequestExtension", "*tls.SignatureAlgorithmsExtension", "*tls.UtlsPaddingExtension"}
	if !reflect.DeepEqual(names, wantNames) || !reflect.DeepEqual(spec.Extensions[3].(*utls.SupportedCurvesExtension).Curves, []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}) || !reflect.DeepEqual(spec.Extensions[6].(*utls.ALPNExtension).AlpnProtocols, []string{"http/1.1"}) {
		t.Fatal("Conscrypt extensions/curves/ALPN changed")
	}
	wantSignatures := []utls.SignatureScheme{utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256, utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384, utls.PSSWithSHA512, utls.PKCS1WithSHA512, utls.PKCS1WithSHA1}
	if !reflect.DeepEqual(spec.Extensions[8].(*utls.SignatureAlgorithmsExtension).SupportedSignatureAlgorithms, wantSignatures) {
		t.Fatal("Conscrypt signature algorithm order changed")
	}
}
