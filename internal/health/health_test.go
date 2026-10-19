package health

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/trust"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestTraceAndIndependentPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, trace, independent, fallback, want string
		first, second                            int
	}{
		{"on", "warp=on\nip=192.0.2.1\n", "", "", "", 204, 0},
		{"plus", "warp=plus\r\n", "", "", "", 204, 0},
		{"off", "warp=off\n", "", "", "warp_not_enabled", 204, 0},
		{"duplicate", "warp=on\nwarp=on\n", "", "", "warp_not_enabled", 204, 0},
		{"spoof", "notwarp=on\n", "", "", "warp_not_enabled", 204, 0},
		{"invalid_utf8", "warp=on\n\xff", "", "", "warp_not_enabled", 204, 0},
		{"apple", "warp=on", "not empty", "<BODY>Success</BODY>", "", 204, 200},
		{"both_fail", "warp=on", "bad", "bad", "external_unavailable", 200, 200},
		{"oversize", "warp=on\n" + strings.Repeat("x", maxResponse), "", "", "health_response_large", 204, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Scheme != "https" {
					t.Fatal("TLS downgraded")
				}
				switch r.URL.String() {
				case TraceURL:
					return response(200, tc.trace), nil
				case IndependentURL:
					return response(tc.first, tc.independent), nil
				case FallbackURL:
					return response(tc.second, tc.fallback), nil
				default:
					t.Fatal("unexpected URL")
					return nil, errors.New("unexpected")
				}
			}), CheckRedirect: noRedirect}
			_, err := check(context.Background(), client, [3]string{TraceURL, IndependentURL, FallbackURL}, time.Second)
			if model.Code(err) != tc.want {
				t.Fatalf("code=%s want=%s", model.Code(err), tc.want)
			}
			if tc.want == "warp_not_enabled" && calls != 1 {
				t.Fatal("independent check ran without verified WARP")
			}
		})
	}
}

func TestSharedBudgetAndCancellation(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() == TraceURL {
				return response(200, "warp=on"), nil
			}
			if cancelled {
				cancel()
			}
			<-r.Context().Done()
			return nil, r.Context().Err()
		})}
		started := time.Now()
		_, err := check(ctx, client, [3]string{TraceURL, IndependentURL, FallbackURL}, 30*time.Millisecond)
		want := "health_timeout"
		if cancelled {
			want = "cancelled"
		}
		if model.Code(err) != want || time.Since(started) > time.Second {
			t.Fatalf("cancellation/budget failed: %s", model.Code(err))
		}
		cancel()
	}
}

// The proxy receives the destination DOMAIN even though no host resolver knows
// our target. Only its loopback address is dialled by the health transport.
func TestRealSOCKSRemoteDNSAndTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/trace":
			_, _ = io.WriteString(w, "warp=on\n")
		case "/check":
			w.WriteHeader(204)
		default:
			t.Error("unexpected request")
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var names []string
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				reader := bufio.NewReader(conn)
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(reader, greeting); err != nil {
					return
				}
				_, _ = conn.Write([]byte{5, 0})
				header := make([]byte, 5)
				if _, err := io.ReadFull(reader, header); err != nil {
					return
				}
				if header[0] != 5 || header[1] != 1 || header[3] != 3 {
					t.Error("destination was not SOCKS domain CONNECT")
					return
				}
				name := make([]byte, int(header[4])+2)
				if _, err := io.ReadFull(reader, name); err != nil {
					return
				}
				mu.Lock()
				names = append(names, string(name[:len(name)-2]))
				mu.Unlock()
				upstream, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
				done := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, reader); _ = upstream.Close(); close(done) }()
				_, _ = io.Copy(conn, upstream)
				_ = conn.Close()
				<-done
			}()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	tr, err := transport(port, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	if tr.Proxy != nil || tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("security policy weakened")
	}
	// Deliberately poisoned environment must have no effect on this transport.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	client := &http.Client{Transport: tr, CheckRedirect: noRedirect}
	urls := [3]string{"https://example.com/trace", "https://example.com/check", "https://example.com/unused"}
	if _, err := check(context.Background(), client, urls, 3*time.Second); err != nil {
		t.Fatal(model.SafeMessage(err))
	}
	_ = listener.Close()
	tr.CloseIdleConnections()
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(names, ",") != "example.com,example.com" {
		t.Fatalf("remote DNS names=%v", names)
	}
}

func TestNoDirectFallback(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = Check(ctx, port)
	if model.Code(err) != "health_failed" {
		t.Fatalf("closed proxy did not fail closed: %s (port %s)", model.Code(err), strconv.Itoa(port))
	}
	pool, err := trust.Pool()
	if err != nil || len(pool.Subjects()) < 50 {
		t.Fatal("embedded certificates unavailable")
	}
}

func TestLocalRootTransportAndRequestSetupHaveDistinctTerminalCode(t *testing.T) {
	_, err := checkProxy(context.Background(), 25344, func() (*x509.CertPool, error) {
		return nil, errors.New("synthetic private setup details")
	})
	if model.Code(err) != "health_setup_failed" || strings.Contains(err.Error(), "synthetic") {
		t.Fatal("embedded root setup was confused with remote TLS verification or exposed inputs")
	}
	for _, port := range []int{0, 65536} {
		if _, err := Check(context.Background(), port); model.Code(err) != "health_setup_failed" {
			t.Fatal("invalid local SOCKS transport was classified as remote failure")
		}
	}
	if _, err := transport(25344, nil); model.Code(err) != "health_setup_failed" {
		t.Fatal("missing local root pool was classified as remote failure")
	}
	client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		t.Error("invalid local request setup reached the network")
		return nil, errors.New("unexpected request")
	})}
	if _, err := check(context.Background(), client, [3]string{"http://example.com/trace", IndependentURL, FallbackURL}, time.Second); model.Code(err) != "health_setup_failed" {
		t.Fatal("invalid local health URL was not terminal setup failure")
	}
}

func TestRemoteTLSFailureIsVerificationFailureWithoutResourceFallback(t *testing.T) {
	for _, failedURL := range []string{TraceURL, IndependentURL} {
		for _, remoteErr := range []error{&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, tls.RecordHeaderError{}} {
			calls := 0
			client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() == failedURL {
					return nil, remoteErr
				}
				if r.URL.String() == TraceURL {
					return response(http.StatusOK, "warp=on\n"), nil
				}
				t.Error("TLS failure attempted another resource")
				return response(http.StatusNoContent, ""), nil
			})}
			_, err := check(context.Background(), client, [3]string{TraceURL, IndependentURL, FallbackURL}, time.Second)
			wantCalls := 1
			if failedURL == IndependentURL {
				wantCalls = 2
			}
			if model.Code(err) != "health_tls" || calls != wantCalls {
				t.Fatal("remote TLS rejection was treated as local setup or allowed fallback")
			}
		}
	}
}
