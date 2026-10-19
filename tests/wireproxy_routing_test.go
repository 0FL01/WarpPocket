// Injected into the pinned wireproxy root, not the nested wireguard module.
package wireproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

func TestWarpPocketRoutingHosts(t *testing.T) {
	direct := map[string]string{
		"example.ru": "example.ru", "a.b.example.su": "a.b.example.su",
		"EXAMPLE.RU.": "example.ru", "пример.рф": "xn--e1afmkfd.xn--p1ai",
		"ПРИМЕР.РФ.": "xn--e1afmkfd.xn--p1ai", "example.xn--p1ai": "example.xn--p1ai",
		"r3---sn.example.ru": "r3---sn.example.ru",
	}
	// Independent expected list: do not derive the test from the production list.
	roots := []string{"vk.com", "vkontakte.com", "vk.cc", "vk.link", "vk.me", "userapi.com", "vk-cdn.net", "vkuser.net",
		"vkuseraudio.com", "vkuseraudio.net", "vkuservideo.com", "vkuservideo.net", "vkuserlive.com", "vkuserlive.net"}
	for _, root := range roots {
		direct[root] = root
		direct["a.b."+root] = "a.b." + root
	}
	for host, expected := range direct {
		t.Run(host, func(t *testing.T) {
			canonical, ok := warpPocketDirectHost(host)
			if !ok || canonical != expected {
				t.Fatalf("classify %q = %q/%v, want %q/DIRECT", host, canonical, ok, expected)
			}
		})
	}
	other := []string{"", "ru", "su", "xn--p1ai", "рф", "www.cloudflare.com", "www.gstatic.com", "www.apple.com",
		"example.com", "EXAMPLE.COM.", "evilvk.com", "vk.com.evil.org", "example.ru.evil", "userapi.com.evil",
		"eviluserapi.com", "notvk-cdn.net", "vk.com:443", "user@vk.com", "vk.com/path", " vk.com", "vk.com ",
		".vk.com", "vk..com", "vk.com..", "*.vk.com", "-bad.ru", "bad-.ru", "bad_name.ru", string([]byte{0xff}) + ".ru",
		strings.Repeat("a", 64) + ".ru", strings.Repeat("label.", 51) + "ru",
		"93.184.215.14", "127.0.0.1", "::1", "2606:4700:4700::1111", "::ffff:93.184.215.14", "fe80::1%eth0"}
	for _, host := range other {
		t.Run("WARP/"+host, func(t *testing.T) {
			if canonical, direct := warpPocketDirectHost(host); direct {
				t.Fatalf("unexpected DIRECT for %q (%q)", host, canonical)
			}
		})
	}
}

func TestWarpPocketRoutingSharedResolver(t *testing.T) {
	for _, tc := range []struct{ host, expected string }{
		{"API.VK.COM.", "api.vk.com"}, {"пример.рф", "xn--e1afmkfd.xn--p1ai"},
		{"other.example.COM.", "other.example.COM."}, {"bad_name.ru", "bad_name.ru"}, {"93.184.215.14", "93.184.215.14"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			calls := 0
			r := &warpPocketSOCKSRouter{lookup: func(ctx context.Context, name string) (context.Context, net.IP, error) {
				calls++
				if name != tc.expected {
					t.Errorf("upstream lookup received %q, want %q", name, tc.expected)
				}
				return ctx, net.ParseIP("93.184.215.14"), nil
			}}
			ctx := context.Background()
			returned, ip, err := r.Resolve(ctx, tc.host)
			if err != nil || returned != ctx || !ip.Equal(net.ParseIP("93.184.215.14")) || calls != 1 {
				t.Fatalf("shared resolver: %v, %v, calls=%d", ip, err, calls)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &warpPocketSOCKSRouter{lookup: func(context.Context, string) (context.Context, net.IP, error) {
		t.Fatal("lookup started after cancellation")
		return nil, nil, nil
	}}
	if _, _, err := r.Resolve(ctx, "vk.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	r.lookup = func(ctx context.Context, name string) (context.Context, net.IP, error) {
		cancel()
		return ctx, net.ParseIP("93.184.215.14"), nil
	}
	if _, ip, err := r.Resolve(ctx, "vk.com"); !errors.Is(err, context.Canceled) || ip != nil {
		t.Fatalf("late resolver success escaped cancellation: %v, %v", ip, err)
	}
}

func warpRoutingRequest(host string) *socks5.Request {
	return &socks5.Request{RawDestAddr: &statute.AddrSpec{FQDN: host, Port: 443},
		DestAddr: &statute.AddrSpec{FQDN: "rewritten.ru", IP: net.ParseIP("93.184.215.14"), Port: 443}}
}

func TestWarpPocketRoutingSelectedDialerAndErrors(t *testing.T) {
	for _, host := range []string{"vk.com", "example.ru", "other.example", "", "::ffff:93.184.215.14"} {
		t.Run(host, func(t *testing.T) {
			var calls []string
			failure := errors.New("selected dial failed")
			dial := func(route string) warpPocketDial {
				return func(ctx context.Context, network, addr string) (net.Conn, error) {
					calls = append(calls, route)
					if network != "tcp" || addr != "93.184.215.14:443" {
						t.Errorf("dial arguments changed: %q %q", network, addr)
					}
					return nil, failure
				}
			}
			r := &warpPocketSOCKSRouter{warpDial: dial("WARP"), directDial: dial("DIRECT")}
			_, err := r.Dial(context.Background(), "tcp", "93.184.215.14:443", warpRoutingRequest(host))
			want := "WARP"
			if host == "vk.com" || host == "example.ru" {
				want = "DIRECT"
			}
			if !errors.Is(err, failure) || !reflect.DeepEqual(calls, []string{want}) {
				t.Fatalf("selected route retried/changed: calls=%v, error=%v", calls, err)
			}
		})
	}
	// A missing request cannot accidentally inherit another request's DIRECT route.
	r := &warpPocketSOCKSRouter{warpDial: func(context.Context, string, string) (net.Conn, error) { return nil, io.EOF }}
	if _, err := r.Dial(context.Background(), "tcp", "93.184.215.14:80", nil); err != io.EOF {
		t.Fatalf("nil request must default to WARP: %v", err)
	}
}

func TestWarpPocketRoutingDirectAddressGuard(t *testing.T) {
	blocked := []string{"vk.com:443", "93.184.215.14", "127.0.0.1:80", "10.1.2.3:80", "172.16.1.1:80", "192.168.0.1:80",
		"169.254.169.254:80", "100.64.0.1:80", "100.127.255.254:80", "0.0.0.0:80", "224.0.0.1:80", "255.255.255.255:80",
		"[::]:80", "[::1]:80", "[fc00::1]:80", "[fe80::1]:80", "[ff02::1]:80", "[::ffff:127.0.0.1]:80",
		"[::ffff:192.168.1.1]:80", "[::ffff:100.64.1.1]:80", "[2606:4700:4700::1111%eth0]:80", "[::ffff:93.184.215.14%eth0]:80"}
	for _, addr := range blocked {
		t.Run(addr, func(t *testing.T) {
			unexpected := func(context.Context, string, string) (net.Conn, error) {
				t.Error("blocked DIRECT address reached a dialer")
				return nil, nil
			}
			r := &warpPocketSOCKSRouter{warpDial: unexpected, directDial: unexpected}
			if _, err := r.Dial(context.Background(), "tcp", addr, warpRoutingRequest("example.ru")); err == nil {
				t.Fatal("expected closed-route error")
			}
		})
	}
	for _, addr := range []string{"93.184.215.14:8443", "[2606:4700:4700::1111]:443", "[::ffff:93.184.215.14]:443"} {
		t.Run(addr, func(t *testing.T) {
			called := false
			r := &warpPocketSOCKSRouter{directDial: func(_ context.Context, _ string, got string) (net.Conn, error) {
				called = got == addr
				return nil, io.EOF
			}}
			if _, err := r.Dial(context.Background(), "tcp", addr, warpRoutingRequest("vk.com")); err != io.EOF || !called {
				t.Fatalf("numeric public destination/port changed: %v", err)
			}
		})
	}
}

func TestWarpPocketRoutingContextAndConcurrency(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	r := &warpPocketSOCKSRouter{directDial: func(got context.Context, _, _ string) (net.Conn, error) {
		if got != ctx {
			t.Error("dial context was replaced")
		}
		<-got.Done()
		return nil, got.Err()
	}}
	if _, err := r.Dial(ctx, "tcp", "93.184.215.14:443", warpRoutingRequest("vk.com")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial cancellation lost: %v", err)
	}
	if _, err := r.Dial(ctx, "tcp", "93.184.215.14:443", warpRoutingRequest("other.example")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled WARP call reached nil dialer: %v", err)
	}
	if _, err := r.Dial(context.Background(), "udp", "93.184.215.14:443", warpRoutingRequest("vk.com")); err == nil {
		t.Fatal("UDP must not reach a TCP dialer")
	}
	var lock sync.Mutex
	counts := map[string]int{}
	dial := func(route string) warpPocketDial {
		return func(context.Context, string, string) (net.Conn, error) {
			lock.Lock()
			counts[route]++
			lock.Unlock()
			return nil, io.EOF
		}
	}
	r = &warpPocketSOCKSRouter{warpDial: dial("WARP"), directDial: dial("DIRECT")}
	var done sync.WaitGroup
	for i := 0; i < 32; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			host := "other.example"
			if i%2 == 0 {
				host = "пример.рф"
			}
			r.Dial(context.Background(), "tcp", "93.184.215.14:443", warpRoutingRequest(host))
		}(i)
	}
	done.Wait()
	if counts["WARP"] != 16 || counts["DIRECT"] != 16 {
		t.Fatalf("request route contamination: %v", counts)
	}
}

type warpRoutingPipe struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *warpRoutingPipe) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (c *warpRoutingPipe) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *warpRoutingPipe) CloseWrite() error { return c.Close() }

func warpRoutingEcho(t *testing.T) *warpRoutingPipe {
	t.Helper()
	conn, peer := net.Pipe()
	wrapped := &warpRoutingPipe{Conn: conn, closed: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer peer.Close()
		io.Copy(peer, peer)
	}()
	t.Cleanup(func() {
		wrapped.Close()
		peer.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("outbound fixture did not close")
		}
	})
	return wrapped
}

func TestWarpPocketRoutingSOCKSProtocol(t *testing.T) {
	tests := []struct {
		name, host, lookup, route string
		atyp, command, reply      byte
		lookupError, dialError    bool
		privateAnswer             bool
	}{
		{"direct", "API.VK.COM.", "api.vk.com", "DIRECT", 3, 1, 0, false, false, false},
		{"IDN", "пример.рф", "xn--e1afmkfd.xn--p1ai", "DIRECT", 3, 1, 0, false, false, false},
		{"warp", "www.cloudflare.com", "www.cloudflare.com", "WARP", 3, 1, 0, false, false, false},
		{"boundary", "vk.com.evil.org", "vk.com.evil.org", "WARP", 3, 1, 0, false, false, false},
		{"IPv4", "93.184.215.14", "", "WARP", 1, 1, 0, false, false, false},
		{"IPv6", "2606:4700:4700::1111", "", "WARP", 4, 1, 0, false, false, false},
		{"IP-as-domain", "93.184.215.14", "93.184.215.14", "WARP", 3, 1, 0, false, false, false},
		{"direct-DNS-error", "vk.com", "vk.com", "", 3, 1, statute.RepHostUnreachable, true, false, false},
		{"warp-DNS-error", "example.com", "example.com", "", 3, 1, statute.RepHostUnreachable, true, false, false},
		{"private-answer", "example.ru", "example.ru", "", 3, 1, statute.RepHostUnreachable, false, false, true},
		{"direct-dial-error", "vk.com", "vk.com", "DIRECT", 3, 1, statute.RepHostUnreachable, false, true, false},
		{"warp-dial-error", "example.com", "example.com", "WARP", 3, 1, statute.RepHostUnreachable, false, true, false},
		{"BIND", "93.184.215.14", "", "", 1, 2, statute.RepRuleFailure, false, false, false},
		{"ASSOCIATE", "93.184.215.14", "", "", 1, 3, statute.RepRuleFailure, false, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var routes, lookups, addresses []string
			var outbound *warpRoutingPipe
			dial := func(route string) warpPocketDial {
				return func(_ context.Context, network, addr string) (net.Conn, error) {
					routes = append(routes, route)
					addresses = append(addresses, addr)
					if tc.dialError {
						return nil, errors.New("outbound failed")
					}
					outbound = warpRoutingEcho(t)
					return outbound, nil
				}
			}
			r := &warpPocketSOCKSRouter{warpDial: dial("WARP"), directDial: dial("DIRECT"),
				lookup: func(ctx context.Context, name string) (context.Context, net.IP, error) {
					lookups = append(lookups, name)
					if tc.lookupError {
						return ctx, nil, errors.New("upstream DNS failed")
					}
					if tc.privateAnswer {
						return ctx, net.IPv4(127, 0, 0, 1), nil
					}
					return ctx, net.ParseIP("93.184.215.14"), nil
				}}
			server := socks5.NewServer(r.options()...)
			client, connection := net.Pipe()
			defer client.Close()
			defer connection.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			done := make(chan error, 1)
			go func() { done <- server.ServeConn(connection) }()
			if _, err := client.Write([]byte{5, 1, 0}); err != nil {
				t.Fatal(err)
			}
			auth := make([]byte, 2)
			if _, err := io.ReadFull(client, auth); err != nil || !bytes.Equal(auth, []byte{5, 0}) {
				t.Fatalf("authentication: %v, %v", auth, err)
			}
			request := []byte{5, tc.command, 0, tc.atyp}
			if tc.atyp == 3 {
				request = append(request, byte(len(tc.host)))
				request = append(request, []byte(tc.host)...)
			} else {
				ip := netip.MustParseAddr(tc.host)
				request = append(request, ip.AsSlice()...)
			}
			request = append(request, 1, 187) // Port 443.
			if _, err := client.Write(request); err != nil {
				t.Fatal(err)
			}
			header := make([]byte, 4)
			if _, err := io.ReadFull(client, header); err != nil {
				t.Fatal(err)
			}
			if header[0] != 5 || header[1] != tc.reply {
				t.Fatalf("SOCKS reply %v, want status %d", header, tc.reply)
			}
			length := 6
			if header[3] == 4 {
				length = 18
			}
			if _, err := io.ReadFull(client, make([]byte, length)); err != nil {
				t.Fatal(err)
			}
			if tc.reply == 0 {
				data := []byte("routing")
				if _, err := client.Write(data); err != nil {
					t.Fatal(err)
				}
				echo := make([]byte, len(data))
				if _, err := io.ReadFull(client, echo); err != nil || !bytes.Equal(data, echo) {
					t.Fatalf("bidirectional TCP copy: %q, %v", echo, err)
				}
			}
			client.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("SOCKS server did not release the connection")
			}
			wantRoutes, wantLookups := []string{}, []string{}
			if tc.route != "" {
				wantRoutes = append(wantRoutes, tc.route)
			}
			if tc.lookup != "" {
				wantLookups = append(wantLookups, tc.lookup)
			}
			if strings.Join(routes, ",") != strings.Join(wantRoutes, ",") || strings.Join(lookups, ",") != strings.Join(wantLookups, ",") {
				t.Fatalf("hook paths: routes=%v, lookups=%v", routes, lookups)
			}
			if len(addresses) != 0 {
				wantAddr := "93.184.215.14:443"
				if tc.atyp == 4 {
					wantAddr = "[2606:4700:4700::1111]:443"
				}
				if !reflect.DeepEqual(addresses, []string{wantAddr}) {
					t.Fatalf("dial destination is not the original numeric address and port: %v", addresses)
				}
			}
			if outbound != nil {
				select {
				case <-outbound.closed:
				default:
					t.Errorf("%s outbound was not closed", tc.route)
				}
			}
		})
	}
}
