// Injected into the pinned netstack package by the WarpPocket helper build.
package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func warpDNSTestNet() *Net {
	return &Net{
		dnsServers: []netip.Addr{
			netip.MustParseAddr("83.220.169.155"),
			netip.MustParseAddr("212.109.195.93"),
			netip.MustParseAddr("9.9.9.9"),
		},
		hasV4: true,
	}
}

func warpDNSTestPacket(q dnsmessage.Question, id uint16, code dnsmessage.RCode, address bool, truncated bool) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: id, Response: true, RecursionAvailable: true, RCode: code, Truncated: truncated,
	})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if address {
		h := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
		var err error
		if q.Type == dnsmessage.TypeA {
			err = b.AResource(h, dnsmessage.AResource{A: [4]byte{192, 0, 2, 7}})
		} else {
			err = b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::7").As16()})
		}
		if err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

func warpDNSTestAnswer(q dnsmessage.Question, code dnsmessage.RCode, address bool) (dnsmessage.Parser, dnsmessage.Header, error) {
	packet, err := warpDNSTestPacket(q, 1, code, address, false)
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	var p dnsmessage.Parser
	h, err := p.Start(packet)
	if err != nil {
		return p, h, err
	}
	if _, err = p.Question(); err != nil {
		return p, h, err
	}
	if err = p.SkipQuestion(); err != dnsmessage.ErrSectionDone {
		return p, h, fmt.Errorf("invalid test question section: %v", err)
	}
	return p, h, nil
}

func TestWarpPocketDNSOrderedFailover(t *testing.T) {
	cases := []struct {
		name   string
		modes  [3]string
		stages []int
		found  bool
		absent bool
	}{
		{"first-primary", [3]string{"answer"}, []int{0}, true, false},
		{"second-primary", [3]string{"transport", "answer"}, []int{0, 1}, true, false},
		{"fallback", [3]string{"transport", "transport", "answer"}, []int{0, 1, 2}, true, false},
		{"all-failed", [3]string{"transport", "transport", "transport"}, []int{0, 1, 2}, false, false},
		{"nxdomain", [3]string{"nxdomain"}, []int{0}, false, true},
		{"nodata", [3]string{"nodata"}, []int{0}, false, true},
		{"second-negative", [3]string{"transport", "nxdomain"}, []int{0, 1}, false, true},
		{"servfail-refused", [3]string{"servfail", "refused", "answer"}, []int{0, 1, 2}, true, false},
		{"malformed", [3]string{"malformed", "answer"}, []int{0, 1}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tnet := warpDNSTestNet()
			original := append([]netip.Addr(nil), tnet.dnsServers...)
			var mu sync.Mutex
			var calls []int
			exchange := func(ctx context.Context, server netip.Addr, q dnsmessage.Question, timeout time.Duration) (dnsmessage.Parser, dnsmessage.Header, error) {
				stage := -1
				for index, candidate := range original {
					if candidate == server {
						stage = index
					}
				}
				if stage < 0 {
					return dnsmessage.Parser{}, dnsmessage.Header{}, errors.New("unexpected fourth DNS server")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > warpDNSStageTimeout {
					t.Error("DNS exchange is missing the one-second stage bound")
				}
				mu.Lock()
				calls = append(calls, stage)
				mu.Unlock()
				switch tc.modes[stage] {
				case "answer":
					return warpDNSTestAnswer(q, dnsmessage.RCodeSuccess, true)
				case "nxdomain":
					return warpDNSTestAnswer(q, dnsmessage.RCodeNameError, false)
				case "nodata":
					return warpDNSTestAnswer(q, dnsmessage.RCodeSuccess, false)
				case "servfail":
					return warpDNSTestAnswer(q, dnsmessage.RCodeServerFailure, false)
				case "refused":
					return warpDNSTestAnswer(q, dnsmessage.RCodeRefused, false)
				case "malformed":
					return dnsmessage.Parser{}, dnsmessage.Header{}, nil
				case "transport":
					return dnsmessage.Parser{}, dnsmessage.Header{}, &net.OpError{Op: "read", Net: "udp", Err: errTimeout}
				default:
					return dnsmessage.Parser{}, dnsmessage.Header{}, errors.New("DNS must not be consulted")
				}
			}
			addrs, err := tnet.lookupOrderedDNS(context.Background(), "example.test", exchange)
			if tc.found {
				if err != nil || !reflect.DeepEqual(addrs, []string{"192.0.2.7"}) {
					t.Fatalf("lookup: %v, %v", addrs, err)
				}
			} else {
				var dnsErr *net.DNSError
				if len(addrs) != 0 || !errors.As(err, &dnsErr) || dnsErr.IsNotFound != tc.absent {
					t.Fatalf("expected DNS error (negative=%v), got %v, %v", tc.absent, addrs, err)
				}
			}
			var stages []int
			for _, stage := range calls {
				if len(stages) == 0 || stages[len(stages)-1] != stage {
					stages = append(stages, stage)
				}
			}
			if !reflect.DeepEqual(stages, tc.stages) {
				t.Fatalf("server stages: %v, want %v (calls %v)", stages, tc.stages, calls)
			}
			for _, stage := range tc.stages[:len(tc.stages)-1] {
				count := 0
				for _, call := range calls {
					if call == stage {
						count++
					}
				}
				if count != 2 {
					t.Errorf("stage %d advanced before its two immediate-error attempts: %d", stage, count)
				}
			}
			if !reflect.DeepEqual(tnet.dnsServers, original) {
				t.Fatal("per-call lookup mutated the shared DNS configuration")
			}
		})
	}
}

func TestWarpPocketDNSFamiliesShareOneServerStage(t *testing.T) {
	for _, outcome := range []string{"address", "negative"} {
		t.Run(outcome, func(t *testing.T) {
			tnet := warpDNSTestNet()
			tnet.hasV6 = true
			exchange := func(ctx context.Context, server netip.Addr, q dnsmessage.Question, timeout time.Duration) (dnsmessage.Parser, dnsmessage.Header, error) {
				if server != tnet.dnsServers[0] {
					t.Error("another resolver was used despite a usable primary response")
					return dnsmessage.Parser{}, dnsmessage.Header{}, errors.New("unexpected resolver")
				}
				if q.Type == dnsmessage.TypeA {
					if outcome == "address" {
						return warpDNSTestAnswer(q, dnsmessage.RCodeSuccess, true)
					}
					<-ctx.Done()
					return dnsmessage.Parser{}, dnsmessage.Header{}, ctx.Err()
				}
				if outcome == "negative" {
					return warpDNSTestAnswer(q, dnsmessage.RCodeSuccess, false)
				}
				<-ctx.Done()
				return dnsmessage.Parser{}, dnsmessage.Header{}, ctx.Err()
			}
			addrs, err := tnet.lookupOrderedDNS(context.Background(), "example.test", exchange)
			if outcome == "address" {
				if err != nil || !reflect.DeepEqual(addrs, []string{"192.0.2.7"}) {
					t.Fatalf("primary A was lost to AAAA timeout: %v, %v", addrs, err)
				}
			} else {
				var dnsErr *net.DNSError
				if len(addrs) != 0 || !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
					t.Fatalf("negative answer was lost to other-family timeout: %v, %v", addrs, err)
				}
			}
		})
	}
}

func TestWarpPocketDNSCancellationAndInputGuards(t *testing.T) {
	for _, mode := range []string{"pre-cancel", "during-positive", "during-error", "empty-servers", "literal", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			tnet := warpDNSTestNet()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			host := "example.test"
			if mode == "pre-cancel" {
				cancel()
			} else if mode == "empty-servers" {
				tnet.dnsServers = nil
			} else if mode == "literal" {
				host = "192.0.2.9"
			} else if mode == "invalid" {
				host = "bad/name"
			}
			calls := 0
			exchange := func(ctx context.Context, server netip.Addr, q dnsmessage.Question, timeout time.Duration) (dnsmessage.Parser, dnsmessage.Header, error) {
				calls++
				cancel()
				if mode == "during-positive" {
					return warpDNSTestAnswer(q, dnsmessage.RCodeSuccess, true)
				}
				return dnsmessage.Parser{}, dnsmessage.Header{}, ctx.Err()
			}
			addrs, err := tnet.lookupOrderedDNS(ctx, host, exchange)
			if mode == "literal" {
				if err != nil || !reflect.DeepEqual(addrs, []string{host}) {
					t.Fatalf("literal IP failed: %v, %v", addrs, err)
				}
			} else if err == nil || len(addrs) != 0 {
				t.Fatalf("lookup should fail closed: %v, %v", addrs, err)
			}
			expected := 0
			if mode == "during-positive" || mode == "during-error" {
				expected = 1
			}
			if calls != expected {
				t.Fatalf("unexpected query after cancellation/invalid input: %d", calls)
			}
		})
	}
}

func TestWarpPocketDNSLookupDeadline(t *testing.T) {
	tnet := warpDNSTestNet()
	exchange := func(ctx context.Context, server netip.Addr, q dnsmessage.Question, timeout time.Duration) (dnsmessage.Parser, dnsmessage.Header, error) {
		<-ctx.Done()
		return dnsmessage.Parser{}, dnsmessage.Header{}, ctx.Err()
	}
	start := time.Now()
	addrs, err := tnet.lookupOrderedDNS(context.Background(), "example.test", exchange)
	var dnsErr *net.DNSError
	if len(addrs) != 0 || !errors.As(err, &dnsErr) || !dnsErr.IsTimeout {
		t.Fatalf("expected lookup deadline, got %v, %v", addrs, err)
	}
	if elapsed := time.Since(start); elapsed > warpDNSLookupTimeout+time.Second {
		t.Fatalf("DNS lookup exceeded its three-second budget: %v", elapsed)
	}
}

func TestWarpPocketDNSConcurrentLookups(t *testing.T) {
	tnet := warpDNSTestNet()
	original := append([]netip.Addr(nil), tnet.dnsServers...)
	const count = 24
	finished := make(chan error, count)
	for i := 0; i < count; i++ {
		go func(index int) {
			last := index % len(original)
			exchange := func(ctx context.Context, server netip.Addr, q dnsmessage.Question, timeout time.Duration) (dnsmessage.Parser, dnsmessage.Header, error) {
				if server == original[last] {
					return warpDNSTestAnswer(q, dnsmessage.RCodeSuccess, true)
				}
				return dnsmessage.Parser{}, dnsmessage.Header{}, errors.New("unreachable")
			}
			addrs, err := tnet.lookupOrderedDNS(context.Background(), fmt.Sprintf("request%d.test", index), exchange)
			if err == nil && !reflect.DeepEqual(addrs, []string{"192.0.2.7"}) {
				err = fmt.Errorf("wrong addresses: %v", addrs)
			}
			finished <- err
		}(i)
	}
	for i := 0; i < count; i++ {
		if err := <-finished; err != nil {
			t.Error(err)
		}
	}
	if !reflect.DeepEqual(tnet.dnsServers, original) {
		t.Fatal("concurrent lookups changed shared DNS configuration")
	}
}

func TestWarpPocketDNSExchangeCancellationClosesUDP(t *testing.T) {
	server := netip.MustParseAddr("192.0.2.53")
	device, tnet, err := CreateNetTUN([]netip.Addr{server}, []netip.Addr{server}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { device.Close() })
	listener, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(server, 53))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("example.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	go func() {
		_, _, err := tnet.exchange(ctx, server, q, 10*time.Second)
		finished <- err
	}()
	listener.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := listener.ReadFrom(make([]byte, 512)); err != nil {
		t.Fatalf("virtual DNS server did not receive query: %v", err)
	}
	cancel()
	select {
	case err := <-finished:
		if err != errCanceled {
			t.Fatalf("canceled DNS read: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS UDP read was not interrupted by cancellation")
	}
}

func TestWarpPocketDNSUDPToTCPBudgetAndCancellation(t *testing.T) {
	for _, mode := range []string{"answer", "cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			server := netip.MustParseAddr("192.0.2.53")
			device, tnet, err := CreateNetTUN([]netip.Addr{server}, []netip.Addr{server}, 1280)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { device.Close() })
			udp, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(server, 53))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { udp.Close() })
			tcp, err := tnet.ListenTCPAddrPort(netip.AddrPortFrom(server, 53))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { tcp.Close() })
			serverDone := make(chan error, 1)
			tcpReady := make(chan struct{})
			go func() {
				serve := func() error {
					udp.SetReadDeadline(time.Now().Add(3 * time.Second))
					buffer := make([]byte, 512)
					n, peer, err := udp.ReadFrom(buffer)
					if err != nil {
						return err
					}
					var p dnsmessage.Parser
					h, err := p.Start(buffer[:n])
					if err != nil {
						return err
					}
					q, err := p.Question()
					if err != nil {
						return err
					}
					if mode == "deadline" {
						// Most of the single exchange budget is already consumed
						// by UDP: TCP must not receive a fresh one-second budget.
						time.Sleep(750 * time.Millisecond)
					}
					response, err := warpDNSTestPacket(q, h.ID, dnsmessage.RCodeSuccess, false, true)
					if err != nil {
						return err
					}
					if _, err := udp.WriteTo(response, peer); err != nil {
						return err
					}
					conn, err := tcp.Accept()
					if err != nil {
						return err
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					prefix := make([]byte, 2)
					if _, err := io.ReadFull(conn, prefix); err != nil {
						return err
					}
					packet := make([]byte, int(binary.BigEndian.Uint16(prefix)))
					if _, err := io.ReadFull(conn, packet); err != nil {
						return err
					}
					h, err = p.Start(packet)
					if err != nil {
						return err
					}
					q, err = p.Question()
					if err != nil {
						return err
					}
					close(tcpReady)
					if mode == "answer" {
						response, err = warpDNSTestPacket(q, h.ID, dnsmessage.RCodeSuccess, true, false)
						if err != nil {
							return err
						}
						binary.BigEndian.PutUint16(prefix, uint16(len(response)))
						_, err = conn.Write(append(prefix, response...))
						return err
					}
					_, err = conn.Read(make([]byte, 1))
					if err != io.EOF {
						return fmt.Errorf("client did not close the canceled/expired TCP DNS socket: %v", err)
					}
					return nil
				}
				serverDone <- serve()
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			timeout := 10 * time.Second
			if mode == "deadline" {
				timeout = time.Second
			}
			finished := make(chan error, 1)
			start := time.Now()
			go func() {
				q := dnsmessage.Question{Name: dnsmessage.MustNewName("example.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
				p, h, err := tnet.exchange(ctx, server, q, timeout)
				if err == nil && mode == "answer" {
					err = checkHeader(&p, h)
					if err == nil {
						err = skipToAnswer(&p, dnsmessage.TypeA)
					}
					if err == nil {
						var answer dnsmessage.AResource
						answer, err = p.AResource()
						if err == nil && answer.A != [4]byte{192, 0, 2, 7} {
							err = errors.New("wrong TCP DNS answer")
						}
					}
				}
				finished <- err
			}()
			if mode == "cancel" {
				select {
				case <-tcpReady:
					cancel()
				case <-time.After(2 * time.Second):
					t.Fatal("truncated UDP response did not start tunneled TCP DNS")
				}
			}
			select {
			case err := <-finished:
				if mode == "answer" && err != nil {
					t.Fatal(err)
				}
				if mode == "cancel" && err != errCanceled {
					t.Fatalf("TCP DNS cancellation: %v", err)
				}
				if mode == "deadline" {
					var timeoutErr net.Error
					if err != errTimeout && (!errors.As(err, &timeoutErr) || !timeoutErr.Timeout()) {
						t.Fatalf("expected shared UDP/TCP deadline: %v", err)
					}
					if time.Since(start) > 1600*time.Millisecond {
						t.Fatal("TCP DNS received a new timeout after UDP consumed the budget")
					}
				}
			case <-time.After(3 * time.Second):
				t.Fatal("TCP DNS did not finish within its shared/canceled budget")
			}
			select {
			case err := <-serverDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("virtual DNS server did not observe connection cleanup")
			}
		})
	}
}
