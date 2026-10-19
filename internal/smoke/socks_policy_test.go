package smoke

import (
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// socksPolicyServer emulates the SOCKS5 surface of a worker: greeting, then one
// scripted reply for a BIND or UDP ASSOCIATE request.
type socksPolicyServer struct {
	listener net.Listener
	mu       sync.Mutex
	commands []byte
}

func newSOCKSPolicyServer(t *testing.T, reply func(command byte) []byte) *socksPolicyServer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &socksPolicyServer{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(connection, greeting); err != nil {
					return
				}
				_, _ = connection.Write([]byte{5, 0})
				header := make([]byte, 10)
				if _, err := io.ReadFull(connection, header); err != nil {
					return
				}
				server.mu.Lock()
				server.commands = append(server.commands, header[1])
				server.mu.Unlock()
				_, _ = connection.Write(reply(header[1]))
			}()
		}
	}()
	return server
}

func (s *socksPolicyServer) port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *socksPolicyServer) observed() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.commands...)
}

func TestSOCKSPolicyRejectsNonConnectCommands(t *testing.T) {
	server := newSOCKSPolicyServer(t, func(byte) []byte { return []byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0} })
	if err := verifySOCKSPolicy(server.port()); err != nil {
		t.Fatal(err)
	}
	if observed := server.observed(); len(observed) != 2 || observed[0] != 2 || observed[1] != 3 {
		t.Fatalf("policy proof did not request both non-CONNECT commands: %v", observed)
	}
}

func TestSOCKSPolicyRejectsGarbageTimeoutAndSuccess(t *testing.T) {
	for _, test := range []struct {
		name  string
		reply func(byte) []byte
	}{
		{"unexpected command accepted", func(byte) []byte { return []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 53} }},
		{"command not supported", func(byte) []byte { return []byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0} }},
		{"truncated reply", func(byte) []byte { return []byte{5, 2} }},
		{"silent server", func(byte) []byte { time.Sleep(3 * time.Second); return nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newSOCKSPolicyServer(t, test.reply)
			if err := verifySOCKSPolicy(server.port()); err == nil {
				t.Fatal("worker restriction was not enforced by the smoke proof")
			}
		})
	}
	if err := verifySOCKSPolicy(0); err == nil {
		t.Fatal("closed port accepted by the smoke proof")
	}
}

func TestProbeSOCKSCommandTreatsRuleFailureAsTheOnlySuccess(t *testing.T) {
	server := newSOCKSPolicyServer(t, func(byte) []byte { return []byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0} })
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(server.port()))
	if !probeSOCKSCommand(address, 2) {
		t.Fatal("valid rule-failure reply was not accepted")
	}
	if observed := server.observed(); len(observed) != 1 || observed[0] != 2 {
		t.Fatalf("probe sent the wrong command: %v", observed)
	}
}
