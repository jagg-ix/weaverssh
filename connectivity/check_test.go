package connectivity

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type memoryConn struct {
	*bytes.Reader
	closed bool
}

func (conn *memoryConn) Write(payload []byte) (int, error) { return len(payload), nil }
func (conn *memoryConn) Close() error                      { conn.closed = true; return nil }
func (conn *memoryConn) LocalAddr() net.Addr               { return fakeAddr("local") }
func (conn *memoryConn) RemoteAddr() net.Addr              { return fakeAddr("remote") }
func (conn *memoryConn) SetDeadline(time.Time) error       { return nil }
func (conn *memoryConn) SetReadDeadline(time.Time) error   { return nil }
func (conn *memoryConn) SetWriteDeadline(time.Time) error  { return nil }

type fakeAddr string

func (addr fakeAddr) Network() string { return "tcp" }
func (addr fakeAddr) String() string  { return string(addr) }

func TestCheckWithDependenciesAcceptsNebulaSSHPath(t *testing.T) {
	conn := &memoryConn{Reader: bytes.NewReader([]byte("notice\r\nSSH-2.0-OpenSSH_9.9\r\n"))}
	deps := Dependencies{
		CommandOutput: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "ssh" || strings.Join(args, " ") != "-G wv-dev-node" {
				t.Fatalf("unexpected command %q %q", name, args)
			}
			return []byte("hostname 10.80.0.20\nport 22\nuser developer\n"), nil
		},
		DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "10.80.0.20:22" {
				t.Fatalf("unexpected dial %s %s", network, address)
			}
			return conn, nil
		},
	}
	result, err := CheckWithDependencies(context.Background(), Options{
		Underlay: "nebula", SSHHost: "wv-dev-node", OverlayAddress: "10.80.0.20",
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if !result.SSHConfigResolved || !result.OverlayReachable || !result.SSHReachable {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.ResolvedUser != "developer" || result.ResolvedPort != 22 {
		t.Fatalf("unexpected resolution: %+v", result)
	}
	if !conn.closed {
		t.Fatal("connection was not closed")
	}
}

func TestCheckAcceptsNonNebulaUnderlayLabel(t *testing.T) {
	deps := Dependencies{
		CommandOutput: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("hostname 203.0.113.20\nport 22\n"), nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return &memoryConn{Reader: bytes.NewReader([]byte("SSH-2.0-test\r\n"))}, nil
		},
	}
	result, err := CheckWithDependencies(context.Background(), Options{
		Underlay: "public-ssh", SSHHost: "node",
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if result.Underlay != "public-ssh" || !result.SSHReachable {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestCheckRejectsOverlayMismatch(t *testing.T) {
	deps := Dependencies{
		CommandOutput: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("hostname 10.80.0.20\nport 22\n"), nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("dial should not run")
			return nil, io.EOF
		},
	}
	_, err := CheckWithDependencies(context.Background(), Options{
		SSHHost: "node", OverlayAddress: "10.80.0.21",
	}, deps)
	if err == nil || !strings.Contains(err.Error(), "conflicts with") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseSSHConfigRejectsInvalidPort(t *testing.T) {
	_, err := ParseSSHConfig([]byte("hostname node\nport 70000\n"))
	if err == nil {
		t.Fatal("expected invalid port error")
	}
}
