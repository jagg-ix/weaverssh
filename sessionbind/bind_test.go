package sessionbind

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestRequestRoundTrip(t *testing.T) {
	payload, err := EncodeRequest("tcp", "127.0.0.1:2222")
	if err != nil { t.Fatal(err) }
	request, err := DecodeRequest(payload)
	if err != nil { t.Fatal(err) }
	if request.Protocol != ProtocolVersion || request.Network != "tcp" || request.ExpectedPeer != "127.0.0.1:2222" { t.Fatalf("request=%+v", request) }
}

func TestWildcardRequestRequiresUnspecifiedZeroEndpoint(t *testing.T) {
	request, err := NormalizeRequest(Request{Network: "tcp", ExpectedPeer: "0.0.0.0:0"})
	if err != nil { t.Fatal(err) }
	if !IsWildcardPeer(request.ExpectedPeer) { t.Fatalf("not wildcard: %+v", request) }
	if _, err := NormalizeRequest(Request{Network: "tcp", ExpectedPeer: "example.test:0"}); err == nil { t.Fatal("domain zero-port wildcard accepted") }
	if _, err := NormalizeRequest(Request{Network: "tcp", ExpectedPeer: "127.0.0.1:0"}); err == nil { t.Fatal("concrete zero-port wildcard accepted") }
}

func TestPeerMatchesResolvedAddress(t *testing.T) {
	expected := []net.IP{net.ParseIP("127.0.0.1")}
	if !peerMatchesResolved(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}, "2222", expected) { t.Fatal("matching peer rejected") }
	if peerMatchesResolved(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2223}, "2222", expected) { t.Fatal("wrong port accepted") }
	if peerMatchesResolved(&net.TCPAddr{IP: net.ParseIP("127.0.0.2"), Port: 2222}, "2222", expected) { t.Fatal("wrong IP accepted") }
}

func TestAcceptExpectedPeerResolvesDNSName(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	accepted := make(chan error, 1)
	go func() {
		conn, err := acceptExpectedPeer(ctx, listener, "tcp4", net.JoinHostPort("peer.test", stringPort(port)), false, func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		})
		if conn != nil { _ = conn.Close() }
		accepted <- err
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil { t.Fatal(err) }
	_ = client.Close()
	if err := <-accepted; err != nil { t.Fatal(err) }
}

func TestAcceptExpectedPeerWildcardAcceptsOnePeer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	accepted := make(chan error, 1)
	go func() {
		conn, err := acceptExpectedPeer(ctx, listener, "tcp", "0.0.0.0:0", true, nil)
		if conn != nil { _ = conn.Close() }
		accepted <- err
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil { t.Fatal(err) }
	_ = client.Close()
	if err := <-accepted; err != nil { t.Fatal(err) }
}

type memoryStream struct{ bytes.Buffer }
func (*memoryStream) Close() error { return nil }

func TestServerRejectsWildcardWithoutExplicitPermission(t *testing.T) {
	metadata, err := EncodeRequest("tcp", "0.0.0.0:0")
	if err != nil { t.Fatal(err) }
	stream := &memoryStream{}
	server := &Server{AllowAnyPeer: false}
	if err := server.Serve(context.Background(), stream, metadata); err == nil { t.Fatal("wildcard BIND accepted without explicit permission") }
}

func TestOpenClientStreamConsumesBoundResponse(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	go func() { _ = writeResponse(server, Response{Protocol: ProtocolVersion, Phase: "bound", Network: "tcp", Address: "127.0.0.1:3456"}); _ = server.Close() }()
	listener, err := OpenClientStream(client)
	if err != nil { t.Fatal(err) }
	defer listener.Close()
	if listener.Addr().String() != "127.0.0.1:3456" { t.Fatalf("address=%s", listener.Addr()) }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := listener.Accept(ctx); err == nil { t.Fatal("expected closed stream accept failure") }
}

func stringPort(port int) string {
	if port == 0 { return "0" }
	var digits [5]byte
	index := len(digits)
	for port > 0 { index--; digits[index] = byte('0' + port%10); port /= 10 }
	return string(digits[index:])
}
