package sessionudp

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"weaverssh/socksudp"
)

func TestServerRelaysRFC1928Datagram(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, source, readErr := echo.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			_, _ = echo.WriteToUDP(append([]byte("echo:"), buffer[:n]...), source)
		}
	}()

	allow, err := ParseAllowlist(echo.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Authorize: allow.Authorize, ReadTimeout: 100 * time.Millisecond}
	metadata, err := EncodeRequest("udp4")
	if err != nil {
		t.Fatal(err)
	}
	client, service := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, service, metadata) }()
	if err := readResult(client); err != nil {
		t.Fatal(err)
	}

	packet, err := socksudp.Marshal(echo.LocalAddr().String(), []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(client, packet); err != nil {
		t.Fatal(err)
	}
	responsePacket, err := ReadFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	response, err := socksudp.Parse(responsePacket)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Data) != "echo:ping" {
		t.Fatalf("response=%q", response.Data)
	}
	if response.Address != echo.LocalAddr().String() {
		t.Fatalf("source=%q want=%q", response.Address, echo.LocalAddr())
	}

	_ = client.Close()
	select {
	case err := <-done:
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP association did not stop with stream")
	}
}

func TestServerDropsFragmentedDatagrams(t *testing.T) {
	allow, err := ParseAllowlist("127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	writes := make(chan struct{}, 1)
	server := &Server{
		Authorize: allow.Authorize,
		ListenPacket: func(context.Context, string, string) (net.PacketConn, error) {
			return &recordingPacketConn{writes: writes}, nil
		},
		Resolve: func(context.Context, string, string) (net.Addr, error) {
			return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, nil
		},
	}
	metadata, _ := EncodeRequest("udp4")
	client, service := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx, service, metadata) //nolint:errcheck
	if err := readResult(client); err != nil {
		t.Fatal(err)
	}
	fragmented, _ := socksudp.Marshal("127.0.0.1:9", []byte("blocked"))
	fragmented[2] = 1
	if err := WriteFrame(client, fragmented); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writes:
		t.Fatal("fragmented datagram reached final UDP socket")
	case <-time.After(150 * time.Millisecond):
	}
}

type recordingPacketConn struct {
	writes chan struct{}
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}
func (c *recordingPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	select { case c.writes <- struct{}{}: default: }
	return 0, nil
}
func (*recordingPacketConn) Close() error                       { return nil }
func (*recordingPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (*recordingPacketConn) SetDeadline(time.Time) error        { return nil }
func (*recordingPacketConn) SetReadDeadline(time.Time) error    { return nil }
func (*recordingPacketConn) SetWriteDeadline(time.Time) error   { return nil }
