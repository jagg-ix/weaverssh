package sessionproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"weaverssh/socksudp"
)

type echoUDPAssociation struct {
	responses chan []byte
	closed    chan struct{}
	once      sync.Once
}

func newEchoUDPAssociation() *echoUDPAssociation {
	return &echoUDPAssociation{responses: make(chan []byte, 4), closed: make(chan struct{})}
}

func (a *echoUDPAssociation) Send(packet []byte) error {
	datagram, err := socksudp.Parse(packet)
	if err != nil {
		return err
	}
	response, err := socksudp.Marshal(datagram.Address, append([]byte("echo:"), datagram.Data...))
	if err != nil {
		return err
	}
	select {
	case a.responses <- response:
		return nil
	case <-a.closed:
		return net.ErrClosed
	}
}

func (a *echoUDPAssociation) Receive() ([]byte, error) {
	select {
	case packet := <-a.responses:
		return packet, nil
	case <-a.closed:
		return nil, net.ErrClosed
	}
}

func (a *echoUDPAssociation) Close() error {
	a.once.Do(func() { close(a.closed) })
	return nil
}

func TestSOCKS5UDPAssociateRoundTripAndControlLifetime(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	association := newEchoUDPAssociation()
	server := &Server{
		AllowNoAuth: true,
		AssociateUDP: func(context.Context, string) (UDPAssociation, error) {
			return association, nil
		},
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx, listener) }()

	control, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	selection := make([]byte, 2)
	if _, err := io.ReadFull(control, selection); err != nil {
		t.Fatal(err)
	}
	if selection[0] != 0x05 || selection[1] != 0x00 {
		t.Fatalf("method selection=%x", selection)
	}
	// RFC 1928: UDP ASSOCIATE with 0.0.0.0:0 asks the server to learn the client endpoint.
	if _, err := control.Write([]byte{0x05, commandUDPAssociate, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	relayAddress, err := readBoundAddress(control)
	if err != nil {
		t.Fatal(err)
	}

	udpClient, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()
	request, err := socksudp.Marshal("dns.internal:53", []byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udpClient.WriteToUDP(request, relayAddress); err != nil {
		t.Fatal(err)
	}
	_ = udpClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, socksudp.MaxDatagramBytes)
	n, _, err := udpClient.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	response, err := socksudp.Parse(buffer[:n])
	if err != nil {
		t.Fatal(err)
	}
	if response.Address != "dns.internal:53" || string(response.Data) != "echo:query" {
		t.Fatalf("response=%+v", response)
	}

	_ = control.Close()
	select {
	case <-association.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("UDP association survived its TCP control connection")
	}
	cancel()
	_ = listener.Close()
	select {
	case err := <-serveDone:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS server did not stop")
	}
}

func readBoundAddress(reader io.Reader) (*net.UDPAddr, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if header[0] != 0x05 || header[1] != 0x00 || header[2] != 0x00 {
		return nil, errors.New("SOCKS5 UDP ASSOCIATE failed")
	}
	var ip net.IP
	switch header[3] {
	case 0x01:
		buffer := make([]byte, 4)
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return nil, err
		}
		ip = net.IP(buffer)
	case 0x04:
		buffer := make([]byte, 16)
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return nil, err
		}
		ip = net.IP(buffer)
	default:
		return nil, errors.New("unexpected SOCKS5 bound address type")
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(portBytes))}, nil
}
