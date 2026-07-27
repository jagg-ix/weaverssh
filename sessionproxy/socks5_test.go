package sessionproxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestSOCKS5ConnectUsesSuppliedDialer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialed := make(chan string, 1)
	server := &Server{
		AllowNoAuth: true,
		Dial: func(_ context.Context, network, address string) (net.Conn, error) {
			dialed <- network + " " + address
			left, right := net.Pipe()
			go func() {
				defer right.Close()
				buf := make([]byte, 4)
				if _, err := io.ReadFull(right, buf); err == nil {
					_, _ = right.Write(append([]byte("echo:"), buf...))
				}
			}()
			return left, nil
		},
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(ctx, listener) }()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(client, method); err != nil {
		t.Fatal(err)
	}
	if method[0] != 5 || method[1] != 0 {
		t.Fatalf("method reply=%v", method)
	}
	host := []byte("service.internal")
	request := []byte{5, 1, 0, 3, byte(len(host))}
	request = append(request, host...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, 8443)
	request = append(request, port...)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("SOCKS reply=%v", reply)
	}
	if got := <-dialed; got != "tcp service.internal:8443" {
		t.Fatalf("dialed=%q", got)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("echo:ping"))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "echo:ping" {
		t.Fatalf("response=%q", response)
	}
	cancel()
	_ = listener.Close()
	select {
	case err := <-serverErr:
		if err != nil && ctx.Err() == nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS server did not exit")
	}
}
