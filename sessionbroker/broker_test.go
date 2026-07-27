package sessionbroker

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"weaverssh/sessionmux"
)

func TestBrokerBridgesAuthorizedLogicalStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "session.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Open: func(_ context.Context, request OpenRequest) (io.ReadWriteCloser, error) {
		if request.Node != "origin" || request.Service != sessionmux.ServiceFS {
			t.Fatalf("unexpected request: %+v", request)
		}
		left, right := net.Pipe()
		go func() {
			defer right.Close()
			_, _ = io.Copy(right, right)
		}()
		return left, nil
	}}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(ctx, listener) }()

	conn, err := Dial(ctx, "unix", path, OpenRequest{Node: "origin", Service: sessionmux.ServiceFS})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("broker-echo")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("broker-echo"))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "broker-echo" {
		t.Fatalf("response=%q", response)
	}
	_ = conn.Close()
	cancel()
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestBrokerPreservesResponseAfterClientCloseWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "session.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}

	server := &Server{Open: func(_ context.Context, request OpenRequest) (io.ReadWriteCloser, error) {
		if request.Node != "endpoint" || request.Service != sessionmux.ServiceTCP {
			t.Fatalf("unexpected request: %+v", request)
		}
		stream, peer := newHalfClosePipe()
		go func() {
			defer peer.Close()
			payload, readErr := io.ReadAll(peer)
			if readErr == nil {
				_, _ = peer.Write(append([]byte("reply:"), payload...))
			}
		}()
		return stream, nil
	}}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(ctx, listener) }()

	conn, err := Dial(ctx, "unix", path, OpenRequest{Node: "endpoint", Service: sessionmux.ServiceTCP})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatalf("broker connection type=%T", conn)
	}
	if err := unixConn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("reply:request"))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "reply:request" {
		t.Fatalf("response=%q", response)
	}
	_ = conn.Close()
	cancel()
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

type halfClosePipe struct {
	read      *io.PipeReader
	write     *io.PipeWriter
	closeOnce sync.Once
}

func newHalfClosePipe() (*halfClosePipe, *halfClosePipe) {
	leftRead, rightWrite := io.Pipe()
	rightRead, leftWrite := io.Pipe()
	return &halfClosePipe{read: leftRead, write: leftWrite}, &halfClosePipe{read: rightRead, write: rightWrite}
}

func (p *halfClosePipe) Read(buffer []byte) (int, error)  { return p.read.Read(buffer) }
func (p *halfClosePipe) Write(buffer []byte) (int, error) { return p.write.Write(buffer) }
func (p *halfClosePipe) Close() error {
	p.closeOnce.Do(func() { _ = p.write.Close() })
	return nil
}
