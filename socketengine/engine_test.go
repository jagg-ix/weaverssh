package socketengine

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestEngineServesMultipleListeners(t *testing.T) {
	first := reserveTCPAddress(t)
	second := reserveTCPAddress(t)
	config := Config{
		EventLoops:     2,
		MaxConnections: 8,
		QueueDepth:     4,
		Routes: []Route{
			{Name: "first", Listen: "tcp://" + first, Node: "node-a", Address: "first.internal:443", MaxConnections: 4},
			{Name: "second", Listen: "tcp://" + second, Node: "node-b", Address: "second.internal:443", MaxConnections: 4},
		},
	}
	engine, err := New(config, func(_ context.Context, route Route) (net.Conn, error) {
		client, service := net.Pipe()
		go func() {
			defer service.Close()
			payload := make([]byte, 256)
			n, readErr := service.Read(payload)
			if readErr != nil {
				return
			}
			_, _ = service.Write([]byte(route.Name + ":" + string(payload[:n])))
		}()
		return client, nil
	}, func(route Route, remote string, err error) {
		t.Logf("route=%s remote=%s error=%v", route.Name, remote, err)
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()
	waitEngineReady(t, engine, done)

	for _, test := range []struct {
		address string
		prefix  string
	}{
		{address: first, prefix: "first:"},
		{address: second, prefix: "second:"},
	} {
		connection, err := net.DialTimeout("tcp", test.address, 2*time.Second)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if _, err := connection.Write([]byte("ping")); err != nil {
			_ = connection.Close()
			cancel()
			t.Fatal(err)
		}
		response := make([]byte, len(test.prefix)+len("ping"))
		if _, err := io.ReadFull(connection, response); err != nil {
			_ = connection.Close()
			cancel()
			t.Fatal(err)
		}
		_ = connection.Close()
		if string(response) != test.prefix+"ping" {
			cancel()
			t.Fatalf("response=%q", response)
		}
	}

	stats := engine.Snapshot()
	if stats.Accepted != 2 || stats.BytesIn < 8 || stats.BytesOut < uint64(len("first:ping")+len("second:ping")) {
		t.Fatalf("stats=%+v", stats)
	}
	stopEngine(t, cancel, done)
}

func TestEnginePreservesRequestEOFBeforeDelayedResponse(t *testing.T) {
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendListener.Close()
	backendDone := make(chan error, 1)
	go func() {
		connection, acceptErr := backendListener.Accept()
		if acceptErr != nil {
			backendDone <- acceptErr
			return
		}
		defer connection.Close()
		request, readErr := io.ReadAll(connection)
		if readErr != nil {
			backendDone <- readErr
			return
		}
		_, writeErr := connection.Write(append([]byte("reply:"), request...))
		backendDone <- writeErr
	}()

	frontendAddress := reserveTCPAddress(t)
	engine, err := New(Config{Routes: []Route{{
		Name: "half-close", Listen: "tcp://" + frontendAddress,
		Node: "node", Address: backendListener.Addr().String(),
	}}}, func(ctx context.Context, route Route) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, route.Network, route.Address)
	}, func(route Route, remote string, err error) {
		t.Logf("route=%s remote=%s error=%v", route.Name, remote, err)
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()
	waitEngineReady(t, engine, done)

	address, err := net.ResolveTCPAddr("tcp", frontendAddress)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	client, err := net.DialTCP("tcp", nil, address)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("request")); err != nil {
		_ = client.Close()
		cancel()
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		_ = client.Close()
		cancel()
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	_ = client.Close()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if string(response) != "reply:request" {
		cancel()
		t.Fatalf("response=%q", response)
	}
	select {
	case err := <-backendDone:
		if err != nil {
			cancel()
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("backend did not observe request EOF")
	}
	stopEngine(t, cancel, done)
}

func TestEngineRejectsMissingDialer(t *testing.T) {
	_, err := New(Config{Routes: []Route{{Name: "route", Listen: "tcp://127.0.0.1:5000", Node: "node", Address: "service.internal:443"}}}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "dial function") {
		t.Fatalf("error=%v", err)
	}
}

func waitEngineReady(t *testing.T, engine *Engine, done <-chan error) {
	t.Helper()
	select {
	case <-engine.Ready():
	case err := <-done:
		t.Fatalf("engine exited before ready: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("engine did not become ready")
	}
}

func stopEngine(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("engine did not shut down")
	}
}

func reserveTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		t.Fatalf("reserved address %q: %v", address, err)
	}
	return address
}
