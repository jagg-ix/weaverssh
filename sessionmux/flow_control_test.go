package sessionmux

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func newFlowMuxPair(t *testing.T, leftConfig, rightConfig Config) (*Mux, *Mux) {
	t.Helper()
	leftConn, rightConn := net.Pipe()
	leftConfig.Role = RoleInitiator
	rightConfig.Role = RoleResponder
	left, err := New(leftConn, leftConfig)
	if err != nil {
		t.Fatal(err)
	}
	right, err := New(rightConn, rightConfig)
	if err != nil {
		_ = left.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})
	return left, right
}

func acceptOne(t *testing.T, ctx context.Context, mux *Mux) <-chan *Stream {
	t.Helper()
	result := make(chan *Stream, 1)
	go func() {
		stream, err := mux.Accept(ctx)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		result <- stream
	}()
	return result
}

func waitForBuffered(t *testing.T, stream *Stream, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		buffered, _, _, _ := stream.flowSnapshot()
		if buffered == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	buffered, sendCredit, recvCredit, pending := stream.flowSnapshot()
	t.Fatalf("buffered=%d want=%d send=%d recv=%d pending=%d", buffered, want, sendCredit, recvCredit, pending)
}

func TestWindowBoundsUnreadDataAndReturnsCreditAfterRead(t *testing.T) {
	config := Config{InitialWindow: 8, WindowUpdateThreshold: 4, MaxDataPayload: 4}
	left, right := newFlowMuxPair(t, config, config)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	accepted := acceptOne(t, ctx, right)
	client, err := left.Open(ctx, ServiceFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted

	payload := []byte("0123456789abcdef")
	writeResult := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := client.Write(payload)
		writeResult <- struct {
			n   int
			err error
		}{n: n, err: err}
	}()

	waitForBuffered(t, server, 8)
	select {
	case result := <-writeResult:
		t.Fatalf("write completed before credit was returned: %+v", result)
	default:
	}

	first := make([]byte, 4)
	if _, err := io.ReadFull(server, first); err != nil {
		t.Fatal(err)
	}
	if string(first) != "0123" {
		t.Fatalf("first=%q", first)
	}

	rest := make([]byte, len(payload)-len(first))
	if _, err := io.ReadFull(server, rest); err != nil {
		t.Fatal(err)
	}
	if string(append(first, rest...)) != string(payload) {
		t.Fatalf("received=%q", append(first, rest...))
	}
	select {
	case result := <-writeResult:
		if result.err != nil || result.n != len(payload) {
			t.Fatalf("write result=%+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("write did not resume after WINDOW credit")
	}
}

func TestDirectionalWindowsMayDiffer(t *testing.T) {
	left, right := newFlowMuxPair(t,
		Config{InitialWindow: 4, MaxDataPayload: 4},
		Config{InitialWindow: 12, MaxDataPayload: 4},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	accepted := acceptOne(t, ctx, right)
	client, err := left.Open(ctx, ServiceFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted

	payload := []byte("abcdefghijkl")
	if n, err := client.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	waitForBuffered(t, server, len(payload))
	data := make([]byte, len(payload))
	if _, err := io.ReadFull(server, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != string(payload) {
		t.Fatalf("data=%q", data)
	}
}

func TestDataBeyondGrantedWindowResetsOnlyOffendingStream(t *testing.T) {
	config := Config{InitialWindow: 8, WindowUpdateThreshold: 4, MaxDataPayload: 8}
	left, right := newFlowMuxPair(t, config, config)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	firstAccepted := acceptOne(t, ctx, right)
	client, err := left.Open(ctx, ServiceFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := <-firstAccepted

	// Bypass Stream.Write to simulate a malicious peer exceeding its eight-byte
	// grant in one DATA frame.
	if err := left.send(Frame{Type: FrameData, StreamID: client.ID(), Service: ServiceFS, Payload: make([]byte, 9)}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Read(make([]byte, 1)); !errors.Is(err, ErrFlowControlViolation) {
		t.Fatalf("server read=%v, want ErrFlowControlViolation", err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, ErrStreamReset) {
		t.Fatalf("client read=%v, want ErrStreamReset", err)
	}

	secondAccepted := acceptOne(t, ctx, right)
	second, err := left.Open(ctx, ServiceEvents, nil)
	if err != nil {
		t.Fatalf("session did not survive flow violation: %v", err)
	}
	peerSecond := <-secondAccepted
	if _, err := second.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 2)
	if _, err := io.ReadFull(peerSecond, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "ok" {
		t.Fatalf("data=%q", data)
	}
}

func TestCloseWakesWriterBlockedOnCredit(t *testing.T) {
	config := Config{InitialWindow: 4, WindowUpdateThreshold: 2, MaxDataPayload: 4}
	left, right := newFlowMuxPair(t, config, config)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	accepted := acceptOne(t, ctx, right)
	client, err := left.Open(ctx, ServiceFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted

	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("eightbyt"))
		writeDone <- err
	}()
	waitForBuffered(t, server, 4)

	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close() }()
	select {
	case err := <-writeDone:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("blocked write error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked writer did not wake on Close")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close remained blocked behind writer")
	}
}

func TestIncomingBacklogRejectsExcessWithoutBlockingReader(t *testing.T) {
	config := Config{InitialWindow: 16, MaxDataPayload: 8}
	left, right := newFlowMuxPair(t, config, Config{InitialWindow: 16, MaxDataPayload: 8, IncomingBacklog: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	first, err := left.Open(ctx, ServiceFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := left.Open(ctx, ServiceFS, nil); !errors.Is(err, ErrStreamReset) {
		t.Fatalf("second Open=%v, want ErrStreamReset", err)
	}

	peerFirst, err := right.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer peerFirst.Close()
	thirdAccepted := acceptOne(t, ctx, right)
	third, err := left.Open(ctx, ServiceEvents, nil)
	if err != nil {
		t.Fatalf("reader remained blocked after backlog rejection: %v", err)
	}
	defer third.Close()
	if <-thirdAccepted == nil {
		t.Fatal("third stream was not accepted")
	}
}

func TestExcessWindowCreditResetsStream(t *testing.T) {
	config := Config{InitialWindow: 8, MaxDataPayload: 8}
	left, right := newFlowMuxPair(t, config, config)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	accepted := acceptOne(t, ctx, right)
	client, err := left.Open(ctx, ServiceFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted

	payload, _ := encodeWindowCredit(1)
	// The normal initial WINDOW already grants eight bytes. One extra byte must
	// reset this stream rather than creating unbounded sender credit.
	if err := right.send(Frame{Type: FrameWindow, StreamID: client.ID(), Service: ServiceFS, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, ErrFlowControlViolation) {
		t.Fatalf("client read=%v, want ErrFlowControlViolation", err)
	}
	if _, err := server.Read(make([]byte, 1)); !errors.Is(err, ErrStreamReset) {
		t.Fatalf("server read=%v, want ErrStreamReset", err)
	}
}
