package sessionmux

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestCodecRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	want := Frame{
		Type:     FrameOpen,
		Flags:    7,
		StreamID: 11,
		Service:  ServiceFS,
		Payload:  []byte(`{"node":"endpoint"}`),
	}
	codec := Codec{MaxPayload: 1024}
	if err := codec.WriteFrame(&wire, want); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := codec.ReadFrame(&wire)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Type != want.Type || got.Flags != want.Flags || got.StreamID != want.StreamID || got.Service != want.Service || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}
}

func TestLogicalStreamOverNetPipe(t *testing.T) {
	leftConn, rightConn := net.Pipe()
	left, err := New(leftConn, Config{Role: RoleInitiator})
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	right, err := New(rightConn, Config{Role: RoleResponder})
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	accepted := make(chan *Stream, 1)
	go func() {
		stream, acceptErr := right.Accept(ctx)
		if acceptErr != nil {
			t.Errorf("Accept: %v", acceptErr)
			return
		}
		accepted <- stream
	}()

	client, err := left.Open(ctx, ServiceFS, []byte("endpoint"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	server := <-accepted
	if server.Service() != ServiceFS || string(server.Metadata()) != "endpoint" {
		t.Fatalf("accepted stream service=%s metadata=%q", server.Service(), server.Metadata())
	}

	if _, err := client.Write([]byte("9p-request")); err != nil {
		t.Fatalf("client Write: %v", err)
	}
	request := make([]byte, len("9p-request"))
	if _, err := io.ReadFull(server, request); err != nil {
		t.Fatalf("server Read: %v", err)
	}
	if string(request) != "9p-request" {
		t.Fatalf("request=%q", request)
	}

	if _, err := server.Write([]byte("9p-reply")); err != nil {
		t.Fatalf("server Write: %v", err)
	}
	reply := make([]byte, len("9p-reply"))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("client Read: %v", err)
	}
	if string(reply) != "9p-reply" {
		t.Fatalf("reply=%q", reply)
	}
}

func TestClosingStreamKeepsSessionAlive(t *testing.T) {
	leftConn, rightConn := net.Pipe()
	left, _ := New(leftConn, Config{Role: RoleInitiator})
	defer left.Close()
	right, _ := New(rightConn, Config{Role: RoleResponder})
	defer right.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	firstAccepted := make(chan *Stream, 1)
	go func() {
		stream, _ := right.Accept(ctx)
		firstAccepted <- stream
	}()
	first, err := left.Open(ctx, ServiceFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	peerFirst := <-firstAccepted
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := peerFirst.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("peer read after close = %v, want EOF", err)
	}
	_ = peerFirst.Close()

	secondAccepted := make(chan *Stream, 1)
	go func() {
		stream, _ := right.Accept(ctx)
		secondAccepted <- stream
	}()
	second, err := left.Open(ctx, ServiceEvents, nil)
	if err != nil {
		t.Fatalf("second Open after first close: %v", err)
	}
	peerSecond := <-secondAccepted
	if _, err := second.Write([]byte("still-alive")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, len("still-alive"))
	if _, err := io.ReadFull(peerSecond, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "still-alive" {
		t.Fatalf("data=%q", data)
	}
}

func TestUnsupportedServiceFailsClosed(t *testing.T) {
	leftConn, rightConn := net.Pipe()
	left, _ := New(leftConn, Config{Role: RoleInitiator})
	defer left.Close()
	right, _ := New(rightConn, Config{
		Role: RoleResponder,
		AllowedServices: map[ServiceID]bool{
			ServiceControl: true,
		},
	})
	defer right.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := left.Open(ctx, ServiceFS, nil)
	if !errors.Is(err, ErrStreamReset) {
		t.Fatalf("Open error=%v, want ErrStreamReset", err)
	}
}

func TestRolesAllocateDisjointStreamIDs(t *testing.T) {
	leftConn, rightConn := net.Pipe()
	left, _ := New(leftConn, Config{Role: RoleInitiator})
	defer left.Close()
	right, _ := New(rightConn, Config{Role: RoleResponder})
	defer right.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	leftAccepted := make(chan *Stream, 1)
	rightAccepted := make(chan *Stream, 1)
	go func() { stream, _ := left.Accept(ctx); leftAccepted <- stream }()
	go func() { stream, _ := right.Accept(ctx); rightAccepted <- stream }()

	var fromLeft, fromRight *Stream
	var leftErr, rightErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); fromLeft, leftErr = left.Open(ctx, ServiceFS, nil) }()
	go func() { defer wg.Done(); fromRight, rightErr = right.Open(ctx, ServiceEvents, nil) }()
	wg.Wait()
	if leftErr != nil || rightErr != nil {
		t.Fatalf("simultaneous Open errors: left=%v right=%v", leftErr, rightErr)
	}
	if fromLeft.ID()%2 != 1 || fromRight.ID()%2 != 0 {
		t.Fatalf("stream parity: initiator=%d responder=%d", fromLeft.ID(), fromRight.ID())
	}
	if (<-leftAccepted).ID() != fromRight.ID() || (<-rightAccepted).ID() != fromLeft.ID() {
		t.Fatal("accepted stream IDs do not match peer-opened streams")
	}
}

func TestSimultaneousOpenDoesNotDeadlock(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		leftConn, rightConn := net.Pipe()
		left, _ := New(leftConn, Config{Role: RoleInitiator})
		right, _ := New(rightConn, Config{Role: RoleResponder})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)

		leftAccepted := make(chan *Stream, 1)
		rightAccepted := make(chan *Stream, 1)
		go func() { stream, _ := left.Accept(ctx); leftAccepted <- stream }()
		go func() { stream, _ := right.Accept(ctx); rightAccepted <- stream }()

		errs := make(chan error, 2)
		go func() { _, err := left.Open(ctx, ServiceFS, nil); errs <- err }()
		go func() { _, err := right.Open(ctx, ServiceEvents, nil); errs <- err }()
		for i := 0; i < 2; i++ {
			if err := <-errs; err != nil {
				t.Fatalf("iteration %d simultaneous open: %v", iteration, err)
			}
		}
		if <-leftAccepted == nil || <-rightAccepted == nil {
			t.Fatalf("iteration %d missing accepted stream", iteration)
		}
		cancel()
		_ = left.Close()
		_ = right.Close()
	}
}

func TestMismatchedDataServiceResetsStream(t *testing.T) {
	leftConn, rightConn := net.Pipe()
	left, _ := New(leftConn, Config{Role: RoleInitiator})
	defer left.Close()
	right, _ := New(rightConn, Config{Role: RoleResponder})
	defer right.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	accepted := make(chan *Stream, 1)
	go func() { stream, _ := right.Accept(ctx); accepted <- stream }()
	client, err := left.Open(ctx, ServiceFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted

	if err := left.send(Frame{Type: FrameData, StreamID: client.ID(), Service: ServiceTCP, Payload: []byte("wrong service")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, ErrStreamReset) {
		t.Fatalf("client read after mismatched DATA = %v, want ErrStreamReset", err)
	}
	_ = server.Close()
}
