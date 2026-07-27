package sessionmux

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"
)

func TestCodecRejectsFixedShapePayloadBeforeReadingBody(t *testing.T) {
	header := make([]byte, headerSize)
	copy(header[:4], frameMagic[:])
	header[4] = protocolVersion
	header[5] = byte(FrameWindow)
	binary.BigEndian.PutUint32(header[8:12], 1)
	binary.BigEndian.PutUint16(header[12:14], uint16(ServiceFS))
	binary.BigEndian.PutUint32(header[16:20], 1<<20)

	// Only the header is supplied. A decoder that tries to allocate/read the body
	// would return EOF instead of the fixed-shape protocol error.
	_, err := (Codec{}).ReadFrame(bytes.NewReader(header))
	if !errors.Is(err, ErrFlowControlViolation) {
		t.Fatalf("ReadFrame error=%v, want ErrFlowControlViolation", err)
	}
}

func TestCodecRejectsPayloadOnPayloadlessControlFrame(t *testing.T) {
	var wire bytes.Buffer
	err := (Codec{}).WriteFrame(&wire, Frame{
		Type:     FrameClose,
		StreamID: 1,
		Service:  ServiceFS,
		Payload:  []byte{1},
	})
	if err == nil {
		t.Fatal("CLOSE with payload was accepted")
	}
}

func TestOversizedDataFrameResetsOnlyOffendingStream(t *testing.T) {
	config := Config{InitialWindow: 16, WindowUpdateThreshold: 8, MaxDataPayload: 4}
	left, right := newFlowMuxPair(t, config, config)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	firstAccepted := acceptOne(t, ctx, right)
	client, err := left.Open(ctx, ServiceFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := <-firstAccepted

	// The payload fits the receive window but exceeds the configured DATA-frame
	// ceiling. Bypass Stream.Write to simulate a nonconforming peer.
	if err := left.send(Frame{
		Type:     FrameData,
		StreamID: client.ID(),
		Service:  ServiceFS,
		Payload:  []byte("12345"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Read(make([]byte, 1)); !errors.Is(err, ErrFlowControlViolation) {
		t.Fatalf("server Read error=%v, want ErrFlowControlViolation", err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, ErrStreamReset) {
		t.Fatalf("client Read error=%v, want ErrStreamReset", err)
	}

	secondAccepted := acceptOne(t, ctx, right)
	second, err := left.Open(ctx, ServiceEvents, nil)
	if err != nil {
		t.Fatalf("session did not survive oversized DATA: %v", err)
	}
	peerSecond := <-secondAccepted
	if _, err := second.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(peerSecond, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "ok" {
		t.Fatalf("got=%q", got)
	}
}
