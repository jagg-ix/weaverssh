package sessionmux

import (
	"context"
	"net"
	"testing"
	"time"

	"weaverssh/flowcontrol"
)

func TestBufferSyncedMuxGrowsAndRejectsActiveShrink(t *testing.T) {
	coordinator := flowcontrol.NewDefaultBufferCoordinator()
	leftConn, rightConn := net.Pipe()
	left, err := NewBufferSynced(leftConn, Config{Role: RoleInitiator}, coordinator)
	if err != nil { t.Fatal(err) }
	defer left.Close()
	right, err := NewBufferSynced(rightConn, Config{Role: RoleResponder}, coordinator)
	if err != nil { t.Fatal(err) }
	defer right.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	accepted := make(chan *Stream, 1)
	acceptErr := make(chan error, 1)
	go func() {
		stream, err := right.Accept(ctx)
		if err != nil { acceptErr <- err; return }
		accepted <- stream
	}()
	leftStream, err := left.Open(ctx, ServiceTCP, nil)
	if err != nil { t.Fatal(err) }
	var rightStream *Stream
	select {
	case rightStream = <-accepted:
	case err := <-acceptErr: t.Fatal(err)
	case <-ctx.Done(): t.Fatal(ctx.Err())
	}
	defer leftStream.Close()
	defer rightStream.Close()

	before := coordinator.Current()
	grown := flowcontrol.ProtocolBuffersFromFrame(before.Buffers.FrameBytes*2, before.Buffers.QueueDepth)
	after, err := coordinator.Update(grown)
	if err != nil { t.Fatal(err) }
	if left.maxDataPayload != uint32(after.Buffers.SSHChannelFrameBytes) || right.maxDataPayload != uint32(after.Buffers.SSHChannelFrameBytes) {
		t.Fatalf("SSH frame limits not synchronized: left=%d right=%d want=%d", left.maxDataPayload, right.maxDataPayload, after.Buffers.SSHChannelFrameBytes)
	}
	if left.initialWindow != uint32(after.Buffers.SSHChannelWindowBytes) || right.initialWindow != uint32(after.Buffers.SSHChannelWindowBytes) {
		t.Fatalf("SSH windows not synchronized: left=%d right=%d want=%d", left.initialWindow, right.initialWindow, after.Buffers.SSHChannelWindowBytes)
	}

	if _, err := coordinator.Update(before.Buffers); err == nil {
		t.Fatal("expected active SSH streams to reject shrinking update")
	}
	if coordinator.Current() != after { t.Fatal("coordinator changed after rejected SSH shrink") }
}
