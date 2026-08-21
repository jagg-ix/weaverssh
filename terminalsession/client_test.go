package terminalsession

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

func TestClientNegotiatesAndReadsOutputAndExit(t *testing.T) {
	clientStream, serverStream := net.Pipe()
	defer serverStream.Close()
	codec := Codec{}
	serverDone := make(chan error, 1)
	go func() {
		frame, err := codec.ReadFrame(serverStream)
		if err != nil {
			serverDone <- err
			return
		}
		if frame.Type != FrameOpen {
			serverDone <- ErrInvalidRequest
			return
		}
		readyPayload, _ := json.Marshal(Ready{Protocol: ProtocolVersion, SessionID: "session-a", ResumeToken: "resume", Generation: 1, State: StateActive, ReplayFloor: 1})
		if err := codec.WriteFrame(serverStream, Frame{Type: FrameReady, Payload: readyPayload}); err != nil {
			serverDone <- err
			return
		}
		if err := codec.WriteFrame(serverStream, Frame{Type: FrameOutput, Sequence: 1, Payload: []byte("hello")}); err != nil {
			serverDone <- err
			return
		}
		exitPayload, _ := json.Marshal(Exit{Protocol: ProtocolVersion, ExitCode: 7, Reason: "process-exited"})
		serverDone <- codec.WriteFrame(serverStream, Frame{Type: FrameExit, Payload: exitPayload})
	}()

	client, err := NewClient(clientStream, codec)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ready, err := client.Negotiate(ctx, testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if ready.SessionID != "session-a" || ready.ResumeToken != "resume" {
		t.Fatalf("ready=%+v", ready)
	}
	output, err := client.ReadEvent()
	if err != nil || output.Type != FrameOutput || string(output.Payload) != "hello" {
		t.Fatalf("output=%+v error=%v", output, err)
	}
	exitFrame, err := client.ReadEvent()
	if err != nil {
		t.Fatal(err)
	}
	exit, err := DecodeExit(exitFrame.Payload)
	if err != nil || exit.ExitCode != 7 || exit.Reason != "process-exited" {
		t.Fatalf("exit=%+v error=%v", exit, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestClientNegotiationTimeoutClosesBlockedStream(t *testing.T) {
	clientStream, serverStream := net.Pipe()
	defer serverStream.Close()
	client, err := NewClient(clientStream, Codec{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := client.Negotiate(ctx, testRequest()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v want deadline exceeded", err)
	}
}
