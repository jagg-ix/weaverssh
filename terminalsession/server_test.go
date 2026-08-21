package terminalsession

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func TestServerNegotiatesInputResizeAndDetach(t *testing.T) {
	terminal := newFakeTerminal()
	manager, err := NewManager(context.Background(), ManagerConfig{Authorizer: testAuthorizer(), Spawner: fakeSpawner{terminal: terminal}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	server := &Server{Manager: manager}
	serverSide, clientSide := net.Pipe()
	result := make(chan error, 1)
	go func() { result <- server.Serve(context.Background(), serverSide, testIdentity()) }()

	requestPayload, err := json.Marshal(testRequest())
	if err != nil {
		t.Fatal(err)
	}
	codec := Codec{}
	if err := codec.WriteFrame(clientSide, Frame{Type: FrameOpen, Payload: requestPayload}); err != nil {
		t.Fatal(err)
	}
	readyFrame, err := codec.ReadFrame(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if readyFrame.Type != FrameReady {
		t.Fatalf("frame type=%d want READY", readyFrame.Type)
	}
	if err := codec.WriteFrame(clientSide, Frame{Type: FrameInput, Payload: []byte("ls\r")}); err != nil {
		t.Fatal(err)
	}
	if err := codec.WriteFrame(clientSide, Frame{Type: FrameResize, Payload: encodeSize(TerminalSize{Rows: 50, Cols: 160})}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		terminal.inputMu.Lock()
		defer terminal.inputMu.Unlock()
		return terminal.input.String() == "ls\r"
	})
	waitFor(t, func() bool {
		terminal.resizeMu.Lock()
		defer terminal.resizeMu.Unlock()
		return len(terminal.resize) == 1 && terminal.resize[0] == (TerminalSize{Rows: 50, Cols: 160})
	})
	if err := codec.WriteFrame(clientSide, Frame{Type: FrameDetach}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestBoundMetadataPreservesOriginAcrossForwarders(t *testing.T) {
	raw, err := NewOpenMetadata("jump-a")
	if err != nil {
		t.Fatal(err)
	}
	chain := strings.Repeat("b", 64)
	first, err := BindSource(raw, "laptop", "binding-a", chain, "jump-a")
	if err != nil {
		t.Fatal(err)
	}
	forwarded, err := BindSource(first, "jump-a", "binding-b", chain, "worker-b")
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := ParseOpenMetadata(forwarded)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.SourceNode != "laptop" || metadata.SourceBinding != "binding-a" || metadata.TargetNode != "worker-b" {
		t.Fatalf("forwarded metadata=%+v", metadata)
	}
}
