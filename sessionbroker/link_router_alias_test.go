package sessionbroker

import (
	"context"
	"io"
	"testing"
	"time"

	"weaverssh/sessionlink"
)

func TestLinkRouterCopiesTopologyDescriptor(t *testing.T) {
	descriptor := linkRouterDescriptor()
	router, err := NewLinkRouter(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Topology[0] = "mutated"
	descriptor.Topology[1] = "elsewhere"

	transportID, _ := sessionlink.NewTransportID()
	if _, _, _, err := router.Publish(transportID, time.Minute, pipeOpen("stable")); err != nil {
		t.Fatal(err)
	}
	stream, err := router.TryOpen(context.Background(), OpenRequest{})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	if string(payload) != "stable" {
		t.Fatalf("payload=%q", payload)
	}
}
