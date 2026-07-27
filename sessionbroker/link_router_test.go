package sessionbroker

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"weaverssh/sessionlink"
)

func linkRouterDescriptor() sessionlink.Descriptor {
	return sessionlink.Descriptor{
		ChainSHA256: strings.Repeat("b", 64),
		Topology:    []string{"node-a", "node-b"},
		LocalNode:   "node-a",
		PeerNode:    "node-b",
	}
}

func pipeOpen(label string) OpenFunc {
	return func(context.Context, OpenRequest) (io.ReadWriteCloser, error) {
		left, right := net.Pipe()
		go func() {
			_, _ = right.Write([]byte(label))
			_ = right.Close()
		}()
		return left, nil
	}
}

func TestLinkRouterFencesOldCleanup(t *testing.T) {
	router, err := NewLinkRouter(linkRouterDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	firstID, _ := sessionlink.NewTransportID()
	_, _, cleanupFirst, err := router.Publish(firstID, time.Minute, pipeOpen("first"))
	if err != nil {
		t.Fatal(err)
	}
	secondID, _ := sessionlink.NewTransportID()
	_, _, cleanupSecond, err := router.Publish(secondID, time.Minute, pipeOpen("second"))
	if err != nil {
		t.Fatal(err)
	}
	cleanupFirst()
	stream, err := router.TryOpen(context.Background(), OpenRequest{})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	if string(payload) != "second" {
		t.Fatalf("payload=%q", payload)
	}
	cleanupSecond()
	if _, err := router.TryOpen(context.Background(), OpenRequest{}); err != ErrNoActiveSession {
		t.Fatalf("err=%v", err)
	}
}

func TestLinkRouterWaitsForReplacement(t *testing.T) {
	router, err := NewLinkRouter(linkRouterDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan string, 1)
	go func() {
		stream, openErr := router.Open(ctx, OpenRequest{})
		if openErr != nil {
			result <- openErr.Error()
			return
		}
		payload, _ := io.ReadAll(stream)
		_ = stream.Close()
		result <- string(payload)
	}()
	time.Sleep(20 * time.Millisecond)
	transportID, _ := sessionlink.NewTransportID()
	if _, _, _, err := router.Publish(transportID, time.Minute, pipeOpen("replacement")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got != "replacement" {
			t.Fatal(got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out")
	}
}

func TestLinkRouterDrainingRejectsNewOpen(t *testing.T) {
	router, err := NewLinkRouter(linkRouterDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	transportID, _ := sessionlink.NewTransportID()
	token, _, _, err := router.Publish(transportID, time.Minute, pipeOpen("ready"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := router.Drain(token); err != nil {
		t.Fatal(err)
	}
	if _, err := router.TryOpen(context.Background(), OpenRequest{}); err != ErrNoActiveSession {
		t.Fatalf("err=%v", err)
	}
}
