package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"weaverssh/sessionbroker"
	"weaverssh/sessionlink"
)

func TestAttachSupervisorPublishesReplacementGeneration(t *testing.T) {
	descriptor := sessionlink.Descriptor{
		ChainSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Topology:    []string{"origin", "node"},
		LocalNode:   "node",
		PeerNode:    "origin",
	}
	router, err := sessionbroker.NewLinkRouter(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	linkID := router.LinkID()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var generations []uint64
	attempt := 0
	supervisor, err := NewAttachSupervisor(AttachSupervisorConfig{
		Router:    router,
		Lease:     time.Minute,
		Reconnect: true,
		Policy:    ReconnectPolicy{MinDelay: time.Millisecond, MaxDelay: time.Millisecond},
		AttachFunc: func(context.Context, AttachConfig) (*AttachedSession, error) {
			attempt++
			transport := sessionlink.TransportID("transport-generation-one")
			if attempt == 2 {
				transport = sessionlink.TransportID("transport-generation-two")
			}
			done := make(chan error, 1)
			if attempt == 1 {
				done <- errors.New("first transport lost")
			}
			return &AttachedSession{LinkID: linkID, TransportID: transport, serviceDone: done}, nil
		},
		OnReady: func(generation AttachGeneration) (func(error), error) {
			mu.Lock()
			generations = append(generations, generation.Token.Generation)
			count := len(generations)
			mu.Unlock()
			if count == 2 {
				cancel()
			}
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(generations) != 2 || generations[0] != 1 || generations[1] != 2 {
		t.Fatalf("generations=%v want=[1 2]", generations)
	}
}
