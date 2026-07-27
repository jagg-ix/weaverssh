package sessionevents

import (
	"context"
	"net"
	"testing"
	"time"
)

const testChain = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func testPolicy(t *testing.T) Policy {
	t.Helper()
	raw := []byte(`{"version":"weaverssh.events-policy.v1","default":"deny","rules":[{"id":"origin-events","action":"allow","sources":["origin"],"operations":["publish","subscribe"],"topics":["weaverssh/#"]}]}`)
	policy, err := ParsePolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func boundMetadata(t *testing.T) []byte {
	t.Helper()
	raw, err := NewOpenMetadata("target")
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindSource(raw, "origin", "binding-1", testChain, "target")
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

func TestPublishSubscribeRoundTrip(t *testing.T) {
	engine, err := NewEngine(EngineConfig{Topology: []string{"origin", "target"}, ChainSHA256: testChain, CurrentNode: "target", Policy: testPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	subServer, subClient := net.Pipe()
	go func() { _ = engine.Serve(ctx, subServer, boundMetadata(t)) }()
	got := make(chan Response, 1)
	subErr := make(chan error, 1)
	go func() {
		subErr <- SubscribeStream(ctx, subClient, "weaverssh/runtime/#", 1, 4, func(response Response) error { got <- response; return nil })
	}()
	time.Sleep(20 * time.Millisecond)

	pubServer, pubClient := net.Pipe()
	go func() { _ = engine.Serve(ctx, pubServer, boundMetadata(t)) }()
	if _, err := PublishStream(ctx, pubClient, "weaverssh/runtime/status", []byte("ready")); err != nil {
		t.Fatal(err)
	}

	select {
	case response := <-got:
		if response.Topic != "weaverssh/runtime/status" || string(response.Payload) != "ready" {
			t.Fatalf("unexpected response: %+v", response)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := <-subErr; err != nil {
		t.Fatal(err)
	}
}

func TestDenyUnknownSource(t *testing.T) {
	engine, err := NewEngine(EngineConfig{Topology: []string{"origin", "other", "target"}, ChainSHA256: testChain, CurrentNode: "target", Policy: testPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := NewOpenMetadata("target")
	bound, _ := BindSource(raw, "other", "binding-2", testChain, "target")
	server, client := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _ = engine.Serve(ctx, server, bound) }()
	if _, err := PublishStream(ctx, client, "weaverssh/runtime/status", []byte("bad")); err == nil {
		t.Fatal("unauthorized source was accepted")
	}
}

func TestSubscribeFilterCannotBroadenPolicy(t *testing.T) {
	policy, err := ParsePolicy([]byte(`{"version":"weaverssh.events-policy.v1","default":"deny","rules":[{"id":"narrow","action":"allow","sources":["origin"],"operations":["subscribe"],"topics":["weaverssh/runtime/#"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := NewEngine(EngineConfig{Topology: []string{"origin", "target"}, ChainSHA256: testChain, CurrentNode: "target", Policy: policy})
	metadata, _ := ParseOpenMetadata(boundMetadata(t))
	if err := engine.authorize(metadata, normalizeRequest(Request{Operation: OperationSubscribe, Topic: "weaverssh/#"})); err == nil {
		t.Fatal("broader subscription was accepted")
	}
}
