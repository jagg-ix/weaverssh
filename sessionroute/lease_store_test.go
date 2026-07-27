package sessionroute

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionlink"
)

func leaseTestContext(now time.Time) authproof.NodeContext {
	nodes := []string{"origin", "jump", "endpoint"}
	return authproof.NodeContext{
		IssuerPeerID:  "authority",
		Audience:      authproof.AudienceNodeContext,
		ChainID:       "chain",
		ChainSHA256:   authproof.ChainBindingSHA256(nodes...),
		Nodes:         nodes,
		CurrentNode:   "jump",
		OriginNode:    "origin",
		EndpointNode:  "endpoint",
		Capabilities:  []string{authproof.CapabilityNodeContext},
		Nonce:         "lease-test-nonce",
		IssuedAtUnix:  now.Add(-time.Minute).Unix(),
		ExpiresAtUnix: now.Add(time.Hour).Unix(),
	}
}

func TestLeaseStoreGenerationFencingAndExpiry(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	store := LeaseStore{Path: filepath.Join(t.TempDir(), "leases.json"), Now: func() time.Time { return now }}
	ctx := leaseTestContext(now)
	linkID, err := sessionlink.DeriveID(sessionlink.Descriptor{
		ChainSHA256: ctx.ChainSHA256, Topology: ctx.Nodes, LocalNode: "jump", PeerNode: "endpoint",
	})
	if err != nil {
		t.Fatal(err)
	}
	entry := func(generation uint64, transport, binding string) LeaseEntry {
		value, err := NewLeaseEntry(ctx, binding, "/tmp/broker.sock", "endpoint", 100,
			now, sessionlink.Token{LinkID: linkID, TransportID: sessionlink.TransportID(transport), Generation: generation}, now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}

	first := entry(1, "transport-one", "binding-one")
	second := entry(2, "transport-two", "binding-two")
	if err := store.Register(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := store.Register(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if err := store.Register(context.Background(), first); !errors.Is(err, sessionlink.ErrGenerationMismatch) {
		t.Fatalf("stale register error=%v", err)
	}
	if err := store.Remove(context.Background(), first.Token()); err != nil {
		t.Fatal(err)
	}
	resolved, _, _, err := store.ResolveAdjacent("", ctx, "endpoint")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Generation != 2 || resolved.TransportID != second.TransportID {
		t.Fatalf("resolved generation=%d transport=%s", resolved.Generation, resolved.TransportID)
	}

	now = now.Add(2 * time.Minute)
	snapshot, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entries) != 0 {
		t.Fatalf("expired entries=%d want=0", len(snapshot.Entries))
	}
}

func TestLeaseStoreResetLinkAllowsProcessGenerationRestart(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	store := LeaseStore{Path: filepath.Join(t.TempDir(), "leases.json"), Now: func() time.Time { return now }}
	ctx := leaseTestContext(now)
	linkID, err := sessionlink.DeriveID(sessionlink.Descriptor{
		ChainSHA256: ctx.ChainSHA256, Topology: ctx.Nodes, LocalNode: "jump", PeerNode: "endpoint",
	})
	if err != nil {
		t.Fatal(err)
	}
	old, err := NewLeaseEntry(ctx, "old-binding", "/tmp/broker.sock", "endpoint", 100, now,
		sessionlink.Token{LinkID: linkID, TransportID: "old-transport", Generation: 9}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Register(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := store.ResetLink(context.Background(), linkID); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewLeaseEntry(ctx, "new-binding", "/tmp/broker.sock", "endpoint", 101, now,
		sessionlink.Token{LinkID: linkID, TransportID: "new-transport", Generation: 1}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Register(context.Background(), fresh); err != nil {
		t.Fatalf("register fresh generation after reset: %v", err)
	}
}
