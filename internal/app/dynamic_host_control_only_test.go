package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"weaverssh/authproof"
)

func TestDynamicHostControlOnlyRequiresExplicitMode(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nodes := []string{"workstation-42", "jump-a", "compute-node"}
	now := time.Now()
	signed, err := authproof.SignNodeContext(authproof.NodeContext{
		IssuerPeerID:  "control-only-test",
		Audience:      authproof.AudienceNodeContext,
		ChainID:       "control-only-chain",
		ChainSHA256:   authproof.ChainBindingSHA256(nodes...),
		Nodes:         nodes,
		CurrentNode:   "jump-a",
		OriginNode:    "workstation-42",
		EndpointNode:  "compute-node",
		Capabilities:  []string{authproof.CapabilityNodeContext},
		Nonce:         "control-only-jump-a",
		IssuedAtUnix:  now.Add(-time.Second).Unix(),
		ExpiresAtUnix: now.Add(5 * time.Minute).Unix(),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDynamicHost(DynamicHostConfig{SignedContext: signed, PublicKey: publicKey}); err == nil {
		t.Fatal("empty ordinary host unexpectedly accepted")
	}
	host, err := NewDynamicHost(DynamicHostConfig{
		SignedContext: signed,
		PublicKey:     publicKey,
		ControlOnly:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !host.local.Empty() || len(host.local.Services()) != 0 {
		t.Fatalf("control-only services=%v", host.local.Services())
	}
}

func TestDynamicHostControlOnlyRejectsAdvertisedService(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	nodes := []string{"a", "b"}
	now := time.Now()
	signed, err := authproof.SignNodeContext(authproof.NodeContext{
		IssuerPeerID:  "control-only-conflict",
		Audience:      authproof.AudienceNodeContext,
		ChainID:       "control-only-conflict-chain",
		ChainSHA256:   authproof.ChainBindingSHA256(nodes...),
		Nodes:         nodes,
		CurrentNode:   "a",
		OriginNode:    "a",
		EndpointNode:  "b",
		Capabilities:  []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh},
		Nonce:         "control-only-conflict-a",
		IssuedAtUnix:  now.Add(-time.Second).Unix(),
		ExpiresAtUnix: now.Add(5 * time.Minute).Unix(),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDynamicHost(DynamicHostConfig{
		Root:          t.TempDir(),
		SignedContext: signed,
		PublicKey:     publicKey,
		ControlOnly:   true,
	}); err == nil {
		t.Fatal("control-only host unexpectedly accepted fs service")
	}
}
