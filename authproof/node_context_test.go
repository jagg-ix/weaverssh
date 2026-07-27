package authproof

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestSignedNodeContextVerifiesChainAndNode(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Unix(1781234500, 0)
	nodes := []string{"origin", "node1", "node2"}
	ctx := NodeContext{
		IssuerPeerID:  "origin-peer",
		ChainID:       "prod-chain",
		ChainSHA256:   ChainBindingSHA256(nodes...),
		Nodes:         nodes,
		CurrentNode:   "node1",
		Capabilities:  []string{CapabilityNodeContext, CapabilityVFSMesh},
		Nonce:         "nonce-node-context",
		IssuedAtUnix:  now.Unix(),
		ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}
	signed, err := SignNodeContext(ctx, privateKey)
	if err != nil {
		t.Fatalf("SignNodeContext: %v", err)
	}
	verified, err := VerifySignedNodeContext(signed, publicKey, NodeContextVerifyOptions{
		Now:         now.Add(time.Second),
		Audience:    AudienceNodeContext,
		ChainID:     "prod-chain",
		ChainSHA256: ChainBindingSHA256(nodes...),
		CurrentNode: "node1",
		MaxTTL:      time.Minute,
	})
	if err != nil {
		t.Fatalf("VerifySignedNodeContext: %v", err)
	}
	if verified.OriginNode != "origin" || verified.EndpointNode != "node2" || verified.CurrentNode != "node1" {
		t.Fatalf("verified node context wrong: %+v", verified)
	}
}

func TestSignedNodeContextRejectsWrongChainAndExpired(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Unix(1781234500, 0)
	nodes := []string{"origin", "node1"}
	ctx := NodeContext{
		IssuerPeerID:  "origin-peer",
		ChainID:       "prod-chain",
		ChainSHA256:   ChainBindingSHA256(nodes...),
		Nodes:         nodes,
		CurrentNode:   "node1",
		Nonce:         "nonce-node-context",
		IssuedAtUnix:  now.Unix(),
		ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}
	signed, err := SignNodeContext(ctx, privateKey)
	if err != nil {
		t.Fatalf("SignNodeContext: %v", err)
	}
	_, err = VerifySignedNodeContext(signed, publicKey, NodeContextVerifyOptions{Now: now.Add(time.Second), ChainSHA256: ChainBindingSHA256("other")})
	if !errors.Is(err, ErrWrongChainHash) {
		t.Fatalf("expected ErrWrongChainHash, got %v", err)
	}
	_, err = VerifySignedNodeContext(signed, publicKey, NodeContextVerifyOptions{Now: now.Add(2 * time.Minute)})
	if !errors.Is(err, ErrExpiredGrant) {
		t.Fatalf("expected ErrExpiredGrant, got %v", err)
	}
}
