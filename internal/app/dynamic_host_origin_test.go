package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"weaverssh/authproof"
)

func TestDynamicHostAllowsSignedIntermediateIdentity(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	nodes := []string{"workstation-42", "jump-a", "compute-node"}
	signed, err := authproof.SignNodeContext(authproof.NodeContext{
		IssuerPeerID:  "recursive-host-test",
		Audience:      authproof.AudienceNodeContext,
		ChainID:       "recursive-host-chain",
		ChainSHA256:   authproof.ChainBindingSHA256(nodes...),
		Nodes:         nodes,
		CurrentNode:   "jump-a",
		OriginNode:    "workstation-42",
		EndpointNode:  "compute-node",
		Capabilities:  []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh},
		Nonce:         "recursive-host-jump-a",
		IssuedAtUnix:  now.Add(-time.Second).Unix(),
		ExpiresAtUnix: now.Add(5 * time.Minute).Unix(),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	host, err := NewDynamicHost(DynamicHostConfig{
		Root:          t.TempDir(),
		SignedContext: signed,
		PublicKey:     publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if host.local.Context.CurrentNode != "jump-a" {
		t.Fatalf("local node=%q", host.local.Context.CurrentNode)
	}
}
