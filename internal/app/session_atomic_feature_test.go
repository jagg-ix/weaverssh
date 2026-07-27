package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"weaverssh/authproof"
)

func TestSessionAPIDescribesAtomicFilesystemReplace(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	nodes := []string{"workstation-42", "compute-node"}
	signed, err := authproof.SignNodeContext(authproof.NodeContext{
		IssuerPeerID: "atomic-feature-test",
		Audience: authproof.AudienceNodeContext,
		ChainID: "atomic-feature-chain",
		ChainSHA256: authproof.ChainBindingSHA256(nodes...),
		Nodes: nodes,
		CurrentNode: nodes[0],
		OriginNode: nodes[0],
		EndpointNode: nodes[1],
		Capabilities: []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh},
		Nonce: "atomic-feature-nonce",
		IssuedAtUnix: now.Add(-time.Second).Unix(),
		ExpiresAtUnix: now.Add(5 * time.Minute).Unix(),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	local, err := NewLocalServices(LocalServiceConfig{
		SignedContext: signed,
		PublicKey: publicKey,
		Root: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	server := NewSessionAPIServer(SessionAPIConfig{Binding: "binding", Context: signed.Context, Local: local})
	snapshot, err := server.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(snapshot.Features, "fs.atomic-replace.v1") {
		t.Fatalf("features=%v", snapshot.Features)
	}
}
