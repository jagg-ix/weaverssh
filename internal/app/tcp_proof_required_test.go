package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessiontcp"
)

func TestTCPRequireProofNeedsVerifier(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	context, err := authproof.SignNodeContext(authproof.NodeContext{
		IssuerPeerID:  "tcp-proof-test",
		Audience:      authproof.AudienceNodeContext,
		ChainID:       "tcp-proof-chain",
		ChainSHA256:   authproof.ChainBindingSHA256("node-a"),
		Nodes:         []string{"node-a"},
		CurrentNode:   "node-a",
		OriginNode:    "node-a",
		EndpointNode:  "node-a",
		Capabilities:  []string{authproof.CapabilityNodeContext, authproof.CapabilitySocksProxy},
		Nonce:         "tcp-proof-required-nonce",
		IssuedAtUnix:  now.Add(-time.Second).Unix(),
		ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	allow, err := sessiontcp.ParseAllowlist("127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewLocalServices(LocalServiceConfig{
		SignedContext:   context,
		PublicKey:       publicKey,
		TCPAllow:        allow,
		TCPRequireProof: true,
	})
	if err == nil || !strings.Contains(err.Error(), "no verifier") {
		t.Fatalf("error=%v", err)
	}
}
