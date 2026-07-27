package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionbroker"
	"weaverssh/sessionlink"
)

func TestRuntimeProofSignerCreatesFreshGenerationGrant(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = publicKey
	ctx := authproof.NodeContext{
		Version: authproof.NodeContextVersion, Algorithm: authproof.Algorithm,
		IssuerPeerID: "authority", Audience: authproof.AudienceNodeContext,
		ChainID: "chain-a", ChainSHA256: authproof.ChainBindingSHA256("origin", "node"),
		Nodes: []string{"origin", "node"}, CurrentNode: "node", OriginNode: "origin", EndpointNode: "node",
		Capabilities: []string{authproof.CapabilityNodeContext}, Nonce: "node-context-nonce",
		IssuedAtUnix: time.Now().Add(-time.Second).Unix(), ExpiresAtUnix: time.Now().Add(time.Hour).Unix(),
	}
	signer := RuntimeProofSigner{Template: authproof.RuntimeConfig{
		SecurityLevel: authproof.SecurityLevelAgentProof,
		IssuerPeerID: "origin", SubjectPeerID: "node", Audience: authproof.AudienceAgent,
		PrivateKey: authproof.EncodePrivateKey(privateKey), TTL: time.Minute,
		RequiredCapabilities: authproof.DefaultRelayCapabilities(), SessionID: "reconnect",
	}}
	first, err := signer.RuntimeProof(context.Background(), RuntimeProofRequest{
		Generation: 1, Cookie: "001122", NodeContext: ctx, IssuedAt: time.Unix(1700000000, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := signer.RuntimeProof(context.Background(), RuntimeProofRequest{
		Generation: 2, Cookie: "001122", NodeContext: ctx, IssuedAt: time.Unix(1700000001, 2),
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Grant.Nonce == second.Grant.Nonce {
		t.Fatal("proof provider reused nonce across generations")
	}
	if first.Grant.SessionID == second.Grant.SessionID {
		t.Fatal("proof provider reused session id across generations")
	}
	if first.Grant.X11CookieSHA256 != authproof.HashX11Cookie("001122") {
		t.Fatalf("cookie hash=%q", first.Grant.X11CookieSHA256)
	}
	if first.Grant.ChainSHA256 != ctx.ChainSHA256 {
		t.Fatalf("chain hash=%q", first.Grant.ChainSHA256)
	}
}

func TestProofRefreshingAttachSupervisorInjectsProof(t *testing.T) {
	router, err := sessionbroker.NewLinkRouter(sessionlink.Descriptor{
		ChainSHA256: authproof.ChainBindingSHA256("origin", "node"),
		Topology: []string{"origin", "node"}, LocalNode: "node", PeerNode: "origin",
	})
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("attach stopped after proof capture")
	var captured *authproof.SignedGrant
	provider := RuntimeProofProviderFunc(func(_ context.Context, request RuntimeProofRequest) (*authproof.SignedGrant, error) {
		grant := authproof.SignedGrant{Grant: authproof.Grant{SessionID: "generation"}}
		if request.Generation != 1 {
			t.Fatalf("generation=%d", request.Generation)
		}
		return &grant, nil
	})
	supervisor, err := NewProofRefreshingAttachSupervisor(AttachSupervisorConfig{
		Attach: AttachConfig{AuthCookie: "cookie", SignedContext: authproof.SignedNodeContext{Context: authproof.NodeContext{
			ChainSHA256: authproof.ChainBindingSHA256("origin", "node"), CurrentNode: "node",
		}}},
		AttachFunc: func(_ context.Context, config AttachConfig) (*AttachedSession, error) {
			captured = config.RuntimeProof
			return nil, sentinel
		},
		Router: router, Lease: 30 * time.Second,
	}, provider)
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Run(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("Run error=%v", err)
	}
	if captured == nil || captured.Grant.SessionID != "generation" {
		t.Fatalf("proof not injected: %+v", captured)
	}
}

func TestProofRefreshingAttachSupervisorRejectsStaticProof(t *testing.T) {
	router, err := sessionbroker.NewLinkRouter(sessionlink.Descriptor{
		ChainSHA256: authproof.ChainBindingSHA256("origin", "node"),
		Topology: []string{"origin", "node"}, LocalNode: "node", PeerNode: "origin",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewProofRefreshingAttachSupervisor(AttachSupervisorConfig{
		Attach: AttachConfig{RuntimeProof: &authproof.SignedGrant{}}, Router: router, Lease: 30 * time.Second,
	}, RuntimeProofProviderFunc(func(context.Context, RuntimeProofRequest) (*authproof.SignedGrant, error) {
		return &authproof.SignedGrant{}, nil
	}))
	if err == nil {
		t.Fatal("expected static/provider conflict")
	}
}
