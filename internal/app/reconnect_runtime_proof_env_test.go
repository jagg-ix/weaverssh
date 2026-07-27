package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"weaverssh/authproof"
)

func TestRuntimeProofProviderFromEnvironment(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvRuntimeProofRefresh, "1")
	t.Setenv("WEAVERSSH_PROOF_MODE", authproof.ProofModeRequired)
	t.Setenv("WEAVERSSH_PROOF_PRIVATE_KEY", authproof.EncodePrivateKey(privateKey))
	t.Setenv("WEAVERSSH_PROOF_SIGNER_PROVIDER", authproof.SignerProviderKeyMaterial)
	t.Setenv("WEAVERSSH_PROOF_ISSUER_ID", "origin")
	t.Setenv("WEAVERSSH_PROOF_SUBJECT_ID", "host")
	t.Setenv("WEAVERSSH_PROOF_TTL", "45s")

	provider, enabled, err := RuntimeProofProviderFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if !enabled || provider == nil {
		t.Fatal("environment provider was not enabled")
	}
	chain := authproof.ChainBindingSHA256("origin", "node")
	now := time.Unix(1700000000, 0)
	proof, err := provider.RuntimeProof(context.Background(), RuntimeProofRequest{
		Generation: 4,
		Cookie:     "cookie-four",
		NodeContext: authproof.NodeContext{
			ChainSHA256: chain,
			CurrentNode: "node",
		},
		IssuedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if proof.Grant.Audience != authproof.AudienceAgent || proof.Grant.X11CookieSHA256 != authproof.HashX11Cookie("cookie-four") || proof.Grant.ChainSHA256 != chain {
		t.Fatalf("proof=%+v", proof.Grant)
	}
	if proof.Grant.ExpiresAtUnix-proof.Grant.IssuedAtUnix != 45 {
		t.Fatalf("ttl=%d", proof.Grant.ExpiresAtUnix-proof.Grant.IssuedAtUnix)
	}
}

func TestRuntimeProofProviderFromEnvironmentDisabledByDefault(t *testing.T) {
	t.Setenv(EnvRuntimeProofRefresh, "")
	t.Setenv("WEAVERSSH_PROOF_MODE", "")
	t.Setenv("WEAVERSSH_PROOF_PRIVATE_KEY", "")
	t.Setenv("WEAVERSSH_PROOF_PRIVATE_KEY_FILE", "")
	t.Setenv("WEAVERSSH_PROOF_IDENTITY", "")
	t.Setenv("WEAVERSSH_PROOF_IDENTITY_FILE", "")
	t.Setenv("WEAVERSSH_PROOF_AGENT_SOCKET", "")
	provider, enabled, err := RuntimeProofProviderFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if enabled || provider != nil {
		t.Fatal("provider enabled without signer configuration")
	}
}
