package app

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"weaverssh/authproof"
)

func TestConfigRequiredProofRejectsMissingChainBinding(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cfg := DefaultConfig()
	cfg.Security.AuthCookie = "cookie"
	cfg.Security.ProofMode = authproof.ProofModeRequired
	cfg.Security.ProofPeerID = "agent-linode-a"
	cfg.Security.ProofPublicKey = authproof.EncodePublicKey(publicKey)
	cfg.Security.ProofChainSHA256 = ""

	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "proof_chain_sha256") {
		t.Fatalf("expected proof_chain_sha256 validation error, got %v", err)
	}
}

func TestConfigRequiredProofAcceptsExplicitChainBinding(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cfg := DefaultConfig()
	cfg.Security.AuthCookie = "cookie"
	cfg.Security.ProofMode = authproof.ProofModeRequired
	cfg.Security.ProofPeerID = "agent-linode-a"
	cfg.Security.ProofPublicKey = authproof.EncodePublicKey(publicKey)
	cfg.Security.ProofChainSHA256 = authproof.ChainBindingSHA256("origin-alise", "agent-linode-a")

	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config with explicit chain binding: %v", err)
	}
}
