package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"weaverssh/authproof"
	"weaverssh/socksproof"
)

func TestOpenSSHEd25519FingerprintHasStandardShape(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := openSSHEd25519Fingerprint(publicKey)
	if !strings.HasPrefix(fingerprint, "SHA256:") || len(fingerprint) < len("SHA256:")+20 {
		t.Fatalf("fingerprint=%q", fingerprint)
	}
}

func TestSocksPolicyDigestAvailableAfterValidation(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := socksproof.Policy{
		Version:  socksproof.PolicyVersion,
		ServerID: "proxy-a",
		Principals: []socksproof.PrincipalPolicy{{
			ID:           "client-a",
			PublicKey:    authproof.EncodePublicKey(publicKey),
			Capabilities: []string{socksproof.CapabilityConnect},
			Destinations: []string{"api.internal:443"},
			MaxTTL:       "30s",
		}},
	}
	payload, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := socksproof.LoadPolicyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := socksproof.NewVerifier(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if len(verifier.PolicySHA256) != 64 || verifier.PolicySHA256 != strings.ToLower(verifier.PolicySHA256) {
		t.Fatalf("policy digest=%q", verifier.PolicySHA256)
	}
}
