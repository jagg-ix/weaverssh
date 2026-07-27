package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"weaverssh/hopproof"
)

func TestVerifyIncomingRecursiveHop(t *testing.T) {
	nodes := []string{"workstation-42", "jump-a"}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := appHopSigner{private: map[string]ed25519.PrivateKey{"workstation-42": priv}}
	verifier := appHopVerifier{public: map[string]ed25519.PublicKey{"workstation-42": pub}}
	now := time.Unix(2_000_000_000, 0)
	chain, err := hopproof.Append(context.Background(), recursiveHopContext(nodes, "workstation-42"), hopproof.Chain{}, "", 5*time.Minute, now, signer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := hopproof.Encode(chain)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := verifyIncomingRecursiveHop(
		context.Background(),
		recursiveHopContext(nodes, "jump-a"),
		encoded,
		"workstation-42",
		verifier,
		now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.PreviousNode != "workstation-42" || verified.Depth != 1 {
		t.Fatalf("verified=%+v", verified)
	}
	if _, err := verifyIncomingRecursiveHop(context.Background(), recursiveHopContext(nodes, "jump-a"), encoded, "attacker", verifier, now.Add(time.Second)); err == nil || !strings.Contains(err.Error(), "signed hop predecessor") {
		t.Fatalf("wrong origin error=%v", err)
	}
}

func TestVerifyIncomingRecursiveHopRejectsTamperedSignature(t *testing.T) {
	nodes := []string{"a", "b"}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := appHopSigner{private: map[string]ed25519.PrivateKey{"a": priv}}
	verifier := appHopVerifier{public: map[string]ed25519.PublicKey{"a": pub}}
	now := time.Unix(2_000_000_000, 0)
	chain, err := hopproof.Append(context.Background(), recursiveHopContext(nodes, "a"), hopproof.Chain{}, "", time.Minute, now, signer)
	if err != nil {
		t.Fatal(err)
	}
	chain.Hops[0].Signature = "AAAA"
	encoded, err := hopproof.Encode(chain)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifyIncomingRecursiveHop(context.Background(), recursiveHopContext(nodes, "b"), encoded, "a", verifier, now.Add(time.Second))
	if !errors.Is(err, hopproof.ErrSignature) {
		t.Fatalf("error=%v", err)
	}
}

func TestVerifyIncomingRecursiveHopCanRequireProof(t *testing.T) {
	_, err := VerifyIncomingRecursiveHop(context.Background(), recursiveHopContext([]string{"a", "b"}, "b"), "", "a", "", "", true, time.Now())
	if err == nil || !strings.Contains(err.Error(), EnvWVHop) {
		t.Fatalf("error=%v", err)
	}
}
