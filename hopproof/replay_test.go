package hopproof

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"weaverssh/authproof"
)

func TestVerifyRejectsDuplicateNonceWithinChain(t *testing.T) {
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nodes := []string{"a", "b", "c"}
	signer := testSigner{private: map[string]ed25519.PrivateKey{"a": privA, "b": privB}}
	verifier := testVerifier{public: map[string]ed25519.PublicKey{"a": pubA, "b": pubB}}
	now := time.Unix(2_000_000_000, 0)
	first, err := Append(context.Background(), hopContext(nodes, "a"), Chain{}, "", time.Minute, now, signer)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := Append(context.Background(), hopContext(nodes, "b"), first, "parent-binding", time.Minute, now.Add(time.Second), signer)
	if err != nil {
		t.Fatal(err)
	}
	chain.Hops[1].Hop.Nonce = chain.Hops[0].Hop.Nonce
	message, err := CanonicalHopBytes(chain.Hops[1].Hop)
	if err != nil {
		t.Fatal(err)
	}
	chain.Hops[1].Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privB, message))

	err = Verify(context.Background(), hopContext(nodes, "c"), chain, verifier, VerifyOptions{
		Now:         now.Add(2 * time.Second),
		ReplayCache: authproof.NewNonceCache(),
	})
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("error=%v want ErrReplay", err)
	}
}

func TestDecodeRejectsOversizedEnvironmentValue(t *testing.T) {
	oversized := make([]byte, MaxEncodedBytes+1)
	for index := range oversized {
		oversized[index] = 'A'
	}
	if _, err := Decode(string(oversized)); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("error=%v want ErrInvalidChain", err)
	}
}
