package hopproof

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
)

type testSigner struct {
	private map[string]ed25519.PrivateKey
}

func (s testSigner) Sign(_ context.Context, principal string, message []byte) ([]byte, error) {
	key := s.private[principal]
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("missing test private key")
	}
	return ed25519.Sign(key, message), nil
}

type testVerifier struct {
	public map[string]ed25519.PublicKey
}

func (v testVerifier) Verify(_ context.Context, principal string, message, signature []byte) error {
	key := v.public[principal]
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message, signature) {
		return ErrSignature
	}
	return nil
}

func TestRecursiveSignedHopChain(t *testing.T) {
	principals := []string{"workstation-42", "jump-a", "compute-node"}
	private := make(map[string]ed25519.PrivateKey)
	public := make(map[string]ed25519.PublicKey)
	for _, principal := range principals {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		private[principal] = priv
		public[principal] = pub
	}
	signer := testSigner{private: private}
	verifier := testVerifier{public: public}
	now := time.Unix(2_000_000_000, 0)

	workstation := hopContext(principals, "workstation-42")
	jump := hopContext(principals, "jump-a")
	compute := hopContext(principals, "compute-node")

	first, err := Append(context.Background(), workstation, Chain{}, "", 5*time.Minute, now, signer)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Hops) != 1 || first.Hops[0].Hop.FromNode != "workstation-42" || first.Hops[0].Hop.ToNode != "jump-a" {
		t.Fatalf("first chain=%+v", first)
	}
	if err := Verify(context.Background(), jump, first, verifier, VerifyOptions{Now: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	previous, err := ImmediatePrevious(first)
	if err != nil || previous != "workstation-42" {
		t.Fatalf("previous=%q err=%v", previous, err)
	}

	second, err := Append(context.Background(), jump, first, "parent-binding-a", 5*time.Minute, now.Add(2*time.Second), signer)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Hops) != 2 || second.Hops[1].Hop.ParentSessionBinding != "parent-binding-a" || second.Hops[1].Hop.ParentHopSHA256 == "" {
		t.Fatalf("second chain=%+v", second)
	}
	if err := Verify(context.Background(), compute, second, verifier, VerifyOptions{Now: now.Add(3 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(second)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(context.Background(), compute, decoded, verifier, VerifyOptions{Now: now.Add(3 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	previous, err = ImmediatePrevious(decoded)
	if err != nil || previous != "jump-a" {
		t.Fatalf("previous=%q err=%v", previous, err)
	}
}

func TestHopChainRejectsTamperAndExpiry(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	principals := []string{"workstation-42", "jump-a"}
	signer := testSigner{private: map[string]ed25519.PrivateKey{"workstation-42": priv}}
	verifier := testVerifier{public: map[string]ed25519.PublicKey{"workstation-42": pub}}
	now := time.Unix(2_000_000_000, 0)
	chain, err := Append(context.Background(), hopContext(principals, "workstation-42"), Chain{}, "", time.Minute, now, signer)
	if err != nil {
		t.Fatal(err)
	}
	jump := hopContext(principals, "jump-a")

	tampered := chain
	tampered.Hops = append([]SignedHop(nil), chain.Hops...)
	tampered.Hops[0].Hop.ToNode = "attacker"
	if err := Verify(context.Background(), jump, tampered, verifier, VerifyOptions{Now: now.Add(time.Second)}); !errors.Is(err, ErrWrongHop) {
		t.Fatalf("tamper error=%v", err)
	}
	if err := Verify(context.Background(), jump, chain, verifier, VerifyOptions{Now: now.Add(2 * time.Minute)}); !errors.Is(err, ErrExpiredHop) {
		t.Fatalf("expiry error=%v", err)
	}
}

func TestAppendRequiresBindingAfterFirstHop(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	_, privB, _ := ed25519.GenerateKey(rand.Reader)
	principals := []string{"a", "b", "c"}
	signer := testSigner{private: map[string]ed25519.PrivateKey{"a": privA, "b": privB}}
	verifier := testVerifier{public: map[string]ed25519.PublicKey{"a": pubA}}
	now := time.Unix(2_000_000_000, 0)
	first, err := Append(context.Background(), hopContext(principals, "a"), Chain{}, "", time.Minute, now, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(context.Background(), hopContext(principals, "b"), first, verifier, VerifyOptions{Now: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(context.Background(), hopContext(principals, "b"), first, "", time.Minute, now, signer); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("append error=%v", err)
	}
}

func hopContext(nodes []string, current string) authproof.NodeContext {
	now := time.Now()
	return authproof.NodeContext{
		IssuerPeerID:  "hop-test",
		ChainID:       "hop-chain",
		ChainSHA256:   strings.Repeat("a", 64),
		Nodes:         append([]string(nil), nodes...),
		CurrentNode:   current,
		OriginNode:    nodes[0],
		EndpointNode:  nodes[len(nodes)-1],
		Capabilities:  []string{authproof.CapabilityNodeContext},
		Nonce:         "node-context-" + current,
		IssuedAtUnix:  now.Add(-time.Minute).Unix(),
		ExpiresAtUnix: now.Add(time.Hour).Unix(),
	}
}
