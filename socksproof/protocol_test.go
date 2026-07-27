package socksproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"weaverssh/authproof"
)

type proofFixture struct {
	policy    Policy
	verifier  *Verifier
	signer    Ed25519Signer
	challenge Challenge
	identity  SignedIdentity
	connect   SignedConnect
}

func newProofFixture(t *testing.T) proofFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{
		Version:  PolicyVersion,
		ServerID: "proxy-a",
		Principals: []PrincipalPolicy{{
			ID:           "client-a",
			PublicKey:    authproof.EncodePublicKey(publicKey),
			Capabilities: []string{CapabilityConnect},
			Destinations: []string{"*.internal:443", "127.0.0.1:*"},
			MaxTTL:       "30s",
		}},
	}
	verifier, err := NewVerifier(policy)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0)
	challenge, err := NewChallenge("proxy-a", verifier.PolicySHA256, "binding-1", "compute-node", 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	signer := Ed25519Signer(privateKey)
	identity, err := SignIdentity(challenge, "client-a", []string{CapabilityConnect}, signer, 20*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	connect, err := SignConnect(challenge, identity, "tcp", "api.internal:443", signer, 20*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	return proofFixture{
		policy: policy, verifier: verifier, signer: signer,
		challenge: challenge, identity: identity, connect: connect,
	}
}

func TestVerifyCompleteBundle(t *testing.T) {
	fixture := newProofFixture(t)
	principal, err := fixture.verifier.VerifyBundle(
		Bundle{Challenge: fixture.challenge, Identity: fixture.identity, Connect: fixture.connect},
		"tcp", "api.internal:443", "compute-node", time.Unix(2_000_000_001, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID != "client-a" {
		t.Fatalf("principal=%q", principal.ID)
	}
}

func TestConnectProofBindsDestinationAndNode(t *testing.T) {
	fixture := newProofFixture(t)
	now := time.Unix(2_000_000_001, 0)
	for _, test := range []struct {
		address string
		node    string
	}{
		{address: "other.internal:443", node: "compute-node"},
		{address: "api.internal:443", node: "jump-a"},
	} {
		fresh, err := NewVerifier(fixture.policy)
		if err != nil {
			t.Fatal(err)
		}
		_, err = fresh.VerifyBundle(
			Bundle{Challenge: fixture.challenge, Identity: fixture.identity, Connect: fixture.connect},
			"tcp", test.address, test.node, now,
		)
		if !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("address=%s node=%s error=%v", test.address, test.node, err)
		}
	}
}

func TestReplayRejected(t *testing.T) {
	fixture := newProofFixture(t)
	bundle := Bundle{Challenge: fixture.challenge, Identity: fixture.identity, Connect: fixture.connect}
	now := time.Unix(2_000_000_001, 0)
	if _, err := fixture.verifier.VerifyBundle(bundle, "tcp", "api.internal:443", "compute-node", now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.verifier.VerifyBundle(bundle, "tcp", "api.internal:443", "compute-node", now); !errors.Is(err, ErrReplay) {
		t.Fatalf("error=%v", err)
	}
}

func TestTamperedProofRejected(t *testing.T) {
	fixture := newProofFixture(t)
	fixture.connect.Statement.Address = "db.internal:443"
	_, err := fixture.verifier.VerifyBundle(
		Bundle{Challenge: fixture.challenge, Identity: fixture.identity, Connect: fixture.connect},
		"tcp", "db.internal:443", "compute-node", time.Unix(2_000_000_001, 0),
	)
	if !errors.Is(err, authproof.ErrInvalidSignature) {
		t.Fatalf("error=%v", err)
	}
}

func TestExpiredProofRejected(t *testing.T) {
	fixture := newProofFixture(t)
	_, err := fixture.verifier.VerifyBundle(
		Bundle{Challenge: fixture.challenge, Identity: fixture.identity, Connect: fixture.connect},
		"tcp", "api.internal:443", "compute-node", time.Unix(2_000_000_100, 0),
	)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("error=%v", err)
	}
}

func TestPolicyDigestIsCanonicalAndSensitive(t *testing.T) {
	fixture := newProofFixture(t)
	first, err := PolicyDigest(fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	reordered := fixture.policy
	reordered.Principals = append([]PrincipalPolicy(nil), fixture.policy.Principals...)
	reordered.Principals[0].Destinations = []string{"127.0.0.1:*", "*.internal:443"}
	second, err := PolicyDigest(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("canonical digests differ: %s != %s", first, second)
	}
	changed := fixture.policy
	changed.Principals = append([]PrincipalPolicy(nil), fixture.policy.Principals...)
	changed.Principals[0].Destinations = []string{"db.internal:443"}
	third, err := PolicyDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	if first == third {
		t.Fatal("policy digest did not change after destination policy changed")
	}
}
