package sessionudpproof

import (
	"crypto/ed25519"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/socksproof"
	"weaverssh/socksudp"
)

func testProofBundle(t *testing.T, now time.Time) (*socksproof.Verifier, socksproof.Bundle, socksproof.Signer) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	policy, err := socksproof.NormalizePolicy(socksproof.Policy{
		Version:  socksproof.PolicyVersion,
		ServerID: "proxy-a",
		Principals: []socksproof.PrincipalPolicy{{
			ID:           "udp-client",
			PublicKey:    authproof.EncodePublicKey(publicKey),
			Capabilities: []string{socksproof.CapabilityConnect, socksproof.CapabilityUDPAssociate},
			Destinations: []string{"127.0.0.1:53"},
			MaxTTL:       "30s",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := socksproof.NewVerifier(policy)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := socksproof.NewChallenge(
		policy.ServerID,
		verifier.PolicySHA256,
		"binding-a",
		"node-a",
		30*time.Second,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	signer := socksproof.Ed25519Signer(privateKey)
	identity, err := socksproof.SignIdentity(
		challenge,
		"udp-client",
		[]string{socksproof.CapabilityConnect, socksproof.CapabilityUDPAssociate},
		signer,
		30*time.Second,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	association, err := socksproof.SignUDPAssociate(
		challenge,
		identity,
		"udp",
		"0.0.0.0:0",
		signer,
		30*time.Second,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	return verifier, socksproof.Bundle{Challenge: challenge, Identity: identity, Connect: association}, signer
}

func TestRequestRoundTripAndFinalDatagramVerification(t *testing.T) {
	now := time.Unix(1785001000, 0)
	verifier, bundle, signer := testProofBundle(t, now)
	metadata, err := EncodeRequest("udp", "0.0.0.0:0", bundle)
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodeRequest(metadata)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := verifier.VerifyCommandBundle(
		request.Proof,
		socksproof.CommandUDPAssociate,
		"udp",
		request.ClientEndpoint,
		"node-a",
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := socksudp.Marshal("127.0.0.1:53", []byte("dns"))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := socksproof.SignDatagram(
		bundle.Challenge,
		bundle.Identity,
		1,
		"udp",
		"127.0.0.1:53",
		packet,
		signer,
		30*time.Second,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyDatagram(
		socksproof.ServerSession{Challenge: bundle.Challenge, Identity: bundle.Identity, Principal: principal},
		proof,
		packet,
		"udp",
		"127.0.0.1:53",
		"binding-a",
		"node-a",
		now,
	); err != nil {
		t.Fatal(err)
	}
}

func TestFinalDatagramVerificationRejectsWrongNode(t *testing.T) {
	now := time.Unix(1785001100, 0)
	verifier, bundle, _ := testProofBundle(t, now)
	if _, err := verifier.VerifyCommandBundle(
		bundle,
		socksproof.CommandUDPAssociate,
		"udp",
		"0.0.0.0:0",
		"node-b",
		now,
	); err == nil {
		t.Fatal("association bundle was accepted for the wrong final node")
	}
}
