package socksproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/socksudp"
)

func commandTestFixture(t *testing.T) (*Verifier, Challenge, SignedIdentity, Ed25519Signer, time.Time) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	policy := Policy{Version: PolicyVersion, ServerID: "proxy-a", Principals: []PrincipalPolicy{{
		ID: "client-a", PublicKey: authproof.EncodePublicKey(publicKey),
		Capabilities: []string{CapabilityConnect, CapabilityBind, CapabilityUDPAssociate},
		Destinations: []string{"example.com:443", "dns.example:53"}, MaxTTL: "30s",
	}}}
	verifier, err := NewVerifier(policy); if err != nil { t.Fatal(err) }
	now := time.Unix(1700000000, 0)
	challenge, err := NewChallenge("proxy-a", verifier.PolicySHA256, "binding-a", "node-a", 30*time.Second, now); if err != nil { t.Fatal(err) }
	signer := Ed25519Signer(privateKey)
	identity, err := SignIdentity(challenge, "client-a", []string{CapabilityConnect, CapabilityBind, CapabilityUDPAssociate}, signer, 20*time.Second, now); if err != nil { t.Fatal(err) }
	return verifier, challenge, identity, signer, now
}

func TestVerifyBindBundleAtFinalNode(t *testing.T) {
	verifier, challenge, identity, signer, now := commandTestFixture(t)
	proof, err := SignBind(challenge, identity, "tcp", "example.com:443", signer, 15*time.Second, now); if err != nil { t.Fatal(err) }
	bundle := Bundle{Challenge: challenge, Identity: identity, Connect: proof}
	principal, err := verifier.VerifyCommandBundle(bundle, CommandBind, "tcp", "example.com:443", "node-a", now.Add(time.Second))
	if err != nil { t.Fatal(err) }
	if principal.ID != "client-a" { t.Fatalf("principal=%q", principal.ID) }
	if _, err := verifier.VerifyCommandBundle(bundle, CommandBind, "tcp", "example.com:443", "node-a", now.Add(time.Second)); !errors.Is(err, ErrReplay) { t.Fatalf("replay error=%v", err) }
}

func TestSignedDatagramEnvelopeTamperAndReplay(t *testing.T) {
	verifier, challenge, identity, signer, now := commandTestFixture(t)
	if _, err := verifier.VerifyIdentity(challenge, identity, now.Add(time.Second)); err != nil { t.Fatal(err) }
	packet, err := socksudp.Marshal("dns.example:53", []byte("query")); if err != nil { t.Fatal(err) }
	proof, err := SignDatagram(challenge, identity, 1, "udp", "dns.example:53", packet, signer, 15*time.Second, now); if err != nil { t.Fatal(err) }
	envelope, err := EncodeDatagramEnvelope(proof, packet); if err != nil { t.Fatal(err) }
	decoded, decodedPacket, err := DecodeDatagramEnvelope(envelope); if err != nil { t.Fatal(err) }
	session := ServerSession{Challenge: challenge, Identity: identity}
	if _, err := verifier.VerifyDatagram(session, decoded, decodedPacket, "udp", "dns.example:53", "binding-a", "node-a", now.Add(time.Second)); err != nil { t.Fatal(err) }
	if _, err := verifier.VerifyDatagram(session, decoded, decodedPacket, "udp", "dns.example:53", "binding-a", "node-a", now.Add(time.Second)); !errors.Is(err, ErrReplay) { t.Fatalf("replay error=%v", err) }

	verifier2, challenge2, identity2, signer2, now2 := commandTestFixture(t)
	if _, err := verifier2.VerifyIdentity(challenge2, identity2, now2.Add(time.Second)); err != nil { t.Fatal(err) }
	packet2, _ := socksudp.Marshal("dns.example:53", []byte("query"))
	proof2, _ := SignDatagram(challenge2, identity2, 2, "udp", "dns.example:53", packet2, signer2, 15*time.Second, now2)
	packet2[len(packet2)-1] ^= 0xff
	if _, err := verifier2.VerifyDatagram(ServerSession{Challenge: challenge2, Identity: identity2}, proof2, packet2, "udp", "dns.example:53", "binding-a", "node-a", now2.Add(time.Second)); err == nil { t.Fatal("tampered packet accepted") }
}

func TestDecodeDatagramEnvelopeDefersProofValidation(t *testing.T) {
	_, packet, err := DecodeDatagramEnvelope([]byte{0, 0, 0, 2, '{', '}', 'x'})
	if err != nil { t.Fatal(err) }
	if string(packet) != "x" { t.Fatalf("packet=%q", packet) }
}

func TestDecodeDatagramEnvelopeRejectsTrailingMetadata(t *testing.T) {
	_, _, err := DecodeDatagramEnvelope([]byte{0, 0, 0, 3, '{', '}', 'x', 'y'})
	if err == nil { t.Fatal("trailing metadata accepted") }
}
