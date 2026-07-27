package socksproof

import (
	"crypto/ed25519"
	"testing"
	"time"

	"weaverssh/authproof"
)

func wildcardBindFixture(t *testing.T, destinations []string, now time.Time) (*Verifier, Bundle) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed { seed[index] = byte(index + 17) }
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	policy := Policy{Version: PolicyVersion, ServerID: "proxy-wildcard", Principals: []PrincipalPolicy{{
		ID: "bind-client", PublicKey: authproof.EncodePublicKey(publicKey),
		Capabilities: []string{CapabilityConnect, CapabilityBind},
		Destinations: destinations, MaxTTL: "30s",
	}}}
	verifier, err := NewVerifier(policy)
	if err != nil { t.Fatal(err) }
	challenge, err := NewChallenge(policy.ServerID, verifier.PolicySHA256, "binding-a", "node-a", 30*time.Second, now)
	if err != nil { t.Fatal(err) }
	signer := Ed25519Signer(privateKey)
	identity, err := SignIdentity(challenge, "bind-client", []string{CapabilityConnect, CapabilityBind}, signer, 20*time.Second, now)
	if err != nil { t.Fatal(err) }
	proof, err := SignBind(challenge, identity, "tcp", "0.0.0.0:0", signer, 15*time.Second, now)
	if err != nil { t.Fatal(err) }
	return verifier, Bundle{Challenge: challenge, Identity: identity, Connect: proof}
}

func TestWildcardBindRequiresExplicitAnyDestination(t *testing.T) {
	now := time.Unix(1785002000, 0)
	verifier, bundle := wildcardBindFixture(t, []string{"127.0.0.1:2222"}, now)
	if _, err := verifier.VerifyCommandBundle(bundle, CommandBind, "tcp", "0.0.0.0:0", "node-a", now.Add(time.Second)); err == nil {
		t.Fatal("wildcard BIND accepted without *:* principal policy")
	}
}

func TestWildcardBindAcceptedWithExplicitAnyDestination(t *testing.T) {
	now := time.Unix(1785002100, 0)
	verifier, bundle := wildcardBindFixture(t, []string{"*:*"}, now)
	principal, err := verifier.VerifyCommandBundle(bundle, CommandBind, "tcp", "0.0.0.0:0", "node-a", now.Add(time.Second))
	if err != nil { t.Fatal(err) }
	if principal.ID != "bind-client" { t.Fatalf("principal=%q", principal.ID) }
}
