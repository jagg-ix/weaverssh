package authproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReconnectIdentityIsReusableButKeyBound(t *testing.T) {
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nodePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	context := reconnectTestContext(now, "peer")
	identity, err := NewReconnectIdentity(context, nodePublic)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignReconnectIdentity(identity, authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	options := ReconnectIdentityVerifyOptions{
		Now: now, Audience: AudienceReconnectIdentity, ChainID: context.ChainID,
		ChainSHA256: context.ChainSHA256, CurrentNode: "peer", MaxTTL: time.Hour,
	}
	for attempt := 0; attempt < 2; attempt++ {
		verified, err := VerifySignedReconnectIdentity(signed, authorityPublic, options)
		if err != nil {
			t.Fatalf("verify attempt %d: %v", attempt, err)
		}
		if verified.Context.CurrentNode != "peer" {
			t.Fatalf("node=%s", verified.Context.CurrentNode)
		}
	}
	tampered := signed
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	tampered.Identity.NodePublicKey = base64Raw(otherPublic)
	if _, err := VerifySignedReconnectIdentity(tampered, authorityPublic, options); err == nil {
		t.Fatal("tampered key was accepted")
	}
}

func TestReconnectIdentityExpiry(t *testing.T) {
	authorityPublic, authorityPrivate, _ := ed25519.GenerateKey(rand.Reader)
	nodePublic, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().Truncate(time.Second)
	context := reconnectTestContext(now.Add(-2*time.Hour), "peer")
	context.ExpiresAtUnix = now.Add(-time.Hour).Unix()
	identity, err := NewReconnectIdentity(context, nodePublic)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignReconnectIdentity(identity, authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifySignedReconnectIdentity(signed, authorityPublic, ReconnectIdentityVerifyOptions{Now: now})
	if !errors.Is(err, ErrExpiredGrant) {
		t.Fatalf("error=%v", err)
	}
}

func reconnectTestContext(now time.Time, current string) NodeContext {
	return NodeContext{
		IssuerPeerID: "authority", Audience: AudienceNodeContext,
		ChainID: "chain-a", ChainSHA256: strings.Repeat("a", 64),
		Nodes: []string{"host", "peer"}, CurrentNode: current,
		OriginNode: "host", EndpointNode: "peer",
		Capabilities: []string{CapabilityNodeContext}, Nonce: "certificate-serial",
		IssuedAtUnix: now.Unix(), ExpiresAtUnix: now.Add(30 * time.Minute).Unix(),
	}
}

func base64Raw(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
