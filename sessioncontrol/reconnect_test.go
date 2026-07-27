package sessioncontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionlink"
	"weaverssh/sessionmux"
)

func TestReconnectProofBindsTransportServicesAndChallenge(t *testing.T) {
	authorityPublic, authorityPrivate, _ := ed25519.GenerateKey(rand.Reader)
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().Truncate(time.Second)
	hostContext := reconnectContext(now, "host", "host-nonce")
	peerContext := reconnectContext(now, "peer", "peer-certificate")
	identity, err := authproof.NewReconnectIdentity(peerContext, nodePublic)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := authproof.SignReconnectIdentity(identity, authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := NewReconnectChallenge(hostContext, "peer", sessionlink.TransportID("transport-123"), "binding-123", 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := BuildReconnectProof(challenge, signed, nodePrivate, []sessionmux.ServiceID{sessionmux.ServiceFS}, now)
	if err != nil {
		t.Fatal(err)
	}
	cache := authproof.NewNonceCache()
	verified, services, err := VerifyReconnectProof(challenge, signed, proof, authorityPublic, time.Hour, cache, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Context.CurrentNode != "peer" || len(services) != 1 || services[0] != sessionmux.ServiceFS {
		t.Fatalf("verified=%+v services=%v", verified, services)
	}
	if _, _, err := VerifyReconnectProof(challenge, signed, proof, authorityPublic, time.Hour, cache, now); !errors.Is(err, authproof.ErrReplay) {
		t.Fatalf("replay error=%v", err)
	}
	tampered := proof
	tampered.Statement.Services = []sessionmux.ServiceID{sessionmux.ServiceTCP}
	if _, _, err := VerifyReconnectProof(challenge, signed, tampered, authorityPublic, time.Hour, nil, now); !errors.Is(err, ErrReconnectProof) && !errors.Is(err, authproof.ErrInvalidSignature) {
		t.Fatalf("tampered services error=%v", err)
	}
}

func TestReconnectProofCannotMoveToFreshChallenge(t *testing.T) {
	authorityPublic, authorityPrivate, _ := ed25519.GenerateKey(rand.Reader)
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().Truncate(time.Second)
	hostContext := reconnectContext(now, "host", "host-nonce")
	peerContext := reconnectContext(now, "peer", "peer-certificate")
	identity, _ := authproof.NewReconnectIdentity(peerContext, nodePublic)
	signed, _ := authproof.SignReconnectIdentity(identity, authorityPrivate)
	first, _ := NewReconnectChallenge(hostContext, "peer", sessionlink.TransportID("transport-123"), "binding-123", 30*time.Second, now)
	proof, _ := BuildReconnectProof(first, signed, nodePrivate, []sessionmux.ServiceID{sessionmux.ServiceFS}, now)
	second, _ := NewReconnectChallenge(hostContext, "peer", sessionlink.TransportID("transport-456"), "binding-456", 30*time.Second, now)
	if _, _, err := VerifyReconnectProof(second, signed, proof, authorityPublic, time.Hour, nil, now); err == nil {
		t.Fatal("proof unexpectedly accepted on replacement challenge")
	}
}

func TestReconnectStreamRoundTrip(t *testing.T) {
	authorityPublic, authorityPrivate, _ := ed25519.GenerateKey(rand.Reader)
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().Truncate(time.Second)
	hostContext := reconnectContext(now, "host", "host-nonce")
	peerContext := reconnectContext(now, "peer", "peer-certificate")
	identity, _ := authproof.NewReconnectIdentity(peerContext, nodePublic)
	signed, _ := authproof.SignReconnectIdentity(identity, authorityPrivate)
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	serverResult := make(chan error, 1)
	go func() {
		accepted, err := ServeReconnectStream(context.Background(), server, &Registry{}, ReconnectServerConfig{
			AuthorityPublicKey: authorityPublic, LocalContext: hostContext, PeerNode: "peer",
			SessionBinding: "binding-123", TransportID: sessionlink.TransportID("transport-123"),
			ChallengeTTL: 30 * time.Second, MaxIdentityTTL: time.Hour, ReplayCache: authproof.NewNonceCache(),
			Now: func() time.Time { return now },
		})
		if err == nil && (accepted.LinkID == "" || accepted.Node.ID != "peer") {
			err = errors.New("bad accepted result")
		}
		serverResult <- err
	}()
	response, challenge, err := RegisterNodeReconnectStream(context.Background(), client, ReconnectClientConfig{
		Identity: signed, NodePrivateKey: nodePrivate, Services: []sessionmux.ServiceID{sessionmux.ServiceFS},
		ExpectedAcceptorNode: "host", ExpectedSessionBinding: "binding-123",
		ExpectedTransportID: sessionlink.TransportID("transport-123"), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Node != "peer" || challenge.ProverNode != "peer" {
		t.Fatalf("response=%+v challenge=%+v", response, challenge)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func reconnectContext(now time.Time, current, nonce string) authproof.NodeContext {
	return authproof.NodeContext{
		IssuerPeerID: "authority", Audience: authproof.AudienceNodeContext,
		ChainID: "chain-a", ChainSHA256: strings.Repeat("a", 64),
		Nodes: []string{"host", "peer"}, CurrentNode: current,
		OriginNode: "host", EndpointNode: "peer",
		Capabilities: []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh}, Nonce: nonce,
		IssuedAtUnix: now.Unix(), ExpiresAtUnix: now.Add(30 * time.Minute).Unix(),
	}
}
