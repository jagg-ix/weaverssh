package sessionproxy

import (
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/socksproof"
)

type legacyUDPAssociation struct{}
func (*legacyUDPAssociation) Send([]byte) error { return nil }
func (*legacyUDPAssociation) Receive() ([]byte, error) { return nil, io.EOF }
func (*legacyUDPAssociation) Close() error { return nil }

type tcpAddressConn struct {
	net.Conn
	local  *net.TCPAddr
	remote *net.TCPAddr
}
func (c *tcpAddressConn) LocalAddr() net.Addr { return c.local }
func (c *tcpAddressConn) RemoteAddr() net.Addr { return c.remote }

func TestProofUDPRejectsLegacyRoutedAssociation(t *testing.T) {
	now := time.Now()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed { seed[index] = byte(index + 29) }
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	policy := socksproof.Policy{Version: socksproof.PolicyVersion, ServerID: "proxy-a", Principals: []socksproof.PrincipalPolicy{{
		ID: "udp-client", PublicKey: authproof.EncodePublicKey(publicKey),
		Capabilities: []string{socksproof.CapabilityConnect, socksproof.CapabilityUDPAssociate},
		Destinations: []string{"127.0.0.1:53"}, MaxTTL: "30s",
	}}}
	verifier, err := socksproof.NewVerifier(policy)
	if err != nil { t.Fatal(err) }
	challenge, err := socksproof.NewChallenge(policy.ServerID, verifier.PolicySHA256, "binding-a", "node-a", 30*time.Second, now)
	if err != nil { t.Fatal(err) }
	signer := socksproof.Ed25519Signer(privateKey)
	identity, err := socksproof.SignIdentity(challenge, "udp-client", []string{socksproof.CapabilityConnect, socksproof.CapabilityUDPAssociate}, signer, 20*time.Second, now)
	if err != nil { t.Fatal(err) }
	principal, err := verifier.VerifyIdentity(challenge, identity, now)
	if err != nil { t.Fatal(err) }
	associationProof, err := socksproof.SignUDPAssociate(challenge, identity, "udp", "0.0.0.0:0", signer, 15*time.Second, now)
	if err != nil { t.Fatal(err) }

	serverPipe, clientPipe := net.Pipe()
	defer clientPipe.Close()
	serverConn := &tcpAddressConn{
		Conn: serverPipe,
		local: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080},
		remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000},
	}
	server := &Server{AssociateUDP: func(context.Context, string) (UDPAssociation, error) {
		return &legacyUDPAssociation{}, nil
	}}
	proofConfig := &socksproof.ServerConfig{
		Verifier: verifier, ServerID: policy.ServerID,
		SessionBinding: "binding-a", SelectedNode: "node-a", ChallengeTTL: 30 * time.Second,
	}
	result := make(chan error, 1)
	go func() {
		result <- server.handleProofUDPAssociate(
			context.Background(), serverConn, proofConfig,
			socksproof.ServerSession{Challenge: challenge, Identity: identity, Principal: principal},
			"udp", "0.0.0.0:0",
		)
	}()
	var session socksproof.DatagramSession
	if err := socksproof.ReadFrame(clientPipe, &session); err != nil { t.Fatal(err) }
	if err := socksproof.WriteFrame(clientPipe, associationProof); err != nil { t.Fatal(err) }
	reply := make([]byte, 10)
	if _, err := io.ReadFull(clientPipe, reply); err != nil { t.Fatal(err) }
	if reply[0] != 0x05 || reply[1] == 0x00 { t.Fatalf("unexpected SOCKS reply %v", reply) }
	err = <-result
	if err == nil { t.Fatal("legacy routed association was accepted") }
	if err.Error() != "sessionproxy: proof UDP route does not support final-node verification" { t.Fatalf("error=%v", err) }
}
