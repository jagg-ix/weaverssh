package sessionproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/socksproof"
)

func proofTestConfig(t *testing.T) (*socksproof.Verifier, *socksproof.Verifier, socksproof.Ed25519Signer) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := socksproof.Policy{
		Version:  socksproof.PolicyVersion,
		ServerID: "proxy-test",
		Principals: []socksproof.PrincipalPolicy{{
			ID:           "client",
			PublicKey:    authproof.EncodePublicKey(publicKey),
			Capabilities: []string{socksproof.CapabilityConnect},
			Destinations: []string{"echo.internal:443"},
			MaxTTL:       "30s",
		}},
	}
	local, err := socksproof.NewVerifier(policy)
	if err != nil {
		t.Fatal(err)
	}
	final, err := socksproof.NewVerifier(policy)
	if err != nil {
		t.Fatal(err)
	}
	return local, final, socksproof.Ed25519Signer(privateKey)
}

func TestProofSOCKS5EndToEnd(t *testing.T) {
	localVerifier, finalVerifier, signer := proofTestConfig(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &Server{
		Proof: &socksproof.ServerConfig{
			Verifier:       localVerifier,
			ServerID:       "proxy-test",
			SessionBinding: "binding",
			SelectedNode:   "compute-node",
			ChallengeTTL:   30 * time.Second,
		},
		DialProof: func(_ context.Context, network, address string, bundle socksproof.Bundle) (net.Conn, error) {
			if _, err := finalVerifier.VerifyBundle(bundle, network, address, "compute-node", time.Now()); err != nil {
				return nil, err
			}
			client, service := net.Pipe()
			go func() {
				defer service.Close()
				buffer := make([]byte, 256)
				for {
					n, err := service.Read(buffer)
					if n > 0 {
						_, _ = service.Write(buffer[:n])
					}
					if err != nil {
						return
					}
				}
			}()
			return client, nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, _, err := socksproof.Dial(dialCtx, listener.Addr().String(), "echo.internal:443", socksproof.ClientConfig{
		Principal:            "client",
		Signer:               signer,
		ProofTTL:             20 * time.Second,
		ExpectedServerID:     "proxy-test",
		ExpectedPolicySHA256: localVerifier.PolicySHA256,
		ExpectedNode:         "compute-node",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("proof-echo")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got=%q", got)
	}
	cancel()
	_ = listener.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestProofServerRejectsNoAuthDowngrade(t *testing.T) {
	localVerifier, _, _ := proofTestConfig(t)
	client, serverConn := net.Pipe()
	server := &Server{
		Proof: &socksproof.ServerConfig{
			Verifier:       localVerifier,
			ServerID:       "proxy-test",
			SessionBinding: "binding",
			SelectedNode:   "node",
		},
		DialProof: func(context.Context, string, string, socksproof.Bundle) (net.Conn, error) {
			return nil, errors.New("unexpected")
		},
	}
	done := make(chan error, 1)
	go func() { done <- server.handle(context.Background(), serverConn) }()
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0xff {
		t.Fatalf("reply=%x", reply)
	}
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("no-auth downgrade accepted")
	}
}

func TestAlteredRoutedDestinationRejected(t *testing.T) {
	localVerifier, finalVerifier, signer := proofTestConfig(t)
	challenge, err := socksproof.NewChallenge("proxy-test", localVerifier.PolicySHA256, "binding", "compute-node", 30*time.Second, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := socksproof.SignIdentity(challenge, "client", []string{socksproof.CapabilityConnect}, signer, 20*time.Second, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	connect, err := socksproof.SignConnect(challenge, identity, "tcp", "echo.internal:443", signer, 20*time.Second, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bundle := socksproof.Bundle{Challenge: challenge, Identity: identity, Connect: connect}
	if _, err := localVerifier.VerifyBundle(bundle, "tcp", "echo.internal:443", "compute-node", time.Now()); err != nil {
		t.Fatal(err)
	}
	_, err = finalVerifier.VerifyBundle(bundle, "tcp", "other.internal:443", "compute-node", time.Now())
	if !errors.Is(err, socksproof.ErrInvalidProof) {
		t.Fatalf("error=%v", err)
	}
}
