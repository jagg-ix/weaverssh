package sessiontcpproof

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
	"weaverssh/sessiontcp"
	"weaverssh/socksproof"
)

func proofBundle(t *testing.T) (*socksproof.Verifier, socksproof.Bundle) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := socksproof.Policy{
		Version:  socksproof.PolicyVersion,
		ServerID: "proxy",
		Principals: []socksproof.PrincipalPolicy{{
			ID:           "client",
			PublicKey:    authproof.EncodePublicKey(publicKey),
			Capabilities: []string{socksproof.CapabilityConnect},
			Destinations: []string{"127.0.0.1:8443"},
		}},
	}
	verifier, err := socksproof.NewVerifier(policy)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	challenge, err := socksproof.NewChallenge("proxy", verifier.PolicySHA256, "binding", "node-a", 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	signer := socksproof.Ed25519Signer(privateKey)
	identity, err := socksproof.SignIdentity(challenge, "client", []string{socksproof.CapabilityConnect}, signer, 20*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	connect, err := socksproof.SignConnect(challenge, identity, "tcp", "127.0.0.1:8443", signer, 20*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	return verifier, socksproof.Bundle{Challenge: challenge, Identity: identity, Connect: connect}
}

func TestServerVerifiesProofBeforeDial(t *testing.T) {
	verifier, bundle := proofBundle(t)
	allow, err := sessiontcp.ParseAllowlist("127.0.0.1:8443")
	if err != nil {
		t.Fatal(err)
	}
	dialed := make(chan struct{}, 1)
	server := &Server{
		Verifier:     verifier,
		ExpectedNode: "node-a",
		Authorize:    allow.Authorize,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed <- struct{}{}
			client, service := net.Pipe()
			go func() {
				defer service.Close()
				_, _ = io.Copy(service, service)
			}()
			return client, nil
		},
	}
	metadata, err := EncodeRequest("tcp", "127.0.0.1:8443", bundle)
	if err != nil {
		t.Fatal(err)
	}
	client, service := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background(), service, metadata) }()
	if err := readResult(client); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dialed:
	case <-time.After(time.Second):
		t.Fatal("dial not reached")
	}
	_ = client.Close()
	<-done
}

func TestServerRejectsAlteredDestinationBeforeDial(t *testing.T) {
	verifier, bundle := proofBundle(t)
	allow, _ := sessiontcp.ParseAllowlist("*:*")
	dialed := false
	server := &Server{
		Verifier:     verifier,
		ExpectedNode: "node-a",
		Authorize:    allow.Authorize,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("unexpected")
		},
	}
	metadata, err := EncodeRequest("tcp", "127.0.0.1:9443", bundle)
	if err != nil {
		t.Fatal(err)
	}
	client, service := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background(), service, metadata) }()
	if err := readResult(client); err == nil {
		t.Fatal("altered destination accepted")
	}
	_ = client.Close()
	<-done
	if dialed {
		t.Fatal("dial called for altered destination")
	}
}

func TestServerRejectsReplay(t *testing.T) {
	verifier, bundle := proofBundle(t)
	allow, _ := sessiontcp.ParseAllowlist("127.0.0.1:8443")
	server := &Server{
		Verifier:     verifier,
		ExpectedNode: "node-a",
		Authorize:    allow.Authorize,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			client, service := net.Pipe()
			go service.Close()
			return client, nil
		},
	}
	metadata, _ := EncodeRequest("tcp", "127.0.0.1:8443", bundle)
	run := func() error {
		client, service := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- server.Serve(context.Background(), service, metadata) }()
		err := readResult(client)
		_ = client.Close()
		<-done
		return err
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil {
		t.Fatal("replayed proof accepted")
	}
}
