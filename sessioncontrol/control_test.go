package sessioncontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionmux"
)

func TestSignedRegistrationAndAuthorizedTarget(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chainSHA := strings.Repeat("a", 64)
	contextValue := testNodeContext("endpoint", "chain-a", chainSHA, "signed-endpoint-nonce")
	signed, err := authproof.SignNodeContext(contextValue, privateKey)
	if err != nil {
		t.Fatalf("sign node context: %v", err)
	}

	leftConn, rightConn := net.Pipe()
	left, err := sessionmux.New(leftConn, sessionmux.Config{Role: sessionmux.RoleInitiator})
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	right, err := sessionmux.New(rightConn, sessionmux.Config{Role: sessionmux.RoleResponder})
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()

	registry := NewRegistry()
	verify := NewAuthproofVerifier(publicKey, authproof.NodeContextVerifyOptions{
		Audience:    authproof.AudienceNodeContext,
		ChainID:     "chain-a",
		ChainSHA256: chainSHA,
		CurrentNode: "endpoint",
		MaxTTL:      2 * time.Minute,
		ReplayCache: authproof.NewNonceCache(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverResult := make(chan struct {
		node Node
		err  error
	}, 1)
	go func() {
		node, serveErr := ServeRegistration(ctx, right, registry, verify, "x11-session-binding")
		serverResult <- struct {
			node Node
			err  error
		}{node: node, err: serveErr}
	}()

	response, err := RegisterNode(
		ctx,
		left,
		signed,
		[]sessionmux.ServiceID{sessionmux.ServiceFS, sessionmux.ServiceTCP},
		"x11-session-binding",
	)
	if err != nil {
		t.Fatalf("register node: %v", err)
	}
	if response.Node != "endpoint" {
		t.Fatalf("registered node=%q", response.Node)
	}
	served := <-serverResult
	if served.err != nil {
		t.Fatalf("serve registration: %v", served.err)
	}
	if served.node.ID != "endpoint" || !served.node.Supports(sessionmux.ServiceFS) {
		t.Fatalf("registered node=%+v", served.node)
	}

	acceptedResult := make(chan struct {
		target AcceptedTarget
		err    error
	}, 1)
	go func() {
		target, acceptErr := AcceptTarget(ctx, right, registry, "endpoint")
		acceptedResult <- struct {
			target AcceptedTarget
			err    error
		}{target: target, err: acceptErr}
	}()

	clientStream, err := OpenTarget(ctx, left, "endpoint", sessionmux.ServiceFS, []byte("root=/srv/data"))
	if err != nil {
		t.Fatalf("open authorized target: %v", err)
	}
	accepted := <-acceptedResult
	if accepted.err != nil {
		t.Fatalf("accept authorized target: %v", accepted.err)
	}
	if accepted.target.Node.ID != "endpoint" || string(accepted.target.Data) != "root=/srv/data" {
		t.Fatalf("accepted target=%+v data=%q", accepted.target.Node, accepted.target.Data)
	}

	if _, err := clientStream.Write([]byte("filesystem-request")); err != nil {
		t.Fatal(err)
	}
	request := make([]byte, len("filesystem-request"))
	if _, err := io.ReadFull(accepted.target.Stream, request); err != nil {
		t.Fatal(err)
	}
	if string(request) != "filesystem-request" {
		t.Fatalf("request=%q", request)
	}
	_ = clientStream.Close()
	_ = accepted.target.Stream.Close()
}

func TestUnknownNodeIsResetBeforeTargetUse(t *testing.T) {
	registry := NewRegistry()
	if _, err := registry.RegisterVerified(
		testNodeContext("endpoint", "chain-a", strings.Repeat("a", 64), "known-node-nonce"),
		[]sessionmux.ServiceID{sessionmux.ServiceFS},
	); err != nil {
		t.Fatal(err)
	}

	leftConn, rightConn := net.Pipe()
	left, _ := sessionmux.New(leftConn, sessionmux.Config{Role: sessionmux.RoleInitiator})
	defer left.Close()
	right, _ := sessionmux.New(rightConn, sessionmux.Config{Role: sessionmux.RoleResponder})
	defer right.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		_, err := AcceptTarget(ctx, right, registry, "endpoint")
		serverErr <- err
	}()
	_, err := OpenTarget(ctx, left, "unknown-node", sessionmux.ServiceFS, nil)
	if !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("OpenTarget error=%v want ErrTargetDenied", err)
	}
	if err := <-serverErr; !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("AcceptTarget error=%v want ErrTargetDenied", err)
	}
}

func TestRegistrationRejectsWrongSessionBinding(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chainSHA := strings.Repeat("a", 64)
	signed, err := authproof.SignNodeContext(
		testNodeContext("endpoint", "chain-a", chainSHA, "wrong-binding-nonce"),
		privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	leftConn, rightConn := net.Pipe()
	left, _ := sessionmux.New(leftConn, sessionmux.Config{Role: sessionmux.RoleInitiator})
	defer left.Close()
	right, _ := sessionmux.New(rightConn, sessionmux.Config{Role: sessionmux.RoleResponder})
	defer right.Close()
	registry := NewRegistry()
	verify := NewAuthproofVerifier(publicKey, authproof.NodeContextVerifyOptions{
		Audience:    authproof.AudienceNodeContext,
		ChainID:     "chain-a",
		ChainSHA256: chainSHA,
		CurrentNode: "endpoint",
		MaxTTL:      2 * time.Minute,
		ReplayCache: authproof.NewNonceCache(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		_, err := ServeRegistration(ctx, right, registry, verify, "expected-binding")
		serverErr <- err
	}()
	_, err = RegisterNode(ctx, left, signed, []sessionmux.ServiceID{sessionmux.ServiceFS}, "wrong-binding")
	if !errors.Is(err, ErrControlDenied) {
		t.Fatalf("RegisterNode error=%v want ErrControlDenied", err)
	}
	if err := <-serverErr; !errors.Is(err, ErrWrongBinding) {
		t.Fatalf("ServeRegistration error=%v want ErrWrongBinding", err)
	}
}
