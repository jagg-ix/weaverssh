package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/internal/p9client"
	"weaverssh/internal/p9svc"
	"weaverssh/sessioncontrol"
	"weaverssh/sessionmux"
	"weaverssh/sessionruntime"
)

func TestAuthorizedP9OverX11DerivedDynamicSession(t *testing.T) {
	const (
		cookie   = "0123456789abcdef0123456789abcdef"
		chainID  = "chain-runtime-test"
		chainSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello over x11-derived session\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p9Server, err := p9svc.New(p9svc.Config{Root: root, ReadOnly: false})
	if err != nil {
		t.Fatal(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewAgentRuntime(AgentConfig{
		InterfaceMode: string(AgentInterfaceLibrary),
		X11Network:   "tcp",
		X11Target:    "unused:0",
		AuthTimeout:  2 * time.Second,
		Proof: authproof.RuntimeConfig{
			Mode:          authproof.ProofModeOff,
			SecurityLevel: authproof.SecurityLevelCompat,
		},
	}, cookie)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- runtime.ServeDynamicSessionConn(ctx, serverConn, func(ctx context.Context, session *sessionruntime.Session, authority DynamicSessionContext) error {
			registry := sessioncontrol.NewRegistry()
			verify := sessioncontrol.NewAuthproofVerifier(publicKey, authproof.NodeContextVerifyOptions{
				Audience:    authproof.AudienceNodeContext,
				ChainID:     chainID,
				ChainSHA256: chainSHA,
				CurrentNode: "endpoint",
				MaxTTL:      2 * time.Minute,
				ReplayCache: authproof.NewNonceCache(),
			})
			if _, err := sessioncontrol.ServeRegistration(ctx, session.Mux, registry, verify, authority.Binding); err != nil {
				return err
			}
			accepted, err := sessioncontrol.AcceptTarget(ctx, session.Mux, registry, "endpoint")
			if err != nil {
				return err
			}
			if accepted.Node.ID != "endpoint" || accepted.Stream.Service() != sessionmux.ServiceFS {
				return errors.New("authorized filesystem target resolved incorrectly")
			}
			return p9Server.ServeTransport(accepted.Stream)
		})
	}()

	clientSession, err := OpenDynamicSessionConn(ctx, clientConn, DynamicSessionClientConfig{AuthCookie: cookie})
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	now := time.Now()
	nonce, err := authproof.NewRandomNonce(24)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := authproof.SignNodeContext(authproof.NodeContext{
		IssuerPeerID:  "runtime-test-issuer",
		Audience:      authproof.AudienceNodeContext,
		ChainID:       chainID,
		ChainSHA256:   chainSHA,
		Nodes:         []string{"origin", "endpoint"},
		CurrentNode:   "endpoint",
		OriginNode:    "origin",
		EndpointNode:  "endpoint",
		Capabilities:  []string{authproof.CapabilityNodeContext, authproof.CapabilityVFSMesh},
		Nonce:         nonce,
		IssuedAtUnix:  now.Add(-time.Second).Unix(),
		ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	registered, err := sessioncontrol.RegisterNode(ctx, clientSession.Mux, signed, []sessionmux.ServiceID{sessionmux.ServiceFS}, clientSession.Binding)
	if err != nil {
		t.Fatal(err)
	}
	if registered.Node != "endpoint" {
		t.Fatalf("registered node=%q", registered.Node)
	}

	fsStream, err := sessioncontrol.OpenTarget(ctx, clientSession.Mux, "endpoint", sessionmux.ServiceFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := p9client.Attach(fsStream)
	if err != nil {
		t.Fatal(err)
	}
	data, err := client.ReadFile("hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello over x11-derived session\n" {
		t.Fatalf("hello.txt=%q", data)
	}
	if err := client.WriteFile("uploaded.txt", []byte("uploaded through authenticated dynamic session\n")); err != nil {
		t.Fatal(err)
	}
	uploaded, err := os.ReadFile(filepath.Join(root, "uploaded.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(uploaded) != "uploaded through authenticated dynamic session\n" {
		t.Fatalf("uploaded.txt=%q", uploaded)
	}
	if err := client.Close(); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}

	select {
	case err := <-serverResult:
		if err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "closed") {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("dynamic session server did not terminate")
	}
}
