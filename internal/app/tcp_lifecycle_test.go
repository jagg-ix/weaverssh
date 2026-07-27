package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessioncontrol"
	"weaverssh/sessionroute"
	"weaverssh/sessionruntime"
	"weaverssh/sessiontcp"
)

func TestDynamicSessionTCPDialsOnNamedNode(t *testing.T) {
	const cookie = "0123456789abcdef0123456789abcdef"
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := []string{"origin", "endpoint"}
	chainHash := authproof.ChainBindingSHA256(chain...)
	now := time.Now()
	sign := func(node, nonce string) authproof.SignedNodeContext {
		signed, err := authproof.SignNodeContext(authproof.NodeContext{
			IssuerPeerID: "test-issuer",
			Audience: authproof.AudienceNodeContext,
			ChainID: "test-chain",
			ChainSHA256: chainHash,
			Nodes: chain,
			CurrentNode: node,
			OriginNode: "origin",
			EndpointNode: "endpoint",
			Capabilities: []string{authproof.CapabilityNodeContext, authproof.CapabilitySocksProxy},
			Nonce: nonce,
			IssuedAtUnix: now.Add(-time.Second).Unix(),
			ExpiresAtUnix: now.Add(5 * time.Minute).Unix(),
		}, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	originContext := sign("origin", "origin-tcp-nonce")
	endpointContext := sign("endpoint", "endpoint-tcp-nonce")
	allow, err := sessiontcp.ParseAllowlist("echo.internal:9000")
	if err != nil {
		t.Fatal(err)
	}
	calls := make(chan string, 4)
	makeDial := func(node string) sessiontcp.DialContextFunc {
		return func(_ context.Context, network, address string) (net.Conn, error) {
			calls <- node + " " + network + " " + address
			server, peer := net.Pipe()
			go func() {
				defer peer.Close()
				buf := make([]byte, 64)
				n, err := peer.Read(buf)
				if err == nil {
					_, _ = peer.Write(append([]byte(node+":"), buf[:n]...))
				}
			}()
			return server, nil
		}
	}

	hostReady := make(chan *sessionruntime.Session, 1)
	host, err := NewDynamicHost(DynamicHostConfig{
		SignedContext: originContext,
		PublicKey: publicKey,
		TCPAllow: allow,
		TCPDial: makeDial("origin"),
		OnReady: func(
			session *sessionruntime.Session,
			_ *sessioncontrol.Registry,
			_, _ sessioncontrol.Node,
			_ *sessionroute.Router,
		) (func(), error) {
			hostReady <- session
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	endpointServices, err := NewLocalServices(LocalServiceConfig{
		SignedContext: endpointContext,
		PublicKey: publicKey,
		TCPAllow: allow,
		TCPDial: makeDial("endpoint"),
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewAgentRuntime(AgentConfig{
		InterfaceMode: string(AgentInterfaceLibrary),
		X11Network: "tcp",
		X11Target: "unused:0",
		AuthTimeout: 2 * time.Second,
		Proof: authproof.RuntimeConfig{Mode: authproof.ProofModeOff, SecurityLevel: authproof.SecurityLevelCompat},
	}, cookie)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	hostErr := make(chan error, 1)
	go func() { hostErr <- runtime.ServeDynamicSessionConn(ctx, serverConn, host.Serve) }()
	oldDisplay := os.Getenv("DISPLAY")
	_ = os.Setenv("DISPLAY", "localhost:10.0")
	defer os.Setenv("DISPLAY", oldDisplay)
	attached, err := AttachDynamicSession(ctx, AttachConfig{
		AuthCookie: cookie,
		SignedContext: endpointContext,
		LocalServices: endpointServices,
		DialTimeout: time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) { return clientConn, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	hostSession := <-hostReady

	assertEcho := func(session *sessionruntime.Session, node, payload, wantPrefix string) {
		t.Helper()
		stream, err := sessiontcp.OpenMux(ctx, session.Mux, node, "tcp", "echo.internal:9000")
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		if _, err := stream.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len(wantPrefix)+len(payload))
		if _, err := io.ReadFull(stream, response); err != nil {
			t.Fatal(err)
		}
		if string(response) != wantPrefix+payload {
			t.Fatalf("node=%s response=%q", node, response)
		}
	}
	assertEcho(attached.Session, "origin", "from-endpoint", "origin:")
	assertEcho(hostSession, "endpoint", "from-origin", "endpoint:")

	first := <-calls
	second := <-calls
	joined := first + "\n" + second
	if !strings.Contains(joined, "origin tcp echo.internal:9000") || !strings.Contains(joined, "endpoint tcp echo.internal:9000") {
		t.Fatalf("dial calls:\n%s", joined)
	}
	cancel()
	_ = attached.Close()
	select {
	case err := <-hostErr:
		if err != nil && ctx.Err() == nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("host did not exit")
	}
}
