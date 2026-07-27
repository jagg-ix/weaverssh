package app

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionbroker"
	"weaverssh/sessioncontrol"
	"weaverssh/sessiondispatch"
	"weaverssh/sessionmux"
	"weaverssh/sessionroute"
	"weaverssh/sessiontcp"
)

func TestThreeNodeTCPRoutingAcrossTwoMuxes(t *testing.T) {
	nodes := []string{"workstation-42", "jump-a", "compute-node"}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sign := func(node, nonce string, capabilities []string) authproof.SignedNodeContext {
		t.Helper()
		signed, err := authproof.SignNodeContext(authproof.NodeContext{
			IssuerPeerID: "routed-tcp-test",
			Audience: authproof.AudienceNodeContext,
			ChainID: "routed-tcp-chain",
			ChainSHA256: authproof.ChainBindingSHA256(nodes...),
			Nodes: nodes,
			CurrentNode: node,
			OriginNode: nodes[0],
			EndpointNode: nodes[2],
			Capabilities: capabilities,
			Nonce: nonce,
			IssuedAtUnix: now.Unix(),
			ExpiresAtUnix: now.Add(10 * time.Minute).Unix(),
		}, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	workstationContext := sign(nodes[0], "tcp-workstation", []string{authproof.CapabilityNodeContext, authproof.CapabilitySocksProxy})
	jumpContext := sign(nodes[1], "tcp-jump", []string{authproof.CapabilityNodeContext})
	computeContext := sign(nodes[2], "tcp-compute", []string{authproof.CapabilityNodeContext, authproof.CapabilitySocksProxy})
	allow, err := sessiontcp.ParseAllowlist("echo.internal:9000")
	if err != nil {
		t.Fatal(err)
	}
	makeDial := func(prefix string) sessiontcp.DialContextFunc {
		return func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "echo.internal:9000" {
				return nil, io.ErrUnexpectedEOF
			}
			service, peer := net.Pipe()
			go func() {
				defer peer.Close()
				payload, err := bufio.NewReader(peer).ReadString('\n')
				if err == nil {
					_, _ = io.WriteString(peer, prefix+payload)
				}
			}()
			return service, nil
		}
	}
	workstationServices, err := NewLocalServices(LocalServiceConfig{
		SignedContext: workstationContext,
		PublicKey: publicKey,
		TCPAllow: allow,
		TCPDial: makeDial("workstation:"),
	})
	if err != nil {
		t.Fatal(err)
	}
	computeServices, err := NewLocalServices(LocalServiceConfig{
		SignedContext: computeContext,
		PublicKey: publicKey,
		TCPAllow: allow,
		TCPDial: makeDial("compute:"),
	})
	if err != nil {
		t.Fatal(err)
	}

	workstationConn, jumpParentConn := net.Pipe()
	jumpChildConn, computeConn := net.Pipe()
	workstationMux, err := sessionmux.New(workstationConn, sessionmux.Config{Role: sessionmux.RoleInitiator})
	if err != nil {
		t.Fatal(err)
	}
	jumpParentMux, err := sessionmux.New(jumpParentConn, sessionmux.Config{Role: sessionmux.RoleResponder})
	if err != nil {
		t.Fatal(err)
	}
	jumpChildMux, err := sessionmux.New(jumpChildConn, sessionmux.Config{Role: sessionmux.RoleInitiator})
	if err != nil {
		t.Fatal(err)
	}
	computeMux, err := sessionmux.New(computeConn, sessionmux.Config{Role: sessionmux.RoleResponder})
	if err != nil {
		t.Fatal(err)
	}
	defer workstationMux.Close()
	defer jumpParentMux.Close()
	defer jumpChildMux.Close()
	defer computeMux.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	routeStore := sessionroute.Store{Path: filepath.Join(t.TempDir(), "routes.json")}
	parentSocket := filepath.Join(t.TempDir(), "parent.sock")
	childSocket := filepath.Join(t.TempDir(), "child.sock")
	parentListener, err := net.Listen("unix", parentSocket)
	if err != nil {
		t.Fatal(err)
	}
	childListener, err := net.Listen("unix", childSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer parentListener.Close()
	defer childListener.Close()

	jumpParentRouter := &sessionroute.Router{
		Store: routeStore,
		Context: jumpContext.Context,
		CurrentBinding: "parent-binding",
		CurrentMux: jumpParentMux,
		PeerNode: nodes[0],
	}
	jumpChildRouter := &sessionroute.Router{
		Store: routeStore,
		Context: jumpContext.Context,
		CurrentBinding: "child-binding",
		CurrentMux: jumpChildMux,
		PeerNode: nodes[2],
	}
	parentEntry, err := sessionroute.NewEntry(jumpContext.Context, "parent-binding", parentSocket, nodes[0], os.Getpid(), now)
	if err != nil {
		t.Fatal(err)
	}
	childEntry, err := sessionroute.NewEntry(jumpContext.Context, "child-binding", childSocket, nodes[2], os.Getpid(), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := routeStore.Register(ctx, parentEntry); err != nil {
		t.Fatal(err)
	}
	if err := routeStore.Register(ctx, childEntry); err != nil {
		t.Fatal(err)
	}

	parentBrokerErr := make(chan error, 1)
	childBrokerErr := make(chan error, 1)
	go func() {
		parentBrokerErr <- (&sessionbroker.Server{Open: func(openCtx context.Context, request sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
			return jumpParentRouter.OpenLocal(openCtx, request.Node, request.Service, request.Data)
		}}).Serve(ctx, parentListener)
	}()
	go func() {
		childBrokerErr <- (&sessionbroker.Server{Open: func(openCtx context.Context, request sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
			return jumpChildRouter.OpenLocal(openCtx, request.Node, request.Service, request.Data)
		}}).Serve(ctx, childListener)
	}()

	dispatchErr := make(chan error, 4)
	go func() {
		dispatchErr <- (&sessiondispatch.Dispatcher{Mux: workstationMux, Target: workstationServices.HandleStream}).Serve(ctx)
	}()
	go func() {
		dispatchErr <- (&sessiondispatch.Dispatcher{Mux: computeMux, Target: computeServices.HandleStream}).Serve(ctx)
	}()
	go func() {
		dispatchErr <- (&sessiondispatch.Dispatcher{Mux: jumpParentMux, Target: func(routeCtx context.Context, stream *sessionmux.Stream) error {
			pending, err := sessioncontrol.InspectAcceptedTarget(stream)
			if err != nil {
				return err
			}
			return jumpParentRouter.Forward(routeCtx, pending)
		}}).Serve(ctx)
	}()
	go func() {
		dispatchErr <- (&sessiondispatch.Dispatcher{Mux: jumpChildMux, Target: func(routeCtx context.Context, stream *sessionmux.Stream) error {
			pending, err := sessioncontrol.InspectAcceptedTarget(stream)
			if err != nil {
				return err
			}
			return jumpChildRouter.Forward(routeCtx, pending)
		}}).Serve(ctx)
	}()

	assertRoutedTCP := func(mux *sessionmux.Mux, target, payload, want string) {
		t.Helper()
		stream, err := sessiontcp.OpenMux(ctx, mux, target, "tcp", "echo.internal:9000")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(stream, payload+"\n"); err != nil {
			t.Fatal(err)
		}
		response, err := bufio.NewReader(stream).ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if response != want+"\n" {
			t.Fatalf("response=%q want=%q", response, want+"\n")
		}
		_ = stream.Close()
	}
	assertRoutedTCP(workstationMux, nodes[2], "from-root", "compute:from-root")
	assertRoutedTCP(computeMux, nodes[0], "from-final", "workstation:from-final")

	cancel()
	_ = workstationMux.Close()
	_ = jumpParentMux.Close()
	_ = jumpChildMux.Close()
	_ = computeMux.Close()
	_ = parentListener.Close()
	_ = childListener.Close()
	for count := 0; count < 4; count++ {
		select {
		case err := <-dispatchErr:
			if err != nil && ctx.Err() == nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("dispatcher did not stop")
		}
	}
	for name, channel := range map[string]<-chan error{"parent": parentBrokerErr, "child": childBrokerErr} {
		select {
		case err := <-channel:
			if err != nil && ctx.Err() == nil {
				t.Fatalf("%s broker: %v", name, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s broker did not stop", name)
		}
	}
}
