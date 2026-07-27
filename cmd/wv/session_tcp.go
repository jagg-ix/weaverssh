package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"weaverssh/authproof"
	"weaverssh/internal/app"
	"weaverssh/sessionbind"
	"weaverssh/sessionbroker"
	"weaverssh/sessionproxy"
	"weaverssh/sessiontcp"
	"weaverssh/sessiontcpproof"
	"weaverssh/sessionudp"
	"weaverssh/sessionudpproof"
	"weaverssh/socksproof"
)

func cmdConnect(args []string) int {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	network := fs.String("network", "tcp", "destination network: tcp, tcp4, or tcp6")
	timeout := fs.Duration("timeout", 30*time.Second, "broker and remote dial timeout")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "usage: wv connect [--network tcp] NODE HOST:PORT") }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return 2
	}
	node := strings.TrimSpace(fs.Arg(0))
	address := strings.TrimSpace(fs.Arg(1))
	if node == "" || address == "" {
		fs.Usage()
		return 2
	}
	state, err := sessionbroker.ActiveState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv connect: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	dialCtx, cancel := context.WithTimeout(ctx, *timeout)
	conn, err := sessiontcp.DialBroker(dialCtx, state.Socket, node, *network, address)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv connect: %v\n", err)
		return 1
	}
	defer conn.Close()
	return relayConsole(ctx, conn, "wv connect")
}

func cmdSessionProxy(args []string) int {
	fs := flag.NewFlagSet("session-proxy", flag.ContinueOnError)
	node := fs.String("node", "", "registered node that performs destination operations")
	listenAddress := fs.String("listen", "127.0.0.1:0", "local SOCKS5 TCP control listen address")
	allowNonLoopback := fs.Bool("allow-non-loopback", false, "permit an explicitly configured non-loopback listener")
	enableUDP := fs.Bool("enable-udp", false, "enable RFC 1928 UDP ASSOCIATE, including proof-authenticated datagrams")
	enableBind := fs.Bool("enable-bind", false, "enable one-shot SOCKS5 BIND through the selected node")
	timeout := fs.Duration("timeout", 30*time.Second, "broker and remote operation timeout")
	jsonOut := fs.Bool("json", false, "emit selected listener metadata as JSON")
	authMode := fs.String("auth", "proof", "SOCKS5 authentication: proof or none")
	proofPolicy := fs.String("proof-policy", os.Getenv(app.EnvSocksProofPolicy), "cryptographic SOCKS client policy JSON")
	proofServerID := fs.String("proof-server-id", "", "expected policy server ID; defaults to policy value")
	challengeTTL := fs.Duration("proof-challenge-ttl", 30*time.Second, "SOCKS proof challenge lifetime")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv session-proxy --node NODE [--auth proof --proof-policy FILE] [--enable-udp] [--enable-bind] [--listen 127.0.0.1:0]")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(*node) == "" {
		fs.Usage()
		return 2
	}
	if !*allowNonLoopback && !isLoopbackListen(*listenAddress) {
		fmt.Fprintln(os.Stderr, "wv session-proxy: refusing non-loopback listener without --allow-non-loopback")
		return 2
	}
	initialState, err := sessionbroker.ActiveState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv session-proxy: %v\n", err)
		return 1
	}
	mode := strings.ToLower(strings.TrimSpace(*authMode))
	if mode != "proof" && mode != "none" {
		fmt.Fprintln(os.Stderr, "wv session-proxy: --auth must be proof or none")
		return 2
	}

	var verifier *socksproof.Verifier
	var proofPolicyServerID string
	if mode == "proof" {
		if strings.TrimSpace(*proofPolicy) == "" {
			fmt.Fprintln(os.Stderr, "wv session-proxy: proof mode requires --proof-policy")
			return 2
		}
		policy, err := socksproof.LoadPolicyFile(*proofPolicy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wv session-proxy: load proof policy: %v\n", err)
			return 1
		}
		if strings.TrimSpace(*proofServerID) != "" && strings.TrimSpace(*proofServerID) != strings.TrimSpace(policy.ServerID) {
			fmt.Fprintln(os.Stderr, "wv session-proxy: --proof-server-id does not match policy")
			return 2
		}
		verifier, err = socksproof.NewVerifier(policy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wv session-proxy: proof policy: %v\n", err)
			return 1
		}
		proofPolicyServerID = policy.ServerID
	}
	currentState := func() (sessionbroker.State, error) {
		state, err := sessionbroker.ActiveState()
		if err != nil {
			return sessionbroker.State{}, err
		}
		if strings.TrimSpace(state.Socket) == "" || strings.TrimSpace(state.Binding) == "" {
			return sessionbroker.State{}, fmt.Errorf("active session has incomplete broker state")
		}
		return state, nil
	}
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv session-proxy: listen: %v\n", err)
		return 1
	}
	defer listener.Close()
	metadata := map[string]any{
		"listen":          listener.Addr().String(),
		"node":            strings.TrimSpace(*node),
		"socket":          initialState.Socket,
		"startup_binding": initialState.Binding,
		"binding_refresh": true,
		"auth":            mode,
		"udp_associate":   *enableUDP,
		"bind":            *enableBind,
	}
	if verifier != nil {
		metadata["method"] = fmt.Sprintf("0x%02x", socksproof.MethodPrivate)
		metadata["server_id"] = proofPolicyServerID
		metadata["policy_sha256"] = verifier.PolicySHA256
		metadata["final_node_udp_verification"] = *enableUDP
	}
	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(metadata)
	} else {
		fmt.Printf("SOCKS5 listening on %s via node %s auth=%s udp_associate=%t bind=%t binding_refresh=true\n", listener.Addr(), strings.TrimSpace(*node), mode, *enableUDP, *enableBind)
		if verifier != nil {
			fmt.Printf("proof method=0x%02x server_id=%s policy_sha256=%s startup_binding=%s final_node_udp_verification=%t\n", socksproof.MethodPrivate, proofPolicyServerID, verifier.PolicySHA256, initialState.Binding, *enableUDP)
		}
		fmt.Println("static forwarding ports: none")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	server := &sessionproxy.Server{AllowNoAuth: mode == "none"}
	if verifier != nil {
		server.ProofProvider = func(_ context.Context) (*socksproof.ServerConfig, error) {
			state, err := currentState()
			if err != nil {
				return nil, err
			}
			return &socksproof.ServerConfig{
				Verifier:       verifier,
				ServerID:       proofPolicyServerID,
				SessionBinding: state.Binding,
				SelectedNode:   strings.TrimSpace(*node),
				ChallengeTTL:   *challengeTTL,
			}, nil
		}
	}
	server.Dial = func(openCtx context.Context, network, address string) (net.Conn, error) {
		state, err := currentState()
		if err != nil {
			return nil, err
		}
		dialCtx, cancel := context.WithTimeout(openCtx, *timeout)
		defer cancel()
		return sessiontcp.DialBroker(dialCtx, state.Socket, strings.TrimSpace(*node), network, address)
	}
	server.DialProof = func(openCtx context.Context, network, address string, bundle socksproof.Bundle) (net.Conn, error) {
		state, err := currentState()
		if err != nil {
			return nil, err
		}
		dialCtx, cancel := context.WithTimeout(openCtx, *timeout)
		defer cancel()
		return sessiontcpproof.DialBroker(dialCtx, state.Socket, strings.TrimSpace(*node), network, address, bundle)
	}
	if *enableBind {
		server.Bind = func(openCtx context.Context, network, address string) (sessionproxy.BindListener, error) {
			state, err := currentState()
			if err != nil {
				return nil, err
			}
			bindCtx, cancel := context.WithTimeout(openCtx, *timeout)
			defer cancel()
			return sessionbind.DialBroker(bindCtx, state.Socket, strings.TrimSpace(*node), network, address)
		}
		server.BindProof = func(openCtx context.Context, network, address string, bundle socksproof.Bundle) (sessionproxy.BindListener, error) {
			state, err := currentState()
			if err != nil {
				return nil, err
			}
			bindCtx, cancel := context.WithTimeout(openCtx, *timeout)
			defer cancel()
			return sessiontcpproof.DialBindBroker(bindCtx, state.Socket, strings.TrimSpace(*node), network, address, bundle)
		}
	}
	if *enableUDP {
		server.AssociateUDP = func(openCtx context.Context, network string) (sessionproxy.UDPAssociation, error) {
			state, err := currentState()
			if err != nil {
				return nil, err
			}
			if verifier != nil {
				// The proof association dials lazily after the client association
				// bundle is available. This prevents proof mode from falling back
				// to the unsigned routed UDP protocol.
				return sessionudpproof.NewAssociation(state.Socket, strings.TrimSpace(*node), network), nil
			}
			dialCtx, cancel := context.WithTimeout(openCtx, *timeout)
			defer cancel()
			return sessionudp.DialBroker(dialCtx, state.Socket, strings.TrimSpace(*node), network)
		}
	}
	if err := server.Serve(ctx, listener); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "wv session-proxy: %v\n", err)
		return 1
	}
	return 0
}

func cmdSocksConnect(args []string) int {
	fs := flag.NewFlagSet("socks-connect", flag.ContinueOnError)
	proxy := fs.String("proxy", "", "proof-enabled SOCKS5 proxy HOST:PORT")
	principal := fs.String("principal", "", "client principal from policy")
	serverID := fs.String("server-id", "", "expected proof-policy server ID")
	policySHA256 := fs.String("policy-sha256", "", "expected canonical SOCKS policy SHA-256")
	node := fs.String("node", "", "expected final node that performs the dial")
	privateKeyFile := fs.String("private-key", "", "raw/base64 Ed25519 private key file")
	signerProvider := fs.String("signer", "ssh-agent", "signer: ssh-agent, gpg-agent, or key")
	agentSocket := fs.String("agent-socket", "", "SSH-compatible agent socket")
	identity := fs.String("identity", "", "agent identity selector")
	identityFile := fs.String("identity-file", "", "agent identity/public-key selector file")
	proofTTL := fs.Duration("proof-ttl", 30*time.Second, "proof lifetime")
	timeout := fs.Duration("timeout", 30*time.Second, "proxy handshake timeout")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv socks-connect --proxy HOST:PORT --server-id ID --policy-sha256 HEX --node NODE --principal ID [signer options] DEST:PORT")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || strings.TrimSpace(*proxy) == "" || strings.TrimSpace(*principal) == "" || strings.TrimSpace(*serverID) == "" || strings.TrimSpace(*policySHA256) == "" || strings.TrimSpace(*node) == "" {
		fs.Usage()
		return 2
	}
	signer, code := buildSocksProofSigner(*signerProvider, *privateKeyFile, *agentSocket, *identity, *identityFile)
	if code != 0 {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	dialCtx, cancel := context.WithTimeout(ctx, *timeout)
	conn, _, err := socksproof.Dial(dialCtx, *proxy, fs.Arg(0), socksproof.ClientConfig{
		Principal:            *principal,
		Capabilities:         []string{socksproof.CapabilityConnect},
		Signer:               signer,
		ProofTTL:             *proofTTL,
		ExpectedServerID:     strings.TrimSpace(*serverID),
		ExpectedPolicySHA256: strings.ToLower(strings.TrimSpace(*policySHA256)),
		ExpectedNode:         strings.TrimSpace(*node),
	})
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socks-connect: %v\n", err)
		return 1
	}
	defer conn.Close()
	return relayConsole(ctx, conn, "wv socks-connect")
}

func buildSocksProofSigner(providerText, privateKeyFile, agentSocket, identity, identityFile string) (socksproof.Signer, int) {
	provider := authproof.NormalizeSignerProvider(providerText)
	switch provider {
	case authproof.SignerProviderKeyMaterial:
		if strings.TrimSpace(privateKeyFile) == "" {
			fmt.Fprintln(os.Stderr, "wv: --private-key is required for key signer")
			return nil, 2
		}
		payload, err := os.ReadFile(privateKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wv: read private key: %v\n", err)
			return nil, 1
		}
		key, err := authproof.DecodePrivateKey(strings.TrimSpace(string(payload)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "wv: decode private key: %v\n", err)
			return nil, 1
		}
		return socksproof.Ed25519Signer(key), 0
	case authproof.SignerProviderSSHAgent, authproof.SignerProviderGPGAgent:
		if strings.TrimSpace(identity) == "" && strings.TrimSpace(identityFile) == "" {
			fmt.Fprintln(os.Stderr, "wv: agent signing requires --identity or --identity-file")
			return nil, 2
		}
		return socksproof.AgentSigner{Config: authproof.AgentMessageSigner{
			Provider:      provider,
			Socket:        agentSocket,
			Identity:      identity,
			IdentityFile:  identityFile,
			PublicKeyFile: identityFile,
		}}, 0
	default:
		fmt.Fprintf(os.Stderr, "wv: unsupported signer provider %q\n", providerText)
		return nil, 2
	}
}

func relayConsole(ctx context.Context, conn net.Conn, label string) int {
	writeDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, os.Stdin)
		if closer, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		writeDone <- err
	}()
	_, readErr := io.Copy(os.Stdout, conn)
	_ = conn.Close()
	select {
	case writeErr := <-writeDone:
		if writeErr != nil && readErr == nil {
			readErr = writeErr
		}
	case <-time.After(250 * time.Millisecond):
	}
	if readErr != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "%s: relay: %v\n", label, readErr)
		return 1
	}
	return 0
}

func isLoopbackListen(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
