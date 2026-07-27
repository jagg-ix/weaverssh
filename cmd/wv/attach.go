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

	"weaverssh/internal/app"
	"weaverssh/sessionbroker"
	"weaverssh/sessionlink"
	"weaverssh/sessionroute"
	"weaverssh/sessiontcp"
	"weaverssh/sessionudp"
)

const envHopAllowedSigners = "WEAVERSSH_HOP_ALLOWED_SIGNERS"
const envRouteRegistry = "WEAVERSSH_ROUTE_REGISTRY"
const envReconnectIdentityFile = "WEAVERSSH_RECONNECT_IDENTITY_FILE"
const envReconnectPrivateKeyFile = "WEAVERSSH_RECONNECT_PRIVATE_KEY_FILE"
const envReconnect = "WEAVERSSH_RECONNECT"

func cmdAttach(args []string) int {
	fs := flag.NewFlagSet("attach", flag.ContinueOnError)
	contextFile := fs.String("node-context", os.Getenv(envNodeContextFile), "signed node-context JSON for this SSH node")
	publicKeyFile := fs.String("public-key-file", os.Getenv(envNodeContextPublicKeyFile), "trusted node-context public key; required when serving local services")
	wvOriginText := fs.String("wvorigin", os.Getenv(app.EnvWVOrigin), "concrete immediate previous node received through SSH SetEnv")
	hopChainText := fs.String("hop-chain", os.Getenv(app.EnvWVHop), "encoded recursive SSHSIG hop chain received through SSH SetEnv")
	hopAllowedSigners := fs.String("hop-allowed-signers", os.Getenv(envHopAllowedSigners), "OpenSSH allowed-signers file for recursive hop verification")
	hopSSHKeygen := fs.String("hop-ssh-keygen", "ssh-keygen", "ssh-keygen executable used for SSHSIG verification")
	requireHopProof := fs.Bool("require-hop-proof", false, "reject attach when WVHOP is absent")
	proofFile := fs.String("proof", "", "optional signed runtime authproof JSON")
	reconnectIdentityFile := fs.String("reconnect-identity", os.Getenv(envReconnectIdentityFile), "authority-signed reusable reconnect identity JSON")
	reconnectPrivateKeyFile := fs.String("reconnect-private-key-file", os.Getenv(envReconnectPrivateKeyFile), "node Ed25519 private key certified by reconnect identity")
	reconnect := fs.Bool("reconnect", parseBoolEnvironment(os.Getenv(envReconnect)), "keep the broker alive and retry replacement transports")
	root := fs.String("root", "", "local directory served when this node receives fs targets")
	readOnly := fs.Bool("read-only", true, "serve --root read-only")
	tcpAllowText := fs.String("tcp-allow", "", "comma-separated TCP allow rules")
	udpAllowText := fs.String("udp-allow", "", "comma-separated UDP allow rules for SOCKS5 UDP ASSOCIATE")
	tcpProofPolicy := fs.String("tcp-proof-policy", os.Getenv(app.EnvSocksProofPolicy), "SOCKS client proof policy used by the final TCP service")
	tcpRequireProof := fs.Bool("tcp-require-proof", parseBoolEnvironment(os.Getenv(app.EnvTCPRequireProof)), "reject legacy unsigned TCP target metadata")
	maxTTL := fs.Duration("max-context-ttl", 10*time.Minute, "maximum accepted local node-context TTL")
	socketPath := fs.String("socket", "", "stable local Unix broker socket path")
	statePath := fs.String("state", "", "session state JSON path")
	routeRegistryPath := fs.String("route-registry", os.Getenv(envRouteRegistry), "base path for local multi-session route registries")
	timeout := fs.Duration("timeout", 10*time.Second, "DISPLAY dial and protocol handshake timeout")
	linkLease := fs.Duration("link-lease", 30*time.Second, "logical-link and route lease duration")
	brokerWait := fs.Duration("broker-wait", 15*time.Second, "maximum broker wait for a replacement transport")
	reconnectMinDelay := fs.Duration("reconnect-min-delay", time.Second, "minimum reconnect delay")
	reconnectMaxDelay := fs.Duration("reconnect-max-delay", 30*time.Second, "maximum reconnect delay")
	reconnectResetAfter := fs.Duration("reconnect-reset-after", time.Minute, "connected duration that resets reconnect history")
	reconnectJitter := fs.Float64("reconnect-jitter", 0.2, "fractional reconnect-delay jitter from 0 to 1")
	jsonOut := fs.Bool("json", false, "print attached session metadata as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv attach --node-context FILE [--reconnect --reconnect-identity FILE --reconnect-private-key-file KEY] [--root DIR]")
		fmt.Fprintf(os.Stderr, "Requires %s. Recursive sessions also pass %s.\n", app.EnvWVOrigin, app.EnvWVHop)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(*contextFile) == "" {
		fs.Usage()
		return 2
	}
	if *linkLease <= 0 || *linkLease > sessionlink.MaxLease {
		fmt.Fprintf(os.Stderr, "attach: --link-lease must be positive and at most %s\n", sessionlink.MaxLease)
		return 2
	}
	if *brokerWait <= 0 {
		fmt.Fprintln(os.Stderr, "attach: --broker-wait must be positive")
		return 2
	}

	signedContext, err := app.LoadSignedNodeContextFile(*contextFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attach: load node context: %v\n", err)
		return 1
	}
	wvOrigin, err := app.ValidateWVOrigin(*wvOriginText, signedContext.Context)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attach: %v\n", err)
		return 1
	}
	verifiedHop, err := app.VerifyIncomingRecursiveHop(
		context.Background(),
		signedContext.Context,
		*hopChainText,
		wvOrigin,
		*hopAllowedSigners,
		*hopSSHKeygen,
		*requireHopProof,
		time.Now(),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attach: recursive hop proof: %v\n", err)
		return 1
	}
	_ = os.Setenv(app.EnvWVOrigin, wvOrigin)
	if verifiedHop.Depth > 0 {
		_ = os.Setenv(app.EnvWVHop, strings.TrimSpace(*hopChainText))
	}

	tcpAllow, err := sessiontcp.ParseAllowlist(*tcpAllowText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attach: tcp allowlist: %v\n", err)
		return 2
	}
	udpAllow, err := sessionudp.ParseAllowlist(*udpAllowText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attach: udp allowlist: %v\n", err)
		return 2
	}
	attachConfig := app.AttachConfig{
		SignedContext:  signedContext,
		DialTimeout:    *timeout,
		PreviousNode:   wvOrigin,
		HopDepth:       verifiedHop.Depth,
		EncodedWVHop:   strings.TrimSpace(*hopChainText),
		RouteStorePath: *routeRegistryPath,
	}
	if strings.TrimSpace(*proofFile) != "" {
		proof, err := app.LoadSignedGrantFile(*proofFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "attach: load runtime proof: %v\n", err)
			return 1
		}
		attachConfig.RuntimeProof = &proof
	}
	identityConfigured := strings.TrimSpace(*reconnectIdentityFile) != "" || strings.TrimSpace(*reconnectPrivateKeyFile) != ""
	if identityConfigured {
		if strings.TrimSpace(*reconnectIdentityFile) == "" || strings.TrimSpace(*reconnectPrivateKeyFile) == "" {
			fmt.Fprintln(os.Stderr, "attach: --reconnect-identity and --reconnect-private-key-file are required together")
			return 2
		}
		identity, err := app.LoadSignedReconnectIdentityFile(*reconnectIdentityFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "attach: load reconnect identity: %v\n", err)
			return 1
		}
		privateKey, err := app.LoadEd25519PrivateKeyFile(*reconnectPrivateKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "attach: load reconnect private key: %v\n", err)
			return 1
		}
		attachConfig.ReconnectIdentity = &identity
		attachConfig.ReconnectPrivateKey = privateKey
	}
	if *reconnect && !identityConfigured {
		fmt.Fprintln(os.Stderr, "attach: --reconnect requires reusable reconnect identity and private key")
		return 2
	}

	serveLocal := strings.TrimSpace(*root) != "" || !tcpAllow.Empty() || !udpAllow.Empty() || app.MapReduceConfigured()
	var local *app.LocalServices
	if serveLocal {
		if strings.TrimSpace(*publicKeyFile) == "" {
			fmt.Fprintln(os.Stderr, "attach: --public-key-file is required when local fs, tcp, udp, or mapreduce service is configured")
			return 2
		}
		publicKey, err := app.LoadEd25519PublicKeyFile(*publicKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "attach: load public key: %v\n", err)
			return 1
		}
		localConfig := app.LocalServiceConfig{
			SignedContext: signedContext, PublicKey: publicKey, MaxTTL: *maxTTL,
			Root: *root, ReadOnly: *readOnly, TCPAllow: tcpAllow,
			TCPRequireProof: *tcpRequireProof, UDPAllow: udpAllow,
		}
		if !tcpAllow.Empty() {
			if strings.TrimSpace(*tcpProofPolicy) != "" {
				verifier, err := app.LoadSocksProofVerifier(*tcpProofPolicy)
				if err != nil {
					fmt.Fprintf(os.Stderr, "attach: load TCP proof policy: %v\n", err)
					return 1
				}
				localConfig.TCPProofVerifier = verifier
			} else if *tcpRequireProof {
				fmt.Fprintln(os.Stderr, "attach: --tcp-require-proof requires --tcp-proof-policy")
				return 2
			}
		}
		local, err = app.NewLocalServices(localConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "attach: local services: %v\n", err)
			return 1
		}
		if err := app.InstallConfiguredMapReduce(local); err != nil {
			_ = local.Close()
			fmt.Fprintf(os.Stderr, "attach: mapreduce: %v\n", err)
			return 1
		}
		defer local.Close()
		attachConfig.LocalServices = local
	}

	defaultSocket, defaultState, err := sessionbroker.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "attach: runtime paths: %v\n", err)
		return 1
	}
	if strings.TrimSpace(*socketPath) == "" {
		*socketPath = defaultSocket
	}
	if strings.TrimSpace(*statePath) == "" {
		*statePath = defaultState
	}
	leasePath, err := sessionroute.ResolveLeasePath(*routeRegistryPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attach: route lease path: %v\n", err)
		return 1
	}
	attachConfig.RouteLeaseStorePath = leasePath
	linkRouter, err := sessionbroker.NewLinkRouter(sessionlink.Descriptor{
		ChainSHA256: signedContext.Context.ChainSHA256,
		Topology:    signedContext.Context.Nodes,
		LocalNode:   signedContext.Context.CurrentNode,
		PeerNode:    wvOrigin,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "attach: logical link: %v\n", err)
		return 1
	}
	if err := prepareAttachSocket(*socketPath); err != nil {
		fmt.Fprintf(os.Stderr, "attach: %v\n", err)
		return 1
	}
	_ = sessionbroker.RemoveHopState(*statePath)
	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attach: listen on local broker %s: %v\n", *socketPath, err)
		return 1
	}
	_ = os.Chmod(*socketPath, 0o600)
	leaseStore := sessionroute.LeaseStore{Path: leasePath}
	if err := leaseStore.ResetLink(context.Background(), linkRouter.LinkID()); err != nil {
		_ = listener.Close()
		fmt.Fprintf(os.Stderr, "attach: reset stale route lease: %v\n", err)
		return 1
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(*socketPath)
		_ = os.Remove(*statePath)
		_ = sessionbroker.RemoveHopState(*statePath)
	}()
	if verifiedHop.Depth > 0 {
		if err := sessionbroker.WriteHopState(*statePath, sessionbroker.HopState{
			PreviousNode: verifiedHop.PreviousNode,
			HopChain:     strings.TrimSpace(*hopChainText),
			Depth:        verifiedHop.Depth,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "attach: write recursive hop state: %v\n", err)
			return 1
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	supervisor, err := app.NewAttachSupervisor(app.AttachSupervisorConfig{
		Attach: attachConfig, Router: linkRouter, Lease: *linkLease, Reconnect: *reconnect,
		Policy: app.ReconnectPolicy{MinDelay: *reconnectMinDelay, MaxDelay: *reconnectMaxDelay, ResetAfter: *reconnectResetAfter, Jitter: *reconnectJitter},
		OnEvent: func(event app.ReconnectEvent) {
			fmt.Fprintf(os.Stderr, "attach: transport attempt=%d ended err=%v reconnect_in=%s\n", event.Attempt, event.Err, event.NextDelay)
		},
		OnReady: func(generation app.AttachGeneration) (func(error), error) {
			startedAt := time.Now()
			entry, err := sessionroute.NewLeaseEntry(
				signedContext.Context, generation.Attached.Session.Binding, *socketPath,
				wvOrigin, os.Getpid(), startedAt, generation.Token, generation.Snapshot.LeaseUntil,
			)
			if err != nil {
				return nil, err
			}
			if err := leaseStore.Register(context.Background(), entry); err != nil {
				return nil, err
			}
			state := sessionbroker.State{
				PID: os.Getpid(), Socket: *socketPath, Binding: generation.Attached.Session.Binding,
				Node: generation.Attached.Node, StartedAt: startedAt,
			}
			if err := sessionbroker.WriteState(*statePath, state); err != nil {
				_ = leaseStore.Remove(context.Background(), generation.Token)
				return nil, err
			}
			stopRenewal := app.StartLeaseRenewal(context.Background(), *linkLease, func(renewCtx context.Context, leaseUntil time.Time) error {
				if _, err := linkRouter.Renew(generation.Token, *linkLease); err != nil {
					return err
				}
				return leaseStore.Renew(renewCtx, generation.Token, leaseUntil)
			}, func(renewErr error) {
				fmt.Fprintf(os.Stderr, "attach: lease renewal link=%s generation=%d: %v\n", generation.Token.LinkID, generation.Token.Generation, renewErr)
			})
			return func(error) {
				stopRenewal()
				// Preserve the stable broker route until lease expiry so
				// callers can wait through a short transport outage.
			}, nil
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "attach: supervisor: %v\n", err)
		return 1
	}
	brokerDone := make(chan error, 1)
	go func() {
		broker := &sessionbroker.Server{Open: func(openCtx context.Context, request sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
			waitCtx, cancel := context.WithTimeout(openCtx, *brokerWait)
			defer cancel()
			return linkRouter.Open(waitCtx, request)
		}}
		brokerDone <- broker.Serve(ctx, listener)
	}()
	supervisor.Start(ctx)

	var first app.AttachGeneration
	select {
	case first = <-supervisor.Ready():
	case err := <-supervisor.Done():
		if err != nil {
			fmt.Fprintf(os.Stderr, "attach: %v\n", err)
		}
		return 1
	case err := <-brokerDone:
		if err != nil {
			fmt.Fprintf(os.Stderr, "attach: broker: %v\n", err)
		}
		return 1
	case <-ctx.Done():
		return 0
	}
	attached := first.Attached
	state := sessionbroker.State{
		PID: os.Getpid(), Socket: *socketPath, Binding: attached.Session.Binding,
		Node: attached.Node, StartedAt: first.Snapshot.UpdatedAt,
	}
	udpEnabled := attached.Local != nil && attached.Local.UDPEnabled()
	mapReduceEnabled := attached.Local != nil && attached.Local.MapReduceEnabled()
	if *jsonOut {
		payload, _ := json.Marshal(struct {
			sessionbroker.State
			WVOrigin         string `json:"wvorigin"`
			HopDepth         int    `json:"hop_depth,omitempty"`
			RouteLeaseStore  string `json:"route_lease_store"`
			LinkID           string `json:"link_id"`
			Generation       uint64 `json:"generation"`
			TransportID      string `json:"transport_id"`
			RegistrationMode string `json:"registration_mode"`
			TCPRequireProof  bool   `json:"tcp_require_proof"`
			UDPEnabled       bool   `json:"udp_enabled"`
			MapReduceEnabled bool   `json:"mapreduce_enabled"`
		}{
			State: state, WVOrigin: wvOrigin, HopDepth: verifiedHop.Depth,
			RouteLeaseStore: leasePath, LinkID: string(first.Token.LinkID), Generation: first.Token.Generation,
			TransportID: string(first.Token.TransportID), RegistrationMode: string(attached.RegistrationMode),
			TCPRequireProof: *tcpRequireProof, UDPEnabled: udpEnabled, MapReduceEnabled: mapReduceEnabled,
		})
		fmt.Println(string(payload))
	} else {
		fmt.Printf("attached node=%s display=%s binding=%s registration=%s\n", attached.Node, attached.Endpoint.String(), attached.Session.Binding, attached.RegistrationMode)
		fmt.Printf("logical link=%s generation=%d transport=%s lease=%s\n", first.Token.LinkID, first.Token.Generation, first.Token.TransportID, *linkLease)
		fmt.Printf("%s=%s\n", app.EnvWVOrigin, wvOrigin)
		if verifiedHop.Depth > 0 {
			fmt.Printf("verified recursive hop depth=%d sidecar=%s\n", verifiedHop.Depth, sessionbroker.HopStatePath(*statePath))
		}
		fmt.Printf("local broker: unix:%s\nstate: %s\nroute leases: %s\n", *socketPath, *statePath, leasePath)
		if attached.Local != nil {
			fmt.Printf("local services: %v\n", attached.Local.Services())
			if attached.Local.TCPProofEnabled() {
				fmt.Printf("TCP cryptographic proof: enabled required=%t\n", attached.Local.TCPProofRequired())
			}
			if udpEnabled {
				fmt.Println("SOCKS5 UDP ASSOCIATE final-node service: enabled")
			}
			if mapReduceEnabled {
				description := attached.Local.MapReduceDescription()
				fmt.Printf("rule-constrained mapreduce: enabled policy=%s plugins=%d\n", description.PolicySHA256, len(description.Plugins))
			}
		}
		fmt.Printf("transport replacement: enabled=%t broker_wait=%s\n", *reconnect, *brokerWait)
		fmt.Println("in-band API: enabled")
		fmt.Println("linear multi-session routing: generation-leased")
		fmt.Println("static forwarding ports: none")
	}

	select {
	case err := <-supervisor.Done():
		stop()
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "attach: %v\n", err)
			return 1
		}
	case err := <-brokerDone:
		stop()
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "attach: broker: %v\n", err)
			return 1
		}
	case <-ctx.Done():
	}
	return 0
}

func prepareAttachSocket(path string) error {
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	conn, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("an active session broker already owns %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale broker socket %s: %w", path, err)
	}
	return nil
}

func parseBoolEnvironment(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on", "required":
		return true
	default:
		return false
	}
}
