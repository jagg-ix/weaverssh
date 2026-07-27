package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"weaverssh/authproof"
	"weaverssh/hopproof"
	"weaverssh/sessionapi"
	"weaverssh/sessionbroker"
	"weaverssh/sessionlink"
	"weaverssh/sessionmux"
	"weaverssh/sessionroute"
	"weaverssh/sessionruntime"
	"weaverssh/sessiontcp"
	"weaverssh/sessionudp"
)

// RunSessionHost allocates an isolated X display, launches an optional SSH child,
// and serves authenticated WebSocket/mux transports without -R or -L ports.
func RunSessionHost() {
	var (
		root, contextFile, publicKeyFile, listenAddress                     string
		tcpAllowText, udpAllowText, tcpProofPolicy, brokerSocket, statePath string
		routeRegistryPath                                                   string
		proofMode, proofSecurity, proofPeerID                               string
		proofPublicKey, proofPublicFile, proofChain                         string
		hopSigningKey, hopAllowedSigners, hopSSHKeygen                      string
		readOnly, recursive, tcpRequireProof, reconnect                     bool
		maxTTL, authTimeout, hopTTL, linkLease, brokerWait                  time.Duration
		reconnectMinDelay, reconnectMaxDelay, reconnectResetAfter           time.Duration
		reconnectChallengeTTL, maxReconnectIdentityTTL                      time.Duration
		reconnectJitter                                                     float64
	)
	flag.StringVar(&root, "root", "", "directory exported through authorized fs streams")
	flag.StringVar(&contextFile, "node-context", os.Getenv("WEAVERSSH_NODE_CONTEXT_FILE"), "signed local node-context JSON")
	flag.StringVar(&publicKeyFile, "public-key-file", os.Getenv("WEAVERSSH_NODE_CONTEXT_PUBLIC_KEY_FILE"), "trusted Ed25519 node-context public key")
	flag.StringVar(&listenAddress, "listen", "", "debug loopback X listener override; default is ephemeral")
	flag.BoolVar(&readOnly, "read-only", true, "serve --root read-only")
	flag.StringVar(&tcpAllowText, "tcp-allow", "", "comma-separated local TCP allow rules")
	flag.StringVar(&udpAllowText, "udp-allow", "", "comma-separated local UDP allow rules for SOCKS5 UDP ASSOCIATE")
	flag.StringVar(&tcpProofPolicy, "tcp-proof-policy", os.Getenv(EnvSocksProofPolicy), "SOCKS client proof policy used by the final TCP service")
	flag.BoolVar(&tcpRequireProof, "tcp-require-proof", envBoolValue(os.Getenv(EnvTCPRequireProof)), "reject legacy unsigned TCP target metadata")
	flag.StringVar(&brokerSocket, "socket", "", "stable local Unix broker socket path")
	flag.StringVar(&statePath, "state", "", "active-session state JSON path")
	flag.StringVar(&routeRegistryPath, "route-registry", os.Getenv("WEAVERSSH_ROUTE_REGISTRY"), "base path for local multi-session route registries")
	flag.DurationVar(&maxTTL, "max-context-ttl", 10*time.Minute, "maximum accepted legacy node-context TTL")
	flag.DurationVar(&authTimeout, "timeout", 30*time.Second, "X11/WebSocket handshake timeout")
	flag.StringVar(&proofMode, "proof-mode", authproof.ProofModeOff, "runtime authproof mode: off|required")
	flag.StringVar(&proofSecurity, "proof-security-level", authproof.SecurityLevelCompat, "runtime authority level")
	flag.StringVar(&proofPeerID, "proof-peer-id", defaultPeerID("wv-session-host"), "expected peer ID in runtime grants")
	flag.StringVar(&proofPublicKey, "proof-public-key", "", "trusted runtime proof public key")
	flag.StringVar(&proofPublicFile, "proof-public-key-file", "", "file containing runtime proof public key")
	flag.StringVar(&proofChain, "proof-chain-sha256", "", "expected runtime proof chain binding")
	flag.BoolVar(&recursive, "recursive", false, "sign the next topology hop, pass WVHOP, and enable ssh-agent forwarding")
	flag.StringVar(&hopSigningKey, "hop-signing-key", os.Getenv("WEAVERSSH_HOP_SIGNING_KEY"), "SSH public-key file selected for SSHSIG signing")
	flag.StringVar(&hopAllowedSigners, "hop-allowed-signers", os.Getenv("WEAVERSSH_HOP_ALLOWED_SIGNERS"), "OpenSSH allowed-signers file")
	flag.StringVar(&hopSSHKeygen, "hop-ssh-keygen", "ssh-keygen", "ssh-keygen executable")
	flag.DurationVar(&hopTTL, "hop-ttl", 5*time.Minute, "validity period for the newly signed hop")
	flag.BoolVar(&reconnect, "reconnect", false, "restart an exited SSH child and keep the broker available")
	flag.DurationVar(&linkLease, "link-lease", 30*time.Second, "logical-link and route lease duration")
	flag.DurationVar(&brokerWait, "broker-wait", 15*time.Second, "maximum local broker wait for a replacement transport")
	flag.DurationVar(&reconnectMinDelay, "reconnect-min-delay", time.Second, "minimum SSH child restart delay")
	flag.DurationVar(&reconnectMaxDelay, "reconnect-max-delay", 30*time.Second, "maximum SSH child restart delay")
	flag.DurationVar(&reconnectResetAfter, "reconnect-reset-after", time.Minute, "runtime that resets exponential restart history")
	flag.Float64Var(&reconnectJitter, "reconnect-jitter", 0.2, "fractional restart-delay jitter from 0 to 1")
	flag.DurationVar(&reconnectChallengeTTL, "reconnect-challenge-ttl", 30*time.Second, "fresh node reconnect challenge lifetime")
	flag.DurationVar(&maxReconnectIdentityTTL, "max-reconnect-identity-ttl", 24*time.Hour, "maximum accepted reusable reconnect identity TTL")
	flag.Parse()

	if strings.TrimSpace(contextFile) == "" || strings.TrimSpace(publicKeyFile) == "" {
		log.Fatal("session-host requires --node-context and --public-key-file")
	}
	if linkLease <= 0 || linkLease > sessionlink.MaxLease {
		log.Fatalf("session-host: --link-lease must be positive and at most %s", sessionlink.MaxLease)
	}
	if brokerWait <= 0 {
		log.Fatal("session-host: --broker-wait must be positive")
	}
	tcpAllow, err := sessiontcp.ParseAllowlist(tcpAllowText)
	if err != nil {
		log.Fatalf("session-host: tcp allowlist: %v", err)
	}
	udpAllow, err := sessionudp.ParseAllowlist(udpAllowText)
	if err != nil {
		log.Fatalf("session-host: udp allowlist: %v", err)
	}
	computeConfigured := MapReduceConfigured()
	controlOnly := recursive && strings.TrimSpace(root) == "" && tcpAllow.Empty() && udpAllow.Empty() && !computeConfigured
	if strings.TrimSpace(root) == "" && tcpAllow.Empty() && udpAllow.Empty() && !recursive && !computeConfigured {
		log.Fatal("session-host requires at least --root, --tcp-allow, --udp-allow, or mapreduce configuration unless --recursive control-only mode is used")
	}
	if tcpRequireProof && !tcpAllow.Empty() && strings.TrimSpace(tcpProofPolicy) == "" {
		log.Fatal("session-host: --tcp-require-proof requires --tcp-proof-policy")
	}

	signed, err := LoadSignedNodeContextFile(contextFile)
	if err != nil {
		log.Fatalf("session-host: load node context: %v", err)
	}
	peerNode, _, err := sessionroute.ResolveNode(signed.Context, "next")
	if err != nil {
		log.Fatalf("session-host: signed topology has no next peer: %v", err)
	}
	wvOrigin, err := SignedWVOrigin(signed.Context)
	if err != nil {
		log.Fatalf("session-host: derive %s: %v", EnvWVOrigin, err)
	}

	var recursiveEnvironment RecursiveHopEnvironment
	if recursive {
		recursiveEnvironment, err = PrepareRecursiveHop(context.Background(), RecursiveHopConfig{
			NodeContext:        signed.Context,
			IncomingChain:      os.Getenv(EnvWVHop),
			SigningKeyFile:     hopSigningKey,
			AllowedSignersFile: hopAllowedSigners,
			SSHKeygenBinary:    hopSSHKeygen,
			TTL:                hopTTL,
		})
		if err != nil {
			log.Fatalf("session-host: recursive hop: %v", err)
		}
		wvOrigin = recursiveEnvironment.Origin
	}
	publicKey, err := LoadEd25519PublicKeyFile(publicKeyFile)
	if err != nil {
		log.Fatalf("session-host: load public key: %v", err)
	}

	defaultSocket, defaultState, err := sessionbroker.DefaultPaths()
	if err != nil {
		log.Fatalf("session-host: broker paths: %v", err)
	}
	socketExplicit := strings.TrimSpace(brokerSocket) != ""
	stateExplicit := strings.TrimSpace(statePath) != ""
	if recursive {
		index, indexErr := hopproof.CurrentIndex(signed.Context)
		if indexErr != nil {
			log.Fatalf("session-host: topology index: %v", indexErr)
		}
		if index > 0 {
			recursiveSocket, recursiveState := RecursiveRuntimePaths(defaultSocket, defaultState, signed.Context.CurrentNode)
			if !socketExplicit {
				defaultSocket = recursiveSocket
			}
			if !stateExplicit {
				defaultState = recursiveState
			}
		}
	}
	if !socketExplicit {
		brokerSocket = defaultSocket
	}
	if !stateExplicit {
		statePath = defaultState
	}
	leasePath, err := sessionroute.ResolveLeasePath(routeRegistryPath)
	if err != nil {
		log.Fatalf("session-host: route lease path: %v", err)
	}
	leaseStore := sessionroute.LeaseStore{Path: leasePath}
	linkRouter, err := sessionbroker.NewLinkRouter(sessionlink.Descriptor{
		ChainSHA256: signed.Context.ChainSHA256,
		Topology:    signed.Context.Nodes,
		LocalNode:   signed.Context.CurrentNode,
		PeerNode:    peerNode,
	})
	if err != nil {
		log.Fatalf("session-host: logical link: %v", err)
	}

	if err := sessionbroker.PrepareUnixSocket(brokerSocket); err != nil {
		log.Fatalf("session-host: %v", err)
	}
	brokerListener, err := net.Listen("unix", brokerSocket)
	if err != nil {
		log.Fatalf("session-host: broker listen %s: %v", brokerSocket, err)
	}
	defer func() {
		_ = brokerListener.Close()
		_ = os.Remove(brokerSocket)
		_ = os.Remove(statePath)
	}()
	_ = os.Chmod(brokerSocket, 0o600)
	if err := leaseStore.ResetLink(context.Background(), linkRouter.LinkID()); err != nil {
		log.Fatalf("session-host: reset stale route lease: %v", err)
	}

	hostConfig := DynamicHostConfig{
		Root:            root,
		ReadOnly:        readOnly,
		SignedContext:   signed,
		PublicKey:       publicKey,
		MaxTTL:          maxTTL,
		TCPAllow:        tcpAllow,
		TCPRequireProof: tcpRequireProof,
		UDPAllow:        udpAllow,
		ControlOnly:     controlOnly,
		RouteStorePath:  routeRegistryPath,
	}
	if !tcpAllow.Empty() && strings.TrimSpace(tcpProofPolicy) != "" {
		verifier, err := LoadSocksProofVerifier(tcpProofPolicy)
		if err != nil {
			log.Fatalf("session-host: load TCP proof policy: %v", err)
		}
		hostConfig.TCPProofVerifier = verifier
	}
	if recursive {
		hostConfig.PreviousNode = recursiveEnvironment.Origin
		hostConfig.HopDepth = recursiveEnvironment.IncomingHopDepth
		hostConfig.EncodedWVHop = recursiveEnvironment.IncomingHopChain
	}
	host, err := NewDynamicHost(hostConfig)
	if err != nil {
		log.Fatalf("session-host: %v", err)
	}
	defer host.Close()

	var handover generationHandover[*sessionruntime.Session]
	reconnectReplay := authproof.NewNonceCache()
	hostLifecycle := DynamicHostReconnectConfig{
		ExpectedPeerNode:    peerNode,
		ChallengeTTL:        reconnectChallengeTTL,
		MaxIdentityTTL:      maxReconnectIdentityTTL,
		RouteLeaseStorePath: leasePath,
		ReplayCache:         reconnectReplay,
		OnReady: func(generation HostSessionGeneration) (func(error), error) {
			var token sessionlink.Token
			var snapshot sessionlink.Snapshot
			previous, err := handover.Commit(generation.Session, func() error {
				if generation.LinkID != linkRouter.LinkID() {
					return fmt.Errorf("logical link mismatch: expected %s got %s", linkRouter.LinkID(), generation.LinkID)
				}
				var publishErr error
				token, snapshot, _, publishErr = linkRouter.Publish(generation.TransportID, linkLease, func(openCtx context.Context, request sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
					if request.Service == sessionmux.ServiceControl {
						return sessionapi.Open(openCtx, generation.Session.Mux)
					}
					return OpenBrokerTarget(openCtx, host.local, generation.Router, generation.Session.Binding, signed.Context.Normalized(), request)
				})
				if publishErr != nil {
					return publishErr
				}
				startedAt := time.Now()
				entry, entryErr := sessionroute.NewLeaseEntry(
					signed.Context,
					generation.Session.Binding,
					brokerSocket,
					generation.Remote.ID,
					os.Getpid(),
					startedAt,
					token,
					snapshot.LeaseUntil,
				)
				if entryErr != nil {
					linkRouter.Withdraw(token, entryErr)
					return entryErr
				}
				if registerErr := leaseStore.Register(context.Background(), entry); registerErr != nil {
					linkRouter.Withdraw(token, registerErr)
					return registerErr
				}
				state := sessionbroker.State{PID: os.Getpid(), Socket: brokerSocket, Binding: generation.Session.Binding, Node: generation.Local.ID, StartedAt: startedAt}
				if stateErr := sessionbroker.WriteState(statePath, state); stateErr != nil {
					_ = leaseStore.Remove(context.Background(), token)
					linkRouter.Withdraw(token, stateErr)
					return stateErr
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			if previous != nil && previous != generation.Session {
				_ = previous.Close()
			}

			stopRenewal := StartLeaseRenewal(context.Background(), linkLease, func(renewCtx context.Context, leaseUntil time.Time) error {
				if _, err := linkRouter.Renew(token, linkLease); err != nil {
					return err
				}
				return leaseStore.Renew(renewCtx, token, leaseUntil)
			}, func(renewErr error) {
				log.Printf("session-host: link lease renewal failed link=%s generation=%d: %v", token.LinkID, token.Generation, renewErr)
			})
			log.Printf("active logical link=%s generation=%d transport=%s binding=%s local_node=%s peer_node=%s broker=unix:%s registration=%s",
				token.LinkID, token.Generation, token.TransportID, generation.Session.Binding,
				generation.Local.ID, generation.Remote.ID, brokerSocket, generation.RegistrationMode)
			return func(cause error) {
				stopRenewal()
				// Keep the stable broker route published until its short lease
				// expires. During that gap LinkRouter.Open can wait for a
				// replacement transport instead of returning no route.
				linkRouter.Withdraw(token, cause)
				handover.Clear(generation.Session)
			}, nil
		},
	}

	address := "127.0.0.1:0"
	if strings.TrimSpace(listenAddress) != "" {
		network, parsed, _, parseErr := parseAgentListenAddress(listenAddress)
		if parseErr != nil || network != "tcp" {
			log.Fatalf("session-host: --listen must be loopback TCP: %v", parseErr)
		}
		address = parsed
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("session-host: listen %s: %v", address, err)
	}
	defer listener.Close()
	tcpAddress, ok := listener.Addr().(*net.TCPAddr)
	if !ok || tcpAddress.IP == nil || !tcpAddress.IP.IsLoopback() || tcpAddress.Port < 6000 {
		log.Fatalf("session-host: allocated listener is not a valid loopback X display: %s", listener.Addr())
	}
	displayName := fmt.Sprintf("127.0.0.1:%d.0", tcpAddress.Port-6000)
	authority, err := createSessionXAuthority(displayName)
	if err != nil {
		log.Fatalf("session-host: create isolated Xauthority: %v", err)
	}
	defer authority.Close()

	runtime, err := NewAgentRuntime(AgentConfig{
		InterfaceMode: string(AgentInterfaceLibrary),
		X11Network:    "tcp",
		X11Target:     "unused:0",
		AuthTimeout:   authTimeout,
		Proof: authproof.RuntimeConfig{
			Mode:          proofMode,
			SecurityLevel: proofSecurity,
			SubjectPeerID: proofPeerID,
			Audience:      authproof.AudienceAgent,
			PublicKey:     proofPublicKey,
			PublicKeyFile: proofPublicFile,
			ChainSHA256:   proofChain,
			TTL:           authproof.DefaultProofTTL,
			ReplayCache:   authproof.NewNonceCache(),
		},
	}, authority.Cookie)
	if err != nil {
		log.Fatalf("session-host: initialize runtime: %v", err)
	}
	defer runtime.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		_ = brokerListener.Close()
	}()
	go func() {
		broker := &sessionbroker.Server{Open: func(openCtx context.Context, request sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
			waitCtx, cancel := context.WithTimeout(openCtx, brokerWait)
			defer cancel()
			return linkRouter.Open(waitCtx, request)
		}}
		if err := broker.Serve(ctx, brokerListener); err != nil && ctx.Err() == nil {
			log.Printf("session-host broker: %v", err)
			stop()
		}
	}()

	childEnvironment := map[string]string{EnvWVOrigin: wvOrigin}
	if recursive {
		childEnvironment[EnvWVHop] = recursiveEnvironment.HopChain
	}
	commandArgs := flag.Args()
	if len(commandArgs) > 0 {
		preparedArgs, directSSH, prepErr := injectOpenSSHEnvironment(commandArgs, childEnvironment, recursive)
		if prepErr != nil {
			log.Fatalf("session-host: prepare child SSH environment: %v", prepErr)
		}
		if recursive && !directSSH {
			log.Fatal("session-host: --recursive requires a direct ssh/ssh.exe child")
		}
		replacements := map[string]string{"DISPLAY": displayName, "XAUTHORITY": authority.Path, EnvWVOrigin: wvOrigin}
		if recursive {
			replacements[EnvWVHop] = recursiveEnvironment.HopChain
		}
		commandEnvironment := replaceEnvironment(os.Environ(), replacements)
		if directSSH {
			log.Printf("session-host: OpenSSH SetEnv %s=%s", EnvWVOrigin, wvOrigin)
			if recursive {
				log.Printf("session-host: recursive hop depth=%d next_node=%s agent_forwarding=enabled control_only=%t", recursiveEnvironment.HopDepth, recursiveEnvironment.NextNode, controlOnly)
				log.Printf("session-host: WARNING forwarded agents are security-sensitive")
			}
		}
		go func() {
			err := RunCommandSupervisor(ctx, CommandSupervisorConfig{
				Args: preparedArgs, Env: commandEnvironment, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
				Reconnect: reconnect,
				Policy:    ReconnectPolicy{MinDelay: reconnectMinDelay, MaxDelay: reconnectMaxDelay, ResetAfter: reconnectResetAfter, Jitter: reconnectJitter},
				OnEvent: func(event ReconnectEvent) {
					log.Printf("session-host: child attempt=%d ended err=%v restart_in=%s", event.Attempt, event.Err, event.NextDelay)
				},
			})
			if err != nil && ctx.Err() == nil {
				log.Printf("session-host child exited: %v", err)
			}
			if !reconnect {
				stop()
			}
		}()
	} else if recursive {
		fmt.Printf("DISPLAY=%q XAUTHORITY=%q %s=%q %s=%q ssh -A -o SetEnv=%s=%s -o SetEnv=%s=%s -X user@%s\n",
			displayName, authority.Path, EnvWVOrigin, wvOrigin, EnvWVHop, recursiveEnvironment.HopChain,
			EnvWVOrigin, wvOrigin, EnvWVHop, recursiveEnvironment.HopChain, recursiveEnvironment.NextNode)
		fmt.Printf("# remote sshd must allow: AcceptEnv %s %s\n", EnvWVOrigin, EnvWVHop)
	} else {
		fmt.Printf("DISPLAY=%q XAUTHORITY=%q %s=%q ssh -o SetEnv=%s=%s -X user@host\n", displayName, authority.Path, EnvWVOrigin, wvOrigin, EnvWVOrigin, wvOrigin)
		fmt.Printf("# remote sshd must allow: AcceptEnv %s\n", EnvWVOrigin)
	}

	log.Printf("dynamic session host display=%s listener=%s", displayName, listener.Addr())
	log.Printf("%s=%s local broker=unix:%s state=%s route_leases=%s link=%s api=in-band static_forwarding_ports=none",
		EnvWVOrigin, wvOrigin, brokerSocket, statePath, leasePath, linkRouter.LinkID())
	log.Printf("filesystem root=%s read_only=%t tcp_allow=%q udp_allow=%q tcp_proof=%t tcp_proof_required=%t mapreduce=%t control_only=%t reconnect=%t",
		root, readOnly, tcpAllowText, udpAllowText, hostConfig.TCPProofVerifier != nil, tcpRequireProof, host.local.MapReduceEnabled(), controlOnly, reconnect)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("session-host accept: %v", err)
			continue
		}
		go func() {
			handler := func(handlerCtx context.Context, session *sessionruntime.Session, authorityContext DynamicSessionContext) error {
				return host.ServeReconnectable(handlerCtx, session, authorityContext, hostLifecycle)
			}
			if err := runtime.ServeDynamicSessionConn(ctx, conn, handler); err != nil && ctx.Err() == nil {
				log.Printf("dynamic session ended: %v", err)
			}
		}()
	}
}

func replaceEnvironment(environment []string, replacements map[string]string) []string {
	out := make([]string, 0, len(environment)+len(replacements))
	for _, entry := range environment {
		name := entry
		if index := strings.IndexByte(entry, '='); index >= 0 {
			name = entry[:index]
		}
		if _, replaced := replacements[name]; !replaced {
			out = append(out, entry)
		}
	}
	for name, value := range replacements {
		out = append(out, name+"="+value)
	}
	return out
}
