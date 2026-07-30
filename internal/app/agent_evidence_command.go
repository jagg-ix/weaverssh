package app

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"weaverssh/authproof"
	"weaverssh/display"
)

// RunAgentEvidence starts a normal WeaverSSH agent with automatic signed event
// journaling, embedded immudb anchoring, optional durable remote quorum
// delivery, and an authenticated local control API.
func RunAgentEvidence() {
	config := AgentConfig{
		Port: 0, ListenNetwork: "tcp", InterfaceMode: string(AgentInterfaceTCP),
		X11Target: os.Getenv("X11_TARGET"), AuthTimeout: 60 * time.Second,
		TrustedAuth: true, EnableSecurity: true, LogLevel: "info", Proof: defaultAgentProofConfig(),
	}
	embedded := AgentEmbeddedImmuDBConfigFromEnv(os.Getenv)
	remote := AgentRemoteDeliveryConfigFromEnv(embedded.Path, os.Getenv)
	var listenUnixPath, interfaceMode string
	controlNetwork, controlAddress, controlTokenFile := defaultAgentEvidenceControl(embedded.Path)

	fs := flag.NewFlagSet("wv agent-evidence serve", flag.ExitOnError)
	fs.IntVar(&config.Port, "port", 0, "manual port override")
	fs.StringVar(&config.ListenAddr, "listen", "", "listen address")
	fs.StringVar(&interfaceMode, "interface", os.Getenv("WEAVERSSH_AGENT_INTERFACE"), "agent interface: tcp, unix, or library")
	fs.StringVar(&listenUnixPath, "listen-unix", "", "Unix-domain listener path")
	fs.DurationVar(&config.AuthTimeout, "timeout", config.AuthTimeout, "authentication timeout")
	fs.BoolVar(&config.TrustedAuth, "trusted", config.TrustedAuth, "use trusted authentication")
	fs.BoolVar(&config.EnableSecurity, "security", config.EnableSecurity, "enable X11 SECURITY extension")
	fs.StringVar(&config.LogLevel, "loglevel", config.LogLevel, "log level")
	fs.StringVar(&config.Proof.Mode, "proof-mode", config.Proof.Mode, "runtime authproof mode: off|required")
	fs.StringVar(&config.Proof.SecurityLevel, "proof-security-level", config.Proof.SecurityLevel, "runtime authority security level")
	fs.StringVar(&config.Proof.SubjectPeerID, "proof-peer-id", config.Proof.SubjectPeerID, "expected authproof peer ID")
	fs.StringVar(&config.Proof.PublicKey, "proof-public-key", config.Proof.PublicKey, "trusted Ed25519 authproof public key")
	fs.StringVar(&config.Proof.PublicKeyFile, "proof-public-key-file", config.Proof.PublicKeyFile, "trusted authproof public-key file")
	fs.StringVar(&config.Proof.ChainSHA256, "proof-chain-sha256", config.Proof.ChainSHA256, "expected authproof chain digest")
	fs.DurationVar(&config.Proof.TTL, "proof-ttl", config.Proof.TTL, "maximum accepted authproof TTL")
	fs.StringVar(&embedded.Path, "embedded-immudb-path", embedded.Path, "persistent root for embedded immudb and signed journal")
	fs.StringVar(&embedded.ProviderName, "embedded-immudb-provider", embedded.ProviderName, "provider identity written into receipts")
	fs.StringVar(&embedded.StreamID, "evidence-stream", embedded.StreamID, "append-only evidence stream ID")
	fs.StringVar(&remote.ProviderConfigPath, "remote-providers", remote.ProviderConfigPath, "remote N-of-M provider configuration JSON")
	fs.StringVar(&remote.QueuePath, "remote-queue", remote.QueuePath, "durable remote delivery queue path")
	fs.DurationVar(&remote.MinBackoff, "remote-retry-min", remote.MinBackoff, "minimum remote delivery retry backoff")
	fs.DurationVar(&remote.MaxBackoff, "remote-retry-max", remote.MaxBackoff, "maximum remote delivery retry backoff")
	fs.DurationVar(&remote.PollEvery, "remote-poll", remote.PollEvery, "remote delivery queue polling interval")
	fs.DurationVar(&remote.HTTPTimeout, "remote-timeout", remote.HTTPTimeout, "per-attempt remote provider timeout")
	fs.StringVar(&controlNetwork, "evidence-control-network", controlNetwork, "control network: unix or tcp")
	fs.StringVar(&controlAddress, "evidence-control", controlAddress, "authenticated evidence control socket/address")
	fs.StringVar(&controlTokenFile, "evidence-control-token-file", controlTokenFile, "HMAC control token file")
	_ = fs.Parse(os.Args[1:])
	if fs.NArg() != 0 {
		log.Fatalf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if err := embedded.Validate(); err != nil {
		log.Fatal(err)
	}
	if strings.TrimSpace(remote.ProviderConfigPath) != "" && strings.TrimSpace(remote.QueuePath) == "" {
		remote.QueuePath = filepath.Join(strings.TrimSpace(embedded.Path), "remote-delivery.json")
	}

	switch strings.ToLower(config.LogLevel) {
	case "debug":
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	case "warn", "error":
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	default:
		log.SetFlags(log.Ldate | log.Ltime)
	}

	mode, err := normalizeAgentInterfaceMode(interfaceMode)
	if err != nil {
		log.Fatalf("invalid agent interface: %v", err)
	}
	config.InterfaceMode = string(mode)
	if mode == AgentInterfaceLibrary {
		config.ListenNetwork = string(AgentInterfaceLibrary)
		config.ListenAddr = ""
	} else if strings.TrimSpace(listenUnixPath) != "" {
		config.InterfaceMode = string(AgentInterfaceUnix)
		config.ListenNetwork = "unix"
		config.ListenAddr = strings.TrimSpace(listenUnixPath)
	} else if strings.TrimSpace(config.ListenAddr) != "" {
		network, address, parsedPort, parseErr := parseAgentListenAddress(config.ListenAddr)
		if parseErr != nil {
			log.Fatalf("invalid agent listen address: %v", parseErr)
		}
		config.ListenNetwork, config.ListenAddr, config.Port = network, address, parsedPort
	} else if mode == AgentInterfaceUnix {
		config.ListenNetwork = "unix"
		config.ListenAddr = defaultAgentUnixSocketPath()
	} else if config.Port > 0 {
		config.ListenNetwork = "tcp"
		config.ListenAddr = fmt.Sprintf("localhost:%d", config.Port)
	} else {
		port, portErr := display.GetX11Port()
		if portErr != nil {
			log.Fatalf("failed to determine X11 port: %v", portErr)
		}
		config.Port = port
		config.ListenNetwork = "tcp"
		config.ListenAddr = fmt.Sprintf("localhost:%d", port)
	}
	if err := validateAgentInterfaceListen(config); err != nil {
		log.Fatalf("invalid agent listener configuration: %v", err)
	}
	if err := configureX11Target(&config); err != nil {
		log.Fatalf("failed to configure X11 target: %v", err)
	}

	authCookie, err := getSystemX11Cookie()
	if err != nil {
		authCookie = os.Getenv("X11_AUTH_COOKIE")
	}
	if strings.TrimSpace(authCookie) == "" {
		log.Fatal("no X11 authentication cookie available")
	}
	config.Proof.Audience = authproof.AudienceAgent
	config.Proof.X11CookieSHA256 = authproof.HashX11Cookie(authCookie)
	config.Proof.RequiredCapabilities = authproof.DefaultRelayCapabilities()
	if config.Proof.ReplayCache == nil {
		config.Proof.ReplayCache = authproof.NewNonceCache()
	}
	if err := config.Proof.ValidateVerifier(); err != nil {
		log.Fatalf("invalid runtime authproof verifier config: %v", err)
	}

	agent, err := NewAgentRuntimeWithEmbeddedImmuDB(config, authCookie, embedded)
	if err != nil {
		log.Fatalf("initialize evidence-enabled agent: %v", err)
	}
	defer agent.Close()
	if strings.TrimSpace(remote.ProviderConfigPath) != "" {
		queue, queueErr := OpenAgentRemoteDelivery(context.Background(), remote)
		if queueErr != nil {
			log.Fatalf("initialize remote evidence delivery: %v", queueErr)
		}
		if err := agent.EnableRemoteEvidenceDelivery(queue); err != nil {
			_ = queue.Close()
			log.Fatalf("enable remote evidence delivery: %v", err)
		}
		log.Printf("remote evidence delivery enabled providers=%s queue=%s", remote.ProviderConfigPath, remote.QueuePath)
	}
	control, err := StartAgentEvidenceControl(context.Background(), agent, AgentEvidenceControlConfig{
		Network: controlNetwork, Address: controlAddress, TokenFile: controlTokenFile,
	})
	if err != nil {
		log.Fatalf("start agent evidence control: %v", err)
	}
	defer control.Close()
	log.Printf("agent evidence enabled root=%s stream=%s control=%s:%s token=%s", embedded.Path, agent.EvidenceStatus().StreamID, controlNetwork, controlAddress, controlTokenFile)
	if agent.InterfaceMode() == AgentInterfaceLibrary {
		log.Printf("library-only evidence agent initialized; embed AgentRuntimeWithEmbeddedImmuDB and call ServeConn")
		return
	}
	if err := agent.ListenAndServe(); err != nil {
		log.Fatalf("evidence-enabled agent stopped: %v", err)
	}
}

func defaultAgentEvidenceControl(root string) (string, string, string) {
	if runtime.GOOS == "windows" {
		return "tcp", "127.0.0.1:19742", filepath.Join(strings.TrimSpace(root), "control.token")
	}
	base := strings.TrimSpace(root)
	if base == "" {
		base = filepath.Join(os.TempDir(), "weaverssh-agent-evidence")
	}
	return "unix", filepath.Join(base, "control.sock"), filepath.Join(base, "control.token")
}
