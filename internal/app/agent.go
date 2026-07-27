package app

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"weaverssh/authproof"
	"weaverssh/display"
	"weaverssh/flowcontrol"
	"weaverssh/relay"
)

// Config holds the agent proxy configuration
type AgentConfig struct {
	Port           int
	ListenAddr     string
	ListenNetwork  string
	InterfaceMode  string
	X11Target      string
	X11Network     string
	X11Endpoint    display.Endpoint
	AuthTimeout    time.Duration
	TrustedAuth    bool
	EnableSecurity bool
	LogLevel       string
	Proof          authproof.RuntimeConfig
}

// isInteger checks if a string can be parsed as an integer
func isInteger(str string) bool {
	_, err := strconv.Atoi(str)
	return err == nil
}

func RunAgent() {
	// Configuration
	config := AgentConfig{
		Port:           0,
		ListenAddr:     "",
		ListenNetwork:  "tcp",
		InterfaceMode:  string(AgentInterfaceTCP),
		X11Target:      os.Getenv("X11_TARGET"),
		AuthTimeout:    60 * time.Second,
		TrustedAuth:    true,
		EnableSecurity: true,
		LogLevel:       "info",
		Proof:          defaultAgentProofConfig(),
	}

	// Determine listen port
	var port int
	var err error
	var allowMismatch bool
	var listenUnixPath string
	var interfaceMode string

	// Parse command line flags
	flag.IntVar(&config.Port, "port", 0, "Manual port override (if not using DISPLAY)")
	flag.StringVar(&config.ListenAddr, "listen", "", "Listen address (localhost:<port>, tcp://host:port, unix:/path, or library)")
	flag.StringVar(&interfaceMode, "interface", os.Getenv("WEAVERSSH_AGENT_INTERFACE"), "Agent local interface: tcp, unix, or library")
	flag.StringVar(&interfaceMode, "agent-interface", os.Getenv("WEAVERSSH_AGENT_INTERFACE"), "Alias for -interface")
	flag.DurationVar(&config.AuthTimeout, "timeout", config.AuthTimeout, "Authentication timeout")
	flag.StringVar(&listenUnixPath, "listen-unix", "", "Unix-domain socket path for local same-UID authority checks")
	flag.BoolVar(&config.TrustedAuth, "trusted", config.TrustedAuth, "Use trusted authentication")
	flag.BoolVar(&config.EnableSecurity, "security", config.EnableSecurity, "Enable X11 SECURITY extension")
	flag.StringVar(&config.LogLevel, "loglevel", config.LogLevel, "Log level (debug, info, warn, error)")
	flag.StringVar(&config.Proof.Mode, "proof-mode", config.Proof.Mode, "Runtime authproof mode: off|required")
	flag.StringVar(&config.Proof.SecurityLevel, "proof-security-level", config.Proof.SecurityLevel, "Runtime authority security level: compat|same_uid|x11_cookie|agent_proof|strict")
	flag.StringVar(&config.Proof.SubjectPeerID, "proof-peer-id", config.Proof.SubjectPeerID, "Expected peer ID for this agent in authproof grants")
	flag.StringVar(&config.Proof.PublicKey, "proof-public-key", config.Proof.PublicKey, "Trusted Ed25519 public key for authproof verification (base64url, base64, or hex)")
	flag.StringVar(&config.Proof.PublicKeyFile, "proof-public-key-file", config.Proof.PublicKeyFile, "File containing trusted Ed25519 public key for authproof verification")
	flag.StringVar(&config.Proof.ChainSHA256, "proof-chain-sha256", config.Proof.ChainSHA256, "Expected chain binding SHA-256 hex for authproof grants; required when proof mode is required")
	flag.DurationVar(&config.Proof.TTL, "proof-ttl", config.Proof.TTL, "Maximum accepted authproof grant TTL")
	flag.Bool("nolisten_tcp", false, "Compatibility flag for XQuartz (ignored)")
	flag.Bool("listen_tcp", true, "Compatibility flag for XQuartz (ignored)")
	flag.BoolVar(&allowMismatch, "allow-mismatch", false, "Allow X11 cookie mismatches")

	flag.Parse()

	// Set up logging
	switch strings.ToLower(config.LogLevel) {
	case "debug":
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	case "info":
		log.SetFlags(log.Ldate | log.Ltime)
	case "warn", "error":
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	}

	// Handle original-style arguments (non-flag)
	if len(os.Args) == 2 && !strings.HasPrefix(os.Args[1], "-") {
		config.ListenAddr = os.Args[1]
	}

	mode, modeErr := normalizeAgentInterfaceMode(interfaceMode)
	if modeErr != nil {
		log.Fatalf("Invalid agent interface: %v", modeErr)
	}
	config.InterfaceMode = string(mode)

	// If listen address is provided, parse it. Unix-domain listeners are the
	// only local listener type that can provide same-UID peer evidence.
	if mode == AgentInterfaceLibrary {
		config.ListenNetwork = string(AgentInterfaceLibrary)
		config.ListenAddr = ""
	} else if strings.TrimSpace(listenUnixPath) != "" {
		if strings.TrimSpace(interfaceMode) == "" {
			mode = AgentInterfaceUnix
			config.InterfaceMode = string(mode)
		}
		config.ListenNetwork = "unix"
		config.ListenAddr = strings.TrimSpace(listenUnixPath)
	} else if config.ListenAddr != "" {
		network, address, parsedPort, err := parseAgentListenAddress(config.ListenAddr)
		if err != nil {
			fmt.Printf("Invalid local listen address: %v\n", err)
			return
		}
		if strings.TrimSpace(interfaceMode) == "" && network == "unix" {
			mode = AgentInterfaceUnix
			config.InterfaceMode = string(mode)
		}
		if network == string(AgentInterfaceLibrary) && strings.TrimSpace(interfaceMode) == "" {
			mode = AgentInterfaceLibrary
			config.InterfaceMode = string(mode)
		}
		config.ListenNetwork = network
		config.ListenAddr = address
		port = parsedPort
	} else if mode == AgentInterfaceUnix {
		config.ListenNetwork = "unix"
		config.ListenAddr = defaultAgentUnixSocketPath()
	} else if config.Port > 0 {
		// Use manual port from flag.
		port = config.Port
		config.ListenNetwork = "tcp"
		config.ListenAddr = fmt.Sprintf("localhost:%d", port)
	} else {
		// Use X11 port from DISPLAY.
		port, err = display.GetX11Port()
		if err != nil {
			log.Fatalf("Failed to determine X11 port: %v", err)
		}
		config.ListenNetwork = "tcp"
		config.ListenAddr = fmt.Sprintf("localhost:%d", port)
	}
	if err := validateAgentInterfaceListen(config); err != nil {
		log.Fatalf("Invalid agent interface/listener configuration: %v", err)
	}

	if err := configureX11Target(&config); err != nil {
		log.Fatalf("Failed to configure X11 target: %v", err)
	}

	// Get X11 auth cookie from system (same way client does)
	authCookie, err := getSystemX11Cookie()
	if err != nil {
		log.Printf("Warning: Could not get X11 cookie from system: %v", err)
		// Fall back to checking environment variable
		authCookie = os.Getenv("X11_AUTH_COOKIE")
	}

	if authCookie == "" {
		log.Fatalf("No X11 auth cookie available. Make sure X11 server is running and DISPLAY is set")
	}

	config.Proof.Audience = authproof.AudienceAgent
	config.Proof.X11CookieSHA256 = authproof.HashX11Cookie(authCookie)
	config.Proof.RequiredCapabilities = authproof.DefaultRelayCapabilities()
	if config.Proof.ReplayCache == nil {
		config.Proof.ReplayCache = authproof.NewNonceCache()
	}
	if err := config.Proof.ValidateVerifier(); err != nil {
		log.Fatalf("Invalid runtime authproof verifier config: %v", err)
	}
	if config.Proof.Required() {
		log.Printf("Runtime authproof required for agent peer %s", config.Proof.SubjectPeerID)
	}

	log.Printf("Using X11 auth cookie from system")
	runtime, err := NewAgentRuntime(config, authCookie)
	if err != nil {
		log.Fatalf("Failed to initialize agent runtime: %v", err)
	}
	defer runtime.Close()

	if runtime.InterfaceMode() == AgentInterfaceLibrary {
		log.Printf("Agent library-only interface initialized; no TCP or Unix listener opened")
		log.Printf("Embed internal/app.NewAgentRuntime and call AgentRuntime.ServeConn(net.Conn) to attach in-process transports")
		return
	}

	log.Printf("Agent proxy listening on %s:%s (interface=%s)", config.ListenNetwork, config.ListenAddr, runtime.InterfaceMode())
	if err := runtime.ListenAndServe(); err != nil {
		log.Fatalf("Agent runtime stopped: %v", err)
	}
}

type AgentRuntime struct {
	config       AgentConfig
	x11Server    *X11Server
	relayManager *relay.RelayManager
	upgrader     websocket.Upgrader
}

func NewAgentRuntime(config AgentConfig, authCookie string) (*AgentRuntime, error) {
	if strings.TrimSpace(authCookie) == "" {
		return nil, fmt.Errorf("agent runtime requires an X11 auth cookie")
	}
	mode, err := normalizeAgentInterfaceMode(config.InterfaceMode)
	if err != nil {
		return nil, err
	}
	config.InterfaceMode = string(mode)
	if config.AuthTimeout <= 0 {
		config.AuthTimeout = 60 * time.Second
	}
	if config.Proof.Mode == "" {
		config.Proof.Mode = authproof.ProofModeOff
	}
	if config.Proof.SecurityLevel == "" {
		config.Proof.SecurityLevel = authproof.SecurityLevelCompat
	}
	if config.Proof.SubjectPeerID == "" {
		config.Proof.SubjectPeerID = defaultPeerID("wv-agent")
	}
	if config.Proof.TTL <= 0 {
		config.Proof.TTL = authproof.DefaultProofTTL
	}
	if config.Proof.ReplayCache == nil {
		config.Proof.ReplayCache = authproof.NewNonceCache()
	}
	if config.X11Network == "" || config.X11Target == "" {
		if err := configureX11Target(&config); err != nil {
			return nil, err
		}
	}
	config.Proof.Audience = authproof.AudienceAgent
	config.Proof.X11CookieSHA256 = authproof.HashX11Cookie(authCookie)
	config.Proof.RequiredCapabilities = authproof.DefaultRelayCapabilities()
	if err := config.Proof.ValidateVerifier(); err != nil {
		return nil, err
	}

	return &AgentRuntime{
		config:       config,
		x11Server:    NewX11Server(authCookie),
		relayManager: relay.NewRelayManager(),
		upgrader: websocket.Upgrader{
			CheckOrigin:     func(r *http.Request) bool { return true },
			WriteBufferSize: 0,
			ReadBufferSize:  0,
		},
	}, nil
}

func (r *AgentRuntime) Config() AgentConfig {
	return r.config
}

func (r *AgentRuntime) InterfaceMode() AgentInterfaceMode {
	mode, err := normalizeAgentInterfaceMode(r.config.InterfaceMode)
	if err != nil {
		return AgentInterfaceTCP
	}
	return mode
}

func (r *AgentRuntime) Close() error {
	if r == nil {
		return nil
	}
	if r.relayManager != nil {
		r.relayManager.Close()
	}
	if r.x11Server != nil {
		r.x11Server.Close()
	}
	return nil
}

func (r *AgentRuntime) ListenAndServe() error {
	if r.InterfaceMode() == AgentInterfaceLibrary {
		return fmt.Errorf("library interface does not open a listener; call ServeConn with an in-process connection")
	}
	listener, cleanupListener, err := listenAgent(r.config)
	if err != nil {
		return fmt.Errorf("listen on %s:%s: %w", r.config.ListenNetwork, r.config.ListenAddr, err)
	}
	defer cleanupListener()
	defer listener.Close()
	return r.ServeListener(listener)
}

func (r *AgentRuntime) ServeListener(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		log.Printf("Accepted connection from %s", conn.RemoteAddr())
		go r.ServeConn(conn)
	}
}

func (r *AgentRuntime) ServeConn(c net.Conn) {
	defer c.Close()

	if tcpConn, ok := c.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		_ = tcpConn.SetWriteBuffer(4096)
		_ = tcpConn.SetReadBuffer(4096)
	}

	reader := bufio.NewReader(c)
	peek, err := reader.Peek(4)
	if err != nil {
		log.Printf("Failed to peek at connection: %v", err)
		return
	}

	if string(peek) == "GET " || string(peek) == "POST" {
		handleHTTPUpgrade(c, reader, &r.upgrader, r.handleWebSocketSession)
		return
	}
	handleX11ThenWebSocket(c, reader, &r.upgrader, r.handleWebSocketSession, r.x11Server, r.config)
}

func (r *AgentRuntime) handleWebSocketSession(wsConn *websocket.Conn, authorityCtx websocketAuthorityContext) {
	log.Printf("WebSocket connection established")

	var data []byte
	var err error
	if r.config.Proof.Required() {
		if _, err := verifyWebSocketProof(wsConn, r.config); err != nil {
			log.Printf("Runtime authproof rejected WebSocket session: %v", err)
			return
		}
		authorityCtx.AgentKeyProofVerified = true
	}
	if err := authorizeWebSocketSession(r.config, authorityCtx); err != nil {
		log.Printf("Runtime authority rejected WebSocket session: %v", err)
		return
	}
	if !r.config.Proof.Required() {
		_, data, err = wsConn.ReadMessage()
		if err != nil {
			log.Printf("Failed to read initial WebSocket message: %v", err)
			return
		}
	}

	log.Printf("X11 relay mode")
	flowProfile := flowcontrol.DefaultProfile()
	relayInstance := relay.NewRelayWithProfile(wsConn, flowProfile)
	sessionID := fmt.Sprintf("relay-%d", time.Now().UnixNano())
	r.relayManager.AddRelay(sessionID, relayInstance)
	defer r.relayManager.RemoveRelay(sessionID)

	targetConn, err := net.Dial(r.config.X11Network, r.config.X11Target)
	if err != nil {
		log.Printf("Failed to connect to X11 target %s:%s: %v", r.config.X11Network, r.config.X11Target, err)
		return
	}
	defer targetConn.Close()

	log.Printf("Connected to X11 server at %s:%s (%s)", r.config.X11Network, r.config.X11Target, r.config.X11Endpoint.ScreenName)
	relayInstance.SetSessionInfo(sessionID, fmt.Sprintf("%s:%s#%s", r.config.X11Network, targetConn.RemoteAddr().String(), r.config.X11Endpoint.ScreenName))

	if len(data) > 0 {
		if _, err = targetConn.Write(data); err != nil {
			log.Printf("Failed to write initial data to target: %v", err)
			return
		}
	}
	relayInstance.Start(targetConn)
}

func validateAgentInterfaceListen(config AgentConfig) error {
	mode, err := normalizeAgentInterfaceMode(config.InterfaceMode)
	if err != nil {
		return err
	}
	network := strings.ToLower(strings.TrimSpace(config.ListenNetwork))
	switch mode {
	case AgentInterfaceTCP:
		if network != "" && network != "tcp" && network != "tcp4" && network != "tcp6" {
			return fmt.Errorf("tcp interface cannot use listen network %q", config.ListenNetwork)
		}
		if strings.TrimSpace(config.ListenAddr) == "" {
			return fmt.Errorf("tcp interface requires a listen address")
		}
	case AgentInterfaceUnix:
		if network != "unix" {
			return fmt.Errorf("unix interface requires a unix listen network, got %q", config.ListenNetwork)
		}
		if strings.TrimSpace(config.ListenAddr) == "" {
			return fmt.Errorf("unix interface requires a socket path")
		}
	case AgentInterfaceLibrary:
		if network != "" && network != string(AgentInterfaceLibrary) {
			return fmt.Errorf("library interface must not configure a socket listener, got %q", config.ListenNetwork)
		}
	default:
		return fmt.Errorf("unsupported agent interface %q", config.InterfaceMode)
	}
	return nil
}

func configureX11Target(config *AgentConfig) error {
	endpoint, endpointErr := display.ResolveEnvEndpoint()
	if config.X11Target == "" {
		if endpointErr != nil {
			return endpointErr
		}
		config.X11Network = endpoint.Network
		config.X11Target = endpoint.Address
		config.X11Endpoint = endpoint
		log.Printf("Resolved X11 target from DISPLAY: %s", endpoint.String())
		return nil
	}

	network, address, err := display.ParseDialTarget(config.X11Target)
	if err != nil {
		return err
	}
	if endpointErr == nil {
		if !endpoint.Matches(network, address) {
			return fmt.Errorf("configured X11 target %s:%s does not match DISPLAY endpoint %s:%s", network, address, endpoint.Network, endpoint.Address)
		}
		if !endpoint.IsScreen0() {
			return fmt.Errorf("configured X11 target resolves to unsupported %s", endpoint.ScreenName)
		}
		config.X11Endpoint = endpoint
		log.Printf("Verified configured X11 target against DISPLAY: %s", endpoint.String())
	} else {
		log.Printf("Warning: DISPLAY endpoint could not be resolved; using explicit X11 target without socket-match validation: %v", endpointErr)
	}
	config.X11Network = network
	config.X11Target = address
	return nil
}

func defaultAgentProofConfig() authproof.RuntimeConfig {
	return authproof.RuntimeConfig{
		Mode:          getenvDefault("WEAVERSSH_PROOF_MODE", authproof.ProofModeOff),
		SecurityLevel: getenvDefault("WEAVERSSH_PROOF_SECURITY_LEVEL", authproof.SecurityLevelCompat),
		SubjectPeerID: getenvDefault("WEAVERSSH_PROOF_PEER_ID", defaultPeerID("wv-agent")),
		Audience:      authproof.AudienceAgent,
		PublicKey:     os.Getenv("WEAVERSSH_PROOF_PUBLIC_KEY"),
		PublicKeyFile: os.Getenv("WEAVERSSH_PROOF_PUBLIC_KEY_FILE"),
		ChainSHA256:   os.Getenv("WEAVERSSH_PROOF_CHAIN_SHA256"),
		TTL:           authproof.DefaultProofTTL,
		ReplayCache:   authproof.NewNonceCache(),
	}
}

func verifyWebSocketProof(wsConn *websocket.Conn, config AgentConfig) (authproof.Grant, error) {
	if err := wsConn.SetReadDeadline(time.Now().Add(config.AuthTimeout)); err != nil {
		return authproof.Grant{}, fmt.Errorf("set proof read deadline: %w", err)
	}
	messageType, payload, err := wsConn.ReadMessage()
	_ = wsConn.SetReadDeadline(time.Time{})
	if err != nil {
		return authproof.Grant{}, fmt.Errorf("read authproof control frame: %w", err)
	}
	if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
		return authproof.Grant{}, fmt.Errorf("unexpected authproof frame type %d", messageType)
	}
	proof, err := authproof.ParseControlFrame(payload)
	if err != nil {
		return authproof.Grant{}, fmt.Errorf("parse authproof control frame: %w", err)
	}
	grant, err := config.Proof.Verify(proof, time.Now())
	if err != nil {
		return authproof.Grant{}, fmt.Errorf("verify authproof: %w", err)
	}
	log.Printf("Runtime authproof accepted issuer=%s subject=%s session=%s security_level=%s", grant.IssuerPeerID, grant.SubjectPeerID, grant.SessionID, grant.SecurityLevel)
	return grant, nil
}

func defaultPeerID(prefix string) string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return prefix
	}
	return prefix + "-" + hostname
}

func getenvDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// handleHTTPUpgrade handles direct HTTP WebSocket upgrade requests
func handleHTTPUpgrade(conn net.Conn, reader *bufio.Reader, upgrader *websocket.Upgrader, handler func(*websocket.Conn, websocketAuthorityContext)) {
	// Create a custom ResponseWriter that writes to the connection
	rw := &connResponseWriter{
		conn:   conn,
		header: make(http.Header),
		reader: reader,
	}

	// Parse HTTP request
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("Failed to read HTTP request: %v", err)
		return
	}

	// Upgrade to WebSocket
	wsConn, err := upgrader.Upgrade(rw, req, nil)
	if err != nil {
		log.Printf("Failed to upgrade to WebSocket: %v", err)
		return
	}
	defer wsConn.Close()

	// Call the handler
	handler(wsConn, authorityContextFromConn(false, conn))
}

// handleX11ThenWebSocket handles X11 handshake followed by WebSocket upgrade
// This follows the pattern from weaverssh_server_standalone.go
// Handle X11 protocol handshake first, then WebSocket upgrade
func handleX11ThenWebSocket(conn net.Conn, reader *bufio.Reader, upgrader *websocket.Upgrader, handler func(*websocket.Conn, websocketAuthorityContext), x11Server *X11Server, config AgentConfig) {
	// Step 1: Perform X11 authentication handshake
	log.Printf("Performing X11 handshake...")

	client := &ClientConnection{
		conn:      conn,
		state:     StateListening,
		byteOrder: nil,
	}

	// Read connection setup from client
	setup, err := ReadConnectionSetup(reader)
	if err != nil {
		log.Printf("Failed to read X11 setup: %v", err)
		return
	}

	// Determine byte order
	if setup.ByteOrder == BigEndian {
		client.byteOrder = binary.BigEndian
	} else {
		client.byteOrder = binary.LittleEndian
	}

	log.Printf("X11 protocol: %d.%d, byte order: %#x, auth: %s",
		setup.ProtocolMajorVer, setup.ProtocolMinorVer, setup.ByteOrder, setup.AuthProtoName)

	// Validate auth
	authOK := x11Server.validateAuth(setup, client)

	// In trusted mode, allow any connection (auth failures allowed).
	// The X11 handshake is only for establishing the socket, not security.
	if !authOK && config.TrustedAuth {
		log.Printf("Allowing connection despite auth failure (trusted mode)")
		authOK = true
	}

	reply := x11Server.buildConnectionReply(authOK, client)
	if err := reply.Write(conn, client.byteOrder); err != nil {
		log.Printf("Failed to write X11 reply: %v", err)
		return
	}

	if !authOK {
		log.Printf("X11 authentication failed")
		return
	}

	client.authenticated = true
	client.state = StateConnected
	log.Printf("X11 authentication successful")
	log.Printf("DEBUG: About to peek for next protocol (WebSocket or raw X11)")

	// Step 2: Peek to detect what comes next - HTTP upgrade or X11 protocol
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	peek, err := reader.Peek(4)
	conn.SetReadDeadline(time.Time{})

	if err == nil && len(peek) >= 4 && string(peek[:4]) == "GET " {
		log.Printf("DEBUG: Detected WebSocket upgrade request")
	} else {
		if err != nil {
			log.Printf("DEBUG: Peek failed with error: %v", err)
		} else {
			log.Printf("DEBUG: Peeked %d bytes: %q (hex: % x)", len(peek), peek, peek)
		}
		log.Printf("DEBUG: Treating as raw X11 protocol, calling handleX11Requests")
	}

	if err == nil && len(peek) >= 4 && string(peek[:4]) == "GET " {
		req, err := http.ReadRequest(reader)
		if err != nil {
			log.Printf("Failed to read WebSocket upgrade request: %v", err)
			return
		}

		rw := &connResponseWriter{
			conn:   conn,
			header: make(http.Header),
			reader: reader,
		}

		wsConn, err := upgrader.Upgrade(rw, req, nil)
		if err != nil {
			log.Printf("Failed to upgrade to WebSocket: %v", err)
			return
		}
		defer wsConn.Close()

		log.Printf("WebSocket upgrade successful")
		handler(wsConn, authorityContextFromConn(true, conn))
	} else {
		// Raw X11 protocol (xauth generate, xdpyinfo, etc.)
		log.Printf("Detected raw X11 protocol, handling X11 requests")

		// Process X11 requests like weaverssh_server_standalone.go does
		handleX11Requests(conn, reader, client, x11Server)

		return
	}

}

// handleX11Requests handles X11 protocol requests (for xauth, xdpyinfo, etc.)
func handleX11Requests(conn net.Conn, reader *bufio.Reader, client *ClientConnection, server *X11Server) {
	log.Printf("DEBUG: Entered handleX11Requests - starting request processing loop")
	requestCount := 0

	for {
		requestCount++
		log.Printf("DEBUG: Waiting for X11 request #%d (buffered: %d bytes)", requestCount, reader.Buffered())

		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		req, err := ReadRequest(reader, client.byteOrder)
		conn.SetReadDeadline(time.Time{})

		if err != nil {
			if err != io.EOF {
				log.Printf("X11 read error: %v", err)
			}
			log.Printf("DEBUG: Exiting handleX11Requests after %d requests", requestCount-1)
			return
		}

		client.incrementSequence()

		log.Printf("X11 request: opcode=%d, detail=%d, length=%d", req.Opcode, req.Detail, req.Length)

		// Handle basic X11 requests
		switch req.Opcode {
		case OpcodeQueryExtension:
			log.Printf("DEBUG: Handling QueryExtension request")
			err := server.handleQueryExtension(client, req)
			if err != nil {
				log.Printf("ERROR: QueryExtension handling failed: %v", err)
				return
			}
		case SecurityMajorOpcode:
			log.Printf("DEBUG: Handling SECURITY extension request (minor opcode: %d)", req.Detail)
			err := server.handleSecurityRequest(client, req)
			if err != nil {
				log.Printf("ERROR: SECURITY request handling failed: %v", err)
				return
			}

		default:
			log.Printf("DEBUG: Sending generic reply for opcode %d", req.Opcode)
			server.sendGenericReply(client)
		}
	}
}

// connResponseWriter implements http.ResponseWriter for raw connections
type connResponseWriter struct {
	conn   net.Conn
	header http.Header
	reader *bufio.Reader
	mu     sync.Mutex
}

func (w *connResponseWriter) Header() http.Header {
	return w.header
}

func (w *connResponseWriter) Write(data []byte) (int, error) {
	return w.conn.Write(data)
}

func (w *connResponseWriter) WriteHeader(statusCode int) {
	// Headers are written by the upgrader
}

func (w *connResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(w.reader, bufio.NewWriter(w.conn)), nil
}

// getSystemX11Cookie retrieves the X11 MIT-MAGIC-COOKIE from xauth
// This mirrors the approach in weaverssh_socks_proxy.go
func getSystemX11Cookie() (string, error) {
	display := os.Getenv("DISPLAY")
	if display == "" {
		return "", fmt.Errorf("DISPLAY not set")
	}

	// Try to find xauth command
	xauthPaths := []string{
		"/opt/X11/bin/xauth",   // macOS XQuartz
		"/usr/bin/xauth",       // Linux
		"/usr/X11R6/bin/xauth", // BSD
	}

	var xauthCmd string
	for _, path := range xauthPaths {
		if _, err := os.Stat(path); err == nil {
			xauthCmd = path
			break
		}
	}

	if xauthCmd == "" {
		return "", fmt.Errorf("xauth command not found")
	}

	cmd := exec.Command(xauthCmd, "list")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("xauth failed: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "MIT-MAGIC-COOKIE-1") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return parts[2], nil
			}
		}
	}

	return "", fmt.Errorf("cookie not found in xauth database")
}
