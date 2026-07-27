package app

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"weaverssh/authproof"
	"weaverssh/display"
	"weaverssh/flowcontrol"
	"weaverssh/tunnel"
)

func defaultSocksProofConfig() authproof.RuntimeConfig {
	return authproof.RuntimeConfig{
		Mode:           getenvDefault("WEAVERSSH_PROOF_MODE", authproof.ProofModeOff),
		SecurityLevel:  getenvDefault("WEAVERSSH_PROOF_SECURITY_LEVEL", authproof.SecurityLevelCompat),
		IssuerPeerID:   getenvDefault("WEAVERSSH_PROOF_ISSUER_ID", defaultPeerID("wv-socks")),
		SubjectPeerID:  getenvDefault("WEAVERSSH_PROOF_SUBJECT_ID", "wv-agent"),
		Audience:       authproof.AudienceAgent,
		PrivateKey:     os.Getenv("WEAVERSSH_PROOF_PRIVATE_KEY"),
		PrivateKeyFile: os.Getenv("WEAVERSSH_PROOF_PRIVATE_KEY_FILE"),
		SignerProvider: getenvDefault("WEAVERSSH_PROOF_SIGNER_PROVIDER", os.Getenv("WEAVERSSH_PROOF_SIGNER")),
		Identity:       os.Getenv("WEAVERSSH_PROOF_IDENTITY"),
		IdentityFile:   os.Getenv("WEAVERSSH_PROOF_IDENTITY_FILE"),
		AgentSocket:    os.Getenv("WEAVERSSH_PROOF_AGENT_SOCKET"),
		ChainSHA256:    os.Getenv("WEAVERSSH_PROOF_CHAIN_SHA256"),
		SessionID:      os.Getenv("WEAVERSSH_PROOF_SESSION_ID"),
		TTL:            authproof.DefaultProofTTL,
	}
}

// Custom SOCKS5 handler
type SOCKSHandler struct {
	agentEndpoint  string
	proof          authproof.RuntimeConfig
	x11Endpoint    display.Endpoint
	hasX11Endpoint bool
	relayStats     map[string]*RelayStats
	mu             sync.Mutex
}

// RelayStats tracks statistics for an active relay
type RelayStats struct {
	StartTime     time.Time
	BytesSent     int64
	BytesReceived int64
	LastActivity  time.Time
	State         string
	mu            sync.Mutex
}

// updateStats updates the byte counters for a relay
func (s *RelayStats) updateStats(sent, received int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.BytesSent += sent
	s.BytesReceived += received
	s.LastActivity = time.Now()
}

// setState updates the relay state
func (s *RelayStats) setState(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.State = state
	s.LastActivity = time.Now()
}

// getStats returns relay statistics
func (s *RelayStats) getStats() (int64, int64, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.BytesSent, s.BytesReceived, s.State
}

// HandleConnect handles SOCKS5 CONNECT requests
func (h *SOCKSHandler) HandleConnect(ctx context.Context, writer io.Writer, req *socks5.Request) error {
	// Extract target information for logging
	targetIP := req.DestAddr.IP.String()
	targetPort := req.DestAddr.Port
	targetAddr := fmt.Sprintf("%s:%d", targetIP, targetPort)
	log.Printf("SOCKS5 connect request to %s", targetAddr)

	// Create a unique relay ID
	relayID := fmt.Sprintf("relay-%d", time.Now().UnixNano())

	// Initialize stats tracking
	h.mu.Lock()
	if h.relayStats == nil {
		h.relayStats = make(map[string]*RelayStats)
	}
	stats := &RelayStats{
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		State:        "CONNECTING",
	}
	h.relayStats[relayID] = stats
	h.mu.Unlock()

	// Determine if this is an X11 connection (port range 6000-6099)
	isX11Connection := (targetPort >= 6000 && targetPort <= 6099)

	// Handle based on connection type
	var err error
	if isX11Connection {
		log.Printf("Handling as X11 connection to port %d", targetPort)
		err = h.handleX11Connection(writer, req, relayID, stats, targetAddr)
	} else {
		log.Printf("Handling as direct connection to %s", targetAddr)
		err = h.handleDirectConnection(writer, req, relayID, stats, targetAddr)
	}

	// Handle cleanup on error
	if err != nil {
		h.mu.Lock()
		delete(h.relayStats, relayID)
		h.mu.Unlock()
	}

	return err
}

// HandleAssociate validates/logs UDP ASSOCIATE setup before the default handler runs.
// The actual UDP relay path is provided by go-socks5's built-in Associate implementation.
func (h *SOCKSHandler) HandleAssociate(ctx context.Context, writer io.Writer, req *socks5.Request) error {
	_ = ctx
	_ = writer
	clientHint := "<nil>"
	remoteAddr := "<nil>"
	localAddr := "<nil>"
	if req != nil && req.DestAddr != nil {
		clientHint = req.DestAddr.String()
	}
	if req != nil && req.RemoteAddr != nil {
		remoteAddr = req.RemoteAddr.String()
	}
	if req != nil && req.LocalAddr != nil {
		localAddr = req.LocalAddr.String()
	}
	log.Printf("SOCKS5 UDP ASSOCIATE request (RFC1928 cmd=0x03): remote=%s local=%s client_hint=%s", remoteAddr, localAddr, clientHint)
	return nil
}

// handleX11Connection handles X11 connections through the agent proxy
func (h *SOCKSHandler) handleX11Connection(writer io.Writer, req *socks5.Request, relayID string, stats *RelayStats, targetAddr string) error {
	if err := h.validateX11RequestTarget(req); err != nil {
		log.Printf("Rejecting X11 SOCKS request to %s: %v", targetAddr, err)
		return socks5.SendReply(writer, statute.RepRuleFailure, nil)
	}

	session, err := h.openAuthenticatedAgentWebSocket()
	if err != nil {
		log.Printf("Failed to establish authenticated agent WebSocket: %v", err)
		return socks5.SendReply(writer, statute.RepConnectionRefused, nil)
	}

	// Send success to the SOCKS5 client only after X11 auth + WebSocket upgrade.
	if err := socks5.SendReply(writer, statute.RepSuccess, &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	}); err != nil {
		_ = session.Close()
		return fmt.Errorf("failed to send reply: %v", err)
	}

	stats.setState("CONNECTED")
	log.Printf("Starting X11 WebSocket relay %s through agent to %s", relayID, targetAddr)
	stats.setState("RELAYING")

	return h.relayWebSocket(writer.(io.ReadWriter), session, h.openAuthenticatedAgentWebSocket, stats, relayID)
}

func (h *SOCKSHandler) openAuthenticatedAgentWebSocket() (websocketRelaySession, error) {
	network, address, err := parseSocksAgentEndpoint(h.agentEndpoint)
	if err != nil {
		return nil, err
	}
	log.Printf("Connecting to agent at %s:%s", network, address)
	agentConn, err := tunnel.DialWithPolicy(network, address, tunnel.DefaultRetryPolicy())
	if err != nil {
		return nil, fmt.Errorf("connect to agent: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = agentConn.Close()
		}
	}()

	_ = agentConn.SetDeadline(time.Now().Add(10 * time.Second))
	defer agentConn.SetDeadline(time.Time{})

	log.Printf("Performing X11 authentication handshake")
	cookie, err := getMITMagicCookie()
	if err != nil {
		return nil, fmt.Errorf("get X11 cookie: %w", err)
	}

	setupReq, err := createX11SetupRequest(cookie)
	if err != nil {
		return nil, fmt.Errorf("create X11 setup request: %w", err)
	}

	if _, err := agentConn.Write(setupReq); err != nil {
		return nil, fmt.Errorf("send X11 setup: %w", err)
	}

	responseHeader := make([]byte, 8)
	if _, err := io.ReadFull(agentConn, responseHeader); err != nil {
		return nil, fmt.Errorf("read X11 response: %w", err)
	}

	if responseHeader[0] != 1 {
		reasonLen := responseHeader[1]
		reason := make([]byte, reasonLen)
		_, _ = io.ReadFull(agentConn, reason)
		return nil, fmt.Errorf("X11 authentication failed: %s", string(reason))
	}

	additionalLen := binary.LittleEndian.Uint16(responseHeader[6:8]) * 4
	if additionalLen > 0 {
		additional := make([]byte, additionalLen)
		if _, err := io.ReadFull(agentConn, additional); err != nil {
			return nil, fmt.Errorf("read X11 server info: %w", err)
		}
	}

	log.Printf("X11 authentication successful with agentproxy")
	log.Printf("Upgrading to WebSocket for X11 relay")
	flowProfile := flowcontrol.DefaultProfile()
	wsConn, err := tunnel.ClientUpgradeWithProfile(agentConn, flowProfile)
	if err != nil {
		return nil, fmt.Errorf("websocket upgrade: %w", err)
	}

	if h.proof.Required() {
		if err := h.sendAgentProof(wsConn, cookie); err != nil {
			_ = wsConn.Close()
			return nil, fmt.Errorf("send authproof control frame: %w", err)
		}
	}

	closeOnError = false
	return &agentWebSocketSession{ws: wsConn, conn: agentConn}, nil
}

func (h *SOCKSHandler) sendAgentProof(wsConn *websocket.Conn, cookie string) error {
	proofConfig := h.proof
	proofConfig.Audience = authproof.AudienceAgent
	proofConfig.X11CookieSHA256 = authproof.HashX11Cookie(cookie)
	proofConfig.RequiredCapabilities = authproof.DefaultRelayCapabilities()
	proof, err := proofConfig.Sign(time.Now())
	if err != nil {
		return err
	}
	payload, err := authproof.MarshalControlFrame(proof)
	if err != nil {
		return err
	}
	if err := wsConn.WriteMessage(websocket.TextMessage, payload); err != nil {
		return err
	}
	log.Printf("Runtime authproof sent issuer=%s subject=%s session=%s", proof.Grant.IssuerPeerID, proof.Grant.SubjectPeerID, proof.Grant.SessionID)
	return nil
}

func (h *SOCKSHandler) validateX11RequestTarget(req *socks5.Request) error {
	if !h.hasX11Endpoint {
		return nil
	}
	if req == nil || req.DestAddr == nil {
		return fmt.Errorf("missing SOCKS destination")
	}
	target := req.DestAddr.String()
	if !h.x11Endpoint.Matches("tcp", target) {
		return fmt.Errorf("SOCKS target tcp:%s does not match DISPLAY endpoint %s:%s", target, h.x11Endpoint.Network, h.x11Endpoint.Address)
	}
	if !h.x11Endpoint.IsScreen0() {
		return fmt.Errorf("DISPLAY resolves to unsupported %s", h.x11Endpoint.ScreenName)
	}
	return nil
}

// handleDirectConnection handles direct connections to targets
func (h *SOCKSHandler) handleDirectConnection(writer io.Writer, req *socks5.Request, relayID string, stats *RelayStats, targetAddr string) error {
	// Connect directly to the target
	log.Printf("Connecting directly to %s", targetAddr)
	targetConn, err := net.DialTimeout("tcp", targetAddr, 30*time.Second)
	if err != nil {
		log.Printf("Failed to connect to target: %v", err)
		return socks5.SendReply(writer, statute.RepHostUnreachable, nil)
	}
	defer targetConn.Close()

	// Send success to the SOCKS5 client
	if err := socks5.SendReply(writer, statute.RepSuccess, &net.TCPAddr{
		IP:   req.DestAddr.IP,
		Port: req.DestAddr.Port,
	}); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	// Update state and start relay
	stats.setState("CONNECTED")
	log.Printf("Starting direct relay %s to %s", relayID, targetAddr)
	stats.setState("RELAYING")

	// Start the bidirectional relay
	return h.relay(writer.(io.ReadWriter), targetConn, stats, relayID, "DIRECT")
}

// relay handles bidirectional direct TCP data transfer.
func (h *SOCKSHandler) relay(src io.ReadWriter, dst io.ReadWriter, stats *RelayStats, relayID string, relayType string) error {
	type copyResult struct {
		direction string
		bytes     int64
		err       error
	}

	results := make(chan copyResult, 2)
	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			closeRelayEndpoint(src)
			closeRelayEndpoint(dst)
		})
	}

	pump := func(direction string, dst io.ReadWriter, src io.ReadWriter) {
		n, err := io.Copy(dst, src)
		results <- copyResult{direction: direction, bytes: n, err: err}
		shutdown()
	}

	go pump("client_to_target", dst, src)
	go pump("target_to_client", src, dst)

	var sent, received int64
	var terminalErr error
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			switch result.direction {
			case "client_to_target":
				sent = result.bytes
			case "target_to_client":
				received = result.bytes
			}
			if result.err != nil && result.err != io.EOF && terminalErr == nil {
				terminalErr = fmt.Errorf("%s relay %s %s: %w", relayType, relayID, result.direction, result.err)
			}
		case <-time.After(12 * time.Hour):
			terminalErr = fmt.Errorf("%s relay %s timed out", relayType, relayID)
			shutdown()
			i = 2
		}
	}

	stats.updateStats(sent, received)
	state := "CLOSED"
	if terminalErr != nil {
		state = "FAIL_CLOSED"
		log.Printf("%s relay %s failed closed: %v", relayType, relayID, terminalErr)
	}
	stats.setState(state)
	log.Printf("%s relay %s closed. Bytes sent: %d, received: %d",
		relayType, relayID, sent, received)

	h.scheduleRelayStatsCleanup(relayID)
	return terminalErr
}

func closeRelayEndpoint(endpoint io.ReadWriter) {
	if closer, ok := endpoint.(io.Closer); ok {
		_ = closer.Close()
	}
}

type websocketRelayEvent struct {
	generation int
	fromClient bool
	payload    []byte
	err        error
}

// relayWebSocket handles bidirectional data transfer over WebSocket with a
// bounded R5 drain/reconnect path for recoverable WebSocket transport faults.
func (h *SOCKSHandler) relayWebSocket(
	src io.ReadWriter,
	session websocketRelaySession,
	reconnect reconnectWebSocketFunc,
	stats *RelayStats,
	relayID string,
) error {
	flowProfile := flowcontrol.DefaultProfile()
	clientEvents := make(chan websocketRelayEvent, flowProfile.QueueDepth)
	wsEvents := make(chan websocketRelayEvent, flowProfile.QueueDepth)
	stop := make(chan struct{})
	var stopOnce sync.Once
	stopReaders := func() {
		stopOnce.Do(func() {
			close(stop)
			closeRelayEndpoint(src)
			if session != nil {
				_ = session.Close()
			}
		})
	}
	defer stopReaders()

	go readClientRelayEvents(src, clientEvents, stop, flowProfile)
	generation := 1
	startWebSocketRelayReader(session, generation, wsEvents, stop)

	policy := defaultDrainReconnectPolicy()
	policy.Authenticated = func() bool { return true }

	var bytesSent, bytesReceived int64
	finish := func(state string, err error) error {
		stopReaders()
		stats.updateStats(bytesSent, bytesReceived)
		stats.setState(state)
		if err != nil {
			log.Printf("X11 WebSocket relay %s failed closed: %v", relayID, err)
		}
		log.Printf("X11 WebSocket relay %s closed. Bytes sent: %d, received: %d", relayID, bytesSent, bytesReceived)
		h.scheduleRelayStatsCleanup(relayID)
		return err
	}

	recoverSession := func(buffered [][]byte) error {
		stats.setState("DRAINING")
		stats.setState("RECONNECTING")
		next, decision := recoverBufferedWebSocketSession(session, policy, reconnect, buffered)
		log.Printf("X11 WebSocket relay %s R5 recovery outcome=%s attempts=%d accepted=%d delivered=%d buffered=%d audit=%v err=%v",
			relayID, decision.Outcome, decision.Attempts, decision.Accepted, decision.Delivered, decision.Buffered, decision.Audit, decision.Err)
		if decision.Outcome != drainReconnectRecovered {
			return decision.Err
		}
		bytesSent += decision.Delivered
		session = next
		generation++
		stats.setState("RELAYING")
		startWebSocketRelayReader(session, generation, wsEvents, stop)
		return nil
	}

	for {
		select {
		case event := <-clientEvents:
			if event.err != nil {
				if event.err != io.EOF {
					return finish("FAIL_CLOSED", fmt.Errorf("client read: %w", event.err))
				}
				return finish("CLOSED", nil)
			}
			if len(event.payload) == 0 {
				continue
			}
			if err := session.WriteMessage(websocket.BinaryMessage, event.payload); err != nil {
				if recoverErr := recoverSession([][]byte{event.payload}); recoverErr != nil {
					return finish("FAIL_CLOSED", recoverErr)
				}
				continue
			}
			bytesSent += int64(len(event.payload))

		case event := <-wsEvents:
			if event.generation != generation {
				continue
			}
			if event.err != nil {
				if errors.Is(event.err, io.EOF) || websocket.IsCloseError(event.err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					return finish("CLOSED", nil)
				}
				if recoverErr := recoverSession(nil); recoverErr != nil {
					return finish("FAIL_CLOSED", recoverErr)
				}
				continue
			}
			if len(event.payload) == 0 {
				continue
			}
			n, err := src.Write(event.payload)
			bytesReceived += int64(n)
			if err != nil {
				return finish("FAIL_CLOSED", fmt.Errorf("client write: %w", err))
			}
			if n != len(event.payload) {
				return finish("FAIL_CLOSED", io.ErrShortWrite)
			}
		}
	}
}

func readClientRelayEvents(src io.ReadWriter, events chan<- websocketRelayEvent, stop <-chan struct{}, profile flowcontrol.Profile) {
	buf := make([]byte, profile.Normalized().RelayReadBytes)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			payload := append([]byte(nil), buf[:n]...)
			select {
			case events <- websocketRelayEvent{fromClient: true, payload: payload}:
			case <-stop:
				return
			}
		}
		if err != nil {
			select {
			case events <- websocketRelayEvent{fromClient: true, err: err}:
			case <-stop:
			}
			return
		}
	}
}

func startWebSocketRelayReader(session websocketRelaySession, generation int, events chan<- websocketRelayEvent, stop <-chan struct{}) {
	if session == nil {
		return
	}
	go func() {
		for {
			messageType, message, err := session.ReadMessage()
			if err != nil {
				select {
				case events <- websocketRelayEvent{generation: generation, err: err}:
				case <-stop:
				}
				return
			}
			if messageType != websocket.BinaryMessage {
				log.Printf("Received non-binary WebSocket message, ignoring")
				continue
			}
			payload := append([]byte(nil), message...)
			select {
			case events <- websocketRelayEvent{generation: generation, payload: payload}:
			case <-stop:
				return
			}
		}
	}()
}

func (h *SOCKSHandler) scheduleRelayStatsCleanup(relayID string) {
	go func() {
		time.Sleep(1 * time.Minute)
		h.mu.Lock()
		delete(h.relayStats, relayID)
		h.mu.Unlock()
	}()
}

// getMITMagicCookie retrieves the X11 MIT-MAGIC-COOKIE from xauth
func getMITMagicCookie() (string, error) {
	display := os.Getenv("DISPLAY")
	if display == "" {
		return "", fmt.Errorf("DISPLAY not set")
	}

	// Build xauth command
	// If XAUTHORITY is set (SSH X11 forwarding), use that file
	var cmd *exec.Cmd
	xauthFile := os.Getenv("XAUTHORITY")
	if xauthFile != "" {
		log.Printf("DEBUG: Using XAUTHORITY file: %s", xauthFile)
		cmd = exec.Command("xauth", "-f", xauthFile, "list")
	} else {
		cmd = exec.Command("xauth", "list")
	}

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("xauth failed: %v", err)
	}

	log.Printf("DEBUG: xauth output:\n%s", string(output))

	// Parse display to extract the part we need to match
	// For "localhost:10.0", we want to match lines containing ":10"
	displayParts := strings.Split(display, ":")
	displayMatch := ":"
	if len(displayParts) > 1 {
		displayMatch = ":" + strings.Split(displayParts[1], ".")[0]
	}
	log.Printf("DEBUG: Looking for display match: %s", displayMatch)

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Match both the display and the cookie type
		if strings.Contains(line, displayMatch) && strings.Contains(line, "MIT-MAGIC-COOKIE-1") {
			log.Printf("DEBUG: Matched line: %s", line)

			parts := strings.Fields(line)
			if len(parts) >= 3 {
				log.Printf("DEBUG: Returning cookie: %s", parts[2])
				return parts[2], nil
			}
		}
	}

	return "", fmt.Errorf("cookie not found for display %s", display)
}

// createX11SetupRequest creates X11 setup request with MIT-MAGIC-COOKIE-1
func createX11SetupRequest(cookie string) ([]byte, error) {
	// Convert hex cookie to bytes
	cookieBytes := make([]byte, len(cookie)/2)
	for i := 0; i < len(cookie); i += 2 {
		b, err := strconv.ParseUint(cookie[i:i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		cookieBytes[i/2] = byte(b)
	}

	authName := "MIT-MAGIC-COOKIE-1"
	namePad := (4 - (len(authName) % 4)) % 4

	req := make([]byte, 12+len(authName)+namePad+len(cookieBytes))

	// Byte order, protocol version
	req[0] = 'l' // little endian
	req[2] = 11  // major version
	req[4] = 0   // minor version

	// Auth lengths
	req[6] = byte(len(authName) & 0xFF)
	req[7] = byte(len(authName) >> 8)
	req[8] = byte(len(cookieBytes) & 0xFF)
	req[9] = byte(len(cookieBytes) >> 8)

	// Copy auth name and data
	copy(req[12:], []byte(authName))
	copy(req[12+len(authName)+namePad:], cookieBytes)

	return req, nil
}

func RunSocks() {
	// Parse command line flags
	var listenPort int
	var agentEndpoint string
	var x11Mode bool
	var logLevel string
	proofConfig := defaultSocksProofConfig()

	flag.IntVar(&listenPort, "port", 1080, "Port to listen on")
	flag.StringVar(&agentEndpoint, "agent", "localhost:6000", "Agent endpoint (localhost:<port>, tcp://host:port, unix:/path)")
	flag.BoolVar(&x11Mode, "X", false, "Enable X11 mode")
	flag.StringVar(&logLevel, "loglevel", "info", "Log level (debug, info, warn, error)")
	flag.StringVar(&proofConfig.Mode, "proof-mode", proofConfig.Mode, "Runtime authproof mode: off|required")
	flag.StringVar(&proofConfig.SecurityLevel, "proof-security-level", proofConfig.SecurityLevel, "Runtime authority security level: compat|same_uid|x11_cookie|agent_proof|strict")
	flag.StringVar(&proofConfig.IssuerPeerID, "proof-issuer-id", proofConfig.IssuerPeerID, "Issuer peer ID for authproof grants")
	flag.StringVar(&proofConfig.SubjectPeerID, "proof-subject-id", proofConfig.SubjectPeerID, "Expected agent peer ID in authproof grants")
	flag.StringVar(&proofConfig.PrivateKey, "proof-private-key", proofConfig.PrivateKey, "Ed25519 private key or seed for authproof signing (base64url, base64, or hex)")
	flag.StringVar(&proofConfig.PrivateKeyFile, "proof-private-key-file", proofConfig.PrivateKeyFile, "File containing Ed25519 private key or seed for authproof signing")
	flag.StringVar(&proofConfig.SignerProvider, "proof-signer-provider", proofConfig.SignerProvider, "Authproof signer provider: key|ssh-agent|gpg-agent")
	flag.StringVar(&proofConfig.SignerProvider, "proof-signer", proofConfig.SignerProvider, "Alias for -proof-signer-provider")
	flag.StringVar(&proofConfig.Identity, "proof-identity", proofConfig.Identity, "Signer identity selector: SSH key comment, SHA256 fingerprint, or public key text")
	flag.StringVar(&proofConfig.IdentityFile, "proof-identity-file", proofConfig.IdentityFile, "File containing signer identity selector or OpenSSH ssh-ed25519 public key")
	flag.StringVar(&proofConfig.AgentSocket, "proof-agent-socket", proofConfig.AgentSocket, "ssh-agent or gpg-agent SSH socket path; defaults to SSH_AUTH_SOCK or gpgconf for gpg-agent")
	flag.StringVar(&proofConfig.ChainSHA256, "proof-chain-sha256", proofConfig.ChainSHA256, "Chain binding SHA-256 hex for authproof grants; required when proof mode is required")
	flag.StringVar(&proofConfig.SessionID, "proof-session-id", proofConfig.SessionID, "Optional fixed authproof session ID; default is generated per session")
	flag.DurationVar(&proofConfig.TTL, "proof-ttl", proofConfig.TTL, "Authproof grant TTL")

	flag.Parse()

	// Set up logging
	switch strings.ToLower(logLevel) {
	case "debug":
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	case "info":
		log.SetFlags(log.Ldate | log.Ltime)
	case "warn", "error":
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	}

	// Check DISPLAY for X11 auth
	if os.Getenv("DISPLAY") == "" && x11Mode {
		log.Fatal("DISPLAY environment variable required for X11 authentication")
	}

	proofConfig.Audience = authproof.AudienceAgent
	proofConfig.RequiredCapabilities = authproof.DefaultRelayCapabilities()
	if proofConfig.Required() {
		// X11CookieSHA256 is bound per connection after reading the active xauth cookie.
		if err := proofConfig.ValidateSignerKeyConfig(); err != nil {
			log.Fatalf("Invalid runtime authproof signer config: %v", err)
		}
		log.Printf("Runtime authproof required for issuer %s subject %s", proofConfig.IssuerPeerID, proofConfig.SubjectPeerID)
	}

	// Variables for old-style command line parsing
	localPort := ""
	localAddr := ""
	targetHost := ""
	targetPort := ""
	enable_socks5X11 := x11Mode

	// Check if using old-style arguments
	args := flag.Args()
	if len(args) > 0 {
		// Original style command line arguments
		if args[0] == "-X" {
			enable_socks5X11 = true
			if len(args) != 2 {
				fmt.Println("Usage: clientproxy -X localhost:<local-port>")
				return
			}
			localAddr = args[1]
		} else {
			if len(args) != 3 {
				fmt.Println("Usage: clientproxy localhost:<local-port> <target-host> <target-port>")
				return
			}
			localAddr = args[0]
			targetHost = args[1]
			targetPort = args[2]
		}

		// Parse local address
		localParts := strings.Split(localAddr, ":")
		if len(localParts) != 2 {
			fmt.Println("Invalid local address format. Use localhost:<local-port>")
			return
		}

		if isInteger(localParts[1]) {
			listenPort, _ = strconv.Atoi(localParts[1])
			localPort = fmt.Sprintf(":%d", listenPort)
		} else {
			fmt.Println("Local port is not a number")
			return
		}

		// Set agent endpoint for standard mode
		if !enable_socks5X11 && targetHost != "" && targetPort != "" {
			agentEndpoint = fmt.Sprintf("%s:%s", targetHost, targetPort)
		}
	} else {
		// Using flag-based arguments
		localPort = fmt.Sprintf(":%d", listenPort)
	}

	// Handle X11 mode
	manualAgentSet := flag.Lookup("agent").Value.String() != "localhost:6000"
	var x11Endpoint display.Endpoint
	hasX11Endpoint := false

	if enable_socks5X11 {
		endpoint, err := display.ResolveEnvEndpoint()
		if err != nil {
			fmt.Printf("Failed to resolve DISPLAY endpoint: %v\n", err)
			return
		}
		x11Endpoint = endpoint
		hasX11Endpoint = true
		log.Printf("Resolved DISPLAY endpoint: %s", endpoint.String())

		if !manualAgentSet {
			if endpoint.Network == "tcp" {
				agentEndpoint = endpoint.Address
			} else {
				agentEndpoint = fmt.Sprintf("localhost:%d", endpoint.Port())
			}
			log.Printf("Using agent endpoint %s for DISPLAY %s", agentEndpoint, endpoint.RawDisplay)
		}
	}
	if manualAgentSet {
		log.Printf("Using manually specified agent endpoint: %s", agentEndpoint)
	}

	// Create custom handler with stats tracking
	handler := &SOCKSHandler{
		agentEndpoint:  agentEndpoint,
		proof:          proofConfig,
		x11Endpoint:    x11Endpoint,
		hasX11Endpoint: hasX11Endpoint,
		relayStats:     make(map[string]*RelayStats),
	}

	// Configure SOCKS5 server with our handler
	server := socks5.NewServer(
		socks5.WithRule(socks5.NewPermitConnAndAss()),
		socks5.WithConnectHandle(handler.HandleConnect),
		socks5.WithAssociateMiddleware(handler.HandleAssociate),
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)

	// Start server
	addr := localPort
	if addr == "" {
		addr = fmt.Sprintf(":%d", listenPort)
	}

	// Log based on mode
	if enable_socks5X11 {
		log.Printf("Client proxy listening on %s in X11 mode, connecting to %s", addr, agentEndpoint)
	} else {
		log.Printf("Client proxy listening on %s, connecting to %s", addr, agentEndpoint)
	}

	// Start monitoring stats periodically
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			handler.mu.Lock()
			active := 0
			totalSent := int64(0)
			totalReceived := int64(0)

			for _, stats := range handler.relayStats {
				sent, received, state := stats.getStats()
				if state == "RELAYING" {
					active++
					totalSent += sent
					totalReceived += received
				}
			}
			handler.mu.Unlock()

			if active > 0 {
				log.Printf("Status: %d active relays, %d bytes sent, %d bytes received",
					active, totalSent, totalReceived)
			}
		}
	}()

	if err := server.ListenAndServe("tcp", addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
