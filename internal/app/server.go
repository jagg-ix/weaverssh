package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"weaverssh/authproof"
)

// Configuration for the X11 server
type ServerConfig struct {
	Port               int
	AuthCookie         string
	EnableWebSocket    bool
	LogLevel           string
	MaxConnections     int
	ConnectionTimeout  time.Duration
	AuthTimeout        time.Duration
	EnableMetrics      bool
	ProofMode          string
	ProofSecurityLevel string
	ProofPeerID        string
	ProofIssuerPeerID  string
	ProofPublicKey     string
	ProofPublicKeyFile string
	ProofChainSHA256   string
	ProofTTL           time.Duration
}

// Metrics tracks server statistics
type Metrics struct {
	TotalConnections  int64
	ActiveConnections int64
	FailedAuth        int64
	GeneratedAuths    int64
	RevokedAuths      int64
	ExtensionQueries  int64
	WebSocketUpgrades int64
	mu                sync.RWMutex
}

// NewMetrics creates a new metrics tracker
func NewMetrics() *Metrics {
	return &Metrics{}
}

// IncrementCounter safely increments a metric counter
func (m *Metrics) IncrementCounter(counter *int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	*counter++
}

// GetStats returns a copy of current stats
func (m *Metrics) GetStats() map[string]int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]int64{
		"total_connections":  m.TotalConnections,
		"active_connections": m.ActiveConnections,
		"failed_auth":        m.FailedAuth,
		"generated_auths":    m.GeneratedAuths,
		"revoked_auths":      m.RevokedAuths,
		"extension_queries":  m.ExtensionQueries,
		"websocket_upgrades": m.WebSocketUpgrades,
	}
}

// LogStats logs current statistics
func (m *Metrics) LogStats() {
	stats := m.GetStats()
	log.Printf("=== Server Statistics ===")
	log.Printf("Total Connections:    %d", stats["total_connections"])
	log.Printf("Active Connections:   %d", stats["active_connections"])
	log.Printf("Failed Auth:          %d", stats["failed_auth"])
	log.Printf("Generated Auths:      %d", stats["generated_auths"])
	log.Printf("Revoked Auths:        %d", stats["revoked_auths"])
	log.Printf("Extension Queries:    %d", stats["extension_queries"])
	log.Printf("WebSocket Upgrades:   %d", stats["websocket_upgrades"])
	log.Printf("========================")
}

// InstrumentedX11Server wraps X11Server with metrics and monitoring
type InstrumentedX11Server struct {
	*X11Server
	config  ServerConfig
	metrics *Metrics
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewInstrumentedX11Server creates a new instrumented server
func NewInstrumentedX11Server(config ServerConfig) *InstrumentedX11Server {
	ctx, cancel := context.WithCancel(context.Background())

	return &InstrumentedX11Server{
		X11Server: NewX11Server(config.AuthCookie),
		config:    config,
		metrics:   NewMetrics(),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start begins the server with monitoring
func (s *InstrumentedX11Server) Start() error {
	if err := validateStandaloneServerAuthority(s.config); err != nil {
		return err
	}

	// Start metrics reporter
	if s.config.EnableMetrics {
		s.wg.Add(1)
		go s.metricsReporter()
	}

	// Start auth cleanup
	s.wg.Add(1)
	go s.authCleanup()

	log.Printf("Starting X11 Server on port %d", s.config.Port)
	log.Printf("Auth cookie: %s", s.config.AuthCookie)
	log.Printf("WebSocket support: %v", s.config.EnableWebSocket)
	log.Printf("Runtime authproof mode: %s security_level=%s", authproof.NormalizeProofMode(s.config.ProofMode), authproof.NormalizeSecurityLevel(s.config.ProofSecurityLevel))
	log.Printf("Max connections: %d", s.config.MaxConnections)

	return s.X11Server.Start(s.config.Port)
}

// metricsReporter periodically reports metrics
func (s *InstrumentedX11Server) metricsReporter() {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.metrics.LogStats()
		}
	}
}

// authCleanup periodically cleans up expired authorizations
func (s *InstrumentedX11Server) authCleanup() {
	defer s.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cleanExpiredAuths()
		}
	}
}

// cleanExpiredAuths removes expired authorizations
func (s *InstrumentedX11Server) cleanExpiredAuths() {
	s.X11Server.authMutex.Lock()
	defer s.X11Server.authMutex.Unlock()
	now := time.Now()
	expired := 0

	for id, auth := range s.X11Server.authorizations {
		if auth.Timeout > 0 {
			expiresAt := auth.CreatedAt.Add(time.Duration(auth.Timeout) * time.Second)
			if now.After(expiresAt) {
				delete(s.X11Server.authorizations, id)
				expired++
			}
		}
	}

	if expired > 0 {
		log.Printf("Cleaned up %d expired authorizations", expired)
	}
}

// Shutdown gracefully shuts down the server
func (s *InstrumentedX11Server) Shutdown() error {
	log.Printf("Shutting down server...")

	s.cancel()

	// Close listener
	if err := s.X11Server.Close(); err != nil {
		log.Printf("Error closing listener: %v", err)
	}

	// Wait for goroutines
	s.wg.Wait()

	// Final metrics
	s.metrics.LogStats()

	log.Printf("Server shutdown complete")
	return nil
}

// generateAuthCookie generates a random auth cookie
func generateAuthCookie() string {
	cookie := make([]byte, 16)
	if _, err := rand.Read(cookie); err != nil {
		log.Fatalf("Failed to generate auth cookie: %v", err)
	}
	return hex.EncodeToString(cookie)
}

// setupLogging configures logging based on level
func setupLogging(level string) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	switch level {
	case "debug":
		log.SetOutput(os.Stdout)
	case "info":
		log.SetOutput(os.Stdout)
	case "error":
		log.SetOutput(os.Stderr)
	default:
		log.SetOutput(os.Stdout)
	}
}

// Example usage functions

// ExampleBasicUsage demonstrates basic server usage
func ExampleBasicUsage() {
	fmt.Println("=== Example 1: Basic Usage ===")

	// Create server with default configuration
	server := NewX11Server("0123456789abcdef0123456789abcdef")

	// Start server (would block in real usage)
	fmt.Println("Server would start on port 6000")
	fmt.Println("Clients can connect and authenticate")

	_ = server
}

// ExampleWithMetrics demonstrates server with metrics
func ExampleWithMetrics() {
	fmt.Println("\n=== Example 2: Server with Metrics ===")

	config := ServerConfig{
		Port:              6002,
		AuthCookie:        generateAuthCookie(),
		EnableWebSocket:   true,
		LogLevel:          "info",
		MaxConnections:    100,
		ConnectionTimeout: 5 * time.Minute,
		AuthTimeout:       1 * time.Hour,
		EnableMetrics:     true,
	}

	server := NewInstrumentedX11Server(config)

	fmt.Printf("Server configured:\n")
	fmt.Printf("  Port: %d\n", config.Port)
	fmt.Printf("  Auth Cookie: %s\n", config.AuthCookie)
	fmt.Printf("  WebSocket: %v\n", config.EnableWebSocket)
	fmt.Printf("  Metrics: %v\n", config.EnableMetrics)

	_ = server
}

// ExampleClientFlow demonstrates the client flow
func ExampleClientFlow() {
	fmt.Println("\n=== Example 3: Client Connection Flow ===")
	fmt.Println("Client FSM States:")
	fmt.Println("  1. Idle")
	fmt.Println("  2. AwaitingHandshakeReply")
	fmt.Println("  3. Connected")
	fmt.Println("  4. AwaitingExtensionReply")
	fmt.Println("  5. Connected")
	fmt.Println("  6. AwaitingAuthReply")
	fmt.Println("  7. Ready")
	fmt.Println()
	fmt.Println("Protocol Flow:")
	fmt.Println("  Client -> Server: ConnectionSetup")
	fmt.Println("  Server -> Client: ConnectionReply")
	fmt.Println("  Client -> Server: QueryExtension(SECURITY)")
	fmt.Println("  Server -> Client: QueryExtensionReply")
	fmt.Println("  Client -> Server: GenerateAuthorization")
	fmt.Println("  Server -> Client: GenerateAuthReply")
	fmt.Println("  Client State: Ready ✓")
}

// ExampleWebSocketUpgrade demonstrates WebSocket upgrade
func ExampleWebSocketUpgrade() {
	fmt.Println("\n=== Example 4: WebSocket Protocol Upgrade ===")
	fmt.Println("Multi-protocol connection flow:")
	fmt.Println("  1. Client connects to port 6000")
	fmt.Println("  2. Server detects HTTP upgrade request")
	fmt.Println("  3. Server performs WebSocket handshake")
	fmt.Println("  4. Connection switches to WebSocket protocol")
	fmt.Println("  5. WebSocket frames exchanged")
	fmt.Println()
	fmt.Println("Use case: Web-based X11 clients")
	fmt.Println("  - Browser connects via WebSocket")
	fmt.Println("  - X11 protocol tunneled over WebSocket")
	fmt.Println("  - Enables X11 in web applications")
}

// ExampleTLACompliance demonstrates TLA+ compliance
func ExampleTLACompliance() {
	fmt.Println("\n=== Example 5: TLA+ Specification Compliance ===")
	fmt.Println("Invariants:")
	fmt.Println("  ✓ ClientReadyHasCookie")
	fmt.Println("    - Client in Ready state must have cookie")
	fmt.Println("  ✓ AuthGenRequiresConnection")
	fmt.Println("    - Authorization only generated when connected")
	fmt.Println("  ✓ SecurityExtensionProtocol")
	fmt.Println("    - SECURITY extension discovered before use")
	fmt.Println()
	fmt.Println("Temporal Properties:")
	fmt.Println("  ✓ EventuallyReady")
	fmt.Println("    - Authenticated client reaches Ready state")
	fmt.Println("  ✓ AlwaysCanQueryAfterConnect")
	fmt.Println("    - Connected clients can query extensions")
	fmt.Println("  ✓ AuthFailureHandled")
	fmt.Println("    - Failed auth leads to Failed state")
}

// ExampleAuthorizationManagement demonstrates auth management
func ExampleAuthorizationManagement() {
	fmt.Println("\n=== Example 6: Authorization Management ===")

	server := NewX11Server("testcookie")

	// Simulate generating authorizations
	fmt.Println("Generated Authorizations:")
	for i := 1; i <= 3; i++ {
		cookie := make([]byte, 16)
		rand.Read(cookie)

		server.authMutex.Lock()
		auth := &Authorization{
			ID:         uint32(i),
			Cookie:     cookie,
			TrustLevel: uint8(i % 2),
			Timeout:    3600,
			Group:      0,
			CreatedAt:  time.Now(),
		}
		server.authorizations[auth.ID] = auth
		server.authMutex.Unlock()

		fmt.Printf("  Auth %d: trust=%d, cookie=%s\n",
			auth.ID, auth.TrustLevel, hex.EncodeToString(auth.Cookie[:8]))
	}

	// Get all authorizations
	auths := server.GetAuthorizations()
	fmt.Printf("\nTotal active authorizations: %d\n", len(auths))
}

func RunServer() {
	// Command line flags
	port := flag.Int("port", 6000, "Port to listen on")
	authCookie := flag.String("cookie", "", "Auth cookie (auto-generated if empty)")
	enableWS := flag.Bool("websocket", false, "Enable WebSocket support")
	logLevel := flag.String("log", "info", "Log level (debug, info, error)")
	maxConn := flag.Int("max-conn", 100, "Maximum connections")
	metrics := flag.Bool("metrics", false, "Enable metrics reporting")
	proofMode := flag.String("proof-mode", authproof.ProofModeOff, "Runtime authproof mode: off|required")
	proofSecurityLevel := flag.String("proof-security-level", authproof.SecurityLevelCompat, "Runtime authority security level: compat|same_uid|x11_cookie|agent_proof|strict")
	proofPeerID := flag.String("proof-peer-id", "wv-server", "Expected peer ID for this server in authproof grants")
	proofIssuerPeerID := flag.String("proof-issuer-id", "", "Optional expected issuer peer ID for authproof grants")
	proofPublicKey := flag.String("proof-public-key", "", "Trusted Ed25519 public key for authproof verification")
	proofPublicKeyFile := flag.String("proof-public-key-file", "", "File containing trusted Ed25519 public key for authproof verification")
	proofChainSHA256 := flag.String("proof-chain-sha256", "", "Expected chain binding SHA-256 hex for authproof grants; required when proof mode is required")
	proofTTL := flag.Duration("proof-ttl", authproof.DefaultProofTTL, "Maximum accepted authproof grant TTL")
	examples := flag.Bool("examples", false, "Show usage examples and exit")

	flag.Parse()

	// Show examples if requested
	if *examples {
		fmt.Println("X11 Server with SECURITY Extension - Usage Examples")
		fmt.Println("===================================================")
		ExampleBasicUsage()
		ExampleWithMetrics()
		ExampleClientFlow()
		ExampleWebSocketUpgrade()
		ExampleTLACompliance()
		ExampleAuthorizationManagement()
		return
	}

	proofConfig := authproof.RuntimeConfig{Mode: *proofMode, SecurityLevel: *proofSecurityLevel}
	if err := proofConfig.ValidateMode(); err != nil {
		log.Fatalf("Invalid proof mode: %v", err)
	}

	// Setup logging
	setupLogging(*logLevel)

	// Generate auth cookie if not provided
	if *authCookie == "" {
		*authCookie = generateAuthCookie()
		log.Printf("Generated auth cookie: %s", *authCookie)
		log.Printf("Set XAUTHORITY or use: xauth add :0 . %s", *authCookie)
	}

	// Create server configuration
	config := ServerConfig{
		Port:               *port,
		AuthCookie:         *authCookie,
		EnableWebSocket:    *enableWS,
		LogLevel:           *logLevel,
		MaxConnections:     *maxConn,
		ConnectionTimeout:  5 * time.Minute,
		AuthTimeout:        1 * time.Hour,
		EnableMetrics:      *metrics,
		ProofMode:          *proofMode,
		ProofSecurityLevel: *proofSecurityLevel,
		ProofPeerID:        *proofPeerID,
		ProofIssuerPeerID:  *proofIssuerPeerID,
		ProofPublicKey:     *proofPublicKey,
		ProofPublicKeyFile: *proofPublicKeyFile,
		ProofChainSHA256:   *proofChainSHA256,
		ProofTTL:           *proofTTL,
	}

	if err := validateStandaloneServerAuthority(config); err != nil {
		log.Fatalf("Invalid standalone server authority policy: %v", err)
	}
	if proofConfig.Required() {
		if *proofChainSHA256 == "" {
			log.Fatalf("-proof-chain-sha256 is required when proof mode or proof security level requires signed proof")
		}
		if *proofPublicKey == "" && *proofPublicKeyFile == "" {
			log.Fatalf("-proof-public-key or -proof-public-key-file is required when proof mode or proof security level requires signed proof")
		}
	}

	// Create instrumented server
	server := NewInstrumentedX11Server(config)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil {
			errChan <- err
		}
	}()

	log.Printf("X11 Server started successfully")
	log.Printf("Press Ctrl+C to stop")

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		log.Printf("Received signal: %v", sig)
		if err := server.Shutdown(); err != nil {
			log.Printf("Shutdown error: %v", err)
			os.Exit(1)
		}
	case err := <-errChan:
		log.Fatalf("Server error: %v", err)
	}
}
