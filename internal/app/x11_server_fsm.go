package app

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// State represents the FSM states as per TLA+ specification
type State string

const (
	StateListening           State = "Listening"
	StateProcessingHandshake State = "ProcessingHandshake"
	StateConnected           State = "Connected"
	StateProcessingRequest   State = "ProcessingRequest"
	StateFailed              State = "Failed"
)

// Authorization represents a generated security authorization
type Authorization struct {
	ID         uint32
	Cookie     []byte
	TrustLevel uint8
	Timeout    uint32
	Group      uint32
	CreatedAt  time.Time
}

// ClientConnection represents a client connection with FSM state
type ClientConnection struct {
	conn          net.Conn
	state         State
	byteOrder     binary.ByteOrder
	authenticated bool
	sequenceNum   uint16
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
}

// X11Server represents the X11 server with SECURITY extension
type X11Server struct {
	listener       net.Listener
	validCookie    string
	authorizations map[uint32]*Authorization
	authMutex      sync.RWMutex
	clients        map[string]*ClientConnection
	clientMutex    sync.RWMutex
	extensions     map[string]uint8
	nextAuthID     uint32
}

// NewX11Server creates a new X11 server instance
func NewX11Server(authCookie string) *X11Server {
	srv := &X11Server{
		validCookie:    authCookie,
		authorizations: make(map[uint32]*Authorization),
		clients:        make(map[string]*ClientConnection),
		extensions:     make(map[string]uint8),
		nextAuthID:     1,
	}

	// Register SECURITY extension
	srv.extensions[SecurityExtensionName] = SecurityMajorOpcode

	return srv
}

// Start begins listening for X11 connections
func (s *X11Server) Start(port int) error {
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	s.listener = listener
	log.Printf("X11 server listening on %s", addr)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

// handleConnection manages a client connection through the FSM
func (s *X11Server) handleConnection(conn net.Conn) {
	ctx, cancel := context.WithCancel(context.Background())

	client := &ClientConnection{
		conn:   conn,
		state:  StateListening,
		ctx:    ctx,
		cancel: cancel,
	}

	clientAddr := conn.RemoteAddr().String()
	s.clientMutex.Lock()
	s.clients[clientAddr] = client
	s.clientMutex.Unlock()

	defer func() {
		conn.Close()
		cancel()
		s.clientMutex.Lock()
		delete(s.clients, clientAddr)
		s.clientMutex.Unlock()
		log.Printf("Client %s disconnected (final state: %s)", clientAddr, client.state)
	}()

	log.Printf("New connection from %s", clientAddr)

	// FSM: Transition to ProcessingHandshake
	if err := s.processConnectionSetup(client); err != nil {
		log.Printf("Connection setup failed: %v", err)
		client.setState(StateFailed)
		return
	}

	// FSM: Now in Connected state, process requests
	for {
		select {
		case <-client.ctx.Done():
			return
		default:
			// Set a read deadline to prevent hanging forever
			client.conn.SetReadDeadline(time.Now().Add(30 * time.Second))

			if err := s.processRequest(client); err != nil {
				// Check if it's a timeout - if so, continue waiting
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if err == io.EOF || strings.Contains(err.Error(), "closed") {
					log.Printf("Client %s closed connection", clientAddr)
				} else if !strings.Contains(err.Error(), "timeout") {
					log.Printf("Request processing error: %v", err)
				}
				return
			}
		}
	}
}

// processConnectionSetup handles the initial X11 connection setup
func (s *X11Server) processConnectionSetup(client *ClientConnection) error {
	client.setState(StateProcessingHandshake)

	// Read connection setup from client
	setup, err := ReadConnectionSetup(client.conn)
	if err != nil {
		return fmt.Errorf("reading connection setup: %w", err)
	}

	// Determine byte order
	if setup.ByteOrder == BigEndian {
		client.byteOrder = binary.BigEndian
	} else {
		client.byteOrder = binary.LittleEndian
	}

	log.Printf("Client protocol: %d.%d, byte order: %#x",
		setup.ProtocolMajorVer, setup.ProtocolMinorVer, setup.ByteOrder)

	// Validate authentication
	authOK := s.validateAuth(setup, client)

	// Build and send connection reply
	reply := s.buildConnectionReply(authOK, client)
	if err := reply.Write(client.conn, client.byteOrder); err != nil {
		return fmt.Errorf("writing connection reply: %w", err)
	}

	if authOK {
		client.authenticated = true
		client.setState(StateConnected)
		log.Printf("Client authenticated successfully")
	} else {
		client.setState(StateFailed)
		return fmt.Errorf("authentication failed")
	}

	return nil
}

// validateAuth validates the client's authentication
func (s *X11Server) validateAuth(setup *ConnectionSetup, client *ClientConnection) bool {
	// Check for MIT-MAGIC-COOKIE-1
	if setup.AuthProtoName == AuthProtoMITMagicCookie {
		cookieHex := hex.EncodeToString(setup.AuthProtoData)
		log.Printf("Validating MIT-MAGIC-COOKIE-1: received=%s", cookieHex)

		// First check against the initial cookie from xauth
		if cookieHex == s.validCookie {
			log.Printf("X11 authentication successful (initial cookie)")
			return true
		}

		// ALSO check against dynamically generated authorization cookies
		s.authMutex.RLock()
		defer s.authMutex.RUnlock()

		for _, auth := range s.authorizations {
			authCookieHex := hex.EncodeToString(auth.Cookie)
			if cookieHex == authCookieHex {
				// Check if not expired
				if auth.Timeout > 0 {
					expiresAt := auth.CreatedAt.Add(time.Duration(auth.Timeout) * time.Second)
					if time.Now().After(expiresAt) {
						log.Printf("Cookie matched auth ID %d but expired", auth.ID)
						continue
					}
				}
				log.Printf("X11 authentication successful (generated auth ID %d)", auth.ID)
				return true
			}
		}

		log.Printf("Invalid auth cookie (expected=%s or generated cookie)", s.validCookie)
		return false
	}

	// No auth provided
	log.Printf("No authentication provided (proto=%q, data_len=%d)", setup.AuthProtoName, setup.AuthProtoDataLen)
	return false
}

// buildConnectionReply creates a connection reply
func (s *X11Server) buildConnectionReply(success bool, client *ClientConnection) *ConnectionReply {
	reply := &ConnectionReply{
		Success:          success,
		ProtocolMajorVer: ProtocolMajorVersion,
		ProtocolMinorVer: ProtocolMinorVersion,
	}

	if success {
		reply.ReleaseNumber = 1
		reply.ResourceIDBase = 0x10000000
		reply.ResourceIDMask = 0x1fffffff
		reply.MotionBufferSize = 0
		reply.Vendor = "Go X11 Server with SECURITY"
		reply.VendorLength = uint16(len(reply.Vendor))
		reply.MaxRequestLength = 65535
		reply.NumScreens = 1
		reply.NumFormats = 1
		reply.Formats = []Format{
			{Depth: 24, BitsPerPixel: 32, ScanlinePad: 32},
		}

		//reply.ImageByteOrder = client.byteOrder.(interface{ String() string }).String()[0]
		//reply.BitmapBitOrder = reply.ImageByteOrder
		// Set byte order based on client's byte order
		if client.byteOrder == binary.BigEndian {
			reply.ImageByteOrder = 0 // MSBFirst
			reply.BitmapBitOrder = 0
		} else {
			reply.ImageByteOrder = 1 // LSBFirst
			reply.BitmapBitOrder = 1
		}

		reply.BitmapScanlineUnit = 32
		reply.BitmapScanlinePad = 32
		reply.MinKeycode = 8
		reply.MaxKeycode = 255

		// Add a basic screen
		reply.Screens = []Screen{
			{
				RootWindow:          1,
				DefaultColormap:     0,
				WhitePixel:          0xffffff,
				BlackPixel:          0,
				CurrentInputMasks:   0,
				WidthInPixels:       1920,
				HeightInPixels:      1080,
				WidthInMillimeters:  508,
				HeightInMillimeters: 285,
				MinInstalledMaps:    1,
				MaxInstalledMaps:    1,
				RootVisual:          1,
				BackingStores:       0,
				SaveUnders:          0,
				RootDepth:           24,
				NumDepths:           1,
				Depths: []Depth{
					{
						Depth:      24,
						NumVisuals: 1,
						Visuals: []Visual{
							{
								VisualID:        0x21,
								Class:           4, // TrueColor
								BitsPerRGBValue: 8,
								ColormapEntries: 256,
								RedMask:         0xff0000,
								GreenMask:       0x00ff00,
								BlueMask:        0x0000ff,
							},
						},
					},
				},
			},
		}
	} else {
		reply.Reason = "Authentication failed"
		reply.ReasonLength = uint16(len(reply.Reason))
	}

	return reply
}

// processRequest handles X11 protocol requests
func (s *X11Server) processRequest(client *ClientConnection) error {
	client.setState(StateProcessingRequest)
	// Set read timeout to prevent hanging
	if err := client.conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return fmt.Errorf("setting read deadline: %w", err)
	}

	req, err := ReadRequest(client.conn, client.byteOrder)
	if err != nil {
		return err
	}

	client.incrementSequence()

	log.Printf("Request: opcode=%d, detail=%d, length=%d",
		req.Opcode, req.Detail, req.Length)

	// Route request to appropriate handler
	switch req.Opcode {
	case OpcodeQueryExtension:
		return s.handleQueryExtension(client, req)

	case SecurityMajorOpcode:
		return s.handleSecurityRequest(client, req)

	default:
		// Send generic reply for unimplemented requests
		return s.sendGenericReply(client)
	}
}

// handleQueryExtension processes QueryExtension requests
func (s *X11Server) handleQueryExtension(client *ClientConnection, req *Request) error {
	var qeReq QueryExtensionRequest
	if err := qeReq.Parse(req.Data, client.byteOrder); err != nil {
		return fmt.Errorf("parsing QueryExtension: %w", err)
	}

	log.Printf("QueryExtension: %s", qeReq.Name)

	// Check if extension is supported
	majorOpcode, present := s.extensions[qeReq.Name]

	qeReply := &QueryExtensionReply{
		Present:     present,
		MajorOpcode: majorOpcode,
		FirstEvent:  0,
		FirstError:  0,
	}

	reply := qeReply.ToReply(client.sequenceNum, client.byteOrder)

	client.setState(StateConnected)
	return reply.Write(client.conn, client.byteOrder)
}

// handleSecurityRequest processes SECURITY extension requests
func (s *X11Server) handleSecurityRequest(client *ClientConnection, req *Request) error {
	if !client.authenticated {
		return fmt.Errorf("client not authenticated for SECURITY extension")
	}

	log.Printf("DEBUG: SECURITY request - detail=%d, data_len=%d", req.Detail, len(req.Data))
	if len(req.Data) > 0 {
		log.Printf("DEBUG: First 16 bytes of data: % x", req.Data[:min(16, len(req.Data))])
	}

	// Determine minor opcode
	minorOpcode := req.Detail

	// If detail is 0, this might be using an older format where minor opcode
	// wasn't properly set. Check the data to determine the request type.
	if minorOpcode == 0 {
		// For GenerateAuthorization, we expect at least 4 bytes for value-mask
		if len(req.Data) >= 4 {
			// Assume it's GenerateAuthorization (most common)
			minorOpcode = SecurityGenerateAuth
			log.Printf("DEBUG: detail=0, assuming GenerateAuthorization")
		}
	}

	switch minorOpcode {
	case SecurityGenerateAuth:
		return s.handleGenerateAuthorization(client, req)

	case SecurityRevokeAuth:
		return s.handleRevokeAuthorization(client, req)

	default:
		return fmt.Errorf("unknown SECURITY minor opcode: %d", minorOpcode)
	}
}

// handleGenerateAuthorizatio nprocesses GenerateAuthorization requests
func (s *X11Server) handleGenerateAuthorization(client *ClientConnection, req *Request) error {
	var gaReq SecurityGenerateAuthRequest
	if err := gaReq.Parse(req.Data, client.byteOrder); err != nil {
		return fmt.Errorf("parsing GenerateAuthorization: %w", err)
	}

	log.Printf("GenerateAuthorization: trust_level=%d, timeout=%d, group=%d",
		gaReq.TrustLevel, gaReq.Timeout, gaReq.Group)

	// Generate new authorization
	cookie := make([]byte, 16)
	if _, err := rand.Read(cookie); err != nil {
		return fmt.Errorf("generating auth cookie: %w", err)
	}

	s.authMutex.Lock()
	authID := s.nextAuthID
	s.nextAuthID++

	auth := &Authorization{
		ID:         authID,
		Cookie:     cookie,
		TrustLevel: gaReq.TrustLevel,
		Timeout:    gaReq.Timeout,
		Group:      gaReq.Group,
		CreatedAt:  time.Now(),
	}
	s.authorizations[authID] = auth
	s.authMutex.Unlock()

	log.Printf("Generated authorization ID %d, cookie: %s", authID, hex.EncodeToString(auth.Cookie))

	// Build reply
	gaReply := &SecurityGenerateAuthReply{
		AuthID:      authID,
		AuthData:    cookie,
		AuthDataLen: uint16(len(cookie)),
	}

	log.Printf("DEBUG: Building reply for sequence %d", client.sequenceNum)
	reply := gaReply.ToReply(client.sequenceNum, client.byteOrder)

	log.Printf("DEBUG: Setting client state to Connected")
	client.setState(StateConnected)
	log.Printf("DEBUG: Writing reply to client connection")
	err := reply.Write(client.conn, client.byteOrder)
	log.Printf("DEBUG: Reply write completed with error: %v", err)
	return err
}

// handleRevokeAuthorization processes RevokeAuthorization requests
func (s *X11Server) handleRevokeAuthorization(client *ClientConnection, req *Request) error {
	if len(req.Data) < 5 {
		return fmt.Errorf("insufficient data for RevokeAuthorization")
	}

	authID := client.byteOrder.Uint32(req.Data[1:5])

	s.authMutex.Lock()
	delete(s.authorizations, authID)
	s.authMutex.Unlock()

	log.Printf("Revoked authorization ID %d", authID)

	client.setState(StateConnected)
	return s.sendGenericReply(client)
}

// sendGenericReply sends a generic empty reply
func (s *X11Server) sendGenericReply(client *ClientConnection) error {
	reply := &Reply{
		Type:        1,
		Detail:      0,
		SequenceNum: client.sequenceNum,
		Length:      0,
		Data:        make([]byte, 24),
	}

	client.setState(StateConnected)
	return reply.Write(client.conn, client.byteOrder)
}

// setState safely updates the client state
func (c *ClientConnection) setState(state State) {
	c.mu.Lock()
	defer c.mu.Unlock()

	log.Printf("State transition: %s -> %s", c.state, state)
	c.state = state
}

// incrementSequence increments the sequence number
func (c *ClientConnection) incrementSequence() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sequenceNum++
}

// GetAuthorizations returns a copy of all authorizations
func (s *X11Server) GetAuthorizations() map[uint32]*Authorization {
	s.authMutex.RLock()
	defer s.authMutex.RUnlock()

	auths := make(map[uint32]*Authorization, len(s.authorizations))
	for k, v := range s.authorizations {
		auths[k] = v
	}
	return auths
}

// Close closes the server
func (s *X11Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// writeToXauth writes a generated cookie to the xauth database
func (s *X11Server) writeToXauth(authID uint32, auth *Authorization) error {
	display := os.Getenv("DISPLAY")
	if display == "" {
		return fmt.Errorf("DISPLAY not set")
	}

	// Find xauth command
	xauthPaths := []string{
		"/opt/X11/bin/xauth",
		"/usr/bin/xauth",
		"/usr/X11R6/bin/xauth",
	}

	var xauthCmd string
	for _, path := range xauthPaths {
		if _, err := os.Stat(path); err == nil {
			xauthCmd = path
			break
		}
	}

	if xauthCmd == "" {
		return fmt.Errorf("xauth command not found")
	}

	// Convert cookie to hex string
	cookieHex := hex.EncodeToString(auth.Cookie)

	// Write to xauth: xauth add <display> MIT-MAGIC-COOKIE-1 <cookie>
	cmd := exec.Command(xauthCmd, "add", display, "MIT-MAGIC-COOKIE-1", cookieHex)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("xauth add failed: %v (output: %s)", err, string(output))
	}

	log.Printf("Wrote cookie for auth ID %d to xauth database for display %s", authID, display)
	return nil
}
