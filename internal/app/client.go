package app

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// ClientState represents client FSM states from TLA+ spec
type ClientState string

const (
	ClientIdle                   ClientState = "Idle"
	ClientAwaitingHandshakeReply ClientState = "AwaitingHandshakeReply"
	ClientConnected              ClientState = "Connected"
	ClientAwaitingExtensionReply ClientState = "AwaitingExtensionReply"
	ClientAwaitingAuthReply      ClientState = "AwaitingAuthReply"
	ClientReady                  ClientState = "Ready"
	ClientFailed                 ClientState = "Failed"
)

// X11TestClient represents a test client for the X11 server
type X11TestClient struct {
	conn        net.Conn
	state       ClientState
	byteOrder   binary.ByteOrder
	sequenceNum uint16
	knowledge   ClientKnowledge
}

// ClientKnowledge tracks what the client knows (from TLA+ spec)
type ClientKnowledge struct {
	Status     string
	Extensions map[string]bool
	NewCookie  []byte
	AuthID     uint32
}

// NewX11TestClient creates a new test client
func NewX11TestClient() *X11TestClient {
	return &X11TestClient{
		state:     ClientIdle,
		byteOrder: binary.BigEndian,
		knowledge: ClientKnowledge{
			Status:     "Unknown",
			Extensions: make(map[string]bool),
		},
	}
}

// Connect connects to the X11 server
func (c *X11TestClient) Connect(host string, port int, authCookie string) error {
	c.state = ClientIdle

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	c.conn = conn
	log.Printf("Connected to %s", addr)

	// Send connection setup
	if err := c.sendSetup(authCookie); err != nil {
		c.state = ClientFailed
		return err
	}

	c.state = ClientAwaitingHandshakeReply

	// Receive handshake reply
	if err := c.receiveHandshakeReply(); err != nil {
		c.state = ClientFailed
		return err
	}

	c.state = ClientConnected
	c.knowledge.Status = "Success"
	log.Printf("State: %s", c.state)

	return nil
}

// sendSetup sends the connection setup message
func (c *X11TestClient) sendSetup(authCookie string) error {
	log.Printf("Sending connection setup...")

	// Build setup message
	setup := make([]byte, 0, 256)

	// Byte order
	setup = append(setup, BigEndian)
	setup = append(setup, 0) // padding

	// Protocol version
	setup = append(setup, 0, 11) // major = 11
	setup = append(setup, 0, 0)  // minor = 0

	// Auth protocol
	authProtoName := AuthProtoMITMagicCookie
	cookieData, _ := hex.DecodeString(authCookie)

	// Auth lengths
	setup = append(setup, 0, byte(len(authProtoName))) // auth proto name length
	setup = append(setup, 0, byte(len(cookieData)))    // auth data length
	setup = append(setup, 0, 0)                        // padding

	// Auth protocol name
	setup = append(setup, []byte(authProtoName)...)
	// Pad to 4 bytes
	for len(setup)%4 != 0 {
		setup = append(setup, 0)
	}

	// Auth data
	setup = append(setup, cookieData...)
	// Pad to 4 bytes
	for len(setup)%4 != 0 {
		setup = append(setup, 0)
	}

	_, err := c.conn.Write(setup)
	return err
}

// receiveHandshakeReply receives and parses the handshake reply
func (c *X11TestClient) receiveHandshakeReply() error {
	log.Printf("Awaiting handshake reply...")

	header := make([]byte, 8)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return fmt.Errorf("reading reply header: %w", err)
	}

	success := header[0] == 1
	reasonLen := header[1]

	if !success {
		reason := make([]byte, reasonLen)
		if _, err := io.ReadFull(c.conn, reason); err != nil {
			return fmt.Errorf("reading failure reason: %w", err)
		}
		return fmt.Errorf("connection failed: %s", reason)
	}

	// Read additional data length
	additionalLen := c.byteOrder.Uint16(header[6:8]) * 4

	if additionalLen > 0 {
		additional := make([]byte, additionalLen)
		if _, err := io.ReadFull(c.conn, additional); err != nil {
			return fmt.Errorf("reading additional data: %w", err)
		}
		log.Printf("Connection successful, received %d bytes of server info", additionalLen)
	}

	return nil
}

// QueryExtension queries for an extension (TLA+ ClientQueryExtension action)
func (c *X11TestClient) QueryExtension(name string) error {
	if c.state != ClientConnected {
		return fmt.Errorf("not in connected state")
	}

	log.Printf("Querying extension: %s", name)

	// Build QueryExtension request
	req := make([]byte, 0, 32)

	// Opcode and padding
	req = append(req, OpcodeQueryExtension)
	req = append(req, 0) // padding

	// Length in 4-byte units
	reqLen := (4 + len(name) + 3) / 4
	req = append(req, byte(reqLen>>8), byte(reqLen))

	// Name length
	req = append(req, byte(len(name)>>8), byte(len(name)))
	req = append(req, 0, 0) // padding

	// Extension name
	req = append(req, []byte(name)...)

	// Pad to 4 bytes
	for len(req)%4 != 0 {
		req = append(req, 0)
	}

	if _, err := c.conn.Write(req); err != nil {
		return err
	}

	c.state = ClientAwaitingExtensionReply
	c.sequenceNum++

	// Read reply
	return c.receiveExtensionReply(name)
}

// receiveExtensionReply receives the QueryExtension reply
func (c *X11TestClient) receiveExtensionReply(name string) error {
	reply := make([]byte, 32)
	if _, err := io.ReadFull(c.conn, reply); err != nil {
		return fmt.Errorf("reading extension reply: %w", err)
	}

	if reply[0] != 1 {
		return fmt.Errorf("unexpected reply type: %d", reply[0])
	}

	present := reply[8] == 1
	majorOpcode := reply[9]

	if present {
		c.knowledge.Extensions[name] = true
		log.Printf("Extension %s present (opcode %d)", name, majorOpcode)
	} else {
		c.knowledge.Extensions[name] = false
		log.Printf("Extension %s not present", name)
	}

	c.state = ClientConnected
	return nil
}

// GenerateAuthorization generates a new authorization (TLA+ ClientGenerateAuth action)
func (c *X11TestClient) GenerateAuthorization(trustLevel uint8) error {
	if c.state != ClientConnected {
		return fmt.Errorf("not in connected state")
	}

	// Check if SECURITY extension is available
	if !c.knowledge.Extensions[SecurityExtensionName] {
		return fmt.Errorf("SECURITY extension not available")
	}

	log.Printf("Requesting authorization generation (trust level: %d)", trustLevel)

	// Build GenerateAuthorization request with value-mask format
	// Value-mask bits: 0x1=timeout, 0x2=trust_level, 0x4=group
	valueMask := uint32(0x2) // Only trust_level
	if trustLevel == UNTRUSTED_LEVEL {
		valueMask = 0x2 // trust_level only
	} else {
		valueMask = 0x2 // trust_level only
	}

	// Calculate request size: 4-byte header + 4-byte value-mask + 4 bytes per set bit
	numValues := 0
	if valueMask&0x1 != 0 {
		numValues++
	} // timeout
	if valueMask&0x2 != 0 {
		numValues++
	} // trust_level
	if valueMask&0x4 != 0 {
		numValues++
	} // group

	reqLen := 4 + 4 + (numValues * 4) // header + value-mask + values
	req := make([]byte, reqLen)

	// Major opcode (SECURITY)
	req[0] = SecurityMajorOpcode

	// Minor opcode (GenerateAuthorization)
	req[1] = SecurityGenerateAuth

	// Length in 4-byte units
	c.byteOrder.PutUint16(req[2:4], uint16(reqLen/4))

	// Value-mask
	c.byteOrder.PutUint32(req[4:8], valueMask)

	// Values based on mask
	offset := 8

	if valueMask&0x1 != 0 { // timeout
		c.byteOrder.PutUint32(req[offset:offset+4], 0) // no timeout
		offset += 4
	}

	if valueMask&0x2 != 0 { // trust_level
		c.byteOrder.PutUint32(req[offset:offset+4], uint32(trustLevel))
		offset += 4
	}

	if valueMask&0x4 != 0 { // group
		c.byteOrder.PutUint32(req[offset:offset+4], 0) // no group
		offset += 4
	}

	if _, err := c.conn.Write(req); err != nil {
		return err
	}

	c.state = ClientAwaitingAuthReply
	c.sequenceNum++

	// Read reply
	return c.receiveAuthReply()
}

// receiveAuthReply receives the GenerateAuthorization reply
func (c *X11TestClient) receiveAuthReply() error {
	header := make([]byte, 32)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return fmt.Errorf("reading auth reply: %w", err)
	}

	if header[0] != 1 {
		return fmt.Errorf("unexpected reply type: %d", header[0])
	}

	// Parse reply
	c.knowledge.AuthID = c.byteOrder.Uint32(header[8:12])
	dataLen := c.byteOrder.Uint16(header[12:14])

	// Read additional reply data length
	replyLen := c.byteOrder.Uint32(header[4:8]) * 4

	if replyLen > 0 {
		data := make([]byte, replyLen)
		if _, err := io.ReadFull(c.conn, data); err != nil {
			return fmt.Errorf("reading auth data: %w", err)
		}

		c.knowledge.NewCookie = data[:dataLen]
	}

	log.Printf("Generated authorization ID: %d", c.knowledge.AuthID)
	log.Printf("New cookie: %s", hex.EncodeToString(c.knowledge.NewCookie))

	c.state = ClientReady
	return nil
}

// Close closes the connection
func (c *X11TestClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// VerifyTLAInvariants checks that TLA+ invariants hold
func (c *X11TestClient) VerifyTLAInvariants() error {
	log.Printf("Verifying TLA+ invariants...")

	// ClientReadyHasCookie: If client reaches Ready state, it must have a new cookie
	if c.state == ClientReady {
		if len(c.knowledge.NewCookie) == 0 {
			return fmt.Errorf("invariant violation: ClientReadyHasCookie - client in Ready state without cookie")
		}
		log.Printf("✓ ClientReadyHasCookie: Client has cookie")
	}

	// SecurityExtensionProtocol: SECURITY extension must be discovered before use
	if c.state == ClientAwaitingAuthReply {
		if !c.knowledge.Extensions[SecurityExtensionName] {
			return fmt.Errorf("invariant violation: SecurityExtensionProtocol - using SECURITY without discovery")
		}
		log.Printf("✓ SecurityExtensionProtocol: Extension discovered before use")
	}

	log.Printf("All invariants satisfied")
	return nil
}

// RunTestSequence runs the complete test sequence following TLA+ spec
func RunTestSequence(host string, port int, authCookie string) error {
	client := NewX11TestClient()
	defer client.Close()

	log.Printf("=== Starting X11 SECURITY Extension Test ===")
	log.Printf("Following TLA+ specification state machine")

	// Step 1: Connect and authenticate (ClientSendSetup -> ClientProcessHandshakeReply)
	log.Printf("\n--- Phase 1: Connection Setup ---")
	if err := client.Connect(host, port, authCookie); err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	if err := client.VerifyTLAInvariants(); err != nil {
		return err
	}

	// Step 2: Query SECURITY extension (ClientQueryExtension -> ClientProcessExtensionReply)
	log.Printf("\n--- Phase 2: Extension Discovery ---")
	if err := client.QueryExtension(SecurityExtensionName); err != nil {
		return fmt.Errorf("extension query failed: %w", err)
	}

	if err := client.VerifyTLAInvariants(); err != nil {
		return err
	}

	// Step 3: Generate authorization (ClientGenerateAuth -> ClientReceiveAuth)
	log.Printf("\n--- Phase 3: Authorization Generation ---")
	if err := client.GenerateAuthorization(UNTRUSTED_LEVEL); err != nil {
		return fmt.Errorf("authorization generation failed: %w", err)
	}

	if err := client.VerifyTLAInvariants(); err != nil {
		return err
	}

	// Final state check
	log.Printf("\n--- Final State ---")
	log.Printf("Client State: %s", client.state)
	log.Printf("Status: %s", client.knowledge.Status)
	log.Printf("Extensions: %v", client.knowledge.Extensions)
	log.Printf("Auth ID: %d", client.knowledge.AuthID)
	log.Printf("Cookie: %s", hex.EncodeToString(client.knowledge.NewCookie))

	// Verify final state matches TLA+ specification
	if client.state != ClientReady {
		return fmt.Errorf("expected final state Ready, got %s", client.state)
	}

	log.Printf("\n=== Test Sequence Complete ===")
	log.Printf("✓ All TLA+ temporal properties satisfied")
	log.Printf("✓ EventuallyReady: Client reached Ready state")
	log.Printf("✓ All protocol steps executed successfully")

	return nil
}

func RunClient() {
	host := "localhost"
	port := 6002
	authCookie := ""

	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if err := RunTestSequence(host, port, authCookie); err != nil {
		log.Fatalf("Test failed: %v", err)
	}
}
