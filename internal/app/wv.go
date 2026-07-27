package app

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/websocket"
	"weaverssh/relay"
)

// Mode represents server operating mode
type Mode string

const (
	ModeX11Only Mode = "x11" // Pure X11 server
)

type MainConfig struct {
	Port          int
	Mode          Mode
	AuthCookie    string
	X11Target     string
	EnableMetrics bool
}

func RunWV() {
	config := parseFlags()

	// Setup logging
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	// Generate auth cookie if not provided
	if config.AuthCookie == "" {
		config.AuthCookie = generateAuthCookie()
		log.Printf("Generated auth cookie: %s", config.AuthCookie)
		log.Printf("Set XAUTHORITY or use: xauth add :0 . %s", config.AuthCookie)
	}

	// Create X11 server
	x11Server := NewX11Server(config.AuthCookie)

	// Create relay manager for tracking connections
	relayManager := relay.NewRelayManager()
	defer relayManager.Close()

	// Start server based on mode
	errChan := make(chan error, 1)
	go func() {
		errChan <- startServer(config, x11Server, relayManager)
	}()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	log.Printf("X11/WebSocket Server started on port %d (mode: %s)", config.Port, config.Mode)
	log.Printf("Press Ctrl+C to stop")

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		log.Printf("Received signal: %v", sig)
		x11Server.Close()
	case err := <-errChan:
		log.Fatalf("Server error: %v", err)
	}
}

func parseFlags() MainConfig {
	config := MainConfig{}

	flag.IntVar(&config.Port, "port", 6002, "Port to listen on")
	flag.StringVar(&config.AuthCookie, "cookie", "", "X11 auth cookie (auto-generated if empty)")
	flag.StringVar(&config.X11Target, "x11-target", "localhost:6000", "Target X11 server for relay")
	flag.BoolVar(&config.EnableMetrics, "metrics", false, "Enable metrics reporting")

	flag.Parse()

	config.Mode = ModeX11Only

	return config
}

func startServer(config MainConfig, x11Server *X11Server, relayManager *relay.RelayManager) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", config.Port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()

	log.Printf("Listening on %s", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleConnection(conn, config, x11Server, relayManager)
	}
}

func handleConnection(conn net.Conn, config MainConfig, x11Server *X11Server, relayManager *relay.RelayManager) {
	defer conn.Close()

	log.Printf("New connection from %s", conn.RemoteAddr())

	// Step 1: X11 Handshake (required for SSH -X compatibility)
	client, err := performX11Handshake(conn, x11Server)
	if err != nil {
		log.Printf("X11 handshake failed: %v", err)
		return
	}

	log.Printf("X11 handshake completed for %s", conn.RemoteAddr())

	// Step 2: process the X11 stream
	handlePureX11Stream(client, x11Server)
}

func handlePureX11Stream(client *ClientConnection, server *X11Server) {
	// Process X11 requests until connection closes
	for {
		req, err := ReadRequest(client.conn, client.byteOrder)
		if err != nil {
			if err != io.EOF {
				log.Printf("X11 read error: %v", err)
			}
			break
		}

		client.incrementSequence()

		// Route request
		switch req.Opcode {
		case OpcodeQueryExtension:
			server.handleQueryExtension(client, req)
		case SecurityMajorOpcode:
			server.handleSecurityRequest(client, req)
		default:
			server.sendGenericReply(client)
		}
	}
}

func performX11Handshake(conn net.Conn, server *X11Server) (*ClientConnection, error) {
	client := &ClientConnection{
		conn:      conn,
		state:     StateListening,
		byteOrder: nil,
	}

	// Read connection setup
	setup, err := ReadConnectionSetup(conn)
	if err != nil {
		return nil, fmt.Errorf("read setup: %w", err)
	}

	// Determine byte order
	if setup.ByteOrder == BigEndian {
		client.byteOrder = binary.BigEndian
	} else {
		client.byteOrder = binary.LittleEndian
	}

	// Validate auth
	authOK := server.validateAuth(setup, client)

	// Build and send reply
	reply := server.buildConnectionReply(authOK, client)
	if err := reply.Write(conn, client.byteOrder); err != nil {
		return nil, fmt.Errorf("write reply: %w", err)
	}

	if !authOK {
		return nil, fmt.Errorf("authentication failed")
	}

	client.authenticated = true
	client.state = StateConnected

	return client, nil
}

func upgradeToWebSocket(conn net.Conn) (*websocket.Conn, error) {
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, fmt.Errorf("read websocket upgrade request: %w", err)
	}
	defer req.Body.Close()

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	return upgrader.Upgrade(&rawWebSocketResponseWriter{
		conn:   conn,
		reader: reader,
		header: make(http.Header),
	}, req, nil)
}

type rawWebSocketResponseWriter struct {
	conn   net.Conn
	reader *bufio.Reader
	header http.Header
}

func (w *rawWebSocketResponseWriter) Header() http.Header {
	return w.header
}

func (w *rawWebSocketResponseWriter) WriteHeader(statusCode int) {
	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = "status"
	}
	fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", statusCode, statusText)
}

func (w *rawWebSocketResponseWriter) Write(p []byte) (int, error) {
	return w.conn.Write(p)
}

func (w *rawWebSocketResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(w.reader, bufio.NewWriter(w.conn)), nil
}
