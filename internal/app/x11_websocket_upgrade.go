package app

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
)

// Protocol represents the active protocol on a connection
type Protocol string

const (
	ProtocolX11       Protocol = "X11"
	ProtocolWebSocket Protocol = "WebSocket"
)

// WebSocketFrame represents a WebSocket frame
type WebSocketFrame struct {
	Fin     bool
	Opcode  uint8
	Masked  bool
	Payload []byte
}

// WebSocket opcodes
const (
	OpcodeContinuation = 0x0
	OpcodeText         = 0x1
	OpcodeBinary       = 0x2
	OpcodeClose        = 0x8
	OpcodePing         = 0x9
	OpcodePong         = 0xA
)

// MultiProtocolConnection wraps a connection and tracks the active protocol
type MultiProtocolConnection struct {
	conn         net.Conn
	protocol     Protocol
	reader       *bufio.Reader
	writer       *bufio.Writer
	mu           sync.Mutex
	wsHandshake  bool
	closeHandler func(code uint16, text string) error
}

// NewMultiProtocolConnection creates a new multi-protocol connection
func NewMultiProtocolConnection(conn net.Conn) *MultiProtocolConnection {
	return &MultiProtocolConnection{
		conn:     conn,
		protocol: ProtocolX11,
		reader:   bufio.NewReader(conn),
		writer:   bufio.NewWriter(conn),
	}
}

// GetProtocol returns the current protocol
func (mpc *MultiProtocolConnection) GetProtocol() Protocol {
	mpc.mu.Lock()
	defer mpc.mu.Unlock()
	return mpc.protocol
}

// UpgradeToWebSocket attempts to upgrade the connection to WebSocket
func (mpc *MultiProtocolConnection) UpgradeToWebSocket() error {
	mpc.mu.Lock()
	defer mpc.mu.Unlock()

	if mpc.protocol == ProtocolWebSocket {
		return fmt.Errorf("already upgraded to WebSocket")
	}

	// Read HTTP upgrade request
	req, err := http.ReadRequest(mpc.reader)
	if err != nil {
		return fmt.Errorf("reading upgrade request: %w", err)
	}

	// Validate WebSocket upgrade request
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return fmt.Errorf("not a WebSocket upgrade request")
	}

	if !strings.EqualFold(req.Header.Get("Connection"), "upgrade") {
		return fmt.Errorf("missing Connection: Upgrade header")
	}

	wsKey := req.Header.Get("Sec-WebSocket-Key")
	if wsKey == "" {
		return fmt.Errorf("missing Sec-WebSocket-Key")
	}

	wsVersion := req.Header.Get("Sec-WebSocket-Version")
	if wsVersion != "13" {
		return fmt.Errorf("unsupported WebSocket version: %s", wsVersion)
	}

	// Generate accept key
	acceptKey := computeAcceptKey(wsKey)

	// Send upgrade response
	response := fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n"+
			"\r\n",
		acceptKey,
	)

	if _, err := mpc.writer.WriteString(response); err != nil {
		return fmt.Errorf("writing upgrade response: %w", err)
	}

	if err := mpc.writer.Flush(); err != nil {
		return fmt.Errorf("flushing upgrade response: %w", err)
	}

	// Protocol upgraded
	mpc.protocol = ProtocolWebSocket
	mpc.wsHandshake = true

	log.Printf("Protocol upgraded to WebSocket")
	return nil
}

// computeAcceptKey computes the Sec-WebSocket-Accept key
func computeAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ReadWebSocketFrame reads a WebSocket frame
func (mpc *MultiProtocolConnection) ReadWebSocketFrame() (*WebSocketFrame, error) {
	mpc.mu.Lock()
	defer mpc.mu.Unlock()

	if mpc.protocol != ProtocolWebSocket {
		return nil, fmt.Errorf("not in WebSocket mode")
	}

	// Read first two bytes
	header := make([]byte, 2)
	if _, err := io.ReadFull(mpc.reader, header); err != nil {
		return nil, err
	}

	frame := &WebSocketFrame{
		Fin:    (header[0] & 0x80) != 0,
		Opcode: header[0] & 0x0F,
		Masked: (header[1] & 0x80) != 0,
	}

	// Parse payload length
	payloadLen := uint64(header[1] & 0x7F)

	if payloadLen == 126 {
		// 16-bit length
		lenBytes := make([]byte, 2)
		if _, err := io.ReadFull(mpc.reader, lenBytes); err != nil {
			return nil, err
		}
		payloadLen = uint64(lenBytes[0])<<8 | uint64(lenBytes[1])
	} else if payloadLen == 127 {
		// 64-bit length
		lenBytes := make([]byte, 8)
		if _, err := io.ReadFull(mpc.reader, lenBytes); err != nil {
			return nil, err
		}
		payloadLen = 0
		for i := 0; i < 8; i++ {
			payloadLen = payloadLen<<8 | uint64(lenBytes[i])
		}
	}

	// Read masking key if present
	var maskKey []byte
	if frame.Masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(mpc.reader, maskKey); err != nil {
			return nil, err
		}
	}

	// Read payload
	if payloadLen > 0 {
		frame.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(mpc.reader, frame.Payload); err != nil {
			return nil, err
		}

		// Unmask payload if masked
		if frame.Masked {
			for i := range frame.Payload {
				frame.Payload[i] ^= maskKey[i%4]
			}
		}
	}

	return frame, nil
}

// WriteWebSocketFrame writes a WebSocket frame
func (mpc *MultiProtocolConnection) WriteWebSocketFrame(frame *WebSocketFrame) error {
	mpc.mu.Lock()
	defer mpc.mu.Unlock()

	if mpc.protocol != ProtocolWebSocket {
		return fmt.Errorf("not in WebSocket mode")
	}

	// Build frame header
	var header []byte

	// First byte: FIN + opcode
	firstByte := frame.Opcode
	if frame.Fin {
		firstByte |= 0x80
	}
	header = append(header, firstByte)

	// Second byte: MASK + payload length
	payloadLen := len(frame.Payload)

	if payloadLen < 126 {
		header = append(header, byte(payloadLen))
	} else if payloadLen < 65536 {
		header = append(header, 126)
		header = append(header, byte(payloadLen>>8), byte(payloadLen))
	} else {
		header = append(header, 127)
		for i := 7; i >= 0; i-- {
			header = append(header, byte(payloadLen>>(i*8)))
		}
	}

	// Write header
	if _, err := mpc.writer.Write(header); err != nil {
		return err
	}

	// Write payload
	if len(frame.Payload) > 0 {
		if _, err := mpc.writer.Write(frame.Payload); err != nil {
			return err
		}
	}

	return mpc.writer.Flush()
}

// WriteText writes a text message
func (mpc *MultiProtocolConnection) WriteText(text string) error {
	return mpc.WriteWebSocketFrame(&WebSocketFrame{
		Fin:     true,
		Opcode:  OpcodeText,
		Payload: []byte(text),
	})
}

// WriteBinary writes a binary message
func (mpc *MultiProtocolConnection) WriteBinary(data []byte) error {
	return mpc.WriteWebSocketFrame(&WebSocketFrame{
		Fin:     true,
		Opcode:  OpcodeBinary,
		Payload: data,
	})
}

// WritePing writes a ping frame
func (mpc *MultiProtocolConnection) WritePing(data []byte) error {
	return mpc.WriteWebSocketFrame(&WebSocketFrame{
		Fin:     true,
		Opcode:  OpcodePing,
		Payload: data,
	})
}

// WritePong writes a pong frame
func (mpc *MultiProtocolConnection) WritePong(data []byte) error {
	return mpc.WriteWebSocketFrame(&WebSocketFrame{
		Fin:     true,
		Opcode:  OpcodePong,
		Payload: data,
	})
}

// WriteClose writes a close frame
func (mpc *MultiProtocolConnection) WriteClose(code uint16, text string) error {
	payload := make([]byte, 2+len(text))
	payload[0] = byte(code >> 8)
	payload[1] = byte(code)
	copy(payload[2:], text)

	return mpc.WriteWebSocketFrame(&WebSocketFrame{
		Fin:     true,
		Opcode:  OpcodeClose,
		Payload: payload,
	})
}

// HandleWebSocketLoop handles WebSocket messages in a loop
func (mpc *MultiProtocolConnection) HandleWebSocketLoop(handler func(*WebSocketFrame) error) error {
	for {
		frame, err := mpc.ReadWebSocketFrame()
		if err != nil {
			return err
		}

		switch frame.Opcode {
		case OpcodeClose:
			// Handle close frame
			code := uint16(0)
			text := ""
			if len(frame.Payload) >= 2 {
				code = uint16(frame.Payload[0])<<8 | uint16(frame.Payload[1])
				text = string(frame.Payload[2:])
			}

			// Echo close frame
			mpc.WriteClose(code, text)

			if mpc.closeHandler != nil {
				return mpc.closeHandler(code, text)
			}
			return fmt.Errorf("connection closed: %d %s", code, text)

		case OpcodePing:
			// Respond with pong
			if err := mpc.WritePong(frame.Payload); err != nil {
				return err
			}

		case OpcodePong:
			// Ignore pong frames
			continue

		default:
			// Handle data frames with provided handler
			if handler != nil {
				if err := handler(frame); err != nil {
					return err
				}
			}
		}
	}
}

// Close closes the connection
func (mpc *MultiProtocolConnection) Close() error {
	return mpc.conn.Close()
}

// EnhancedX11Server extends X11Server with WebSocket support
type EnhancedX11Server struct {
	*X11Server
	wsEnabled bool
}

// NewEnhancedX11Server creates a server with WebSocket upgrade support
func NewEnhancedX11Server(authCookie string, wsEnabled bool) *EnhancedX11Server {
	return &EnhancedX11Server{
		X11Server: NewX11Server(authCookie),
		wsEnabled: wsEnabled,
	}
}

// handleEnhancedConnection handles connections with protocol switching
func (s *EnhancedX11Server) handleEnhancedConnection(conn net.Conn) {
	mpc := NewMultiProtocolConnection(conn)
	defer mpc.Close()

	// Check if this is an HTTP upgrade request
	if s.wsEnabled {
		peek, err := mpc.reader.Peek(4)
		if err == nil && string(peek) == "GET " {
			// This looks like an HTTP request, attempt WebSocket upgrade
			if err := mpc.UpgradeToWebSocket(); err != nil {
				log.Printf("WebSocket upgrade failed: %v", err)
				return
			}

			// Handle as WebSocket
			log.Printf("Handling as WebSocket connection")
			err := mpc.HandleWebSocketLoop(func(frame *WebSocketFrame) error {
				// Echo frames back
				return mpc.WriteWebSocketFrame(frame)
			})

			if err != nil {
				log.Printf("WebSocket error: %v", err)
			}
			return
		}
	}

	// Handle as X11 protocol
	log.Printf("Handling as X11 connection")
	// Use the existing X11Server.handleConnection logic here
}
