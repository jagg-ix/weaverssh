// Package sessionruntime binds the logical session multiplexer to an already
// authenticated WebSocket connection. It does not dial, listen, or allocate a
// network port; transport establishment remains the responsibility of SSH X11
// forwarding and the in-place WebSocket upgrade.
package sessionruntime

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"weaverssh/flowcontrol"
	"weaverssh/sessionmux"
	"weaverssh/tunnel"

	"github.com/gorilla/websocket"
)

const (
	// ProtocolVersion identifies the post-WebSocket session bootstrap. Version 2
	// requires the bounded sessionmux WINDOW protocol.
	ProtocolVersion        = "weaverssh.dynamic-session.v2"
	maxHelloBytes          = 4096
	maxBindingBytes        = 512
	defaultMuxPayloadBytes = 16 << 20
	webSocketFrameOverhead = 64
)

var (
	ErrWrongSubprotocol = errors.New("sessionruntime: dynamic-session WebSocket subprotocol not negotiated")
	ErrWrongProtocol    = errors.New("sessionruntime: unsupported session protocol")
	ErrInvalidBinding   = errors.New("sessionruntime: invalid session binding")
)

// Hello is the single pre-mux message sent by the accepting peer. Binding is
// generated on, or supplied to, the already authenticated WebSocket stream and
// is subsequently required by sessioncontrol node registration.
type Hello struct {
	Protocol string `json:"protocol"`
	Binding  string `json:"binding"`
}

// Config controls session bootstrap and the logical multiplexer.
type Config struct {
	Binding string
	Mux     sessionmux.Config
	Profile flowcontrol.Profile
}

// Session is a logical dynamic session carried by one upgraded WebSocket.
type Session struct {
	Binding string
	Mux     *sessionmux.Mux
}

// Close closes the mux and therefore the underlying WebSocket adapter.
func (s *Session) Close() error {
	if s == nil || s.Mux == nil {
		return nil
	}
	return s.Mux.Close()
}

// AcceptWebSocket sends the session hello and starts the responder side of the
// mux. ws must have negotiated tunnel.SessionSubprotocol.
func AcceptWebSocket(ws *websocket.Conn, config Config) (*Session, error) {
	if err := requireSessionSubprotocol(ws); err != nil {
		return nil, err
	}
	binding, err := normalizeOrCreateBinding(config.Binding)
	if err != nil {
		return nil, err
	}
	hello, err := json.Marshal(Hello{Protocol: ProtocolVersion, Binding: binding})
	if err != nil {
		return nil, err
	}
	if err := ws.WriteMessage(websocket.TextMessage, hello); err != nil {
		return nil, fmt.Errorf("sessionruntime: write hello: %w", err)
	}
	return startMux(ws, config, sessionmux.RoleResponder, binding)
}

// ConnectWebSocket receives the session hello and starts the initiator side of
// the mux. Proof frames, when required, must be sent before calling this method.
func ConnectWebSocket(ws *websocket.Conn, config Config) (*Session, error) {
	if err := requireSessionSubprotocol(ws); err != nil {
		return nil, err
	}
	ws.SetReadLimit(maxHelloBytes)
	messageType, payload, err := ws.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("sessionruntime: read hello: %w", err)
	}
	if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
		return nil, fmt.Errorf("sessionruntime: unexpected hello message type %d", messageType)
	}
	if len(payload) == 0 || len(payload) > maxHelloBytes {
		return nil, fmt.Errorf("sessionruntime: hello size %d is invalid", len(payload))
	}
	var hello Hello
	if err := json.Unmarshal(payload, &hello); err != nil {
		return nil, fmt.Errorf("sessionruntime: decode hello: %w", err)
	}
	if hello.Protocol != ProtocolVersion {
		return nil, fmt.Errorf("%w: %q", ErrWrongProtocol, hello.Protocol)
	}
	binding, err := normalizeBinding(hello.Binding)
	if err != nil {
		return nil, err
	}
	if configured := strings.TrimSpace(config.Binding); configured != "" && configured != binding {
		return nil, fmt.Errorf("%w: expected %q got %q", ErrInvalidBinding, configured, binding)
	}
	return startMux(ws, config, sessionmux.RoleInitiator, binding)
}

func startMux(ws *websocket.Conn, config Config, role sessionmux.Role, binding string) (*Session, error) {
	muxConfig := withDefaultServices(config.Mux)
	muxConfig.Role = role
	maxPayload := muxConfig.Codec.MaxPayload
	if maxPayload == 0 {
		maxPayload = defaultMuxPayloadBytes
	}
	ws.SetReadLimit(int64(maxPayload) + webSocketFrameOverhead)
	transport := tunnel.NewWebSocketReadWriterWithProfile(ws, config.Profile)
	mux, err := sessionmux.New(transport, muxConfig)
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	return &Session{Binding: binding, Mux: mux}, nil
}

// withDefaultServices defines the production dynamic-session service set. Keep
// this explicit so adding a wire-valid service cannot leave deployed peers using
// an older package-local default that silently resets it. A caller-provided map
// remains authoritative and is never widened.
func withDefaultServices(config sessionmux.Config) sessionmux.Config {
	if config.AllowedServices != nil {
		return config
	}
	config.AllowedServices = map[sessionmux.ServiceID]bool{
		sessionmux.ServiceControl: true,
		sessionmux.ServiceFS:      true,
		sessionmux.ServiceTCP:     true,
		sessionmux.ServiceExec:    true,
		sessionmux.ServiceEvents:  true,
		sessionmux.ServiceUDP:     true,
	}
	return config
}

func requireSessionSubprotocol(ws *websocket.Conn) error {
	if ws == nil {
		return errors.New("sessionruntime: nil WebSocket")
	}
	if ws.Subprotocol() != tunnel.SessionSubprotocol {
		return fmt.Errorf("%w: got %q", ErrWrongSubprotocol, ws.Subprotocol())
	}
	return nil
}

func normalizeOrCreateBinding(binding string) (string, error) {
	if strings.TrimSpace(binding) != "" {
		return normalizeBinding(binding)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("sessionruntime: generate binding: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func normalizeBinding(binding string) (string, error) {
	binding = strings.TrimSpace(binding)
	if binding == "" || len(binding) > maxBindingBytes {
		return "", ErrInvalidBinding
	}
	return binding, nil
}
