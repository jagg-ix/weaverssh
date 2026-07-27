package app

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"weaverssh/authproof"
	"weaverssh/flowcontrol"
	"weaverssh/sessionruntime"
	"weaverssh/tunnel"

	"github.com/gorilla/websocket"
)

const maxRuntimeProofMessageBytes = 64 << 10

// DynamicSessionContext records the authority evidence accepted before the
// logical session runtime starts.
type DynamicSessionContext struct {
	Binding               string
	Grant                 authproof.Grant
	X11Authenticated      bool
	AgentProofVerified    bool
	NegotiatedSubprotocol string
}

// DynamicSessionHandler serves one authenticated logical session. The handler
// should block until the session is complete; the runtime closes the session on
// return.
type DynamicSessionHandler func(context.Context, *sessionruntime.Session, DynamicSessionContext) error

// DynamicSessionClientConfig controls the initiator side of an in-place
// X11-to-WebSocket-to-mux upgrade.
type DynamicSessionClientConfig struct {
	AuthCookie       string
	Proof            *authproof.SignedGrant
	ExpectedBinding  string
	Profile          flowcontrol.Profile
	HandshakeTimeout time.Duration
}

// ServeDynamicSessionConn accepts a dynamic session on an already-open
// connection. The connection is expected to be an SSH-managed X11 channel (or
// an in-process test equivalent). This method never listens, dials, or allocates
// a network port.
func (r *AgentRuntime) ServeDynamicSessionConn(ctx context.Context, conn net.Conn, handler DynamicSessionHandler) error {
	if r == nil || r.x11Server == nil {
		return errors.New("dynamic session: nil agent runtime")
	}
	if conn == nil {
		return errors.New("dynamic session: nil connection")
	}
	if handler == nil {
		return errors.New("dynamic session: nil handler")
	}
	defer conn.Close()

	timeout := r.config.AuthTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	reader := bufio.NewReader(conn)
	client := &ClientConnection{conn: conn, state: StateListening}
	setup, err := ReadConnectionSetup(reader)
	if err != nil {
		return fmt.Errorf("dynamic session: read X11 setup: %w", err)
	}
	if setup.ByteOrder == BigEndian {
		client.byteOrder = binary.BigEndian
	} else {
		client.byteOrder = binary.LittleEndian
	}

	// Dynamic sessions require an actual cookie match. TrustedAuth remains a
	// legacy relay compatibility option and cannot bypass this boundary.
	x11Authenticated := r.x11Server.validateAuth(setup, client)
	reply := r.x11Server.buildConnectionReply(x11Authenticated, client)
	writeErr := reply.Write(conn, client.byteOrder)
	if !x11Authenticated {
		return errors.New("dynamic session: X11 authentication failed")
	}
	if writeErr != nil {
		return fmt.Errorf("dynamic session: write X11 reply: %w", writeErr)
	}
	client.authenticated = true
	client.state = StateConnected

	request, err := http.ReadRequest(reader)
	if err != nil {
		return fmt.Errorf("dynamic session: read WebSocket upgrade: %w", err)
	}
	upgrader := r.upgrader
	upgrader.Subprotocols = []string{tunnel.SessionSubprotocol}
	rw := &connResponseWriter{conn: conn, header: make(http.Header), reader: reader}
	wsConn, err := upgrader.Upgrade(rw, request, nil)
	if err != nil {
		return fmt.Errorf("dynamic session: WebSocket upgrade: %w", err)
	}
	defer wsConn.Close()
	_ = conn.SetDeadline(time.Time{})
	if wsConn.Subprotocol() != tunnel.SessionSubprotocol {
		return fmt.Errorf("dynamic session: session subprotocol not negotiated: %q", wsConn.Subprotocol())
	}

	authorityCtx := authorityContextFromConn(true, conn)
	var grant authproof.Grant
	if r.config.Proof.Required() {
		wsConn.SetReadLimit(maxRuntimeProofMessageBytes)
		grant, err = verifyWebSocketProof(wsConn, r.config)
		if err != nil {
			return fmt.Errorf("dynamic session: runtime proof: %w", err)
		}
		authorityCtx.AgentKeyProofVerified = true
	}
	if err := authorizeWebSocketSession(r.config, authorityCtx); err != nil {
		return fmt.Errorf("dynamic session: authority: %w", err)
	}

	session, err := sessionruntime.AcceptWebSocket(wsConn, sessionruntime.Config{
		Binding: grant.SessionID,
		Profile: flowcontrol.DefaultProfile(),
	})
	if err != nil {
		return err
	}
	defer session.Close()
	return handler(ctx, session, DynamicSessionContext{
		Binding:               session.Binding,
		Grant:                 grant,
		X11Authenticated:      true,
		AgentProofVerified:    authorityCtx.AgentKeyProofVerified,
		NegotiatedSubprotocol: wsConn.Subprotocol(),
	})
}

// OpenDynamicSessionConn initiates a dynamic session over an already-open
// SSH-managed X11 channel. It sends the X11 setup, upgrades the same connection
// with the dynamic-session WebSocket subprotocol, optionally sends authproof,
// and starts the initiator side of sessionmux.
func OpenDynamicSessionConn(ctx context.Context, conn net.Conn, config DynamicSessionClientConfig) (*sessionruntime.Session, error) {
	if conn == nil {
		return nil, errors.New("dynamic session: nil connection")
	}
	cookie := strings.TrimSpace(config.AuthCookie)
	if cookie == "" {
		_ = conn.Close()
		return nil, errors.New("dynamic session: empty X11 cookie")
	}
	timeout := config.HandshakeTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	setup, err := createX11SetupRequest(cookie)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dynamic session: create X11 setup: %w", err)
	}
	if _, err := conn.Write(setup); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dynamic session: write X11 setup: %w", err)
	}
	responseHeader := make([]byte, 8)
	if _, err := io.ReadFull(conn, responseHeader); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dynamic session: read X11 reply: %w", err)
	}
	if responseHeader[0] != 1 {
		reasonLen := int(responseHeader[1])
		reason := make([]byte, reasonLen)
		_, _ = io.ReadFull(conn, reason)
		_ = conn.Close()
		return nil, fmt.Errorf("dynamic session: X11 authentication rejected: %s", strings.TrimSpace(string(reason)))
	}
	additionalLen := int(binary.LittleEndian.Uint16(responseHeader[6:8])) * 4
	if additionalLen > 0 {
		if _, err := io.CopyN(io.Discard, conn, int64(additionalLen)); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("dynamic session: read X11 server info: %w", err)
		}
	}

	wsConn, err := tunnel.ClientUpgradeSessionWithProfile(conn, config.Profile)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	if config.Proof != nil {
		payload, err := authproof.MarshalControlFrame(*config.Proof)
		if err != nil {
			_ = wsConn.Close()
			return nil, fmt.Errorf("dynamic session: encode authproof: %w", err)
		}
		if len(payload) > maxRuntimeProofMessageBytes {
			_ = wsConn.Close()
			return nil, fmt.Errorf("dynamic session: authproof message too large: %d", len(payload))
		}
		if err := wsConn.WriteMessage(websocket.TextMessage, payload); err != nil {
			_ = wsConn.Close()
			return nil, fmt.Errorf("dynamic session: send authproof: %w", err)
		}
	}
	session, err := sessionruntime.ConnectWebSocket(wsConn, sessionruntime.Config{
		Binding: config.ExpectedBinding,
		Profile: config.Profile,
	})
	if err != nil {
		_ = wsConn.Close()
		return nil, err
	}
	return session, nil
}
