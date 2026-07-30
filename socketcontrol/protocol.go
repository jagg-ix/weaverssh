// Package socketcontrol provides an authenticated local control protocol for a
// long-running socketengine supervisor. Requests and responses are HMAC-SHA256
// authenticated and replay-protected; the transport is normally a mode-0600
// Unix socket.
package socketcontrol

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	ProtocolVersion = "weaverssh.socket-control.v1"
	ActionStatus = "status"
	ActionReload = "reload"
	ActionDrain = "drain"
	ActionStop = "stop"
	ActionChronoProvider = "chrono-provider"
	ActionEvidenceStatus = "evidence-status"
	ActionEvidenceVerify = "evidence-verify"
	ActionEvidenceExport = "evidence-export"
	maxMessageBytes = 1 << 20
	defaultMaxSkew = 30 * time.Second
)

var (
	ErrUnauthorized = errors.New("socketcontrol: unauthorized")
	ErrReplay = errors.New("socketcontrol: replayed request")
	ErrInvalid = errors.New("socketcontrol: invalid request")
)

type Request struct {
	Protocol string `json:"protocol"`
	Action string `json:"action"`
	Config string `json:"config,omitempty"`
	Timestamp int64 `json:"timestamp_unix"`
	Nonce string `json:"nonce"`
	Signature string `json:"signature"`
}

type Response struct {
	Protocol string `json:"protocol"`
	Action string `json:"action"`
	RequestNonce string `json:"request_nonce"`
	OK bool `json:"ok"`
	Error string `json:"error,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Timestamp int64 `json:"timestamp_unix"`
	Nonce string `json:"nonce"`
	Signature string `json:"signature"`
}

type Handler func(context.Context, Request) (any, error)

type Server struct {
	Token []byte
	MaxSkew time.Duration
	Handler Handler
	mu sync.Mutex
	seen map[string]int64
}

func NewToken() ([]byte, error) { token := make([]byte, 32); if _, err := rand.Read(token); err != nil { return nil, err }; return token, nil }
func EncodeToken(token []byte) string { return base64.RawURLEncoding.EncodeToString(token) }
func DecodeToken(raw string) ([]byte, error) { decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw)); if err != nil || len(decoded) < 32 { return nil, errors.New("socketcontrol: token must be at least 32 random bytes encoded as base64url") }; return decoded, nil }

func NewRequest(action, config string, token []byte, now time.Time) (Request, error) {
	if now.IsZero() { now = time.Now() }
	nonce, err := randomNonce(24); if err != nil { return Request{}, err }
	request := Request{Protocol: ProtocolVersion, Action: strings.ToLower(strings.TrimSpace(action)), Config: strings.TrimSpace(config), Timestamp: now.Unix(), Nonce: nonce}
	request.Signature, err = sign(token, requestSigningValue(request)); return request, err
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s == nil || listener == nil || len(s.Token) < 32 || s.Handler == nil { return errors.New("socketcontrol: incomplete server") }
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		conn, err := listener.Accept()
		if err != nil { if ctx.Err() != nil || errors.Is(err, net.ErrClosed) { return nil }; return err }
		go s.serveConn(ctx, conn)
	}
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close(); _ = conn.SetDeadline(time.Now().Add(15*time.Second))
	var request Request
	if err := readJSON(conn, &request); err != nil { _ = s.writeResponse(conn, request, nil, err); return }
	if err := s.verify(request, time.Now()); err != nil { _ = s.writeResponse(conn, request, nil, err); return }
	payload, err := s.Handler(ctx, request); _ = s.writeResponse(conn, request, payload, err)
}

func (s *Server) verify(request Request, now time.Time) error {
	if request.Protocol != ProtocolVersion || request.Nonce == "" || request.Signature == "" { return ErrInvalid }
	switch request.Action { case ActionStatus, ActionReload, ActionDrain, ActionStop, ActionChronoProvider, ActionEvidenceStatus, ActionEvidenceVerify, ActionEvidenceExport: default: return ErrInvalid }
	maxSkew := s.MaxSkew; if maxSkew <= 0 { maxSkew = defaultMaxSkew }
	when := time.Unix(request.Timestamp, 0); if when.Before(now.Add(-maxSkew)) || when.After(now.Add(maxSkew)) { return ErrUnauthorized }
	if !verifySignature(s.Token, requestSigningValue(request), request.Signature) { return ErrUnauthorized }
	s.mu.Lock(); defer s.mu.Unlock()
	if s.seen == nil { s.seen = map[string]int64{} }
	cutoff := now.Add(-2*maxSkew).Unix(); for nonce, timestamp := range s.seen { if timestamp < cutoff { delete(s.seen, nonce) } }
	if _, exists := s.seen[request.Nonce]; exists { return ErrReplay }
	s.seen[request.Nonce] = request.Timestamp; return nil
}

func (s *Server) writeResponse(writer io.Writer, request Request, value any, responseErr error) error {
	payload, err := json.Marshal(value); if err != nil { responseErr = err; payload = nil }
	nonce, err := randomNonce(24); if err != nil { return err }
	response := Response{Protocol: ProtocolVersion, Action: request.Action, RequestNonce: request.Nonce, OK: responseErr == nil, Payload: payload, Timestamp: time.Now().Unix(), Nonce: nonce}
	if responseErr != nil { response.Error = responseErr.Error() }
	response.Signature, err = sign(s.Token, responseSigningValue(response)); if err != nil { return err }
	return writeJSON(writer, response)
}

func Call(ctx context.Context, network, address string, token []byte, action, config string) (Response, error) {
	request, err := NewRequest(action, config, token, time.Now()); if err != nil { return Response{}, err }
	dialer := net.Dialer{}; conn, err := dialer.DialContext(ctx, strings.TrimSpace(network), strings.TrimSpace(address)); if err != nil { return Response{}, err }; defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok { _ = conn.SetDeadline(deadline) }
	if err := writeJSON(conn, request); err != nil { return Response{}, err }
	var response Response
	if err := readJSON(conn, &response); err != nil { return Response{}, err }
	if response.Protocol != ProtocolVersion || response.Action != request.Action || response.RequestNonce != request.Nonce || response.Nonce == "" { return Response{}, ErrInvalid }
	if !verifySignature(token, responseSigningValue(response), response.Signature) { return Response{}, ErrUnauthorized }
	if response.Timestamp < request.Timestamp-60 || response.Timestamp > time.Now().Add(time.Minute).Unix() { return Response{}, ErrUnauthorized }
	if !response.OK { return response, errors.New(response.Error) }
	return response, nil
}

func requestSigningValue(request Request) any { return struct { Protocol string `json:"protocol"`; Action string `json:"action"`; Config string `json:"config,omitempty"`; Timestamp int64 `json:"timestamp_unix"`; Nonce string `json:"nonce"` }{request.Protocol, request.Action, request.Config, request.Timestamp, request.Nonce} }
func responseSigningValue(response Response) any { return struct { Protocol string `json:"protocol"`; Action string `json:"action"`; RequestNonce string `json:"request_nonce"`; OK bool `json:"ok"`; Error string `json:"error,omitempty"`; Payload json.RawMessage `json:"payload,omitempty"`; Timestamp int64 `json:"timestamp_unix"`; Nonce string `json:"nonce"` }{response.Protocol, response.Action, response.RequestNonce, response.OK, response.Error, response.Payload, response.Timestamp, response.Nonce} }

func sign(token []byte, value any) (string, error) { if len(token) < 32 { return "", ErrUnauthorized }; payload, err := json.Marshal(value); if err != nil { return "", err }; mac := hmac.New(sha256.New, token); _, _ = mac.Write(payload); return hex.EncodeToString(mac.Sum(nil)), nil }
func verifySignature(token []byte, value any, signature string) bool { expected, err := sign(token, value); if err != nil { return false }; provided, err := hex.DecodeString(strings.TrimSpace(signature)); if err != nil { return false }; expectedBytes, _ := hex.DecodeString(expected); return hmac.Equal(expectedBytes, provided) }

func writeJSON(writer io.Writer, value any) error {
	payload, err := json.Marshal(value); if err != nil { return err }
	if len(payload) == 0 || len(payload) > maxMessageBytes { return ErrInvalid }
	payload = append(payload, '\n')
	for len(payload) > 0 { n, err := writer.Write(payload); if err != nil { return err }; if n == 0 { return io.ErrShortWrite }; payload = payload[n:] }
	return nil
}

func readJSON(reader io.Reader, target any) error {
	limited := &io.LimitedReader{R: reader, N: maxMessageBytes+2}
	line, err := bufio.NewReader(limited).ReadBytes('\n')
	if err != nil { return err }
	if len(line) == 0 || len(line) > maxMessageBytes+1 || line[len(line)-1] != '\n' { return ErrInvalid }
	line = bytes.TrimSpace(line); if len(line) == 0 { return ErrInvalid }
	decoder := json.NewDecoder(bytes.NewReader(line)); decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil { return err }
	var trailing any; if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) { return ErrInvalid }
	return nil
}

func randomNonce(size int) (string, error) { buffer := make([]byte, size); if _, err := rand.Read(buffer); err != nil { return "", err }; return base64.RawURLEncoding.EncodeToString(buffer), nil }

func DecodePayload(response Response, target any) error {
	if !response.OK { return errors.New(response.Error) }
	if len(response.Payload) == 0 || bytes.Equal(response.Payload, []byte("null")) { return nil }
	if err := json.Unmarshal(response.Payload, target); err != nil { return fmt.Errorf("socketcontrol: decode payload: %w", err) }
	return nil
}
