package sessioncontrol

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"weaverssh/authproof"
	"weaverssh/sessionmux"
)

const (
	ProtocolVersion = "weaverssh.session-control.v1"
	messageRegister = "node.register"
	messageAccepted = "node.registered"
)

var (
	ErrWrongProtocol  = errors.New("sessioncontrol: wrong control protocol")
	ErrWrongBinding   = errors.New("sessioncontrol: wrong authenticated session binding")
	ErrControlDenied  = errors.New("sessioncontrol: node registration denied")
	ErrUnexpectedType = errors.New("sessioncontrol: unexpected control message type")
)

// RegisterRequest is sent on a control logical stream after the underlying
// X11-derived transport has already authenticated and upgraded. SignedContext
// authenticates the node's chain position; SessionBinding binds this registration
// to the upgraded session instance.
type RegisterRequest struct {
	Type           string                      `json:"type"`
	Protocol       string                      `json:"protocol"`
	SessionBinding string                      `json:"session_binding"`
	SignedContext  authproof.SignedNodeContext `json:"signed_context"`
	Services       []sessionmux.ServiceID      `json:"services"`
}

// RegisterResponse confirms the node and the services accepted into the active
// registry.
type RegisterResponse struct {
	Type     string                 `json:"type"`
	Protocol string                 `json:"protocol"`
	Node     string                 `json:"node,omitempty"`
	Services []sessionmux.ServiceID `json:"services,omitempty"`
	Error    string                 `json:"error,omitempty"`
}

// Verifier verifies a signed node context against the trust and replay policy
// associated with the current SSH/X11-derived session.
type Verifier func(authproof.SignedNodeContext) (authproof.NodeContext, error)

// NewAuthproofVerifier adapts authproof verification to the control service.
// A replay cache is allocated when the caller did not provide one.
func NewAuthproofVerifier(publicKey ed25519.PublicKey, options authproof.NodeContextVerifyOptions) Verifier {
	if options.ReplayCache == nil {
		options.ReplayCache = authproof.NewNonceCache()
	}
	return func(signed authproof.SignedNodeContext) (authproof.NodeContext, error) {
		return authproof.VerifySignedNodeContext(signed, publicKey, options)
	}
}

// RegisterNode registers one node through a logical control stream. It returns
// only after the peer has verified the signed node context and stored the node.
func RegisterNode(
	ctx context.Context,
	mux *sessionmux.Mux,
	signed authproof.SignedNodeContext,
	services []sessionmux.ServiceID,
	sessionBinding string,
) (RegisterResponse, error) {
	if mux == nil {
		return RegisterResponse{}, errors.New("sessioncontrol: nil mux")
	}
	sessionBinding = strings.TrimSpace(sessionBinding)
	if sessionBinding == "" {
		return RegisterResponse{}, errors.New("sessioncontrol: empty session binding")
	}

	stream, err := mux.Open(ctx, sessionmux.ServiceControl, []byte(ProtocolVersion))
	if err != nil {
		return RegisterResponse{}, err
	}
	defer stream.Close()

	request := RegisterRequest{
		Type:           messageRegister,
		Protocol:       ProtocolVersion,
		SessionBinding: sessionBinding,
		SignedContext:  signed,
		Services:       append([]sessionmux.ServiceID(nil), services...),
	}
	if err := json.NewEncoder(stream).Encode(request); err != nil {
		_ = stream.Reset()
		return RegisterResponse{}, fmt.Errorf("sessioncontrol: encode registration: %w", err)
	}

	response, err := decodeResponse(ctx, stream)
	if err != nil {
		_ = stream.Reset()
		return RegisterResponse{}, err
	}
	if response.Protocol != ProtocolVersion {
		return response, ErrWrongProtocol
	}
	if response.Type != messageAccepted {
		return response, fmt.Errorf("%w: %s", ErrUnexpectedType, response.Type)
	}
	if response.Error != "" {
		return response, fmt.Errorf("%w: %s", ErrControlDenied, response.Error)
	}
	return response, nil
}

// ServeRegistration accepts and verifies one control registration. Production
// dispatchers may call this for each incoming control stream.
func ServeRegistration(
	ctx context.Context,
	mux *sessionmux.Mux,
	registry *Registry,
	verify Verifier,
	expectedSessionBinding string,
) (Node, error) {
	if mux == nil || registry == nil || verify == nil {
		return Node{}, errors.New("sessioncontrol: incomplete registration server")
	}
	stream, err := mux.Accept(ctx)
	if err != nil {
		return Node{}, err
	}
	defer stream.Close()
	if stream.Service() != sessionmux.ServiceControl || string(stream.Metadata()) != ProtocolVersion {
		_ = stream.Reset()
		return Node{}, ErrWrongProtocol
	}

	request, err := decodeRequest(ctx, stream)
	if err != nil {
		_ = stream.Reset()
		return Node{}, err
	}
	response := RegisterResponse{Type: messageAccepted, Protocol: ProtocolVersion}
	deny := func(reason error) (Node, error) {
		response.Error = reason.Error()
		_ = json.NewEncoder(stream).Encode(response)
		return Node{}, reason
	}
	if request.Type != messageRegister || request.Protocol != ProtocolVersion {
		return deny(ErrWrongProtocol)
	}
	if strings.TrimSpace(request.SessionBinding) == "" || request.SessionBinding != strings.TrimSpace(expectedSessionBinding) {
		return deny(ErrWrongBinding)
	}

	verified, err := verify(request.SignedContext)
	if err != nil {
		return deny(fmt.Errorf("%w: %v", ErrControlDenied, err))
	}
	node, err := registry.RegisterVerified(verified, request.Services)
	if err != nil {
		return deny(err)
	}
	response.Node = node.ID
	response.Services = node.Services()
	if err := json.NewEncoder(stream).Encode(response); err != nil {
		return Node{}, fmt.Errorf("sessioncontrol: encode registration response: %w", err)
	}
	return node, nil
}

type requestResult struct {
	request RegisterRequest
	err     error
}

func decodeRequest(ctx context.Context, stream *sessionmux.Stream) (RegisterRequest, error) {
	result := make(chan requestResult, 1)
	go func() {
		var request RegisterRequest
		err := json.NewDecoder(stream).Decode(&request)
		result <- requestResult{request: request, err: err}
	}()
	select {
	case decoded := <-result:
		if decoded.err != nil {
			return RegisterRequest{}, fmt.Errorf("sessioncontrol: decode registration: %w", decoded.err)
		}
		return decoded.request, nil
	case <-ctx.Done():
		return RegisterRequest{}, ctx.Err()
	}
}

type responseResult struct {
	response RegisterResponse
	err      error
}

func decodeResponse(ctx context.Context, stream *sessionmux.Stream) (RegisterResponse, error) {
	result := make(chan responseResult, 1)
	go func() {
		var response RegisterResponse
		err := json.NewDecoder(stream).Decode(&response)
		result <- responseResult{response: response, err: err}
	}()
	select {
	case decoded := <-result:
		if decoded.err != nil {
			return RegisterResponse{}, fmt.Errorf("sessioncontrol: decode registration response: %w", decoded.err)
		}
		return decoded.response, nil
	case <-ctx.Done():
		return RegisterResponse{}, ctx.Err()
	}
}
