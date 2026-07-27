package sessioncontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"weaverssh/sessionlink"
	"weaverssh/sessionmux"
)

// RegistrationMode identifies the node-registration exchange accepted on a
// ServiceControl stream.
type RegistrationMode string

const (
	RegistrationModeLegacy    RegistrationMode = "legacy"
	RegistrationModeReconnect RegistrationMode = "reconnect"
)

// AcceptedRegistration normalizes legacy and reconnect registration results for
// session lifecycle code. Legacy registrations leave LinkID and TransportID
// empty; the caller derives them from the verified adjacent nodes and its local
// transport generation.
type AcceptedRegistration struct {
	Mode           RegistrationMode
	Node           Node
	LinkID         sessionlink.ID
	TransportID    sessionlink.TransportID
	SessionBinding string
	Services       []sessionmux.ServiceID
}

// AnyRegistrationConfig permits a host to accept legacy one-shot registration
// and challenge-bound reconnect registration without guessing which protocol a
// peer will use before reading the control stream metadata.
type AnyRegistrationConfig struct {
	LegacyVerifier         Verifier
	ExpectedSessionBinding string
	Reconnect              *ReconnectServerConfig
}

// ServeAnyRegistration accepts exactly one node-registration stream and routes
// it according to the explicit OPEN metadata. No fallback is attempted after a
// protocol has been selected.
func ServeAnyRegistration(
	ctx context.Context,
	mux *sessionmux.Mux,
	registry *Registry,
	config AnyRegistrationConfig,
) (AcceptedRegistration, error) {
	if mux == nil || registry == nil {
		return AcceptedRegistration{}, errors.New("sessioncontrol: incomplete registration server")
	}
	stream, err := mux.Accept(ctx)
	if err != nil {
		return AcceptedRegistration{}, err
	}
	defer stream.Close()
	if stream.Service() != sessionmux.ServiceControl {
		_ = stream.Reset()
		return AcceptedRegistration{}, ErrWrongProtocol
	}

	switch string(stream.Metadata()) {
	case ProtocolVersion:
		if config.LegacyVerifier == nil {
			_ = stream.Reset()
			return AcceptedRegistration{}, ErrWrongProtocol
		}
		node, err := ServeRegistrationStream(
			ctx,
			stream,
			registry,
			config.LegacyVerifier,
			config.ExpectedSessionBinding,
		)
		if err != nil {
			return AcceptedRegistration{}, err
		}
		return AcceptedRegistration{
			Mode:           RegistrationModeLegacy,
			Node:           node,
			SessionBinding: strings.TrimSpace(config.ExpectedSessionBinding),
			Services:       node.Services(),
		}, nil

	case ReconnectProtocolVersion:
		if config.Reconnect == nil {
			_ = stream.Reset()
			return AcceptedRegistration{}, ErrReconnectProtocol
		}
		accepted, err := ServeReconnectStream(ctx, stream, registry, *config.Reconnect)
		if err != nil {
			return AcceptedRegistration{}, err
		}
		return AcceptedRegistration{
			Mode:           RegistrationModeReconnect,
			Node:           accepted.Node,
			LinkID:         accepted.LinkID,
			TransportID:    accepted.TransportID,
			SessionBinding: accepted.SessionBinding,
			Services:       append([]sessionmux.ServiceID(nil), accepted.Services...),
		}, nil

	default:
		_ = stream.Reset()
		return AcceptedRegistration{}, ErrWrongProtocol
	}
}

// ServeRegistrationStream performs the legacy node.register exchange on an
// already accepted control stream. It is the stream-level counterpart of
// ServeRegistration and is used by protocol-dispatching hosts.
func ServeRegistrationStream(
	ctx context.Context,
	stream *sessionmux.Stream,
	registry *Registry,
	verify Verifier,
	expectedSessionBinding string,
) (Node, error) {
	if stream == nil || registry == nil || verify == nil {
		return Node{}, errors.New("sessioncontrol: incomplete registration server")
	}
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
	expectedSessionBinding = strings.TrimSpace(expectedSessionBinding)
	if strings.TrimSpace(request.SessionBinding) == "" || request.SessionBinding != expectedSessionBinding {
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
