package sessioncontrol

import (
	"context"
	"errors"

	"weaverssh/sessionmux"
)

// RegisterNodeReconnect opens a challenge-bound registration stream. Unlike
// RegisterNode, the reusable identity is not consumed as a one-shot bearer
// token; the node proves possession of its certified private key for this exact
// transport instance.
func RegisterNodeReconnect(
	ctx context.Context,
	mux *sessionmux.Mux,
	config ReconnectClientConfig,
) (RegisterResponse, ReconnectChallenge, error) {
	if mux == nil {
		return RegisterResponse{}, ReconnectChallenge{}, errors.New("sessioncontrol: nil mux")
	}
	stream, err := mux.Open(ctx, sessionmux.ServiceControl, []byte(ReconnectProtocolVersion))
	if err != nil {
		return RegisterResponse{}, ReconnectChallenge{}, err
	}
	defer stream.Close()
	return RegisterNodeReconnectStream(ctx, stream, config)
}

// ServeReconnectRegistration accepts one reconnect registration stream and
// returns the verified logical-link and transport identity needed by the
// sessionlink manager.
func ServeReconnectRegistration(
	ctx context.Context,
	mux *sessionmux.Mux,
	registry *Registry,
	config ReconnectServerConfig,
) (ReconnectAccepted, error) {
	if mux == nil {
		return ReconnectAccepted{}, errors.New("sessioncontrol: nil mux")
	}
	stream, err := mux.Accept(ctx)
	if err != nil {
		return ReconnectAccepted{}, err
	}
	defer stream.Close()
	if stream.Service() != sessionmux.ServiceControl || string(stream.Metadata()) != ReconnectProtocolVersion {
		_ = stream.Reset()
		return ReconnectAccepted{}, ErrReconnectProtocol
	}
	return ServeReconnectStream(ctx, stream, registry, config)
}
