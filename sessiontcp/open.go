package sessiontcp

import (
	"context"

	"weaverssh/sessioncontrol"
	"weaverssh/sessionmux"
)

// OpenMux opens a TCP stream to node through mux and waits for both target
// authorization and the owning node's destination dial result.
func OpenMux(ctx context.Context, mux *sessionmux.Mux, node, network, address string) (*sessionmux.Stream, error) {
	metadata, err := EncodeRequest(network, address)
	if err != nil {
		return nil, err
	}
	stream, err := sessioncontrol.OpenTarget(ctx, mux, node, sessionmux.ServiceTCP, metadata)
	if err != nil {
		return nil, err
	}
	if err := readResult(stream); err != nil {
		_ = stream.Reset()
		return nil, err
	}
	return stream, nil
}
