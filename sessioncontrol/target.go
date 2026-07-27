package sessioncontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"weaverssh/sessionmux"
)

const targetProtocol = "weaverssh.target-open.v1"

var (
	ErrTargetDenied       = errors.New("sessioncontrol: target stream denied")
	ErrInvalidTarget      = errors.New("sessioncontrol: invalid target metadata")
	ErrUnexpectedControl  = errors.New("sessioncontrol: control stream requires control dispatcher")
	ErrTargetNotLocal     = errors.New("sessioncontrol: target is not served by this peer")
	targetAcceptedMessage = []byte{'W', 'V', 'T', 'A', 1}
)

// OpenMetadata is carried in the mux OPEN frame. Data is service-specific and
// is protected by the authenticated parent session; Node is resolved through
// the verified session registry.
type OpenMetadata struct {
	Protocol string `json:"protocol"`
	Node     string `json:"node"`
	Data     []byte `json:"data,omitempty"`
}

// AcceptedTarget is an authorized logical service stream and its resolved node.
type AcceptedTarget struct {
	Stream *sessionmux.Stream
	Node   Node
	Data   []byte
}

// TargetPolicy performs peer-local routing checks after registry authorization
// but before the target-accepted acknowledgement is sent.
type TargetPolicy func(Node, sessionmux.ServiceID) error

func EncodeOpenMetadata(node string, data []byte) ([]byte, error) {
	node = strings.TrimSpace(node)
	if node == "" {
		return nil, fmt.Errorf("%w: empty node", ErrInvalidTarget)
	}
	return json.Marshal(OpenMetadata{
		Protocol: targetProtocol,
		Node:     node,
		Data:     append([]byte(nil), data...),
	})
}

func DecodeOpenMetadata(raw []byte) (OpenMetadata, error) {
	var metadata OpenMetadata
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return OpenMetadata{}, fmt.Errorf("%w: %v", ErrInvalidTarget, err)
	}
	metadata.Node = strings.TrimSpace(metadata.Node)
	if metadata.Protocol != targetProtocol || metadata.Node == "" {
		return OpenMetadata{}, ErrInvalidTarget
	}
	metadata.Data = append([]byte(nil), metadata.Data...)
	return metadata, nil
}

// OpenTarget opens a service stream to node and waits for a second-stage target
// acknowledgement. The mux-level ACCEPT alone is not authorization: this
// function returns the stream only after the peer has resolved the node and
// confirmed that it advertised and serves the requested service.
func OpenTarget(
	ctx context.Context,
	mux *sessionmux.Mux,
	node string,
	service sessionmux.ServiceID,
	data []byte,
) (*sessionmux.Stream, error) {
	if mux == nil {
		return nil, errors.New("sessioncontrol: nil mux")
	}
	if !service.Valid() || service == sessionmux.ServiceControl {
		return nil, fmt.Errorf("sessioncontrol: invalid target service %d", service)
	}
	metadata, err := EncodeOpenMetadata(node, data)
	if err != nil {
		return nil, err
	}
	stream, err := mux.Open(ctx, service, metadata)
	if err != nil {
		return nil, err
	}

	type acknowledgement struct {
		data []byte
		err  error
	}
	result := make(chan acknowledgement, 1)
	go func() {
		response := make([]byte, len(targetAcceptedMessage))
		_, readErr := io.ReadFull(stream, response)
		result <- acknowledgement{data: response, err: readErr}
	}()
	select {
	case ack := <-result:
		if ack.err != nil {
			_ = stream.Reset()
			return nil, fmt.Errorf("%w: %v", ErrTargetDenied, ack.err)
		}
		if !bytes.Equal(ack.data, targetAcceptedMessage) {
			_ = stream.Reset()
			return nil, ErrTargetDenied
		}
		return stream, nil
	case <-ctx.Done():
		_ = stream.Reset()
		return nil, ctx.Err()
	}
}

// AcceptTarget authorizes one already mux-accepted stream against the signed
// registry and accepts any node that the registry says advertises the service.
// Routers may use this form; direct service hosts should use AcceptTargetWithPolicy.
func AcceptTarget(
	ctx context.Context,
	mux *sessionmux.Mux,
	registry *Registry,
	currentNode string,
) (AcceptedTarget, error) {
	return AcceptTargetWithPolicy(ctx, mux, registry, currentNode, nil)
}

// AcceptTargetWithPolicy adds a peer-local routing policy before acknowledging
// the stream. A failed policy resets the stream, so callers never receive a
// successful OpenTarget for a service that this peer does not actually serve.
func AcceptTargetWithPolicy(
	ctx context.Context,
	mux *sessionmux.Mux,
	registry *Registry,
	currentNode string,
	policy TargetPolicy,
) (AcceptedTarget, error) {
	if mux == nil || registry == nil {
		return AcceptedTarget{}, errors.New("sessioncontrol: incomplete target acceptor")
	}
	stream, err := mux.Accept(ctx)
	if err != nil {
		return AcceptedTarget{}, err
	}
	if stream.Service() == sessionmux.ServiceControl {
		_ = stream.Reset()
		return AcceptedTarget{}, ErrUnexpectedControl
	}
	metadata, err := DecodeOpenMetadata(stream.Metadata())
	if err != nil {
		_ = stream.Reset()
		return AcceptedTarget{}, err
	}
	node, err := registry.Authorize(metadata.Node, currentNode, stream.Service())
	if err != nil {
		_ = stream.Reset()
		return AcceptedTarget{}, fmt.Errorf("%w: %v", ErrTargetDenied, err)
	}
	if policy != nil {
		if err := policy(node, stream.Service()); err != nil {
			_ = stream.Reset()
			return AcceptedTarget{}, fmt.Errorf("%w: %v", ErrTargetDenied, err)
		}
	}
	if _, err := stream.Write(targetAcceptedMessage); err != nil {
		_ = stream.Reset()
		return AcceptedTarget{}, err
	}
	return AcceptedTarget{
		Stream: stream,
		Node:   node,
		Data:   append([]byte(nil), metadata.Data...),
	}, nil
}
