package sessioncontrol

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"weaverssh/authproof"
	"weaverssh/sessionmux"
)

// AcceptLocalTarget accepts one target only when the requested node resolves to
// the supplied verified local context and the service was both advertised and
// authorized by that context's signed capabilities. It sends the target
// acknowledgement only after all local ownership checks pass.
func AcceptLocalTarget(
	ctx context.Context,
	mux *sessionmux.Mux,
	local authproof.NodeContext,
	advertised []sessionmux.ServiceID,
) (AcceptedTarget, error) {
	if mux == nil {
		return AcceptedTarget{}, errors.New("sessioncontrol: nil mux")
	}
	local = local.Normalized()
	if err := local.Validate(); err != nil {
		return AcceptedTarget{}, err
	}
	allowed := make(map[sessionmux.ServiceID]bool, len(advertised))
	for _, service := range advertised {
		if !service.Valid() || service == sessionmux.ServiceControl {
			return AcceptedTarget{}, fmt.Errorf("sessioncontrol: invalid local service %d", service)
		}
		if !serviceAuthorizedByCapabilities(local.Capabilities, service) {
			return AcceptedTarget{}, fmt.Errorf("%w: node=%s service=%s", authproof.ErrMissingCapability, local.CurrentNode, service)
		}
		allowed[service] = true
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
	if !referenceResolvesToLocal(metadata.Node, local) {
		_ = stream.Reset()
		return AcceptedTarget{}, fmt.Errorf("%w: target %q is not local node %q", ErrTargetDenied, metadata.Node, local.CurrentNode)
	}
	if !allowed[stream.Service()] {
		_ = stream.Reset()
		return AcceptedTarget{}, fmt.Errorf("%w: node=%s service=%s", ErrServiceUnavailable, local.CurrentNode, stream.Service())
	}
	if _, err := stream.Write(targetAcceptedMessage); err != nil {
		_ = stream.Reset()
		return AcceptedTarget{}, err
	}
	return AcceptedTarget{
		Stream: stream,
		Node: Node{
			ID:      local.CurrentNode,
			Index:   indexOf(local.Nodes, local.CurrentNode),
			Context: local,
		},
		Data: append([]byte(nil), metadata.Data...),
	}, nil
}

func referenceResolvesToLocal(ref string, local authproof.NodeContext) bool {
	ref = strings.TrimSpace(ref)
	switch strings.ToLower(ref) {
	case "self", "local", "here", "this", "current", ".":
		return true
	case "endpoint", "target", "remote", "last":
		return local.CurrentNode == local.EndpointNode
	case "previous", "prev", "next":
		// These aliases are relative to the requester, whose identity is not part
		// of a peer-local OPEN. A future router may resolve them before forwarding.
		return false
	default:
		// Workstation-bound requests arrive as the concrete node ID supplied by
		// WVORIGIN; "origin" has no reserved meaning here.
		return ref == local.CurrentNode
	}
}
