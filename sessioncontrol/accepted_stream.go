package sessioncontrol

import (
	"context"
	"errors"
	"fmt"

	"weaverssh/authproof"
	"weaverssh/sessionmux"
)

// AuthorizeAcceptedTarget authorizes a stream already accepted by a central
// dispatcher. It sends the second-stage target acknowledgement only after
// registry and peer-local policy checks succeed.
func AuthorizeAcceptedTarget(
	ctx context.Context,
	stream *sessionmux.Stream,
	registry *Registry,
	currentNode string,
	policy TargetPolicy,
) (AcceptedTarget, error) {
	if stream == nil || registry == nil {
		return AcceptedTarget{}, errors.New("sessioncontrol: incomplete accepted target")
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
	select {
	case <-ctx.Done():
		_ = stream.Reset()
		return AcceptedTarget{}, ctx.Err()
	default:
	}
	if _, err := stream.Write(targetAcceptedMessage); err != nil {
		_ = stream.Reset()
		return AcceptedTarget{}, err
	}
	return AcceptedTarget{Stream: stream, Node: node, Data: append([]byte(nil), metadata.Data...)}, nil
}

// AuthorizePendingLocal verifies that a parsed pending target resolves to the
// verified local node and an implemented signed service. It deliberately does
// not send the second-stage acknowledgement, allowing additional fail-closed
// policy such as an enforce hook to run before the caller observes success.
func AuthorizePendingLocal(
	pending PendingTarget,
	local authproof.NodeContext,
	advertised []sessionmux.ServiceID,
) (AcceptedTarget, error) {
	if pending.Stream == nil {
		return AcceptedTarget{}, errors.New("sessioncontrol: nil pending target")
	}
	if pending.Service != pending.Stream.Service() || pending.Service == sessionmux.ServiceControl {
		_ = pending.Stream.Reset()
		return AcceptedTarget{}, errors.New("sessioncontrol: inconsistent pending target service")
	}
	local = local.Normalized()
	if err := local.Validate(); err != nil {
		_ = pending.Stream.Reset()
		return AcceptedTarget{}, err
	}
	allowed := make(map[sessionmux.ServiceID]bool, len(advertised))
	for _, service := range advertised {
		if !service.Valid() || service == sessionmux.ServiceControl {
			_ = pending.Stream.Reset()
			return AcceptedTarget{}, fmt.Errorf("sessioncontrol: invalid local service %d", service)
		}
		if !serviceAuthorizedByCapabilities(local.Capabilities, service) {
			_ = pending.Stream.Reset()
			return AcceptedTarget{}, fmt.Errorf("%w: node=%s service=%s", authproof.ErrMissingCapability, local.CurrentNode, service)
		}
		allowed[service] = true
	}
	if !referenceResolvesToLocal(pending.NodeRef, local) {
		_ = pending.Stream.Reset()
		return AcceptedTarget{}, fmt.Errorf("%w: target %q is not local node %q", ErrTargetDenied, pending.NodeRef, local.CurrentNode)
	}
	if !allowed[pending.Service] {
		_ = pending.Stream.Reset()
		return AcceptedTarget{}, fmt.Errorf("%w: node=%s service=%s", ErrServiceUnavailable, local.CurrentNode, pending.Service)
	}
	return AcceptedTarget{
		Stream: pending.Stream,
		Node:   Node{ID: local.CurrentNode, Index: indexOf(local.Nodes, local.CurrentNode), Context: local},
		Data:   append([]byte(nil), pending.Data...),
	}, nil
}

// AuthorizeAcceptedLocal authorizes a dispatcher-accepted stream only when it
// targets the verified local node and an implemented signed capability. It
// retains the historical behavior of acknowledging immediately after policy.
func AuthorizeAcceptedLocal(
	ctx context.Context,
	stream *sessionmux.Stream,
	local authproof.NodeContext,
	advertised []sessionmux.ServiceID,
) (AcceptedTarget, error) {
	pending, err := InspectAcceptedTarget(stream)
	if err != nil {
		return AcceptedTarget{}, err
	}
	accepted, err := AuthorizePendingLocal(pending, local, advertised)
	if err != nil {
		return AcceptedTarget{}, err
	}
	if err := AcknowledgePendingTarget(ctx, pending); err != nil {
		return AcceptedTarget{}, err
	}
	return accepted, nil
}
