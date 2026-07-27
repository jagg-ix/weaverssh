package sessionbroker

import (
	"context"
	"errors"
	"io"
	"time"

	"weaverssh/sessionlink"
)

// LinkRouter keeps one stable local broker endpoint while the authenticated
// SSH/X11/WebSocket transport for an adjacency is replaced. It remains separate
// from Router until host and attach lifecycles are migrated to logical links.
type LinkRouter struct {
	descriptor sessionlink.Descriptor
	linkID     sessionlink.ID
	manager    *sessionlink.Manager[OpenFunc]
}

func NewLinkRouter(descriptor sessionlink.Descriptor) (*LinkRouter, error) {
	descriptor.Topology = append([]string(nil), descriptor.Topology...)
	id, err := sessionlink.DeriveID(descriptor)
	if err != nil {
		return nil, err
	}
	return &LinkRouter{
		descriptor: descriptor,
		linkID:     id,
		manager:    sessionlink.NewManager[OpenFunc](),
	}, nil
}

func (r *LinkRouter) LinkID() sessionlink.ID {
	if r == nil {
		return ""
	}
	return r.linkID
}

func (r *LinkRouter) Publish(
	transportID sessionlink.TransportID,
	lease time.Duration,
	open OpenFunc,
) (sessionlink.Token, sessionlink.Snapshot, func(), error) {
	if r == nil || open == nil {
		return sessionlink.Token{}, sessionlink.Snapshot{}, nil, errors.New("sessionbroker: incomplete logical link publication")
	}
	return r.manager.Publish(r.descriptor, transportID, lease, open)
}

func (r *LinkRouter) Renew(token sessionlink.Token, lease time.Duration) (sessionlink.Snapshot, error) {
	if r == nil {
		return sessionlink.Snapshot{}, sessionlink.ErrGenerationMismatch
	}
	return r.manager.Renew(token, lease)
}

func (r *LinkRouter) Drain(token sessionlink.Token) (sessionlink.Snapshot, error) {
	if r == nil {
		return sessionlink.Snapshot{}, sessionlink.ErrGenerationMismatch
	}
	return r.manager.Drain(token)
}

func (r *LinkRouter) Withdraw(token sessionlink.Token, cause error) bool {
	return r != nil && r.manager.Withdraw(token, cause)
}

func (r *LinkRouter) Open(ctx context.Context, request OpenRequest) (io.ReadWriteCloser, error) {
	if r == nil {
		return nil, ErrNoActiveSession
	}
	open, _, err := r.manager.Wait(ctx, r.linkID)
	if err != nil {
		return nil, err
	}
	return open(ctx, request)
}

func (r *LinkRouter) TryOpen(ctx context.Context, request OpenRequest) (io.ReadWriteCloser, error) {
	if r == nil {
		return nil, ErrNoActiveSession
	}
	open, _, ok := r.manager.Current(r.linkID)
	if !ok {
		return nil, ErrNoActiveSession
	}
	return open(ctx, request)
}

func (r *LinkRouter) Snapshot() (sessionlink.Snapshot, bool) {
	if r == nil {
		return sessionlink.Snapshot{}, false
	}
	return r.manager.Snapshot(r.linkID)
}
