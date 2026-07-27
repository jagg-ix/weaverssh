package sessionroute

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionbroker"
	"weaverssh/sessioncontrol"
	"weaverssh/sessionmux"
)

type Router struct {
	Store          Store
	LeaseStore     *LeaseStore
	Context        authproof.NodeContext
	CurrentBinding string
	CurrentMux     *sessionmux.Mux
	PeerNode       string
}

type Plan struct {
	TargetNode  string
	TargetIndex int
	Direction   string
	NextHop     string
	NextBinding string
	Available   bool
	UsesCurrent bool
}

func NewEntry(ctx authproof.NodeContext, binding, socket, peerNode string, pid int, startedAt time.Time) (Entry, error) {
	ctx = ctx.Normalized()
	if err := ctx.Validate(); err != nil {
		return Entry{}, err
	}
	entry := Entry{Version: RegistryVersion, Binding: strings.TrimSpace(binding), Socket: strings.TrimSpace(socket), LocalNode: ctx.CurrentNode, PeerNode: strings.TrimSpace(peerNode), ChainID: ctx.ChainID, ChainSHA256: ctx.ChainSHA256, Topology: append([]string(nil), ctx.Nodes...), LocalIndex: indexOf(ctx.Nodes, ctx.CurrentNode), PeerIndex: indexOf(ctx.Nodes, strings.TrimSpace(peerNode)), PID: pid, StartedAt: startedAt}
	entry = normalizeEntry(entry)
	if err := validateEntry(entry); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

func (r *Router) Prepare(target string) (Plan, error) {
	if r == nil {
		return Plan{}, errors.New("sessionroute: nil router")
	}
	ctx := r.Context.Normalized()
	currentIndex := indexOf(ctx.Nodes, ctx.CurrentNode)
	targetNode, targetIndex, err := ResolveNode(ctx, target)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{TargetNode: targetNode, TargetIndex: targetIndex}
	if targetIndex == currentIndex {
		plan.Direction = "local"
		plan.NextHop = ctx.CurrentNode
		plan.Available = true
		return plan, nil
	}
	wantedPeerIndex := currentIndex - 1
	plan.Direction = "previous"
	if targetIndex > currentIndex {
		wantedPeerIndex = currentIndex + 1
		plan.Direction = "next"
	}
	if wantedPeerIndex < 0 || wantedPeerIndex >= len(ctx.Nodes) {
		return plan, ErrNoRoute
	}
	plan.NextHop = ctx.Nodes[wantedPeerIndex]
	if strings.TrimSpace(r.PeerNode) == plan.NextHop && r.CurrentMux != nil {
		plan.NextBinding = strings.TrimSpace(r.CurrentBinding)
		plan.Available = true
		plan.UsesCurrent = true
		return plan, nil
	}
	candidate, _, _, resolveErr := r.resolveAdjacent(r.CurrentBinding, ctx, targetNode)
	if resolveErr != nil {
		if errors.Is(resolveErr, ErrNoRoute) {
			return plan, nil
		}
		return plan, resolveErr
	}
	plan.NextHop = candidate.entry.PeerNode
	plan.NextBinding = candidate.entry.Binding
	plan.Available = true
	return plan, nil
}

func (r *Router) OpenLocal(ctx context.Context, target string, service sessionmux.ServiceID, data []byte) (io.ReadWriteCloser, error) {
	if !routableService(service) {
		return nil, fmt.Errorf("sessionroute: service %s is not routable", service)
	}
	plan, err := r.Prepare(target)
	if err != nil {
		return nil, err
	}
	if plan.Direction == "local" {
		return nil, ErrTargetLocal
	}
	if !plan.Available {
		return nil, fmt.Errorf("%w: target=%s next=%s", ErrNoRoute, plan.TargetNode, plan.NextHop)
	}
	if plan.UsesCurrent {
		return sessioncontrol.OpenTarget(ctx, r.CurrentMux, plan.TargetNode, service, data)
	}
	conn, _, err := r.dialRegistered(ctx, plan.TargetNode, service, data)
	return conn, err
}

func (r *Router) OpenForward(ctx context.Context, pending sessioncontrol.PendingTarget) (io.ReadWriteCloser, Plan, error) {
	if r == nil {
		return nil, Plan{}, errors.New("sessionroute: nil router")
	}
	if !routableService(pending.Service) {
		return nil, Plan{}, fmt.Errorf("sessionroute: service %s is not routable", pending.Service)
	}
	normalized := r.Context.Normalized()
	currentIndex := indexOf(normalized.Nodes, normalized.CurrentNode)
	peerIndex := indexOf(normalized.Nodes, strings.TrimSpace(r.PeerNode))
	targetNode, targetIndex, err := ResolveNode(normalized, pending.NodeRef)
	if err != nil {
		return nil, Plan{}, err
	}
	if targetIndex == currentIndex {
		return nil, Plan{}, ErrTargetLocal
	}
	if peerIndex < 0 || (targetIndex-currentIndex)*(peerIndex-currentIndex) > 0 {
		return nil, Plan{}, fmt.Errorf("%w: target %s is on source-peer side %s", ErrNoRoute, targetNode, r.PeerNode)
	}
	conn, candidate, err := r.dialRegistered(ctx, targetNode, pending.Service, pending.Data)
	direction := "previous"
	if targetIndex > currentIndex {
		direction = "next"
	}
	plan := Plan{TargetNode: targetNode, TargetIndex: targetIndex, Direction: direction, NextHop: candidate.entry.PeerNode, NextBinding: candidate.entry.Binding, Available: err == nil}
	if err != nil {
		return nil, plan, err
	}
	return conn, plan, nil
}

type adjacentCandidate struct {
	entry Entry
	lease *LeaseEntry
}

func (r *Router) resolveAdjacent(currentBinding string, nodeContext authproof.NodeContext, target string) (adjacentCandidate, string, int, error) {
	if r.LeaseStore != nil {
		leased, targetNode, targetIndex, err := r.LeaseStore.ResolveAdjacent(currentBinding, nodeContext, target)
		if err == nil {
			return adjacentCandidate{entry: leased.LegacyEntry(), lease: &leased}, targetNode, targetIndex, nil
		}
		if !errors.Is(err, ErrNoRoute) {
			return adjacentCandidate{}, targetNode, targetIndex, err
		}
	}
	entry, targetNode, targetIndex, err := r.Store.ResolveAdjacent(currentBinding, nodeContext, target)
	if err != nil {
		return adjacentCandidate{}, targetNode, targetIndex, err
	}
	return adjacentCandidate{entry: entry}, targetNode, targetIndex, nil
}
func (r *Router) dialRegistered(ctx context.Context, target string, service sessionmux.ServiceID, data []byte) (io.ReadWriteCloser, adjacentCandidate, error) {
	var lastErr error
	seen := make(map[string]struct{})
	for attempts := 0; attempts < 16; attempts++ {
		candidate, _, _, err := r.resolveAdjacent(r.CurrentBinding, r.Context, target)
		if err != nil {
			if lastErr != nil {
				return nil, adjacentCandidate{}, fmt.Errorf("%w: last broker error: %v", err, lastErr)
			}
			return nil, adjacentCandidate{}, err
		}
		key := candidate.entry.Binding
		if candidate.lease != nil {
			key = fmt.Sprintf("%s/%d", candidate.lease.LinkID, candidate.lease.Generation)
		}
		if _, repeated := seen[key]; repeated {
			return nil, adjacentCandidate{}, fmt.Errorf("%w: no additional live broker for target %s: %v", ErrNoRoute, target, lastErr)
		}
		seen[key] = struct{}{}
		conn, dialErr := sessionbroker.Dial(ctx, "unix", candidate.entry.Socket, sessionbroker.OpenRequest{Node: target, Service: service, Data: append([]byte(nil), data...)})
		if dialErr == nil {
			return conn, candidate, nil
		}
		if !brokerUnavailable(dialErr) {
			return nil, candidate, dialErr
		}
		lastErr = dialErr
		if candidate.lease != nil && r.LeaseStore != nil {
			_ = r.LeaseStore.Remove(context.Background(), candidate.lease.Token())
		} else {
			_ = r.Store.Remove(context.Background(), candidate.entry.Binding)
		}
	}
	return nil, adjacentCandidate{}, fmt.Errorf("%w: exhausted adjacent brokers for target %s: %v", ErrNoRoute, target, lastErr)
}
func brokerUnavailable(err error) bool {
	var operation *net.OpError
	return errors.As(err, &operation) && operation.Op == "dial"
}
func (r *Router) Forward(ctx context.Context, pending sessioncontrol.PendingTarget) error {
	downstream, _, err := r.OpenForward(ctx, pending)
	if err != nil {
		_ = pending.Stream.Reset()
		return err
	}
	defer downstream.Close()
	if err := sessioncontrol.AcknowledgePendingTarget(ctx, pending); err != nil {
		return err
	}
	return Bridge(ctx, pending.Stream, downstream)
}
func Bridge(ctx context.Context, left io.ReadWriteCloser, right io.ReadWriteCloser) error {
	if left == nil || right == nil {
		return errors.New("sessionroute: incomplete bridge")
	}
	type result struct{ err error }
	results := make(chan result, 2)
	copyOne := func(dst io.Writer, src io.Reader, closeWrite func() error) {
		_, err := io.Copy(dst, src)
		if closeWrite != nil {
			_ = closeWrite()
		}
		results <- result{err: err}
	}
	go copyOne(right, left, closeWriteFunc(right))
	go copyOne(left, right, closeWriteFunc(left))
	var terminal error
	for count := 0; count < 2; count++ {
		select {
		case item := <-results:
			if !normalRelayError(item.err) && terminal == nil {
				terminal = item.err
				_ = left.Close()
				_ = right.Close()
			}
		case <-ctx.Done():
			_ = left.Close()
			_ = right.Close()
			return ctx.Err()
		}
	}
	return terminal
}
func closeWriteFunc(value any) func() error {
	if closer, ok := value.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite
	}
	if stream, ok := value.(*sessionmux.Stream); ok {
		return stream.Close
	}
	return nil
}
func normalRelayError(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed)
}
func routableService(service sessionmux.ServiceID) bool {
	return service == sessionmux.ServiceFS || service == sessionmux.ServiceTCP || service == sessionmux.ServiceUDP || service == sessionmux.ServiceExec || service == sessionmux.ServiceEvents
}
