// Package sessioncontrol registers authenticated nodes and resolves session
// topology for logical service streams.
package sessioncontrol

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionmux"
)

var (
	ErrChainMismatch      = errors.New("sessioncontrol: node context belongs to a different chain")
	ErrUnknownNode        = errors.New("sessioncontrol: node is not registered")
	ErrServiceUnavailable = errors.New("sessioncontrol: service is not advertised by node")
	ErrStaleRegistration  = errors.New("sessioncontrol: registration is older than active node context")
)

type Node struct {
	ID       string
	Index    int
	Context  authproof.NodeContext
	services map[sessionmux.ServiceID]struct{}
}

func (n Node) Supports(service sessionmux.ServiceID) bool { _, ok := n.services[service]; return ok }
func (n Node) Services() []sessionmux.ServiceID {
	out := make([]sessionmux.ServiceID, 0, len(n.services))
	for service := range n.services {
		out = append(out, service)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

type Registry struct {
	mu          sync.RWMutex
	chainID     string
	chainSHA256 string
	order       []string
	nodes       map[string]Node
}

func NewRegistry() *Registry { return &Registry{nodes: make(map[string]Node)} }
func (r *Registry) RegisterVerified(ctx authproof.NodeContext, services []sessionmux.ServiceID) (Node, error) {
	ctx = ctx.Normalized()
	if err := ctx.Validate(); err != nil {
		return Node{}, err
	}
	if time.Now().Unix() >= ctx.ExpiresAtUnix {
		return Node{}, authproof.ErrExpiredGrant
	}
	normalizedServices, err := normalizeServices(ctx, services)
	if err != nil {
		return Node{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.nodes == nil {
		r.nodes = make(map[string]Node)
	}
	if r.chainID == "" {
		r.chainID = ctx.ChainID
		r.chainSHA256 = ctx.ChainSHA256
		r.order = append([]string(nil), ctx.Nodes...)
	} else if r.chainID != ctx.ChainID || r.chainSHA256 != ctx.ChainSHA256 || !sameStrings(r.order, ctx.Nodes) {
		return Node{}, ErrChainMismatch
	}
	index := indexOf(r.order, ctx.CurrentNode)
	if index < 0 {
		return Node{}, fmt.Errorf("%w: %s", ErrUnknownNode, ctx.CurrentNode)
	}
	if existing, ok := r.nodes[ctx.CurrentNode]; ok && existing.Context.IssuedAtUnix > ctx.IssuedAtUnix {
		return Node{}, ErrStaleRegistration
	}
	node := Node{ID: ctx.CurrentNode, Index: index, Context: ctx, services: normalizedServices}
	r.nodes[node.ID] = node
	return cloneNode(node), nil
}
func (r *Registry) Resolve(ref, currentNode string) (Node, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	name := strings.TrimSpace(ref)
	currentNode = strings.TrimSpace(currentNode)
	switch strings.ToLower(name) {
	case "endpoint", "target", "remote", "last":
		if len(r.order) > 0 {
			name = r.order[len(r.order)-1]
		}
	case "self", "local", "here", "this", "current", ".":
		name = currentNode
	case "previous", "prev":
		index := indexOf(r.order, currentNode)
		if index <= 0 {
			return Node{}, fmt.Errorf("%w: no previous node from %q", ErrUnknownNode, currentNode)
		}
		name = r.order[index-1]
	case "next":
		index := indexOf(r.order, currentNode)
		if index < 0 || index+1 >= len(r.order) {
			return Node{}, fmt.Errorf("%w: no next node from %q", ErrUnknownNode, currentNode)
		}
		name = r.order[index+1]
	}
	if name == "" {
		return Node{}, fmt.Errorf("%w: empty node reference", ErrUnknownNode)
	}
	node, ok := r.nodes[name]
	if !ok {
		return Node{}, fmt.Errorf("%w: %s", ErrUnknownNode, name)
	}
	return cloneNode(node), nil
}
func (r *Registry) Authorize(nodeRef, currentNode string, service sessionmux.ServiceID) (Node, error) {
	node, err := r.Resolve(nodeRef, currentNode)
	if err != nil {
		return Node{}, err
	}
	if !node.Supports(service) {
		return Node{}, fmt.Errorf("%w: node=%s service=%v", ErrServiceUnavailable, node.ID, service)
	}
	return node, nil
}
func (r *Registry) Topology() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]string(nil), r.order...)
}

func normalizeServices(ctx authproof.NodeContext, services []sessionmux.ServiceID) (map[sessionmux.ServiceID]struct{}, error) {
	out := make(map[sessionmux.ServiceID]struct{})
	requested := append([]sessionmux.ServiceID{sessionmux.ServiceControl}, services...)
	for _, service := range requested {
		if !service.Valid() {
			return nil, fmt.Errorf("sessioncontrol: invalid service %d", service)
		}
		if !serviceAuthorizedByCapabilities(ctx.Capabilities, service) {
			return nil, fmt.Errorf("%w: node=%s service=%v lacks signed capability", authproof.ErrMissingCapability, ctx.CurrentNode, service)
		}
		out[service] = struct{}{}
	}
	return out, nil
}

// ServiceExec and ServiceEvents are programmable routed services. They share the
// existing compute.mapreduce signed capability for backward-compatible node
// contexts, but remain independently default-deny at their final-node policy.
func serviceAuthorizedByCapabilities(capabilities []string, service sessionmux.ServiceID) bool {
	switch service {
	case sessionmux.ServiceControl:
		return containsCapability(capabilities, authproof.CapabilityNodeContext)
	case sessionmux.ServiceFS:
		return containsCapability(capabilities, authproof.CapabilityVFSMesh) || containsCapability(capabilities, authproof.CapabilityFileBackhaul)
	case sessionmux.ServiceTCP, sessionmux.ServiceUDP:
		return containsCapability(capabilities, authproof.CapabilitySocksProxy)
	case sessionmux.ServiceExec, sessionmux.ServiceEvents:
		return containsCapability(capabilities, authproof.CapabilityMapReduce)
	default:
		return false
	}
}
func containsCapability(capabilities []string, want string) bool {
	for _, capability := range capabilities {
		if strings.TrimSpace(capability) == want {
			return true
		}
	}
	return false
}
func cloneNode(node Node) Node {
	copyNode := node
	copyNode.Context = node.Context.Normalized()
	copyNode.services = make(map[sessionmux.ServiceID]struct{}, len(node.services))
	for service := range node.services {
		copyNode.services[service] = struct{}{}
	}
	return copyNode
}
func indexOf(values []string, want string) int {
	for index, value := range values {
		if value == want {
			return index
		}
	}
	return -1
}
func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
