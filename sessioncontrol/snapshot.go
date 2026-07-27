package sessioncontrol

import "sort"

// Registered returns authenticated nodes currently registered on this direct
// session, ordered by their signed topology index.
func (r *Registry) Registered() []Node {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Node, 0, len(r.nodes))
	for _, node := range r.nodes {
		out = append(out, cloneNode(node))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// Lookup returns one authenticated concrete node without applying relative
// aliases.
func (r *Registry) Lookup(nodeID string) (Node, bool) {
	if r == nil {
		return Node{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	node, ok := r.nodes[nodeID]
	if !ok {
		return Node{}, false
	}
	return cloneNode(node), true
}
