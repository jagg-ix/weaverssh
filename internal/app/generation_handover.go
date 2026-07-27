package app

import "sync"

// generationHandover serializes publication of replaceable resources. The
// caller's apply function must publish all externally visible metadata before
// the candidate becomes active.
type generationHandover[T comparable] struct {
	mu     sync.Mutex
	active T
}

func (h *generationHandover[T]) Commit(candidate T, apply func() error) (T, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var zero T
	if apply != nil {
		if err := apply(); err != nil {
			return zero, err
		}
	}
	previous := h.active
	h.active = candidate
	return previous, nil
}

// Clear removes candidate only when it is still the active generation.
func (h *generationHandover[T]) Clear(candidate T) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active != candidate {
		return false
	}
	var zero T
	h.active = zero
	return true
}

func (h *generationHandover[T]) Current() T {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.active
}
