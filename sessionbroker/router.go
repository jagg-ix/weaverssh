package sessionbroker

import (
	"context"
	"errors"
	"io"
	"sync"
)

var ErrNoActiveSession = errors.New("sessionbroker: no active dynamic session")

// Router lets a long-lived local broker follow the currently authenticated
// dynamic session without reopening or changing any SSH transport listener.
type Router struct {
	mu      sync.RWMutex
	open    OpenFunc
	binding string
}

// Set installs the current session opener and returns a function that clears it
// only if the same binding is still active.
func (r *Router) Set(binding string, open OpenFunc) func() {
	r.mu.Lock()
	r.binding = binding
	r.open = open
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		if r.binding == binding {
			r.binding = ""
			r.open = nil
		}
		r.mu.Unlock()
	}
}

// Open dispatches through the current session.
func (r *Router) Open(ctx context.Context, request OpenRequest) (io.ReadWriteCloser, error) {
	r.mu.RLock()
	open := r.open
	r.mu.RUnlock()
	if open == nil {
		return nil, ErrNoActiveSession
	}
	return open(ctx, request)
}

// Binding returns the active session binding, if any.
func (r *Router) Binding() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.binding
}
