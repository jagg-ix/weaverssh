// Package sessiondispatch owns the sole post-registration Mux.Accept loop.
package sessiondispatch

import (
	"context"
	"errors"
	"sync"

	"weaverssh/sessionmux"
)

// Handler processes one already accepted stream and owns its close/reset state.
type Handler func(context.Context, *sessionmux.Stream) error

// Dispatcher routes control streams separately from target-service streams.
type Dispatcher struct {
	Mux     *sessionmux.Mux
	Control Handler
	Target  Handler
}

// Serve accepts streams until the context or mux closes. Handlers own stream
// teardown; the dispatcher never resets a handled stream after return.
func (d *Dispatcher) Serve(ctx context.Context) error {
	if d == nil || d.Mux == nil {
		return errors.New("sessiondispatch: nil mux")
	}
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		stream, err := d.Mux.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, sessionmux.ErrMuxClosed) {
				return nil
			}
			return err
		}
		handler := d.Target
		if stream.Service() == sessionmux.ServiceControl {
			handler = d.Control
		}
		if handler == nil {
			_ = stream.Reset()
			continue
		}
		workers.Add(1)
		go func(accepted *sessionmux.Stream, serve Handler) {
			defer workers.Done()
			_ = serve(ctx, accepted)
		}(stream, handler)
	}
}
