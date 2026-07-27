package sessionevents

import (
	"context"
	"errors"
	"sync"
)

// RuntimeAuthorizer is an optional second policy layer evaluated after the
// native final-node event policy and before publish or subscription side effects.
type RuntimeAuthorizer interface {
	AuthorizeEvent(context.Context, OpenMetadata, Request) error
}

var runtimeAuthorizers sync.Map

func SetRuntimeAuthorizer(engine *Engine, authorizer RuntimeAuthorizer) error {
	if engine == nil {
		return errors.New("sessionevents: engine is required")
	}
	if authorizer == nil {
		runtimeAuthorizers.Delete(engine)
		return nil
	}
	runtimeAuthorizers.Store(engine, authorizer)
	return nil
}

func clearRuntimeAuthorizer(engine *Engine) {
	if engine != nil {
		runtimeAuthorizers.Delete(engine)
	}
}

func (engine *Engine) authorizeRuntime(ctx context.Context, metadata OpenMetadata, request Request) error {
	if engine == nil {
		return ErrDenied
	}
	value, ok := runtimeAuthorizers.Load(engine)
	if !ok {
		return nil
	}
	return value.(RuntimeAuthorizer).AuthorizeEvent(ctx, metadata, request)
}
