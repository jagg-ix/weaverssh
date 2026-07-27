package pubsub

import (
	"context"
	"fmt"
	"strings"
)

// API is the component-facing host for weaverssh events, plugins, and hooks.
// Components embed one API instance and use it to emit classified events or run
// hook points around publish, forward, delivery, and error paths.
type API struct {
	prefix    string
	publisher EventPublisher
	hooks     *HookRegistry
}

type APIConfig struct {
	Prefix    string
	Publisher EventPublisher
	Hooks     *HookRegistry
}

type HookedOperationResult struct {
	Topic   string       `json:"topic"`
	Dropped bool         `json:"dropped"`
	Before  HookDispatch `json:"before,omitempty"`
	After   HookDispatch `json:"after,omitempty"`
	Error   HookDispatch `json:"error,omitempty"`
}

type HookedOperation func(context.Context) error

func NewAPI(cfg APIConfig) *API {
	prefix := strings.TrimSpace(cfg.Prefix)
	if prefix == "" {
		prefix = DefaultPrefix
	}
	publisher := cfg.Publisher
	if publisher == nil {
		publisher = NewBus()
	}
	hooks := cfg.Hooks
	if hooks == nil {
		hooks = NewHookRegistry()
	}
	return &API{prefix: prefix, publisher: publisher, hooks: hooks}
}

func (a *API) Prefix() string {
	if a == nil || strings.TrimSpace(a.prefix) == "" {
		return DefaultPrefix
	}
	return a.prefix
}

func (a *API) Registry() *HookRegistry {
	if a == nil || a.hooks == nil {
		return NewHookRegistry()
	}
	return a.hooks
}

func (a *API) Publisher() EventPublisher {
	if a == nil || a.publisher == nil {
		return NewBus()
	}
	return a.publisher
}

func (a *API) RegisterPlugin(plugin Plugin) error {
	return a.Registry().RegisterPlugin(plugin)
}

func (a *API) RegisterHook(hook Hook) error {
	return a.Registry().RegisterHook(hook)
}

func (a *API) TopicFor(event Event) (string, error) {
	event = event.Normalized()
	return EventTopic(a.Prefix(), event.Component, event.Type)
}

func (a *API) EmitEvent(ctx context.Context, event Event) (HookedEmitResult, error) {
	return HookedEmitter{Prefix: a.Prefix(), Publisher: a.Publisher(), Hooks: a.Registry()}.Emit(ctx, event)
}

func (a *API) EmitInternal(ctx context.Context, component, eventType, message string, fields map[string]string) (HookedEmitResult, error) {
	return a.EmitEvent(ctx, NewEventFrom(EventOriginInternal, eventType, component, message, fields))
}

func (a *API) EmitExternal(ctx context.Context, component, eventType, message string, fields map[string]string) (HookedEmitResult, error) {
	return a.EmitEvent(ctx, NewEventFrom(EventOriginExternal, eventType, component, message, fields))
}

func (a *API) EmitPubSub(ctx context.Context, component, eventType, message string, fields map[string]string) (HookedEmitResult, error) {
	return a.EmitEvent(ctx, NewEventFrom(EventOriginPubSub, eventType, component, message, fields))
}

func (a *API) Dispatch(ctx context.Context, point HookPoint, topic string, event Event) (HookDispatch, error) {
	return a.Registry().Dispatch(ctx, point, topic, event)
}

func (a *API) RunForward(ctx context.Context, topic string, event Event, forward HookedOperation) (HookedOperationResult, error) {
	return a.runHookedOperation(ctx, HookBeforeForward, HookAfterForward, topic, event, forward)
}

func (a *API) ObserveDelivery(ctx context.Context, topic string, event Event) (HookDispatch, error) {
	return a.Dispatch(ctx, HookOnDelivery, topic, event)
}

func (a *API) ObserveError(ctx context.Context, topic string, event Event, cause error) (HookDispatch, error) {
	event = event.Normalized()
	fields := copyFields(event.Fields)
	if fields == nil {
		fields = map[string]string{}
	}
	if cause != nil {
		fields["error"] = cause.Error()
	}
	event.Fields = fields
	return a.Dispatch(ctx, HookOnError, topic, event)
}

func (a *API) runHookedOperation(ctx context.Context, beforePoint HookPoint, afterPoint HookPoint, topic string, event Event, operation HookedOperation) (HookedOperationResult, error) {
	if operation == nil {
		return HookedOperationResult{}, fmt.Errorf("hooked operation is required")
	}
	event = event.Normalized()
	result := HookedOperationResult{Topic: topic}
	before, err := a.Dispatch(ctx, beforePoint, topic, event)
	result.Before = before
	if err != nil {
		return result, err
	}
	if before.Dropped {
		result.Dropped = true
		return result, ErrEventDropped
	}
	if err := operation(ctx); err != nil {
		errDispatch, hookErr := a.ObserveError(ctx, topic, event, err)
		result.Error = errDispatch
		if hookErr != nil {
			return result, hookErr
		}
		return result, err
	}
	after, err := a.Dispatch(ctx, afterPoint, topic, event)
	result.After = after
	if err != nil {
		return result, err
	}
	return result, nil
}
