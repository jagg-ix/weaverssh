package pubsub

import (
	"context"
	"errors"
	"testing"
)

func TestEventOriginsAreClassified(t *testing.T) {
	internal := NewEvent("status", "runtime", "ready", nil)
	if internal.Origin != EventOriginInternal {
		t.Fatalf("NewEvent origin=%q want internal", internal.Origin)
	}
	external := NewEventFrom(EventOriginExternal, "status", "adapter", "tool ready", nil)
	if err := external.Validate(); err != nil {
		t.Fatalf("external event validate: %v", err)
	}
	if external.Origin != EventOriginExternal {
		t.Fatalf("external origin=%q", external.Origin)
	}
	pubsubEvent := NewEventFrom(EventOriginPubSub, "delivery", "pubsub", "delivered", nil)
	if err := pubsubEvent.Validate(); err != nil {
		t.Fatalf("pubsub event validate: %v", err)
	}
	bad := pubsubEvent
	bad.Origin = EventOrigin("kernel")
	if err := bad.Validate(); err == nil {
		t.Fatal("invalid origin should fail validation")
	}
}

func TestHookRegistryDispatchFiltersByOriginAndTopic(t *testing.T) {
	registry := NewHookRegistry()
	var called int
	err := registry.RegisterPlugin(StaticPlugin{
		ManifestData: PluginManifest{ID: "audit", Kind: "internal"},
		HookList: []Hook{{
			ID:     "observe-runtime-status",
			Point:  HookBeforePublish,
			Filter: HookFilter{Origins: []EventOrigin{EventOriginInternal}, Components: []string{"runtime"}, Types: []string{"status"}, TopicFilter: "weaverssh/runtime/#"},
			Handler: func(context.Context, HookInvocation) (HookDecision, error) {
				called++
				return HookDecision{Action: HookContinue, Reason: "recorded"}, nil
			},
		}},
	})
	if err != nil {
		t.Fatalf("register plugin: %v", err)
	}
	event := NewEvent("status", "runtime", "ready", nil)
	dispatch, err := registry.Dispatch(context.Background(), HookBeforePublish, "weaverssh/runtime/status", event)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if called != 1 || dispatch.Matched != 1 || dispatch.Dropped {
		t.Fatalf("unexpected dispatch: called=%d dispatch=%+v", called, dispatch)
	}
	external := NewEventFrom(EventOriginExternal, "status", "runtime", "ready", nil)
	dispatch, err = registry.Dispatch(context.Background(), HookBeforePublish, "weaverssh/runtime/status", external)
	if err != nil {
		t.Fatalf("external dispatch: %v", err)
	}
	if dispatch.Matched != 0 || called != 1 {
		t.Fatalf("external event should not match internal-only hook: called=%d dispatch=%+v", called, dispatch)
	}
}

func TestHookedEmitterCanDropBeforePublish(t *testing.T) {
	registry := NewHookRegistry()
	if err := registry.RegisterHook(Hook{
		ID:       "drop-external-faults",
		PluginID: "policy",
		Point:    HookBeforePublish,
		Filter:   HookFilter{Origins: []EventOrigin{EventOriginExternal}, Types: []string{"fault"}},
		Handler: func(context.Context, HookInvocation) (HookDecision, error) {
			return HookDecision{Action: HookDrop, Reason: "external fault suppressed"}, nil
		},
	}); err != nil {
		t.Fatalf("register hook: %v", err)
	}
	bus := NewBus()
	emitter := HookedEmitter{Prefix: "weaverssh", Publisher: bus, Hooks: registry}
	_, err := emitter.Emit(context.Background(), NewEventFrom(EventOriginExternal, "fault", "adapter", "bad", nil))
	if !errors.Is(err, ErrEventDropped) {
		t.Fatalf("Emit error=%v want ErrEventDropped", err)
	}
}

func TestHookedEmitterPublishesAndRunsAfterHook(t *testing.T) {
	registry := NewHookRegistry()
	var after int
	if err := registry.RegisterHook(Hook{
		ID:       "after-publish",
		PluginID: "audit",
		Point:    HookAfterPublish,
		Filter:   HookFilter{TopicFilter: "weaverssh/runtime/status"},
		Handler: func(context.Context, HookInvocation) (HookDecision, error) {
			after++
			return HookDecision{Action: HookContinue}, nil
		},
	}); err != nil {
		t.Fatalf("register hook: %v", err)
	}
	bus := NewBus()
	ch, cancel, err := bus.Subscribe("weaverssh/#", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	emitter := HookedEmitter{Prefix: "weaverssh", Publisher: bus, Hooks: registry}
	result, err := emitter.Emit(context.Background(), NewEvent("status", "runtime", "ready", nil))
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if result.Topic != "weaverssh/runtime/status" || result.After.Matched != 1 || after != 1 {
		t.Fatalf("unexpected emit result=%+v after=%d", result, after)
	}
	select {
	case msg := <-ch:
		if msg.Topic != "weaverssh/runtime/status" {
			t.Fatalf("unexpected topic %q", msg.Topic)
		}
	default:
		t.Fatal("expected bus message")
	}
}
