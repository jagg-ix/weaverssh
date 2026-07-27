package pubsub

import (
	"context"
	"errors"
	"testing"
)

func TestAPIEmitsClassifiedComponentEvents(t *testing.T) {
	bus := NewBus()
	api := NewAPI(APIConfig{Prefix: "weaverssh", Publisher: bus})
	ch, cancel, err := bus.Subscribe("weaverssh/#", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	result, err := api.EmitInternal(context.Background(), "runtime", "status", "ready", map[string]string{"plane": "ok"})
	if err != nil {
		t.Fatalf("EmitInternal: %v", err)
	}
	if result.Topic != "weaverssh/runtime/status" {
		t.Fatalf("topic=%q", result.Topic)
	}
	select {
	case msg := <-ch:
		event, err := DecodeEvent(msg.Payload)
		if err != nil {
			t.Fatalf("decode event: %v", err)
		}
		if event.Origin != EventOriginInternal || event.Component != "runtime" || event.Type != "status" {
			t.Fatalf("unexpected event: %+v", event)
		}
	default:
		t.Fatal("expected emitted event")
	}
}

func TestAPIRegistersPluginAndDropsExternalEvent(t *testing.T) {
	api := NewAPI(APIConfig{})
	if err := api.RegisterPlugin(StaticPlugin{
		ManifestData: PluginManifest{ID: "external-policy", Kind: "policy"},
		HookList: []Hook{{
			ID:     "drop-external-status",
			Point:  HookBeforePublish,
			Filter: HookFilter{Origins: []EventOrigin{EventOriginExternal}, Components: []string{"adapter"}},
			Handler: func(context.Context, HookInvocation) (HookDecision, error) {
				return HookDecision{Action: HookDrop, Reason: "external adapter gated"}, nil
			},
		}},
	}); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	_, err := api.EmitExternal(context.Background(), "adapter", "status", "ready", nil)
	if !errors.Is(err, ErrEventDropped) {
		t.Fatalf("EmitExternal error=%v want ErrEventDropped", err)
	}
}

func TestAPIRunForwardDispatchesBeforeAfterAndError(t *testing.T) {
	api := NewAPI(APIConfig{})
	var before, after, onError int
	for _, hook := range []Hook{
		{ID: "before", PluginID: "p", Point: HookBeforeForward, Handler: func(context.Context, HookInvocation) (HookDecision, error) {
			before++
			return HookDecision{Action: HookContinue}, nil
		}},
		{ID: "after", PluginID: "p", Point: HookAfterForward, Handler: func(context.Context, HookInvocation) (HookDecision, error) {
			after++
			return HookDecision{Action: HookContinue}, nil
		}},
		{ID: "error", PluginID: "p", Point: HookOnError, Handler: func(context.Context, HookInvocation) (HookDecision, error) {
			onError++
			return HookDecision{Action: HookContinue}, nil
		}},
	} {
		if err := api.RegisterHook(hook); err != nil {
			t.Fatalf("RegisterHook(%s): %v", hook.ID, err)
		}
	}
	event := NewEvent("route", "pubsub", "forward", nil)
	result, err := api.RunForward(context.Background(), "weaverssh/chains/a/#", event, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("RunForward: %v", err)
	}
	if result.Before.Matched != 1 || result.After.Matched != 1 || before != 1 || after != 1 || onError != 0 {
		t.Fatalf("unexpected success dispatch result=%+v before=%d after=%d error=%d", result, before, after, onError)
	}
	_, err = api.RunForward(context.Background(), "weaverssh/chains/a/#", event, func(context.Context) error { return errors.New("boom") })
	if err == nil || onError != 1 {
		t.Fatalf("expected operation error and on_error hook, err=%v onError=%d", err, onError)
	}
}
