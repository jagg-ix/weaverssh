package pubsub

import (
	"context"
	"errors"
	"testing"
)

func TestFileEventContract(t *testing.T) {
	event := NewFileEvent(FileRead, FileEvent{Path: "vfs://docs/readme.md", ViewPath: "docs/readme.md", Protocol: "vfs-9p", Bytes: 42})
	if err := event.Validate(); err != nil {
		t.Fatalf("event validate: %v", err)
	}
	if event.Component != ComponentInfrastructure || event.Type != string(FileRead) {
		t.Fatalf("unexpected event: %+v", event)
	}
	checks := map[string]string{
		"kind":      FileOperationKind,
		"operation": string(FileRead),
		"path":      "vfs://docs/readme.md",
		"view_path": "docs/readme.md",
		"protocol":  "vfs-9p",
		"bytes":     "42",
		"is_dir":    "false",
	}
	for key, want := range checks {
		if got := event.Fields[key]; got != want {
			t.Fatalf("field %s=%q want %q fields=%+v", key, got, want, event.Fields)
		}
	}
}

func TestFileOperationHooksCanGateOperations(t *testing.T) {
	api := NewAPI(APIConfig{})
	if err := api.RegisterHook(Hook{
		ID:       "deny-remove",
		PluginID: "policy",
		Point:    HookBeforeFileOperation,
		Filter:   HookFilter{Components: []string{ComponentInfrastructure}, Types: []string{string(FileRemoved)}},
		Handler: func(context.Context, HookInvocation) (HookDecision, error) {
			return HookDecision{Action: HookDrop, Reason: "remove disabled"}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterHook: %v", err)
	}
	dispatch, err := api.BeforeFileOperation(context.Background(), FileRemoved, FileEvent{Path: "/srv/a.txt"})
	if err != nil {
		t.Fatalf("BeforeFileOperation: %v", err)
	}
	if !dispatch.Dropped || dispatch.Matched != 1 || dispatch.Results[0].Reason != "remove disabled" {
		t.Fatalf("unexpected dispatch: %+v", dispatch)
	}
}

func TestEmitFileEventPublishesAndRunsHooks(t *testing.T) {
	bus := NewBus()
	api := NewAPI(APIConfig{Prefix: "weaverssh", Publisher: bus})
	ch, cancel, err := bus.Subscribe("weaverssh/infrastructure/#", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	var after int
	if err := api.RegisterHook(Hook{
		ID:       "after-file-read",
		PluginID: "audit",
		Point:    HookAfterPublish,
		Filter:   HookFilter{Components: []string{ComponentInfrastructure}, Types: []string{string(FileRead)}},
		Handler: func(context.Context, HookInvocation) (HookDecision, error) {
			after++
			return HookDecision{Action: HookContinue}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterHook: %v", err)
	}
	result, err := api.EmitFileEvent(context.Background(), FileRead, FileEvent{Path: "/srv/a.txt", Bytes: 3})
	if err != nil {
		t.Fatalf("EmitFileEvent: %v", err)
	}
	if result.Topic != "weaverssh/infrastructure/file_read" || after != 1 {
		t.Fatalf("unexpected result=%+v after=%d", result, after)
	}
	select {
	case msg := <-ch:
		event, err := DecodeEvent(msg.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if event.Fields["path"] != "/srv/a.txt" || event.Fields["operation"] != string(FileRead) {
			t.Fatalf("unexpected event fields: %+v", event.Fields)
		}
	default:
		t.Fatal("expected file event")
	}
}

func TestRunFileOperationReturnsDropError(t *testing.T) {
	api := NewAPI(APIConfig{})
	if err := api.RegisterHook(Hook{
		ID:       "drop-open",
		PluginID: "policy",
		Point:    HookBeforeFileOperation,
		Filter:   HookFilter{Types: []string{string(FileOpened)}},
		Handler: func(context.Context, HookInvocation) (HookDecision, error) {
			return HookDecision{Action: HookDrop}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterHook: %v", err)
	}
	_, err := api.RunFileOperation(context.Background(), FileOpened, FileEvent{Path: "/srv/a.txt"}, func(context.Context) error { return nil })
	if !errors.Is(err, ErrEventDropped) {
		t.Fatalf("RunFileOperation error=%v want ErrEventDropped", err)
	}
}
