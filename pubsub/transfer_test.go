package pubsub

import (
	"context"
	"errors"
	"testing"
)

func TestFileTransferEventContract(t *testing.T) {
	transfer := FileTransfer{
		Operation:   "cp",
		Direction:   TransferVfsToLocal,
		Source:      "vfs://Documentation/readme.md",
		Destination: "./readme.md",
		SourceView:  "Documentation/readme.md",
		Protocol:    "vfs-9p",
		Bytes:       42,
		Files:       1,
	}
	event := NewFileTransferEvent(FileTransferCompleted, transfer)
	if err := event.Validate(); err != nil {
		t.Fatalf("event validate: %v", err)
	}
	if event.Component != ComponentVFS || event.Type != "file_transfer_completed" {
		t.Fatalf("unexpected event: %+v", event)
	}
	if event.Fields["direction"] != string(TransferVfsToLocal) || event.Fields["bytes"] != "42" || event.Fields["protocol"] != "vfs-9p" {
		t.Fatalf("unexpected fields: %+v", event.Fields)
	}
}

func TestFileTransferHooksCanGateTransfer(t *testing.T) {
	api := NewAPI(APIConfig{})
	if err := api.RegisterHook(Hook{
		ID:       "deny-private-copy",
		PluginID: "policy",
		Point:    HookBeforeFileTransfer,
		Filter:   HookFilter{Components: []string{ComponentVFS}, Types: []string{"file_transfer_started"}},
		Handler: func(ctx context.Context, inv HookInvocation) (HookDecision, error) {
			if inv.Event.Fields["source"] == "vfs://private/secret.txt" {
				return HookDecision{Action: HookDrop, Reason: "private path denied"}, nil
			}
			return HookDecision{Action: HookContinue}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterHook: %v", err)
	}
	transfer := FileTransfer{Operation: "cp", Direction: TransferVfsToLocal, Source: "vfs://private/secret.txt", Destination: "./secret.txt"}
	dispatch, err := api.BeforeFileTransfer(context.Background(), transfer)
	if err != nil {
		t.Fatalf("BeforeFileTransfer: %v", err)
	}
	if !dispatch.Dropped || dispatch.Matched != 1 {
		t.Fatalf("expected dropped dispatch, got %+v", dispatch)
	}
}

func TestEmitFileTransferPublishesAndRunsHooks(t *testing.T) {
	bus := NewBus()
	api := NewAPI(APIConfig{Prefix: "weaverssh", Publisher: bus})
	ch, cancel, err := bus.Subscribe("weaverssh/vfs/#", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	var after int
	if err := api.RegisterHook(Hook{
		ID:       "after-transfer-event",
		PluginID: "audit",
		Point:    HookAfterPublish,
		Filter:   HookFilter{Components: []string{ComponentVFS}, Types: []string{"file_transfer_completed"}},
		Handler: func(context.Context, HookInvocation) (HookDecision, error) {
			after++
			return HookDecision{Action: HookContinue}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterHook: %v", err)
	}
	transfer := FileTransfer{Operation: "cp", Direction: TransferLocalToVfs, Source: "./a.txt", Destination: "vfs://a.txt", Bytes: 3, Files: 1}
	result, err := api.EmitFileTransfer(context.Background(), FileTransferCompleted, transfer)
	if err != nil {
		t.Fatalf("EmitFileTransfer: %v", err)
	}
	if result.Topic != "weaverssh/vfs/file_transfer_completed" || after != 1 {
		t.Fatalf("unexpected result=%+v after=%d", result, after)
	}
	select {
	case msg := <-ch:
		event, err := DecodeEvent(msg.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if event.Fields["destination"] != "vfs://a.txt" {
			t.Fatalf("unexpected event fields: %+v", event.Fields)
		}
	default:
		t.Fatal("expected transfer event")
	}
}

func TestFileTransferValidation(t *testing.T) {
	api := NewAPI(APIConfig{})
	_, err := api.EmitFileTransfer(context.Background(), FileTransferStarted, FileTransfer{Destination: "./x"})
	if err == nil {
		t.Fatal("expected missing source error")
	}
	if errors.Is(err, ErrEventDropped) {
		t.Fatalf("validation error should not be drop: %v", err)
	}
}
