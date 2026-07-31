package grpcbuffer

import (
	"context"
	"testing"
	"time"

	"weaverssh/flowcontrol"
)

func TestRuntimeTracksCoordinatorAndRecycles(t *testing.T) {
	coordinator := flowcontrol.NewDefaultBufferCoordinator()
	recycled := make(chan [2]Options, 1)
	runtime, err := New(coordinator, func(previous, current Options) { recycled <- [2]Options{previous, current} })
	if err != nil { t.Fatal(err) }
	defer runtime.Close()
	initial := runtime.Current()
	if initial.Generation != 1 { t.Fatalf("generation=%d", initial.Generation) }
	if initial.ReadBufferBytes != initial.WriteBufferBytes || initial.InitialWindowBytes != initial.InitialConnWindowBytes {
		t.Fatalf("unaligned initial options: %+v", initial)
	}
	next, err := coordinator.Update(flowcontrol.ProtocolBuffersFromFrame(64*1024, 4))
	if err != nil { t.Fatal(err) }
	select {
	case pair := <-recycled:
		if pair[0].Generation != initial.Generation || pair[1].Generation != next.Generation { t.Fatalf("unexpected recycle: %+v", pair) }
	case <-time.After(time.Second):
		t.Fatal("missing recycle callback")
	}
	if !runtime.IsStale(initial.Generation) { t.Fatal("old gRPC generation should be stale") }
	if runtime.IsStale(next.Generation) { t.Fatal("current gRPC generation should not be stale") }
}

func TestUpdateServiceAppliesExactEnvelopeAndReturnsSnapshot(t *testing.T) {
	coordinator := flowcontrol.NewDefaultBufferCoordinator()
	update, err := coordinator.BuildUpdate(flowcontrol.ProtocolBuffersFromFrame(128*1024, 2))
	if err != nil { t.Fatal(err) }
	payload, err := flowcontrol.EncodeBufferUpdate(update)
	if err != nil { t.Fatal(err) }
	service := UpdateService{Coordinator: coordinator}
	response, err := service.ApplyBufferUpdate(context.Background(), &UpdateRequest{Payload: payload})
	if err != nil { t.Fatal(err) }
	if response.Generation != update.Snapshot.Generation || response.SHA256 != update.Snapshot.SHA256 {
		t.Fatalf("unexpected apply response: %+v", response)
	}
	snapshot, err := service.GetBufferSnapshot(context.Background(), &SnapshotRequest{})
	if err != nil { t.Fatal(err) }
	if snapshot.Generation != response.Generation || snapshot.SHA256 != response.SHA256 {
		t.Fatalf("snapshot response drifted: apply=%+v snapshot=%+v", response, snapshot)
	}
	if snapshot.Buffers.MQTTReadBufferBytes != snapshot.Buffers.SSHChannelFrameBytes || snapshot.Buffers.SSHChannelFrameBytes != snapshot.Buffers.GRPCReadBufferBytes {
		t.Fatalf("gRPC snapshot reports unaligned transports: %+v", snapshot.Buffers)
	}
	if _, err := service.ApplyBufferUpdate(context.Background(), &UpdateRequest{Payload: payload}); err == nil {
		t.Fatal("replayed gRPC update was accepted")
	}
}
