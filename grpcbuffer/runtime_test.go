package grpcbuffer

import (
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
