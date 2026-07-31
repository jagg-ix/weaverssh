package flowcontrol

import (
	"errors"
	"testing"
)

type testBufferParticipant struct {
	name string
	rejectFrame int
	prepared []BufferSnapshot
	committed []BufferSnapshot
}

func (p *testBufferParticipant) ProtocolBufferName() string { return p.name }
func (p *testBufferParticipant) PrepareProtocolBuffers(snapshot BufferSnapshot) error {
	p.prepared = append(p.prepared, snapshot)
	if snapshot.Buffers.FrameBytes == p.rejectFrame { return errors.New("rejected") }
	return nil
}
func (p *testBufferParticipant) CommitProtocolBuffers(snapshot BufferSnapshot) { p.committed = append(p.committed, snapshot) }

func TestProtocolBuffersDerivedAcrossMQTTSSHAndGRPC(t *testing.T) {
	profile, err := Builtin(ProfileBulk)
	if err != nil { t.Fatal(err) }
	buffers := ProtocolBuffersFromProfile(profile)
	if err := buffers.Validate(); err != nil { t.Fatal(err) }
	if buffers.MQTTReadBufferBytes != buffers.SSHChannelFrameBytes || buffers.SSHChannelFrameBytes != buffers.GRPCReadBufferBytes {
		t.Fatalf("frame buffers are not aligned: %+v", buffers)
	}
	if buffers.MQTTMaxPacketBytes != buffers.SSHChannelWindowBytes || buffers.SSHChannelWindowBytes != buffers.GRPCInitialWindowBytes || buffers.GRPCInitialWindowBytes != buffers.GRPCInitialConnWindowBytes {
		t.Fatalf("window buffers are not aligned: %+v", buffers)
	}
}

func TestBufferCoordinatorRejectsPartialCommit(t *testing.T) {
	coordinator := NewDefaultBufferCoordinator()
	mqtt := &testBufferParticipant{name: "mqtt"}
	ssh := &testBufferParticipant{name: "ssh", rejectFrame: 8192}
	grpc := &testBufferParticipant{name: "grpc"}
	for _, participant := range []*testBufferParticipant{mqtt, ssh, grpc} {
		if _, err := coordinator.Register(participant); err != nil { t.Fatal(err) }
	}
	before := coordinator.Current()
	_, err := coordinator.Update(ProtocolBuffersFromFrame(8192, 8))
	if err == nil { t.Fatal("expected participant rejection") }
	after := coordinator.Current()
	if after != before { t.Fatalf("coordinator changed after rejected update: before=%+v after=%+v", before, after) }
	for _, participant := range []*testBufferParticipant{mqtt, ssh, grpc} {
		if len(participant.committed) != 1 { t.Fatalf("%s received partial commit", participant.name) }
	}
}

func TestBufferUpdateGenerationAndDigest(t *testing.T) {
	coordinator := NewDefaultBufferCoordinator()
	update, err := coordinator.BuildUpdate(ProtocolBuffersFromFrame(16*1024, 4))
	if err != nil { t.Fatal(err) }
	encoded, err := EncodeBufferUpdate(update)
	if err != nil { t.Fatal(err) }
	decoded, err := DecodeBufferUpdate(encoded)
	if err != nil { t.Fatal(err) }
	if _, err := coordinator.Apply(decoded); err != nil { t.Fatal(err) }
	if _, err := coordinator.Apply(decoded); !errors.Is(err, ErrStaleBufferUpdate) { t.Fatalf("expected stale update, got %v", err) }
	decoded.Snapshot.Buffers.MQTTReadBufferBytes++
	if _, err := EncodeBufferUpdate(decoded); err == nil { t.Fatal("expected digest mismatch") }
}
