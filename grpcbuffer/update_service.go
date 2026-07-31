package grpcbuffer

import (
	"context"
	"fmt"

	"weaverssh/flowcontrol"
)

// UpdateRequest and UpdateResponse mirror the protobuf contract while keeping
// generated-code dependencies outside the core package.
type UpdateRequest struct {
	Payload []byte `json:"payload"`
}

type UpdateResponse struct {
	Version    string `json:"version"`
	Generation uint64 `json:"generation"`
	SHA256     string `json:"sha256"`
}

type SnapshotRequest struct{}

type SnapshotResponse struct {
	Version    string                      `json:"version"`
	Generation uint64                      `json:"generation"`
	SHA256     string                      `json:"sha256"`
	Buffers    flowcontrol.ProtocolBuffers `json:"buffers"`
}

type UpdateService struct {
	Coordinator *flowcontrol.BufferCoordinator
}

// ApplyBufferUpdate implements the protobuf ProtocolBufferSync unary method.
// The payload is the same strict BufferUpdate envelope used by MQTT and SSH.
func (s UpdateService) ApplyBufferUpdate(ctx context.Context, request *UpdateRequest) (*UpdateResponse, error) {
	if err := ctx.Err(); err != nil { return nil, err }
	if s.Coordinator == nil || request == nil { return nil, fmt.Errorf("gRPC protocol buffer update service is incomplete") }
	update, err := flowcontrol.DecodeBufferUpdate(request.Payload)
	if err != nil { return nil, err }
	snapshot, err := s.Coordinator.Apply(update)
	if err != nil { return nil, err }
	return &UpdateResponse{Version: snapshot.Version, Generation: snapshot.Generation, SHA256: snapshot.SHA256}, nil
}

// Apply is retained as a concise adapter for integrations that predate the
// explicit .proto contract.
func (s UpdateService) Apply(ctx context.Context, request *UpdateRequest) (*UpdateResponse, error) {
	return s.ApplyBufferUpdate(ctx, request)
}

func (s UpdateService) GetBufferSnapshot(ctx context.Context, _ *SnapshotRequest) (*SnapshotResponse, error) {
	if err := ctx.Err(); err != nil { return nil, err }
	if s.Coordinator == nil { return nil, fmt.Errorf("gRPC protocol buffer update service is incomplete") }
	snapshot := s.Coordinator.Current()
	if err := snapshot.Validate(); err != nil { return nil, err }
	return &SnapshotResponse{
		Version: snapshot.Version,
		Generation: snapshot.Generation,
		SHA256: snapshot.SHA256,
		Buffers: snapshot.Buffers,
	}, nil
}
