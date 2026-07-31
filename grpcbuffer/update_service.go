package grpcbuffer

import (
	"context"
	"fmt"

	"weaverssh/flowcontrol"
)

// UpdateRequest and UpdateResponse are protobuf-friendly DTOs: generators can
// map payload to bytes and the response fields directly without importing this
// package into generated code.
type UpdateRequest struct {
	Payload []byte `json:"payload"`
}

type UpdateResponse struct {
	Version    string `json:"version"`
	Generation uint64 `json:"generation"`
	SHA256     string `json:"sha256"`
}

type UpdateService struct {
	Coordinator *flowcontrol.BufferCoordinator
}

// Apply is suitable for a unary gRPC method implementation. The payload is the
// same strict BufferUpdate envelope used by MQTT and SSH control streams.
func (s UpdateService) Apply(ctx context.Context, request *UpdateRequest) (*UpdateResponse, error) {
	if err := ctx.Err(); err != nil { return nil, err }
	if s.Coordinator == nil || request == nil { return nil, fmt.Errorf("gRPC protocol buffer update service is incomplete") }
	update, err := flowcontrol.DecodeBufferUpdate(request.Payload)
	if err != nil { return nil, err }
	snapshot, err := s.Coordinator.Apply(update)
	if err != nil { return nil, err }
	return &UpdateResponse{Version: snapshot.Version, Generation: snapshot.Generation, SHA256: snapshot.SHA256}, nil
}
