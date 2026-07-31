package sessionmux

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"weaverssh/flowcontrol"
)

const ProtocolBufferControlMetadata = "weaverssh.protocol-buffers.v1"
const maxProtocolBufferUpdateBytes = 64 << 10

// OpenProtocolBufferUpdate sends one digest-bound buffer update through a
// ServiceControl stream. The receiver applies it through the same coordinator
// used by MQTT and gRPC, so independently decoded fields cannot drift.
func OpenProtocolBufferUpdate(ctx context.Context, mux *Mux, update flowcontrol.BufferUpdate) error {
	if mux == nil { return fmt.Errorf("sessionmux is required") }
	payload, err := flowcontrol.EncodeBufferUpdate(update)
	if err != nil { return err }
	if len(payload) > maxProtocolBufferUpdateBytes { return fmt.Errorf("protocol buffer update exceeds %d bytes", maxProtocolBufferUpdateBytes) }
	stream, err := mux.Open(ctx, ServiceControl, []byte(ProtocolBufferControlMetadata))
	if err != nil { return err }
	defer stream.Close()
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if _, err := stream.Write(header); err != nil { return err }
	_, err = stream.Write(payload)
	return err
}

// ApplyProtocolBufferControlStream strictly decodes and applies one update from
// an accepted SSH control stream.
func ApplyProtocolBufferControlStream(coordinator *flowcontrol.BufferCoordinator, stream *Stream) (flowcontrol.BufferSnapshot, error) {
	if coordinator == nil || stream == nil { return flowcontrol.BufferSnapshot{}, fmt.Errorf("coordinator and SSH control stream are required") }
	if string(stream.Metadata()) != ProtocolBufferControlMetadata { return flowcontrol.BufferSnapshot{}, fmt.Errorf("unexpected SSH control metadata") }
	header := make([]byte, 4)
	if _, err := io.ReadFull(stream, header); err != nil { return flowcontrol.BufferSnapshot{}, err }
	length := binary.BigEndian.Uint32(header)
	if length == 0 || length > maxProtocolBufferUpdateBytes { return flowcontrol.BufferSnapshot{}, fmt.Errorf("invalid protocol buffer update length %d", length) }
	payload := make([]byte, length)
	if _, err := io.ReadFull(stream, payload); err != nil { return flowcontrol.BufferSnapshot{}, err }
	update, err := flowcontrol.DecodeBufferUpdate(payload)
	if err != nil { return flowcontrol.BufferSnapshot{}, err }
	return coordinator.Apply(update)
}
