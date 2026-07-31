// Package grpcbuffer exposes dependency-neutral gRPC buffer options. Callers
// can translate Options into grpc.DialOption and grpc.ServerOption values without
// making the core weaverssh module depend on a particular gRPC release.
package grpcbuffer

import (
	"errors"
	"sync"

	"weaverssh/flowcontrol"
)

type Options struct {
	Generation             uint64 `json:"generation"`
	ReadBufferBytes        int    `json:"read_buffer_bytes"`
	WriteBufferBytes       int    `json:"write_buffer_bytes"`
	InitialWindowBytes     int    `json:"initial_window_bytes"`
	InitialConnWindowBytes int    `json:"initial_conn_window_bytes"`
	MaxSendMessageBytes    int    `json:"max_send_message_bytes"`
	MaxRecvMessageBytes    int    `json:"max_recv_message_bytes"`
	ProfileSHA256          string `json:"profile_sha256"`
}

// Runtime participates in the two-phase buffer update and marks prior gRPC
// connections stale. OnRecycle should gracefully replace clients/servers built
// from an older Options generation.
type Runtime struct {
	mu sync.RWMutex
	options Options
	onRecycle func(previous, current Options)
	unregister func()
	closed bool
}

func New(coordinator *flowcontrol.BufferCoordinator, onRecycle func(previous, current Options)) (*Runtime, error) {
	if coordinator == nil { return nil, errors.New("gRPC buffer coordinator is required") }
	runtime := &Runtime{onRecycle: onRecycle}
	unregister, err := coordinator.Register(runtime)
	if err != nil { return nil, err }
	runtime.unregister = unregister
	return runtime, nil
}

func (r *Runtime) ProtocolBufferName() string { return "grpc" }
func (r *Runtime) PrepareProtocolBuffers(snapshot flowcontrol.BufferSnapshot) error {
	if err := snapshot.Validate(); err != nil { return err }
	return snapshot.Buffers.Validate()
}
func (r *Runtime) CommitProtocolBuffers(snapshot flowcontrol.BufferSnapshot) {
	current := optionsFromSnapshot(snapshot)
	r.mu.Lock()
	previous := r.options
	r.options = current
	callback := r.onRecycle
	closed := r.closed
	r.mu.Unlock()
	if !closed && previous.Generation != 0 && previous.Generation != current.Generation && callback != nil {
		go callback(previous, current)
	}
}

func (r *Runtime) Current() Options {
	if r == nil { return Options{} }
	r.mu.RLock(); defer r.mu.RUnlock()
	return r.options
}

// IsStale lets a stream/connection reject work created under an older profile.
func (r *Runtime) IsStale(generation uint64) bool {
	current := r.Current()
	return current.Generation != 0 && generation != current.Generation
}

func (r *Runtime) Close() error {
	if r == nil { return nil }
	r.mu.Lock()
	if r.closed { r.mu.Unlock(); return nil }
	r.closed = true
	unregister := r.unregister
	r.unregister = nil
	r.mu.Unlock()
	if unregister != nil { unregister() }
	return nil
}

func optionsFromSnapshot(snapshot flowcontrol.BufferSnapshot) Options {
	buffers := snapshot.Buffers.Normalized()
	return Options{
		Generation: snapshot.Generation,
		ReadBufferBytes: buffers.GRPCReadBufferBytes,
		WriteBufferBytes: buffers.GRPCWriteBufferBytes,
		InitialWindowBytes: buffers.GRPCInitialWindowBytes,
		InitialConnWindowBytes: buffers.GRPCInitialConnWindowBytes,
		MaxSendMessageBytes: buffers.GRPCMaxMessageBytes,
		MaxRecvMessageBytes: buffers.GRPCMaxMessageBytes,
		ProfileSHA256: snapshot.SHA256,
	}
}
