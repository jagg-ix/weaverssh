package sessionmux

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"weaverssh/flowcontrol"
)

// BufferSyncedMux owns a Mux registration in the shared protocol-buffer
// coordinator. Existing active streams may grow in place. A shrinking update is
// rejected while streams are active because already-advertised peer credit and
// frame limits cannot be revoked safely.
type BufferSyncedMux struct {
	*Mux
	coordinator *flowcontrol.BufferCoordinator
	unregister func()
	closeOnce sync.Once
}

func NewBufferSynced(conn io.ReadWriteCloser, config Config, coordinator *flowcontrol.BufferCoordinator) (*BufferSyncedMux, error) {
	if coordinator == nil { return nil, errors.New("sessionmux protocol buffer coordinator is required") }
	snapshot := coordinator.Current()
	if err := snapshot.Validate(); err != nil { return nil, err }
	config = ConfigWithProtocolBuffers(config, snapshot.Buffers)
	mux, err := New(conn, config)
	if err != nil { return nil, err }
	wrapped := &BufferSyncedMux{Mux: mux, coordinator: coordinator}
	unregister, err := coordinator.Register(wrapped)
	if err != nil { _ = mux.Close(); return nil, err }
	wrapped.unregister = unregister
	return wrapped, nil
}

func ConfigWithProtocolBuffers(config Config, buffers flowcontrol.ProtocolBuffers) Config {
	buffers = buffers.Normalized()
	config.InitialWindow = uint32(buffers.SSHChannelWindowBytes)
	config.WindowUpdateThreshold = uint32(buffers.SSHChannelWindowBytes / 2)
	if config.WindowUpdateThreshold == 0 { config.WindowUpdateThreshold = 1 }
	config.MaxDataPayload = uint32(buffers.SSHChannelFrameBytes)
	if config.Codec.MaxPayload == 0 || config.Codec.MaxPayload < uint32(buffers.SSHChannelWindowBytes) {
		config.Codec.MaxPayload = uint32(buffers.SSHChannelWindowBytes)
	}
	return config
}

func (m *BufferSyncedMux) ProtocolBufferName() string { return "ssh-channel" }

func (m *BufferSyncedMux) PrepareProtocolBuffers(snapshot flowcontrol.BufferSnapshot) error {
	if m == nil || m.Mux == nil { return errors.New("sessionmux is nil") }
	if err := snapshot.Validate(); err != nil { return err }
	buffers := snapshot.Buffers.Normalized()
	if uint64(buffers.SSHChannelWindowBytes) > uint64(maxInitialWindow) {
		return fmt.Errorf("SSH channel window %d exceeds safety limit %d", buffers.SSHChannelWindowBytes, maxInitialWindow)
	}
	if uint32(buffers.SSHChannelFrameBytes) > m.codec.maxPayload() {
		return fmt.Errorf("SSH channel frame %d exceeds codec maximum %d", buffers.SSHChannelFrameBytes, m.codec.maxPayload())
	}
	m.mu.Lock()
	streams := make([]*Stream, 0, len(m.streams))
	for _, stream := range m.streams { streams = append(streams, stream) }
	currentWindow := m.initialWindow
	currentFrame := m.maxDataPayload
	m.mu.Unlock()
	if len(streams) > 0 && (uint32(buffers.SSHChannelWindowBytes) < currentWindow || uint32(buffers.SSHChannelFrameBytes) < currentFrame) {
		return errors.New("cannot shrink SSH channel buffers while streams are active")
	}
	for _, stream := range streams {
		stream.mu.Lock()
		if uint64(buffers.SSHChannelWindowBytes) < stream.initialWindow || uint32(buffers.SSHChannelFrameBytes) < stream.maxDataPayload {
			stream.mu.Unlock()
			return fmt.Errorf("cannot shrink active SSH stream %d", stream.id)
		}
		stream.mu.Unlock()
	}
	return nil
}

func (m *BufferSyncedMux) CommitProtocolBuffers(snapshot flowcontrol.BufferSnapshot) {
	if m == nil || m.Mux == nil { return }
	buffers := snapshot.Buffers.Normalized()
	newWindow := uint64(buffers.SSHChannelWindowBytes)
	newThreshold := newWindow / 2
	if newThreshold == 0 { newThreshold = 1 }
	newFrame := uint32(buffers.SSHChannelFrameBytes)
	m.mu.Lock()
	oldWindow := uint64(m.initialWindow)
	m.initialWindow = uint32(newWindow)
	m.windowThreshold = uint32(newThreshold)
	m.maxDataPayload = newFrame
	streams := make([]*Stream, 0, len(m.streams))
	for _, stream := range m.streams { streams = append(streams, stream) }
	m.mu.Unlock()
	for _, stream := range streams {
		stream.mu.Lock()
		streamOldWindow := stream.initialWindow
		if newWindow >= streamOldWindow {
			delta := newWindow - streamOldWindow
			stream.initialWindow = newWindow
			stream.windowThreshold = newThreshold
			stream.maxDataPayload = newFrame
			stream.recvCredit += delta
			if stream.peerWindowSet {
				stream.peerWindow += delta
				stream.sendCredit += delta
				stream.writeReady.Broadcast()
			}
		}
		stream.mu.Unlock()
	}
	_ = oldWindow
}

// ApplyBufferUpdate applies the same generation/digest update received over an
// MQTT settings topic, an SSH control stream, or a gRPC configuration method.
func (m *BufferSyncedMux) ApplyBufferUpdate(update flowcontrol.BufferUpdate) (flowcontrol.BufferSnapshot, error) {
	if m == nil || m.coordinator == nil { return flowcontrol.BufferSnapshot{}, errors.New("sessionmux buffer coordinator is unavailable") }
	return m.coordinator.Apply(update)
}

func (m *BufferSyncedMux) Close() error {
	if m == nil { return nil }
	m.closeOnce.Do(func() { if m.unregister != nil { m.unregister() } })
	if m.Mux == nil { return nil }
	return m.Mux.Close()
}
