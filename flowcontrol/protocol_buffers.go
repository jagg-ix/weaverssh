package flowcontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

const ProtocolBufferContractVersion = "weaverssh.protocol-buffers.v1"

var (
	ErrProtocolBufferMismatch = errors.New("protocol buffer settings are not aligned")
	ErrStaleBufferUpdate      = errors.New("stale protocol buffer update")
)

// ProtocolBuffers is one cross-transport buffering contract. FrameBytes is the
// common application frame/chunk size. WindowBytes is the common in-flight
// budget used by SSH channel credit and gRPC stream/connection windows.
type ProtocolBuffers struct {
	FrameBytes               int `json:"frame_bytes"`
	QueueDepth               int `json:"queue_depth"`
	WindowBytes              int `json:"window_bytes"`
	MQTTReadBufferBytes      int `json:"mqtt_read_buffer_bytes"`
	MQTTWriteBufferBytes     int `json:"mqtt_write_buffer_bytes"`
	MQTTMaxPacketBytes       int `json:"mqtt_max_packet_bytes"`
	SSHChannelFrameBytes     int `json:"ssh_channel_frame_bytes"`
	SSHChannelWindowBytes    int `json:"ssh_channel_window_bytes"`
	GRPCReadBufferBytes      int `json:"grpc_read_buffer_bytes"`
	GRPCWriteBufferBytes     int `json:"grpc_write_buffer_bytes"`
	GRPCInitialWindowBytes   int `json:"grpc_initial_window_bytes"`
	GRPCInitialConnWindowBytes int `json:"grpc_initial_conn_window_bytes"`
	GRPCMaxMessageBytes      int `json:"grpc_max_message_bytes"`
}

// ProtocolBuffersFromProfile derives MQTT, SSH-channel, and gRPC settings from
// the same flow profile, removing independent defaults that can drift.
func ProtocolBuffersFromProfile(profile Profile) ProtocolBuffers {
	profile = profile.Normalized()
	frame := profile.WebSocketFrameBytes
	window := frame * profile.QueueDepth
	return ProtocolBuffers{
		FrameBytes: frame,
		QueueDepth: profile.QueueDepth,
		WindowBytes: window,
		MQTTReadBufferBytes: frame,
		MQTTWriteBufferBytes: frame,
		MQTTMaxPacketBytes: window,
		SSHChannelFrameBytes: frame,
		SSHChannelWindowBytes: window,
		GRPCReadBufferBytes: frame,
		GRPCWriteBufferBytes: frame,
		GRPCInitialWindowBytes: window,
		GRPCInitialConnWindowBytes: window,
		GRPCMaxMessageBytes: window,
	}
}

// ProtocolBuffersFromFrame builds an aligned contract from one operator-owned
// frame size. This is used by config reloads where Server.BufferSize is the
// authoritative setting.
func ProtocolBuffersFromFrame(frameBytes, queueDepth int) ProtocolBuffers {
	if frameBytes <= 0 {
		frameBytes = DefaultProfile().WebSocketFrameBytes
	}
	if queueDepth <= 0 {
		queueDepth = DefaultProfile().QueueDepth
	}
	profile := DefaultProfile()
	profile.WebSocketFrameBytes = frameBytes
	profile.WebSocketReadBufferBytes = frameBytes
	profile.WebSocketWriteBufferBytes = frameBytes
	profile.RelayReadBytes = frameBytes
	profile.X11PacketMaxBytes = frameBytes
	profile.QueueDepth = queueDepth
	profile.SSHSocketBufferBytes = frameBytes * queueDepth
	return ProtocolBuffersFromProfile(profile)
}

func (b ProtocolBuffers) Normalized() ProtocolBuffers {
	if b.FrameBytes <= 0 {
		b.FrameBytes = DefaultProfile().WebSocketFrameBytes
	}
	if b.QueueDepth <= 0 {
		b.QueueDepth = DefaultProfile().QueueDepth
	}
	if b.WindowBytes <= 0 {
		b.WindowBytes = b.FrameBytes * b.QueueDepth
	}
	if b.MQTTReadBufferBytes <= 0 { b.MQTTReadBufferBytes = b.FrameBytes }
	if b.MQTTWriteBufferBytes <= 0 { b.MQTTWriteBufferBytes = b.FrameBytes }
	if b.MQTTMaxPacketBytes <= 0 { b.MQTTMaxPacketBytes = b.WindowBytes }
	if b.SSHChannelFrameBytes <= 0 { b.SSHChannelFrameBytes = b.FrameBytes }
	if b.SSHChannelWindowBytes <= 0 { b.SSHChannelWindowBytes = b.WindowBytes }
	if b.GRPCReadBufferBytes <= 0 { b.GRPCReadBufferBytes = b.FrameBytes }
	if b.GRPCWriteBufferBytes <= 0 { b.GRPCWriteBufferBytes = b.FrameBytes }
	if b.GRPCInitialWindowBytes <= 0 { b.GRPCInitialWindowBytes = b.WindowBytes }
	if b.GRPCInitialConnWindowBytes <= 0 { b.GRPCInitialConnWindowBytes = b.WindowBytes }
	if b.GRPCMaxMessageBytes <= 0 { b.GRPCMaxMessageBytes = b.WindowBytes }
	return b
}

func (b ProtocolBuffers) Validate() error {
	b = b.Normalized()
	if b.FrameBytes < 1024 || b.FrameBytes > 16<<20 {
		return fmt.Errorf("%w: frame size %d outside 1 KiB..16 MiB", ErrProtocolBufferMismatch, b.FrameBytes)
	}
	if b.QueueDepth < 1 || b.QueueDepth > 1024 {
		return fmt.Errorf("%w: queue depth %d outside 1..1024", ErrProtocolBufferMismatch, b.QueueDepth)
	}
	expectedWindow := b.FrameBytes * b.QueueDepth
	if b.WindowBytes != expectedWindow {
		return fmt.Errorf("%w: window %d != frame %d * queue %d", ErrProtocolBufferMismatch, b.WindowBytes, b.FrameBytes, b.QueueDepth)
	}
	checks := map[string]int{
		"mqtt read": b.MQTTReadBufferBytes,
		"mqtt write": b.MQTTWriteBufferBytes,
		"ssh channel frame": b.SSHChannelFrameBytes,
		"grpc read": b.GRPCReadBufferBytes,
		"grpc write": b.GRPCWriteBufferBytes,
	}
	for name, value := range checks {
		if value != b.FrameBytes {
			return fmt.Errorf("%w: %s %d != common frame %d", ErrProtocolBufferMismatch, name, value, b.FrameBytes)
		}
	}
	windows := map[string]int{
		"mqtt max packet": b.MQTTMaxPacketBytes,
		"ssh channel window": b.SSHChannelWindowBytes,
		"grpc stream window": b.GRPCInitialWindowBytes,
		"grpc connection window": b.GRPCInitialConnWindowBytes,
		"grpc max message": b.GRPCMaxMessageBytes,
	}
	for name, value := range windows {
		if value != b.WindowBytes {
			return fmt.Errorf("%w: %s %d != common window %d", ErrProtocolBufferMismatch, name, value, b.WindowBytes)
		}
	}
	return nil
}

type BufferSnapshot struct {
	Version    string          `json:"version"`
	Generation uint64          `json:"generation"`
	Buffers    ProtocolBuffers `json:"buffers"`
	SHA256     string          `json:"sha256"`
}

type BufferUpdate struct {
	Version        string         `json:"version"`
	PreviousSHA256 string         `json:"previous_sha256"`
	Snapshot       BufferSnapshot `json:"snapshot"`
}

// BufferParticipant implements two-phase local application. Prepare must not
// mutate state. Commit cannot fail. The coordinator only commits after every
// MQTT/SSH/gRPC participant accepts the exact same snapshot.
type BufferParticipant interface {
	ProtocolBufferName() string
	PrepareProtocolBuffers(BufferSnapshot) error
	CommitProtocolBuffers(BufferSnapshot)
}

type BufferCoordinator struct {
	updateMu sync.Mutex
	mu sync.RWMutex
	snapshot BufferSnapshot
	participants map[string]BufferParticipant
}

func NewBufferCoordinator(initial ProtocolBuffers) (*BufferCoordinator, error) {
	initial = initial.Normalized()
	if err := initial.Validate(); err != nil { return nil, err }
	snapshot, err := newBufferSnapshot(1, initial)
	if err != nil { return nil, err }
	return &BufferCoordinator{snapshot: snapshot, participants: map[string]BufferParticipant{}}, nil
}

func NewDefaultBufferCoordinator() *BufferCoordinator {
	coordinator, _ := NewBufferCoordinator(ProtocolBuffersFromProfile(DefaultProfile()))
	return coordinator
}

func (c *BufferCoordinator) Current() BufferSnapshot {
	if c == nil { return BufferSnapshot{} }
	c.mu.RLock(); defer c.mu.RUnlock()
	return c.snapshot
}

func (c *BufferCoordinator) Register(participant BufferParticipant) (func(), error) {
	if c == nil || participant == nil { return nil, errors.New("protocol buffer coordinator and participant are required") }
	name := strings.TrimSpace(participant.ProtocolBufferName())
	if name == "" { return nil, errors.New("protocol buffer participant name is required") }
	c.updateMu.Lock(); defer c.updateMu.Unlock()
	c.mu.RLock(); snapshot := c.snapshot; c.mu.RUnlock()
	if err := participant.PrepareProtocolBuffers(snapshot); err != nil { return nil, fmt.Errorf("%s: %w", name, err) }
	c.mu.Lock()
	if _, exists := c.participants[name]; exists { c.mu.Unlock(); return nil, fmt.Errorf("protocol buffer participant %q already registered", name) }
	c.participants[name] = participant
	c.mu.Unlock()
	participant.CommitProtocolBuffers(snapshot)
	var once sync.Once
	return func() { once.Do(func() { c.updateMu.Lock(); c.mu.Lock(); delete(c.participants, name); c.mu.Unlock(); c.updateMu.Unlock() }) }, nil
}

func (c *BufferCoordinator) BuildUpdate(next ProtocolBuffers) (BufferUpdate, error) {
	if c == nil { return BufferUpdate{}, errors.New("protocol buffer coordinator is nil") }
	current := c.Current()
	snapshot, err := newBufferSnapshot(current.Generation+1, next.Normalized())
	if err != nil { return BufferUpdate{}, err }
	return BufferUpdate{Version: ProtocolBufferContractVersion, PreviousSHA256: current.SHA256, Snapshot: snapshot}, nil
}

func (c *BufferCoordinator) Update(next ProtocolBuffers) (BufferSnapshot, error) {
	update, err := c.BuildUpdate(next)
	if err != nil { return BufferSnapshot{}, err }
	return c.Apply(update)
}

func (c *BufferCoordinator) Apply(update BufferUpdate) (BufferSnapshot, error) {
	if c == nil { return BufferSnapshot{}, errors.New("protocol buffer coordinator is nil") }
	if err := update.Validate(); err != nil { return BufferSnapshot{}, err }
	c.updateMu.Lock(); defer c.updateMu.Unlock()
	c.mu.RLock()
	current := c.snapshot
	participants := make([]BufferParticipant, 0, len(c.participants))
	for _, participant := range c.participants { participants = append(participants, participant) }
	c.mu.RUnlock()
	if update.PreviousSHA256 != current.SHA256 || update.Snapshot.Generation != current.Generation+1 {
		return BufferSnapshot{}, ErrStaleBufferUpdate
	}
	sort.Slice(participants, func(i, j int) bool { return participants[i].ProtocolBufferName() < participants[j].ProtocolBufferName() })
	for _, participant := range participants {
		if err := participant.PrepareProtocolBuffers(update.Snapshot); err != nil {
			return BufferSnapshot{}, fmt.Errorf("%s: %w", participant.ProtocolBufferName(), err)
		}
	}
	c.mu.Lock(); c.snapshot = update.Snapshot; c.mu.Unlock()
	for _, participant := range participants { participant.CommitProtocolBuffers(update.Snapshot) }
	return update.Snapshot, nil
}

func (s BufferSnapshot) Validate() error {
	if s.Version != ProtocolBufferContractVersion || s.Generation == 0 { return ErrProtocolBufferMismatch }
	if err := s.Buffers.Validate(); err != nil { return err }
	digest, err := snapshotDigest(s.Generation, s.Buffers.Normalized())
	if err != nil { return err }
	if s.SHA256 != digest { return fmt.Errorf("%w: snapshot digest mismatch", ErrProtocolBufferMismatch) }
	return nil
}

func (u BufferUpdate) Validate() error {
	if u.Version != ProtocolBufferContractVersion || len(u.PreviousSHA256) != sha256.Size*2 { return ErrProtocolBufferMismatch }
	return u.Snapshot.Validate()
}

func EncodeBufferUpdate(update BufferUpdate) ([]byte, error) {
	if err := update.Validate(); err != nil { return nil, err }
	return json.Marshal(update)
}

func DecodeBufferUpdate(data []byte) (BufferUpdate, error) {
	decoder := json.NewDecoder(bytes.NewReader(data)); decoder.DisallowUnknownFields()
	var update BufferUpdate
	if err := decoder.Decode(&update); err != nil { return BufferUpdate{}, err }
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) { return BufferUpdate{}, ErrProtocolBufferMismatch }
	return update, update.Validate()
}

func newBufferSnapshot(generation uint64, buffers ProtocolBuffers) (BufferSnapshot, error) {
	buffers = buffers.Normalized()
	if err := buffers.Validate(); err != nil { return BufferSnapshot{}, err }
	digest, err := snapshotDigest(generation, buffers)
	if err != nil { return BufferSnapshot{}, err }
	return BufferSnapshot{Version: ProtocolBufferContractVersion, Generation: generation, Buffers: buffers, SHA256: digest}, nil
}

func snapshotDigest(generation uint64, buffers ProtocolBuffers) (string, error) {
	canonical, err := json.Marshal(struct { Version string `json:"version"`; Generation uint64 `json:"generation"`; Buffers ProtocolBuffers `json:"buffers"` }{ProtocolBufferContractVersion, generation, buffers})
	if err != nil { return "", err }
	digest := sha256.Sum256(append([]byte("weaverssh:protocol-buffers:v1\x00"), canonical...))
	return hex.EncodeToString(digest[:]), nil
}
