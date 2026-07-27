package sessionmux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

var (
	// ErrMuxClosed is returned after the underlying session transport closes.
	ErrMuxClosed = errors.New("sessionmux: multiplexer closed")
	// ErrStreamReset reports that the peer rejected or reset a logical stream.
	ErrStreamReset = errors.New("sessionmux: stream reset by peer")
	// ErrIncomingBacklog reports that the bounded incoming-stream queue is full.
	ErrIncomingBacklog = errors.New("sessionmux: incoming stream backlog full")
)

// Role determines which stream-ID parity a peer allocates. Initiators allocate
// odd IDs and responders allocate even IDs, preventing collisions without
// coordination or static network ports.
type Role uint8

const (
	RoleInitiator Role = iota + 1
	RoleResponder
)

// Config controls one multiplexer instance.
type Config struct {
	Role            Role
	Codec           Codec
	IncomingBacklog int
	AllowedServices map[ServiceID]bool

	// InitialWindow is the maximum unread byte count permitted per stream and
	// direction. Zero selects DefaultInitialWindow.
	InitialWindow uint32
	// WindowUpdateThreshold batches returned credit. Zero selects half of the
	// initial window. Draining the read buffer always returns pending credit.
	WindowUpdateThreshold uint32
	// MaxDataPayload bounds one DATA frame. Zero selects
	// DefaultMaxDataPayload, capped by Codec.MaxPayload and InitialWindow.
	MaxDataPayload uint32
}

// Mux carries independent logical streams over one supplied transport.
type Mux struct {
	conn  io.ReadWriteCloser
	codec Codec
	role  Role

	initialWindow   uint32
	windowThreshold uint32
	maxDataPayload  uint32

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32
	err     error

	allowed  map[ServiceID]bool
	incoming chan *Stream
	outgoing chan writeRequest
	done     chan struct{}
	closeOne sync.Once
}

// New starts a multiplexer over conn. New never opens a listener or dials an
// endpoint; ownership of the already-authenticated transport remains explicit.
func New(conn io.ReadWriteCloser, config Config) (*Mux, error) {
	if conn == nil {
		return nil, errors.New("sessionmux: nil transport")
	}
	if config.Role != RoleInitiator && config.Role != RoleResponder {
		return nil, fmt.Errorf("sessionmux: invalid role %d", config.Role)
	}
	backlog := config.IncomingBacklog
	if backlog <= 0 {
		backlog = 16
	}

	initialWindow := config.InitialWindow
	if initialWindow == 0 {
		initialWindow = DefaultInitialWindow
	}
	if initialWindow > 64<<20 {
		return nil, fmt.Errorf("sessionmux: initial window %d exceeds 64 MiB safety limit", initialWindow)
	}
	windowThreshold := config.WindowUpdateThreshold
	if windowThreshold == 0 {
		windowThreshold = initialWindow / 2
		if windowThreshold == 0 {
			windowThreshold = 1
		}
	}
	if windowThreshold > initialWindow {
		return nil, fmt.Errorf("sessionmux: window threshold %d exceeds initial window %d", windowThreshold, initialWindow)
	}

	codecMax := config.Codec.maxPayload()
	maxDataPayload := config.MaxDataPayload
	if maxDataPayload == 0 {
		maxDataPayload = minUint32(DefaultMaxDataPayload, codecMax)
	}
	if maxDataPayload > codecMax {
		return nil, fmt.Errorf("sessionmux: DATA payload %d exceeds codec maximum %d", maxDataPayload, codecMax)
	}
	maxDataPayload = minUint32(maxDataPayload, initialWindow)
	if maxDataPayload == 0 {
		return nil, errors.New("sessionmux: DATA payload limit must be positive")
	}

	allowed := make(map[ServiceID]bool)
	if config.AllowedServices == nil {
		allowed = map[ServiceID]bool{
			ServiceControl: true,
			ServiceFS:      true,
			ServiceTCP:     true,
			ServiceExec:    true,
			ServiceEvents:  true,
		}
	} else {
		for service, enabled := range config.AllowedServices {
			allowed[service] = enabled
		}
	}
	nextID := uint32(1)
	if config.Role == RoleResponder {
		nextID = 2
	}
	mux := &Mux{
		conn:            conn,
		codec:           config.Codec,
		role:            config.Role,
		initialWindow:   initialWindow,
		windowThreshold: windowThreshold,
		maxDataPayload:  maxDataPayload,
		streams:         make(map[uint32]*Stream),
		nextID:          nextID,
		allowed:         allowed,
		incoming:        make(chan *Stream, backlog),
		outgoing:        make(chan writeRequest, backlog*4),
		done:            make(chan struct{}),
	}
	go mux.writerLoop()
	go mux.readLoop()
	return mux, nil
}

// Open creates a logical stream for service and waits for the peer to accept it.
// metadata is service-specific OPEN payload, such as a target node or root.
func (m *Mux) Open(ctx context.Context, service ServiceID, metadata []byte) (*Stream, error) {
	if !service.Valid() {
		return nil, fmt.Errorf("sessionmux: invalid service %d", service)
	}
	stream, err := m.newLocalStream(service)
	if err != nil {
		return nil, err
	}
	if err := m.send(Frame{Type: FrameOpen, StreamID: stream.id, Service: service, Payload: append([]byte(nil), metadata...)}); err != nil {
		m.removeStream(stream.id)
		return nil, err
	}

	select {
	case err := <-stream.accepted:
		if err != nil {
			m.removeStream(stream.id)
			return nil, err
		}
		stream.markAccepted()
		if err := m.sendInitialWindow(stream, false); err != nil {
			stream.remoteClose(err)
			m.removeStream(stream.id)
			return nil, err
		}
		return stream, nil
	case <-ctx.Done():
		_ = m.sendAsync(Frame{Type: FrameReset, StreamID: stream.id, Service: service})
		stream.remoteClose(ctx.Err())
		m.removeStream(stream.id)
		return nil, ctx.Err()
	case <-m.done:
		return nil, m.closeErr()
	}
}

// Accept waits for the next peer-opened logical stream. OPEN metadata is
// available through Stream.Metadata.
func (m *Mux) Accept(ctx context.Context) (*Stream, error) {
	select {
	case stream := <-m.incoming:
		if stream == nil {
			return nil, m.closeErr()
		}
		return stream, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.done:
		return nil, m.closeErr()
	}
}

// Close closes the entire logical session and all remaining streams.
func (m *Mux) Close() error {
	m.shutdown(ErrMuxClosed)
	return nil
}

func (m *Mux) newLocalStream(service ServiceID) (*Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	id := m.nextID
	m.nextID += 2
	stream := newStream(m, id, service, nil, false)
	m.streams[id] = stream
	return stream, nil
}

type writeRequest struct {
	frame  Frame
	result chan error
}

func (m *Mux) send(frame Frame) error {
	result := make(chan error, 1)
	request := writeRequest{frame: frame, result: result}
	select {
	case m.outgoing <- request:
	case <-m.done:
		return m.closeErr()
	}
	select {
	case err := <-result:
		return err
	case <-m.done:
		return m.closeErr()
	}
}

// sendAsync queues a protocol response without blocking the reader loop on the
// underlying transport write. This is required when both peers open streams at
// the same time: each reader must remain able to consume the peer's ACCEPT.
func (m *Mux) sendAsync(frame Frame) error {
	select {
	case m.outgoing <- writeRequest{frame: frame}:
		return nil
	case <-m.done:
		return m.closeErr()
	}
}

func (m *Mux) writerLoop() {
	for {
		select {
		case request := <-m.outgoing:
			err := m.codec.WriteFrame(m.conn, request.frame)
			if request.result != nil {
				request.result <- err
			}
			if err != nil {
				m.shutdown(err)
				return
			}
		case <-m.done:
			return
		}
	}
}

func (m *Mux) readLoop() {
	for {
		frame, err := m.codec.ReadFrame(m.conn)
		if err != nil {
			m.shutdown(err)
			return
		}
		if err := m.handleFrame(frame); err != nil {
			m.shutdown(err)
			return
		}
	}
}

func (m *Mux) handleFrame(frame Frame) error {
	switch frame.Type {
	case FrameOpen:
		return m.handleOpen(frame)
	case FrameAccept:
		stream := m.lookupStream(frame.StreamID)
		if stream == nil {
			return fmt.Errorf("sessionmux: ACCEPT for unknown stream %d", frame.StreamID)
		}
		if stream.Service() != frame.Service {
			return fmt.Errorf("sessionmux: ACCEPT service mismatch for stream %d", frame.StreamID)
		}
		stream.signalAccepted(nil)
		return nil
	case FrameWindow:
		stream := m.lookupStream(frame.StreamID)
		if stream == nil {
			// A WINDOW may race with final stream removal; stale credit is harmless.
			return nil
		}
		if stream.Service() != frame.Service {
			m.resetStream(stream, fmt.Errorf("%w: WINDOW service mismatch", ErrFlowControlViolation))
			return nil
		}
		credit, err := decodeWindowCredit(frame.Payload)
		if err != nil {
			m.resetStream(stream, err)
			return nil
		}
		if err := stream.addSendCredit(credit); err != nil {
			m.resetStream(stream, err)
		}
		return nil
	case FrameData:
		stream := m.lookupStream(frame.StreamID)
		if stream == nil {
			_ = m.sendAsync(Frame{Type: FrameReset, StreamID: frame.StreamID, Service: frame.Service})
			return nil
		}
		if !stream.isAccepted() || stream.Service() != frame.Service {
			m.resetStream(stream, ErrStreamReset)
			return nil
		}
		if err := stream.deliver(frame.Payload); err != nil {
			m.resetStream(stream, err)
		}
		return nil
	case FrameClose:
		stream := m.lookupStream(frame.StreamID)
		if stream == nil {
			return nil
		}
		if stream.Service() != frame.Service {
			m.resetStream(stream, ErrStreamReset)
			return nil
		}
		stream.remoteClose(nil)
		m.maybeRemove(stream)
		return nil
	case FrameReset:
		stream := m.lookupStream(frame.StreamID)
		if stream == nil {
			return nil
		}
		stream.signalAccepted(ErrStreamReset)
		stream.remoteClose(ErrStreamReset)
		m.removeStream(frame.StreamID)
		return nil
	case FramePing:
		return m.sendAsync(Frame{Type: FramePong, StreamID: 0, Payload: frame.Payload})
	case FramePong:
		return nil
	default:
		return fmt.Errorf("sessionmux: unsupported frame type %d", frame.Type)
	}
}

func (m *Mux) handleOpen(frame Frame) error {
	if !frame.Service.Valid() || !m.allowed[frame.Service] {
		return m.sendAsync(Frame{Type: FrameReset, StreamID: frame.StreamID, Service: frame.Service})
	}
	if !m.peerOwns(frame.StreamID) {
		return fmt.Errorf("sessionmux: peer used invalid stream ID %d", frame.StreamID)
	}

	m.mu.Lock()
	if m.err != nil {
		m.mu.Unlock()
		return m.err
	}
	if _, exists := m.streams[frame.StreamID]; exists {
		m.mu.Unlock()
		return fmt.Errorf("sessionmux: duplicate OPEN for stream %d", frame.StreamID)
	}
	stream := newStream(m, frame.StreamID, frame.Service, frame.Payload, true)
	m.streams[frame.StreamID] = stream
	m.mu.Unlock()

	// Only the read loop sends into incoming. Checking capacity here reserves a
	// slot without exposing the stream before ACCEPT and initial WINDOW are queued.
	if len(m.incoming) >= cap(m.incoming) {
		stream.remoteClose(ErrIncomingBacklog)
		m.removeStream(frame.StreamID)
		return m.sendAsync(Frame{Type: FrameReset, StreamID: frame.StreamID, Service: frame.Service})
	}
	if err := m.sendAsync(Frame{Type: FrameAccept, StreamID: frame.StreamID, Service: frame.Service}); err != nil {
		stream.remoteClose(err)
		m.removeStream(frame.StreamID)
		return err
	}
	if err := m.sendInitialWindow(stream, true); err != nil {
		stream.remoteClose(err)
		m.removeStream(frame.StreamID)
		return err
	}
	stream.markAccepted()
	select {
	case m.incoming <- stream:
		return nil
	case <-m.done:
		stream.remoteClose(m.closeErr())
		m.removeStream(frame.StreamID)
		return m.closeErr()
	}
}

func (m *Mux) sendInitialWindow(stream *Stream, async bool) error {
	credit, err := stream.initializeReceiveWindow()
	if err != nil {
		return err
	}
	payload, err := encodeWindowCredit(credit)
	if err != nil {
		return err
	}
	frame := Frame{Type: FrameWindow, StreamID: stream.id, Service: stream.service, Payload: payload}
	if async {
		return m.sendAsync(frame)
	}
	return m.send(frame)
}

func (m *Mux) resetStream(stream *Stream, err error) {
	if stream == nil {
		return
	}
	if err == nil {
		err = ErrStreamReset
	}
	stream.signalAccepted(err)
	stream.remoteClose(err)
	_ = m.sendAsync(Frame{Type: FrameReset, StreamID: stream.id, Service: stream.service})
	m.removeStream(stream.id)
}

func (m *Mux) peerOwns(id uint32) bool {
	if id == 0 {
		return false
	}
	if m.role == RoleInitiator {
		return id%2 == 0
	}
	return id%2 == 1
}

func (m *Mux) lookupStream(id uint32) *Stream {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streams[id]
}

func (m *Mux) removeStream(id uint32) {
	m.mu.Lock()
	delete(m.streams, id)
	m.mu.Unlock()
}

func (m *Mux) maybeRemove(stream *Stream) {
	if stream.isFullyClosed() {
		m.removeStream(stream.id)
	}
}

func (m *Mux) closeErr() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	return ErrMuxClosed
}

func (m *Mux) shutdown(err error) {
	if err == nil {
		err = ErrMuxClosed
	}
	m.closeOne.Do(func() {
		m.mu.Lock()
		m.err = err
		streams := make([]*Stream, 0, len(m.streams))
		for _, stream := range m.streams {
			streams = append(streams, stream)
		}
		m.streams = make(map[uint32]*Stream)
		m.mu.Unlock()

		close(m.done)
		_ = m.conn.Close()
		for _, stream := range streams {
			stream.signalAccepted(err)
			stream.remoteClose(err)
		}
	})
}
