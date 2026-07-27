package sessionmux

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Stream is one logical service channel inside a Mux.
type Stream struct {
	mux      *Mux
	id       uint32
	service  ServiceID
	metadata []byte

	accepted  chan error
	acceptOne sync.Once
	writeMu   sync.Mutex

	mu           sync.Mutex
	readReady    *sync.Cond
	writeReady   *sync.Cond
	readBuf      bytes.Buffer
	isOpen       bool
	localClosed  bool
	remoteClosed bool
	terminalErr  error

	initialWindow    uint64
	windowThreshold  uint64
	maxDataPayload   uint32
	windowAdvertised bool
	recvCredit       uint64
	pendingWindow    uint64

	peerWindowSet bool
	peerWindow    uint64
	sendCredit    uint64
}

func newStream(mux *Mux, id uint32, service ServiceID, metadata []byte, accepted bool) *Stream {
	stream := &Stream{
		mux:             mux,
		id:              id,
		service:         service,
		metadata:        append([]byte(nil), metadata...),
		accepted:        make(chan error, 1),
		isOpen:          accepted,
		initialWindow:   uint64(mux.initialWindow),
		windowThreshold: uint64(mux.windowThreshold),
		maxDataPayload:  mux.maxDataPayload,
	}
	stream.readReady = sync.NewCond(&stream.mu)
	stream.writeReady = sync.NewCond(&stream.mu)
	return stream
}

// ID returns the session-local stream identifier.
func (s *Stream) ID() uint32 { return s.id }

// Service returns the logical service carried by this stream.
func (s *Stream) Service() ServiceID { return s.service }

// Metadata returns a defensive copy of the peer's OPEN payload.
func (s *Stream) Metadata() []byte { return append([]byte(nil), s.metadata...) }

// Read reads service bytes until the peer closes or resets the stream. Consumed
// bytes are returned to the peer as WINDOW credit; unread bytes remain bounded by
// the configured initial window.
func (s *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for {
		s.mu.Lock()
		if s.readBuf.Len() > 0 {
			n, _ := s.readBuf.Read(p)
			var grant uint32
			if !s.remoteClosed {
				s.pendingWindow += uint64(n)
				if s.pendingWindow >= s.windowThreshold || s.readBuf.Len() == 0 {
					if s.recvCredit+s.pendingWindow > s.initialWindow {
						s.mu.Unlock()
						return n, fmt.Errorf("%w: receive-credit invariant exceeded", ErrFlowControlViolation)
					}
					grant = uint32(s.pendingWindow)
					s.recvCredit += s.pendingWindow
					s.pendingWindow = 0
				}
			}
			s.mu.Unlock()

			if grant > 0 {
				payload, err := encodeWindowCredit(grant)
				if err != nil {
					return n, err
				}
				if err := s.mux.sendAsync(Frame{Type: FrameWindow, StreamID: s.id, Service: s.service, Payload: payload}); err != nil {
					return n, err
				}
			}
			return n, nil
		}
		if s.remoteClosed {
			err := s.terminalErr
			s.mu.Unlock()
			if err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
		s.readReady.Wait()
		s.mu.Unlock()
	}
}

// Write sends service bytes without affecting other logical streams. Large
// writes are split into bounded DATA frames and block when peer credit is
// exhausted. Reset, close, or mux shutdown wakes a blocked writer.
func (s *Stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	total := 0
	for total < len(p) {
		s.mu.Lock()
		for {
			if !s.isOpen {
				s.mu.Unlock()
				return total, errors.New("sessionmux: stream is not accepted")
			}
			if s.localClosed {
				s.mu.Unlock()
				return total, io.ErrClosedPipe
			}
			if s.terminalErr != nil {
				err := s.terminalErr
				s.mu.Unlock()
				return total, err
			}
			if s.sendCredit > 0 {
				break
			}
			s.writeReady.Wait()
		}

		chunk := len(p) - total
		if chunk > int(s.maxDataPayload) {
			chunk = int(s.maxDataPayload)
		}
		if uint64(chunk) > s.sendCredit {
			chunk = int(s.sendCredit)
		}
		s.sendCredit -= uint64(chunk)
		data := append([]byte(nil), p[total:total+chunk]...)
		s.mu.Unlock()

		if err := s.mux.send(Frame{Type: FrameData, StreamID: s.id, Service: s.service, Payload: data}); err != nil {
			return total, err
		}
		total += chunk
	}
	return total, nil
}

// Close closes this stream's local write direction only. It does not close the
// parent session or discard unread peer data.
func (s *Stream) Close() error {
	s.mu.Lock()
	if s.localClosed {
		s.mu.Unlock()
		return nil
	}
	s.localClosed = true
	s.writeReady.Broadcast()
	s.mu.Unlock()

	// Wait for an in-progress DATA frame to finish so CLOSE is ordered after it.
	s.writeMu.Lock()
	err := s.mux.send(Frame{Type: FrameClose, StreamID: s.id, Service: s.service})
	s.writeMu.Unlock()
	s.mux.maybeRemove(s)
	return err
}

// Reset rejects or aborts this logical stream without closing the parent
// session. RESET is queued asynchronously so authorization failures do not make
// the accepting read loop wait on transport I/O.
func (s *Stream) Reset() error {
	s.mu.Lock()
	if s.localClosed {
		s.mu.Unlock()
		return nil
	}
	s.localClosed = true
	s.remoteClosed = true
	s.terminalErr = ErrStreamReset
	s.writeReady.Broadcast()
	s.readReady.Broadcast()
	s.mu.Unlock()

	s.writeMu.Lock()
	err := s.mux.sendAsync(Frame{Type: FrameReset, StreamID: s.id, Service: s.service})
	s.writeMu.Unlock()
	s.mux.removeStream(s.id)
	return err
}

func (s *Stream) markAccepted() {
	s.mu.Lock()
	s.isOpen = true
	s.writeReady.Broadcast()
	s.mu.Unlock()
}

func (s *Stream) isAccepted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isOpen
}

func (s *Stream) signalAccepted(err error) {
	s.acceptOne.Do(func() { s.accepted <- err })
}

// initializeReceiveWindow records and returns the one initial credit grant for
// this direction. It must be called exactly once after stream acceptance.
func (s *Stream) initializeReceiveWindow() (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.windowAdvertised {
		return 0, fmt.Errorf("%w: duplicate initial window", ErrFlowControlViolation)
	}
	s.windowAdvertised = true
	s.recvCredit = s.initialWindow
	return uint32(s.initialWindow), nil
}

// addSendCredit applies peer WINDOW credit. The first WINDOW defines the peer's
// directional receive window; later grants can replenish available credit but
// can never raise it above that initial peer-advertised bound.
func (s *Stream) addSendCredit(credit uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.localClosed || s.terminalErr != nil {
		return nil
	}
	if !s.peerWindowSet {
		if credit > maxInitialWindow {
			return fmt.Errorf("%w: peer window %d exceeds safety limit %d", ErrFlowControlViolation, credit, maxInitialWindow)
		}
		s.peerWindowSet = true
		s.peerWindow = uint64(credit)
		s.sendCredit = uint64(credit)
		s.writeReady.Broadcast()
		return nil
	}
	if s.sendCredit+uint64(credit) > s.peerWindow {
		return fmt.Errorf("%w: stream %d credit %d exceeds peer window %d", ErrFlowControlViolation, s.id, s.sendCredit+uint64(credit), s.peerWindow)
	}
	s.sendCredit += uint64(credit)
	s.writeReady.Broadcast()
	return nil
}

func (s *Stream) deliver(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	if uint32(len(payload)) > s.maxDataPayload {
		return fmt.Errorf("%w: stream %d DATA frame %d exceeds limit %d", ErrFlowControlViolation, s.id, len(payload), s.maxDataPayload)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.remoteClosed {
		return fmt.Errorf("%w: DATA after CLOSE on stream %d", ErrFlowControlViolation, s.id)
	}
	if !s.windowAdvertised {
		return fmt.Errorf("%w: DATA before WINDOW on stream %d", ErrFlowControlViolation, s.id)
	}
	if uint64(len(payload)) > s.recvCredit {
		return fmt.Errorf("%w: stream %d received %d bytes with %d credit", ErrFlowControlViolation, s.id, len(payload), s.recvCredit)
	}
	if uint64(s.readBuf.Len()+len(payload)) > s.initialWindow {
		return fmt.Errorf("%w: stream %d unread buffer exceeds %d", ErrFlowControlViolation, s.id, s.initialWindow)
	}
	s.recvCredit -= uint64(len(payload))
	_, _ = s.readBuf.Write(payload)
	s.readReady.Broadcast()
	return nil
}

func (s *Stream) remoteClose(err error) {
	s.mu.Lock()
	if s.remoteClosed && s.terminalErr != nil {
		s.mu.Unlock()
		return
	}
	s.remoteClosed = true
	if err != nil {
		s.terminalErr = err
	}
	s.readReady.Broadcast()
	s.writeReady.Broadcast()
	s.mu.Unlock()
}

func (s *Stream) isFullyClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.localClosed && s.remoteClosed
}

// flowSnapshot is test-only package state used to assert bounded buffering and
// credit invariants without exposing them as public API.
func (s *Stream) flowSnapshot() (buffered int, sendCredit, recvCredit, pending uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readBuf.Len(), s.sendCredit, s.recvCredit, s.pendingWindow
}
