package sessionlink

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxLastErrorBytes = 4096

type Manager[T any] struct {
	mu    sync.Mutex
	now   func() time.Time
	links map[ID]*slot[T]
}

type slot[T any] struct {
	snapshot Snapshot
	value    T
	hasValue bool
	changed  chan struct{}
}

func NewManager[T any]() *Manager[T] {
	return NewManagerWithClock[T](time.Now)
}

func NewManagerWithClock[T any](now func() time.Time) *Manager[T] {
	if now == nil {
		now = time.Now
	}
	return &Manager[T]{now: now, links: make(map[ID]*slot[T])}
}

func (m *Manager[T]) Begin(descriptor Descriptor, transportID TransportID, lease time.Duration) (Token, Snapshot, error) {
	if m == nil {
		return Token{}, Snapshot{}, ErrInvalidDescriptor
	}
	id, err := DeriveID(descriptor)
	if err != nil {
		return Token{}, Snapshot{}, err
	}
	if err := ValidateTransportID(transportID); err != nil {
		return Token{}, Snapshot{}, err
	}
	if err := validateLease(lease); err != nil {
		return Token{}, Snapshot{}, err
	}
	normalized, _, _, err := normalizeDescriptor(descriptor)
	if err != nil {
		return Token{}, Snapshot{}, err
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.slotLocked(id)
	m.expireLocked(s, now)
	generation := s.snapshot.Generation + 1
	s.snapshot = Snapshot{
		Version:     IDVersion,
		LinkID:      id,
		TransportID: TransportID(strings.TrimSpace(string(transportID))),
		Generation:  generation,
		LocalNode:   normalized.LocalNode,
		PeerNode:    normalized.PeerNode,
		State:       StateConnecting,
		LeaseUntil:  now.Add(lease),
		UpdatedAt:   now,
	}
	var zero T
	s.value = zero
	s.hasValue = false
	m.signalLocked(s)
	token := Token{LinkID: id, TransportID: s.snapshot.TransportID, Generation: generation}
	return token, s.snapshot, nil
}

func (m *Manager[T]) Ready(token Token, value T) (Snapshot, func(), error) {
	if m == nil {
		return Snapshot{}, nil, ErrGenerationMismatch
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.links[token.LinkID]
	if !ok || !matches(s.snapshot, token) {
		return Snapshot{}, nil, ErrGenerationMismatch
	}
	if !now.Before(s.snapshot.LeaseUntil) {
		m.disconnectLocked(s, now, ErrLeaseExpired)
		return s.snapshot, nil, ErrLeaseExpired
	}
	if s.snapshot.State != StateConnecting {
		return s.snapshot, nil, ErrGenerationMismatch
	}
	s.snapshot.State = StateReady
	s.snapshot.LastError = ""
	s.snapshot.UpdatedAt = now
	s.value = value
	s.hasValue = true
	m.signalLocked(s)
	cleanup := func() { _ = m.Withdraw(token, nil) }
	return s.snapshot, cleanup, nil
}

func (m *Manager[T]) Publish(descriptor Descriptor, transportID TransportID, lease time.Duration, value T) (Token, Snapshot, func(), error) {
	token, _, err := m.Begin(descriptor, transportID, lease)
	if err != nil {
		return Token{}, Snapshot{}, nil, err
	}
	snapshot, cleanup, err := m.Ready(token, value)
	if err != nil {
		return Token{}, Snapshot{}, nil, err
	}
	return token, snapshot, cleanup, nil
}

func (m *Manager[T]) Renew(token Token, lease time.Duration) (Snapshot, error) {
	if err := validateLease(lease); err != nil {
		return Snapshot{}, err
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.links[token.LinkID]
	if !ok || !matches(s.snapshot, token) {
		return Snapshot{}, ErrGenerationMismatch
	}
	if !now.Before(s.snapshot.LeaseUntil) {
		m.disconnectLocked(s, now, ErrLeaseExpired)
		return s.snapshot, ErrLeaseExpired
	}
	if s.snapshot.State == StateDisconnected {
		return s.snapshot, ErrNotReady
	}
	s.snapshot.LeaseUntil = now.Add(lease)
	s.snapshot.UpdatedAt = now
	m.signalLocked(s)
	return s.snapshot, nil
}

func (m *Manager[T]) Drain(token Token) (Snapshot, error) {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.links[token.LinkID]
	if !ok || !matches(s.snapshot, token) {
		return Snapshot{}, ErrGenerationMismatch
	}
	m.expireLocked(s, now)
	if s.snapshot.State != StateReady {
		return s.snapshot, ErrNotReady
	}
	s.snapshot.State = StateDraining
	s.snapshot.UpdatedAt = now
	m.signalLocked(s)
	return s.snapshot, nil
}

func (m *Manager[T]) Withdraw(token Token, cause error) bool {
	if m == nil {
		return false
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.links[token.LinkID]
	if !ok || !matches(s.snapshot, token) {
		return false
	}
	m.disconnectLocked(s, now, cause)
	return true
}

func (m *Manager[T]) Current(id ID) (T, Snapshot, bool) {
	var zero T
	if m == nil || ValidateID(id) != nil {
		return zero, Snapshot{}, false
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.links[id]
	if !ok {
		return zero, Snapshot{}, false
	}
	m.expireLocked(s, now)
	if !s.snapshot.ReadyAt(now) || !s.hasValue {
		return zero, s.snapshot, false
	}
	return s.value, s.snapshot, true
}

func (m *Manager[T]) Wait(ctx context.Context, id ID) (T, Snapshot, error) {
	var zero T
	if ctx == nil {
		ctx = context.Background()
	}
	if m == nil || ValidateID(id) != nil {
		return zero, Snapshot{}, ErrInvalidDescriptor
	}
	for {
		now := m.now()
		m.mu.Lock()
		s := m.slotLocked(id)
		m.expireLocked(s, now)
		if s.snapshot.ReadyAt(now) && s.hasValue {
			value, snapshot := s.value, s.snapshot
			m.mu.Unlock()
			return value, snapshot, nil
		}
		changed := s.changed
		leaseUntil := s.snapshot.LeaseUntil
		m.mu.Unlock()

		var timer <-chan time.Time
		var stop func()
		if !leaseUntil.IsZero() && now.Before(leaseUntil) {
			t := time.NewTimer(leaseUntil.Sub(now))
			timer = t.C
			stop = func() {
				if !t.Stop() {
					select {
					case <-t.C:
					default:
					}
				}
			}
		} else {
			stop = func() {}
		}
		select {
		case <-changed:
			stop()
		case <-timer:
		case <-ctx.Done():
			stop()
			return zero, Snapshot{}, ctx.Err()
		}
	}
}

func (m *Manager[T]) Snapshot(id ID) (Snapshot, bool) {
	if m == nil || ValidateID(id) != nil {
		return Snapshot{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.links[id]
	if !ok {
		return Snapshot{}, false
	}
	m.expireLocked(s, m.now())
	return s.snapshot, true
}

func (m *Manager[T]) List() []Snapshot {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	out := make([]Snapshot, 0, len(m.links))
	for _, s := range m.links {
		m.expireLocked(s, now)
		out = append(out, s.snapshot)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LinkID < out[j].LinkID })
	return out
}

func (m *Manager[T]) slotLocked(id ID) *slot[T] {
	if s, ok := m.links[id]; ok {
		return s
	}
	s := &slot[T]{
		snapshot: Snapshot{Version: IDVersion, LinkID: id, State: StateDisconnected, UpdatedAt: m.now()},
		changed:  make(chan struct{}),
	}
	m.links[id] = s
	return s
}

func (m *Manager[T]) signalLocked(s *slot[T]) {
	close(s.changed)
	s.changed = make(chan struct{})
}

func (m *Manager[T]) expireLocked(s *slot[T], now time.Time) {
	if s.snapshot.State == StateDisconnected || s.snapshot.LeaseUntil.IsZero() || now.Before(s.snapshot.LeaseUntil) {
		return
	}
	m.disconnectLocked(s, now, ErrLeaseExpired)
}

func (m *Manager[T]) disconnectLocked(s *slot[T], now time.Time, cause error) {
	s.snapshot.State = StateDisconnected
	s.snapshot.UpdatedAt = now
	if cause != nil {
		s.snapshot.LastError = boundedError(cause)
	} else {
		s.snapshot.LastError = ""
	}
	var zero T
	s.value = zero
	s.hasValue = false
	m.signalLocked(s)
}

func matches(snapshot Snapshot, token Token) bool {
	return snapshot.LinkID == token.LinkID && snapshot.TransportID == token.TransportID && snapshot.Generation == token.Generation
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(err.Error())
	if len(value) > maxLastErrorBytes {
		value = value[:maxLastErrorBytes]
	}
	return value
}
