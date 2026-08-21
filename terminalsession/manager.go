package terminalsession

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"weaverssh/containerstream"
)

const (
	defaultDetachTTL   = 60 * time.Minute
	defaultReplayBytes = 4 << 20
	defaultMaxSessions = 256
	defaultSendTimeout = 15 * time.Second
	defaultMaxStdin    = int64(64 << 20)
	maxReplayBytes     = 64 << 20
	maxDetachTTL       = 24 * time.Hour
	maxSendTimeout     = time.Minute
	outputChunkBytes   = 32 << 10
	outputDrainTimeout = 2 * time.Second
)

type stoppableTimer interface{ Stop() bool }
type afterFunc func(time.Duration, func()) stoppableTimer

type ManagerConfig struct {
	Authorizer  Authorizer
	Spawner     Spawner
	Recorder    Recorder
	Observer    Observer
	MaxSessions int
	SendTimeout time.Duration
	Now         func() time.Time
	after       afterFunc
}

// Manager owns PTYs independently of individual tunnel lifetimes.
type Manager struct {
	ctx         context.Context
	cancel      context.CancelFunc
	authorize   Authorizer
	spawner     Spawner
	recorder    Recorder
	observer    Observer
	max         int
	now         func() time.Time
	after       afterFunc
	sendTimeout time.Duration

	mu       sync.RWMutex
	sessions map[string]*session
}

type session struct {
	ioMu   sync.Mutex
	sendMu sync.Mutex
	mu     sync.Mutex

	id           string
	state        State
	generation   uint64
	ownerHash    [sha256.Size]byte
	tokenHash    [sha256.Size]byte
	identity     Identity
	target       containerstream.Request
	action       string
	terminal     Terminal
	attachment   Attachment
	ring         *replayRing
	nextSequence uint64
	detachTTL    time.Duration
	ttl          stoppableTimer
	ttlEpoch     uint64
	detachedAt   time.Time
	recording    RecordingMode
	maxStdin     int64
	stdinBytes   int64
	exitCode     *int
	outputDone   chan struct{}
}

func NewManager(parent context.Context, config ManagerConfig) (*Manager, error) {
	if config.Authorizer == nil || config.Spawner == nil {
		return nil, errors.New("terminalsession: authorizer and spawner are required")
	}
	if parent == nil {
		parent = context.Background()
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = defaultMaxSessions
	}
	if config.MaxSessions < 1 || config.MaxSessions > 65536 {
		return nil, errors.New("terminalsession: invalid maximum session count")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.SendTimeout == 0 {
		config.SendTimeout = defaultSendTimeout
	}
	if config.SendTimeout < 0 || config.SendTimeout > maxSendTimeout {
		return nil, errors.New("terminalsession: invalid attachment send timeout")
	}
	if config.after == nil {
		config.after = func(duration time.Duration, callback func()) stoppableTimer {
			return time.AfterFunc(duration, callback)
		}
	}
	ctx, cancel := context.WithCancel(parent)
	return &Manager{
		ctx: ctx, cancel: cancel, authorize: config.Authorizer, spawner: config.Spawner,
		recorder: config.Recorder, observer: config.Observer, max: config.MaxSessions,
		now: config.Now, after: config.after, sendTimeout: config.SendTimeout,
		sessions: make(map[string]*session),
	}, nil
}

// Connect provisions or reattaches a terminal and binds attachment to the new
// generation. The resume token is returned only inside the initial READY frame.
func (m *Manager) Connect(ctx context.Context, identity Identity, request OpenRequest, attachment Attachment) (Lease, error) {
	if m == nil || attachment == nil {
		return Lease{}, ErrInvalidRequest
	}
	if err := identity.Validate(); err != nil {
		return Lease{}, err
	}
	if err := request.validate(); err != nil {
		return Lease{}, err
	}
	if request.Operation == OperationConnect {
		return m.open(ctx, identity, request, attachment)
	}
	return m.reattach(ctx, identity, request, attachment)
}

func (m *Manager) open(ctx context.Context, identity Identity, request OpenRequest, attachment Attachment) (Lease, error) {
	grant, err := m.authorize.AuthorizeOpen(ctx, identity, request)
	if err != nil {
		return Lease{}, fmt.Errorf("%w: %v", ErrDenied, err)
	}
	if err := normalizeGrant(&grant); err != nil {
		return Lease{}, err
	}
	if grant.RecordingMode == RecordingRequired && m.recorder == nil {
		return Lease{}, errors.New("terminalsession: required recording sink is unavailable")
	}
	target, err := containerstream.ParseURI(request.TargetURI)
	if err != nil {
		return Lease{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	sessionID, token, err := m.reserveSession(identity, target, request.Action, grant)
	if err != nil {
		return Lease{}, err
	}
	s := m.lookup(sessionID)
	terminal, err := m.spawner.Spawn(m.ctx, target, grant.Process)
	if err != nil {
		m.terminateSession(s, "provision-failed")
		return Lease{}, err
	}
	s.mu.Lock()
	s.terminal = terminal
	s.attachment = attachment
	s.generation = 1
	transition, err := m.transitionLocked(s, StateActive, "provisioned")
	ready := s.readyLocked(token)
	s.mu.Unlock()
	if err != nil {
		m.terminateSession(s, "invalid-provision-transition")
		return Lease{}, err
	}
	m.observe(transition)
	if err := m.sendJSON(ctx, attachment, FrameReady, ready); err != nil {
		m.terminateSession(s, "initial-ready-failed")
		return Lease{}, err
	}
	lease := Lease{SessionID: sessionID, Generation: 1}
	go m.pumpOutput(s)
	go m.waitProcess(s)
	return lease, nil
}

func (m *Manager) reserveSession(identity Identity, target containerstream.Request, action string, grant Grant) (string, string, error) {
	for attempts := 0; attempts < 4; attempts++ {
		sessionID, err := randomText(18)
		if err != nil {
			return "", "", err
		}
		token, err := randomText(32)
		if err != nil {
			return "", "", err
		}
		s := &session{
			id: sessionID, state: StateProvisioning, identity: identity, target: target,
			action: strings.TrimSpace(action), ownerHash: identityFingerprint(identity),
			tokenHash: sha256.Sum256([]byte(token)), ring: newReplayRing(grant.ReplayBytes),
			nextSequence: 1, detachTTL: grant.DetachTTL, recording: grant.RecordingMode,
			maxStdin:   grant.Process.MaxStdinBytes,
			outputDone: make(chan struct{}),
		}
		m.mu.Lock()
		active := 0
		for id, existing := range m.sessions {
			existing.mu.Lock()
			terminated := existing.state == StateTerminated
			if !terminated {
				active++
			}
			existing.mu.Unlock()
			if terminated {
				delete(m.sessions, id)
			}
		}
		if active >= m.max {
			m.mu.Unlock()
			return "", "", errors.New("terminalsession: session limit reached")
		}
		if _, exists := m.sessions[sessionID]; !exists {
			m.sessions[sessionID] = s
			m.mu.Unlock()
			return sessionID, token, nil
		}
		m.mu.Unlock()
	}
	return "", "", errors.New("terminalsession: could not allocate unique session id")
}

func (m *Manager) reattach(ctx context.Context, identity Identity, request OpenRequest, attachment Attachment) (Lease, error) {
	s := m.lookup(strings.TrimSpace(request.SessionID))
	if s == nil {
		return Lease{}, ErrNotFound
	}
	ownerHash := identityFingerprint(identity)
	tokenHash := tokenDigest(request.ResumeToken)
	if subtle.ConstantTimeCompare(s.ownerHash[:], ownerHash[:]) != 1 || subtle.ConstantTimeCompare(s.tokenHash[:], tokenHash[:]) != 1 {
		return Lease{}, ErrDenied
	}
	snapshot := m.snapshotSession(s)
	if err := m.authorize.AuthorizeReattach(ctx, identity, snapshot); err != nil {
		return Lease{}, fmt.Errorf("%w: %v", ErrDenied, err)
	}

	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.mu.Lock()
	if s.state == StateTerminated {
		s.mu.Unlock()
		return Lease{}, ErrTerminated
	}
	if s.state != StateActive && s.state != StateDetached {
		s.mu.Unlock()
		return Lease{}, fmt.Errorf("terminalsession: session is %s", s.state)
	}
	transition, err := m.transitionLocked(s, StateRecovering, "reattach")
	if err != nil {
		s.mu.Unlock()
		return Lease{}, err
	}
	old := s.attachment
	s.attachment = attachment
	s.generation++
	lease := Lease{SessionID: s.id, Generation: s.generation}
	if s.ttl != nil {
		s.ttl.Stop()
		s.ttl = nil
	}
	s.ttlEpoch++
	ready := s.readyLocked("")
	replay := s.ring.after(request.AfterSequence)
	s.mu.Unlock()
	m.observe(transition)
	if old != nil && old != attachment {
		_ = old.Close()
	}
	if err := m.sendJSON(ctx, attachment, FrameReady, ready); err != nil {
		m.failRecovery(s, lease, "reattach-ready-failed")
		return Lease{}, err
	}
	for _, frame := range replay {
		if err := m.sendFrame(ctx, attachment, frame); err != nil {
			m.failRecovery(s, lease, "reattach-replay-failed")
			return Lease{}, err
		}
	}
	s.mu.Lock()
	if s.state != StateRecovering || s.generation != lease.Generation || s.attachment != attachment {
		s.mu.Unlock()
		return Lease{}, ErrStaleLease
	}
	activeTransition, err := m.transitionLocked(s, StateActive, "reattach-complete")
	s.mu.Unlock()
	if err != nil {
		return Lease{}, err
	}
	m.observe(activeTransition)
	return lease, nil
}

func (m *Manager) failRecovery(s *session, lease Lease, reason string) {
	s.mu.Lock()
	if s.state != StateRecovering || s.generation != lease.Generation {
		s.mu.Unlock()
		return
	}
	attachment := s.attachment
	s.attachment = nil
	transition, _ := m.transitionLocked(s, StateDetached, reason)
	s.detachedAt = m.now().UTC()
	m.armTTLLocked(s)
	s.mu.Unlock()
	if attachment != nil {
		_ = attachment.Close()
	}
	m.observe(transition)
}

// Input writes bytes only from the current attachment generation.
func (m *Manager) Input(lease Lease, payload []byte) error {
	s := m.lookup(lease.SessionID)
	if s == nil {
		return ErrNotFound
	}
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	s.mu.Lock()
	if s.state != StateActive || s.generation != lease.Generation || s.terminal == nil {
		s.mu.Unlock()
		return ErrStaleLease
	}
	if int64(len(payload)) > s.maxStdin-s.stdinBytes {
		s.mu.Unlock()
		return errors.New("terminalsession: authorized stdin limit exceeded")
	}
	// Reserve the complete frame while holding the lifecycle lock. A provider
	// error cannot otherwise let a client retry partially consumed bytes past
	// the authorization cap.
	s.stdinBytes += int64(len(payload))
	terminal := s.terminal
	s.mu.Unlock()
	for len(payload) > 0 {
		n, err := terminal.WriteInput(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func (m *Manager) Resize(ctx context.Context, lease Lease, size TerminalSize) error {
	if err := size.Validate(); err != nil {
		return err
	}
	s := m.lookup(lease.SessionID)
	if s == nil {
		return ErrNotFound
	}
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	s.mu.Lock()
	if s.state != StateActive || s.generation != lease.Generation || s.terminal == nil {
		s.mu.Unlock()
		return ErrStaleLease
	}
	terminal := s.terminal
	s.mu.Unlock()
	return terminal.Resize(ctx, size)
}

// Detach is idempotent for stale handlers: an old connection can never detach
// a newer generation after an ACTIVE-to-RECOVERING preemption.
func (m *Manager) Detach(lease Lease, reason string) error {
	s := m.lookup(lease.SessionID)
	if s == nil {
		return ErrNotFound
	}
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.mu.Lock()
	if s.generation != lease.Generation {
		s.mu.Unlock()
		return ErrStaleLease
	}
	if s.state == StateDetached || s.state == StateDetaching {
		s.mu.Unlock()
		return nil
	}
	if s.state != StateActive && s.state != StateRecovering {
		s.mu.Unlock()
		return ErrStaleLease
	}
	var transitions []Transition
	if s.state == StateActive {
		transition, _ := m.transitionLocked(s, StateDetaching, reason)
		transitions = append(transitions, transition)
	}
	attachment := s.attachment
	s.attachment = nil
	transition, err := m.transitionLocked(s, StateDetached, reason)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	transitions = append(transitions, transition)
	s.detachedAt = m.now().UTC()
	m.armTTLLocked(s)
	s.mu.Unlock()
	if attachment != nil {
		_ = attachment.Close()
	}
	for _, item := range transitions {
		m.observe(item)
	}
	return nil
}

func (m *Manager) Terminate(lease Lease, reason string) error {
	s := m.lookup(lease.SessionID)
	if s == nil {
		return ErrNotFound
	}
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.mu.Lock()
	stale := s.generation != lease.Generation
	attachment := s.attachment
	active := s.state == StateActive && attachment != nil
	s.mu.Unlock()
	if stale {
		return ErrStaleLease
	}
	var acknowledgementError error
	if active {
		acknowledgementError = m.sendJSON(m.ctx, attachment, FrameExit, Exit{
			Protocol: ProtocolVersion, ExitCode: -1, Reason: strings.TrimSpace(reason),
		})
	}
	m.terminateSessionLockedIO(s, reason)
	return acknowledgementError
}

func (m *Manager) armTTLLocked(s *session) {
	if s.ttl != nil {
		s.ttl.Stop()
	}
	s.ttlEpoch++
	epoch := s.ttlEpoch
	s.ttl = m.after(s.detachTTL, func() { m.expire(s, epoch) })
}

func (m *Manager) expire(s *session, epoch uint64) {
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.mu.Lock()
	if s.state != StateDetached || s.ttlEpoch != epoch {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	m.terminateSessionLockedIO(s, "detach-ttl-expired")
}

func (m *Manager) pumpOutput(s *session) {
	defer close(s.outputDone)
	buffer := make([]byte, outputChunkBytes)
	s.mu.Lock()
	terminal := s.terminal
	s.mu.Unlock()
	if terminal == nil {
		return
	}
	output := terminal.Output()
	if output == nil {
		m.terminateSession(s, "pty-output-unavailable")
		return
	}
	for {
		s.mu.Lock()
		state := s.state
		s.mu.Unlock()
		if state == StateTerminated {
			return
		}
		n, err := output.Read(buffer)
		if n > 0 {
			if !m.handleOutput(s, append([]byte(nil), buffer[:n]...)) {
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				m.terminateSession(s, "pty-output-failed")
			}
			return
		}
	}
}

// handleOutput shares the attachment-send lock with recovery. Therefore a
// frame is either included in the recovery snapshot or appended after recovery
// becomes ACTIVE and sent live; it cannot fall into the gap between both.
func (m *Manager) handleOutput(s *session, payload []byte) bool {
	s.sendMu.Lock()
	s.mu.Lock()
	if s.state == StateTerminated {
		s.mu.Unlock()
		s.sendMu.Unlock()
		return false
	}
	sequence := s.nextSequence
	s.nextSequence++
	frame := Frame{Type: FrameOutput, Sequence: sequence, Payload: payload}
	s.ring.append(frame)
	recording := s.recording
	attachment := Attachment(nil)
	lease := Lease{SessionID: s.id, Generation: s.generation}
	if s.state == StateActive {
		attachment = s.attachment
	}
	s.mu.Unlock()

	if recording != RecordingOff && m.recorder != nil {
		recordErr := m.recorder.RecordOutput(m.ctx, OutputRecord{SessionID: s.id, Sequence: sequence, Payload: append([]byte(nil), payload...), At: m.now().UTC()})
		if recordErr != nil && recording == RecordingRequired {
			s.sendMu.Unlock()
			m.terminateSession(s, "required-recording-failed")
			return false
		}
	}
	var sendErr error
	if attachment != nil {
		sendErr = m.sendFrame(m.ctx, attachment, frame)
	}
	s.sendMu.Unlock()
	if sendErr != nil {
		go func() { _ = m.Detach(lease, "tunnel-write-failed") }()
	}
	return true
}

func (m *Manager) waitProcess(s *session) {
	s.mu.Lock()
	terminal := s.terminal
	s.mu.Unlock()
	if terminal == nil {
		return
	}
	result := terminal.Wait()
	// Process wait and pipe drain are separate asynchronous events. Preserve
	// terminal byte order by allowing the output pump to consume the provider's
	// final bytes before EXIT. A broken provider cannot block teardown forever.
	timer := time.NewTimer(outputDrainTimeout)
	select {
	case <-s.outputDone:
		if !timer.Stop() {
			<-timer.C
		}
	case <-timer.C:
	case <-m.ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
	}
	s.mu.Lock()
	exitCode := result.ExitCode
	s.exitCode = &exitCode
	s.mu.Unlock()
	m.notifyExit(s, exitCode)
	m.terminateSession(s, "process-exited")
}

func (m *Manager) notifyExit(s *session, exitCode int) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.mu.Lock()
	if s.state != StateActive || s.attachment == nil {
		s.mu.Unlock()
		return
	}
	attachment := s.attachment
	s.mu.Unlock()
	_ = m.sendJSON(m.ctx, attachment, FrameExit, Exit{Protocol: ProtocolVersion, ExitCode: exitCode, Reason: "process-exited"})
}

func (m *Manager) terminateSession(s *session, reason string) {
	if s == nil {
		return
	}
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	m.terminateSessionLockedIO(s, reason)
}

func (m *Manager) terminateSessionLockedIO(s *session, reason string) {
	s.mu.Lock()
	if s.state == StateTerminated {
		s.mu.Unlock()
		return
	}
	transition, _ := m.transitionLocked(s, StateTerminated, reason)
	if s.ttl != nil {
		s.ttl.Stop()
		s.ttl = nil
	}
	s.ttlEpoch++
	attachment, terminal := s.attachment, s.terminal
	s.attachment, s.terminal = nil, nil
	s.mu.Unlock()
	if attachment != nil {
		_ = attachment.Close()
	}
	if terminal != nil {
		_ = terminal.Close()
	}
	m.observe(transition)
}

func (m *Manager) transitionLocked(s *session, to State, reason string) (Transition, error) {
	from := s.state
	allowed := false
	switch from {
	case StateProvisioning:
		allowed = to == StateActive || to == StateTerminated
	case StateActive:
		allowed = to == StateDetaching || to == StateRecovering || to == StateTerminated
	case StateDetaching:
		allowed = to == StateDetached || to == StateTerminated
	case StateDetached:
		allowed = to == StateRecovering || to == StateTerminated
	case StateRecovering:
		allowed = to == StateActive || to == StateDetached || to == StateTerminated
	}
	if !allowed {
		return Transition{}, fmt.Errorf("terminalsession: invalid transition %s -> %s", from, to)
	}
	s.state = to
	return Transition{SessionID: s.id, From: from, To: to, Reason: reason, At: m.now().UTC()}, nil
}

func (m *Manager) Snapshot(sessionID string) (Snapshot, bool) {
	s := m.lookup(strings.TrimSpace(sessionID))
	if s == nil {
		return Snapshot{}, false
	}
	return m.snapshotSession(s), true
}

func (m *Manager) snapshotSession(s *session) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	floor, ceiling := s.ring.bounds(s.nextSequence)
	snapshot := Snapshot{
		ID: s.id, State: s.state, Generation: s.generation, Principal: s.identity.Principal,
		SourceNode: s.identity.SourceNode, TargetURI: s.target.URI, Action: s.action,
		ReplayFloor: floor, ReplayCeiling: ceiling, DroppedBytes: s.ring.dropped,
	}
	if s.terminal != nil {
		snapshot.Provider = s.terminal.ProviderName()
	}
	if s.exitCode != nil {
		exitCode := *s.exitCode
		snapshot.ExitCode = &exitCode
	}
	if !s.detachedAt.IsZero() {
		snapshot.DetachedAtUnix = s.detachedAt.Unix()
	}
	return snapshot
}

func (s *session) readyLocked(token string) Ready {
	floor, ceiling := s.ring.bounds(s.nextSequence)
	return Ready{
		Protocol: ProtocolVersion, SessionID: s.id, ResumeToken: token,
		Generation: s.generation, State: s.state, ReplayFloor: floor,
		ReplayCeiling: ceiling, DroppedBytes: s.ring.dropped,
	}
}

// PruneTerminated removes terminal tombstones selected by the caller.
func (m *Manager) PruneTerminated() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for id, s := range m.sessions {
		s.mu.Lock()
		terminated := s.state == StateTerminated
		s.mu.Unlock()
		if terminated {
			delete(m.sessions, id)
			removed++
		}
	}
	return removed
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.cancel()
	m.mu.RLock()
	sessions := make([]*session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.RUnlock()
	for _, s := range sessions {
		m.terminateSession(s, "manager-closed")
	}
	return nil
}

func (m *Manager) lookup(id string) *session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

func (m *Manager) observe(transition Transition) {
	if m.observer != nil && transition.SessionID != "" {
		_ = m.observer.Observe(m.ctx, transition)
	}
}

func normalizeGrant(grant *Grant) error {
	if grant.DetachTTL == 0 {
		grant.DetachTTL = defaultDetachTTL
	}
	if grant.ReplayBytes == 0 {
		grant.ReplayBytes = defaultReplayBytes
	}
	if grant.DetachTTL < 0 || grant.DetachTTL > maxDetachTTL || grant.ReplayBytes < 0 || grant.ReplayBytes > maxReplayBytes {
		return errors.New("terminalsession: authorization grant exceeds session limits")
	}
	if grant.RecordingMode == "" {
		grant.RecordingMode = RecordingOff
	}
	if grant.RecordingMode != RecordingOff && grant.RecordingMode != RecordingBestEffort && grant.RecordingMode != RecordingRequired {
		return errors.New("terminalsession: invalid recording mode")
	}
	if grant.Process.MaxStdinBytes == 0 {
		grant.Process.MaxStdinBytes = defaultMaxStdin
	}
	if grant.Process.MaxStdinBytes < 1 || grant.Process.MaxStdinBytes > containerstream.MaxProcessStdin {
		return errors.New("terminalsession: invalid stdin limit")
	}
	grant.Process.TTY = true
	return nil
}

func sendJSON(ctx context.Context, attachment Attachment, frameType FrameType, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return attachment.Send(ctx, Frame{Type: frameType, Payload: payload})
}

func (m *Manager) sendJSON(ctx context.Context, attachment Attachment, frameType FrameType, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return m.sendFrame(ctx, attachment, Frame{Type: frameType, Payload: payload})
}

func (m *Manager) sendFrame(ctx context.Context, attachment Attachment, frame Frame) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if m.sendTimeout <= 0 {
		return attachment.Send(ctx, frame)
	}
	sendCtx, cancel := context.WithTimeout(ctx, m.sendTimeout)
	defer cancel()
	return attachment.Send(sendCtx, frame)
}

func randomText(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func identityFingerprint(identity Identity) [sha256.Size]byte {
	return sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(identity.Principal), strings.TrimSpace(identity.SourceNode),
		strings.TrimSpace(identity.SourceBinding), strings.ToLower(strings.TrimSpace(identity.ChainSHA256)),
	}, "\x00")))
}

func tokenDigest(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(strings.TrimSpace(token)))
}
