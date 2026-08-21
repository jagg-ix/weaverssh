package containerstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// ProcessManagerConfig bounds the shared provider-neutral process registry.
type ProcessManagerConfig struct {
	MaxSessions          int
	DefaultMaxStdinBytes int64
	NewSessionID         func() (string, error)
}

// ProcessManager is the single lifecycle owner used by every non-terminal
// execution facade. It centralizes provider pinning, authorization, process
// handles, stream single-consumer rules, stdin quotas, and teardown.
type ProcessManager struct {
	ctx        context.Context
	cancel     context.CancelFunc
	router     *Router
	authorizer ProcessAuthorizer
	config     ProcessManagerConfig

	mu       sync.RWMutex
	sessions map[string]*ProcessSession
}

func NewProcessManager(ctx context.Context, router *Router, authorizer ProcessAuthorizer, config ProcessManagerConfig) (*ProcessManager, error) {
	if router == nil || authorizer == nil {
		return nil, errors.New("containerstream: process manager requires a router and authorizer")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = defaultProcessSessions
	}
	if config.DefaultMaxStdinBytes == 0 {
		config.DefaultMaxStdinBytes = defaultStdinBytes
	}
	if config.NewSessionID == nil {
		config.NewSessionID = randomSessionID
	}
	if config.MaxSessions < 1 || config.MaxSessions > 4096 || config.DefaultMaxStdinBytes < 1 || config.DefaultMaxStdinBytes > MaxProcessStdin {
		return nil, errors.New("containerstream: invalid process manager limits")
	}
	managerContext, cancel := context.WithCancel(ctx)
	return &ProcessManager{ctx: managerContext, cancel: cancel, router: router, authorizer: authorizer, config: config, sessions: make(map[string]*ProcessSession)}, nil
}

func (m *ProcessManager) Close() error {
	if m == nil {
		return nil
	}
	m.cancel()
	m.mu.Lock()
	sessions := make([]*ProcessSession, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.sessions = make(map[string]*ProcessSession)
	m.mu.Unlock()
	var failures []error
	for _, session := range sessions {
		failures = append(failures, session.Close())
	}
	return errors.Join(failures...)
}

func (m *ProcessManager) CreateSession(identity ProcessIdentity, target Request) (*ProcessSession, error) {
	if m == nil {
		return nil, errors.New("containerstream: process manager unavailable")
	}
	if m.ctx.Err() != nil {
		return nil, ErrProcessState
	}
	if err := validateProcessTarget(target); err != nil {
		return nil, err
	}
	target.ProviderHint = normalizeProviderName(target.ProviderHint)
	target.Options = cloneOptions(target.Options)
	for attempt := 0; attempt < 4; attempt++ {
		id, err := m.config.NewSessionID()
		if err != nil {
			return nil, fmt.Errorf("containerstream: create process session ID: %w", err)
		}
		if !targetPattern.MatchString(id) {
			return nil, errors.New("containerstream: generated unsafe process session ID")
		}
		key := processSessionKey(target.Endpoint, target.TargetID, id)
		m.mu.Lock()
		if m.ctx.Err() != nil {
			m.mu.Unlock()
			return nil, ErrProcessState
		}
		if len(m.sessions) >= m.config.MaxSessions {
			m.mu.Unlock()
			return nil, ErrProcessLimit
		}
		if _, exists := m.sessions[key]; exists {
			m.mu.Unlock()
			continue
		}
		ctx, cancel := context.WithCancel(m.ctx)
		session := &ProcessSession{
			manager: m, ctx: ctx, cancel: cancel, id: id, identity: identity, target: target, done: make(chan struct{}),
			status: ProcessStatus{Protocol: ProcessStatusProtocol, SessionID: id, State: ProcessCreated, CreatedAt: time.Now().UTC()},
		}
		m.sessions[key] = session
		m.mu.Unlock()
		return session, nil
	}
	return nil, errors.New("containerstream: could not allocate unique process session ID")
}

// RemoveSession performs generation-safe removal: a stale session pointer can
// never remove a newer handle that happens to reuse the same key.
func (m *ProcessManager) RemoveSession(session *ProcessSession) error {
	if m == nil || session == nil || session.manager != m {
		return ErrProcessNotFound
	}
	return m.removeByKey(processSessionKey(session.target.Endpoint, session.target.TargetID, session.id), session)
}

func (m *ProcessManager) removeByKey(key string, expected *ProcessSession) error {
	if m == nil {
		return ErrProcessNotFound
	}
	m.mu.Lock()
	session, ok := m.sessions[key]
	if ok && expected != nil && session != expected {
		ok = false
	}
	if ok {
		delete(m.sessions, key)
	}
	m.mu.Unlock()
	if !ok {
		return ErrProcessNotFound
	}
	return session.Close()
}

func (m *ProcessManager) lookup(key string) (*ProcessSession, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.RLock()
	session, ok := m.sessions[key]
	m.mu.RUnlock()
	return session, ok
}

func validateProcessTarget(target Request) error {
	if !targetPattern.MatchString(target.Endpoint) || !targetPattern.MatchString(target.TargetID) {
		return errors.New("containerstream: invalid process target")
	}
	provider := normalizeProviderName(target.ProviderHint)
	if provider != "" && !providerNamePattern.MatchString(provider) {
		return errors.New("containerstream: invalid process provider")
	}
	if len(target.Options) > maxOptions {
		return errors.New("containerstream: too many process options")
	}
	for name, value := range target.Options {
		if name == "provider" || !optionNamePattern.MatchString(name) || value == "" || len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("containerstream: invalid process option %q", name)
		}
	}
	return nil
}

func (s *ProcessSession) Target() Request {
	if s == nil {
		return Request{}
	}
	target := s.target
	target.Options = cloneOptions(target.Options)
	return target
}

func (s *ProcessSession) Start(ctx context.Context, request StartRequest) error {
	return s.start(ctx, request)
}
func (s *ProcessSession) OpenStdin() (io.WriteCloser, error) { return s.openStdin() }
func (s *ProcessSession) Stdout() (io.ReadCloser, error)     { return s.openOutput(ProcessFileStdout) }
func (s *ProcessSession) Stderr() (io.ReadCloser, error)     { return s.openOutput(ProcessFileStderr) }
func (s *ProcessSession) Signal(ctx context.Context, signal ProcessSignal) error {
	return s.signal(ctx, signal)
}
func (s *ProcessSession) Resize(ctx context.Context, size TerminalSize) error {
	return s.resize(ctx, size)
}
func (s *ProcessSession) CloseStdin() error { return s.closeStdin() }
func (s *ProcessSession) Close() error      { return s.close() }

func (s *ProcessSession) Wait(ctx context.Context) (ProcessStatus, error) {
	if s == nil {
		return ProcessStatus{}, ErrProcessNotFound
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-s.done:
		return s.Status(), nil
	case <-ctx.Done():
		return s.Status(), ctx.Err()
	}
}

func (s *ProcessSession) finish() {
	if s != nil {
		s.doneOnce.Do(func() { close(s.done) })
	}
}
