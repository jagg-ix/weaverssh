package socketcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"weaverssh/socketengine"
)

type EngineFactory func(socketengine.Config) (*socketengine.Engine, error)
type ConfigLoader func(string) (socketengine.Config, error)

type SupervisorConfig struct {
	ConfigPath      string
	Load            ConfigLoader
	NewEngine       EngineFactory
	ShutdownTimeout time.Duration
}

type Status struct {
	Protocol        string             `json:"protocol"`
	Generation      uint64             `json:"generation"`
	ConfigPath      string             `json:"config_path"`
	ConfigSHA256    string             `json:"config_sha256"`
	StartedAt       time.Time          `json:"started_at"`
	ReloadedAt      time.Time          `json:"reloaded_at,omitempty"`
	LastReloadError string             `json:"last_reload_error,omitempty"`
	Plan            socketengine.Plan  `json:"plan"`
	Stats           socketengine.Stats `json:"stats"`
	Stopping        bool               `json:"stopping"`
}

type engineSlot struct {
	generation uint64
	path       string
	config     socketengine.Config
	plan       socketengine.Plan
	digest     string
	engine     *socketengine.Engine
	cancel     context.CancelFunc
	done       chan struct{}
	startedAt  time.Time
	errMu      sync.RWMutex
	runErr     error
}

func (s *engineSlot) setRunError(err error) {
	s.errMu.Lock()
	s.runErr = err
	s.errMu.Unlock()
}

func (s *engineSlot) runError() error {
	if s == nil {
		return nil
	}
	s.errMu.RLock()
	defer s.errMu.RUnlock()
	return s.runErr
}

type Supervisor struct {
	config SupervisorConfig
	ctx    context.Context
	cancel context.CancelFunc

	mu              sync.RWMutex
	current         *engineSlot
	lastReload      time.Time
	lastReloadError string
	stopping        bool
	reloadMu        sync.Mutex
}

func NewSupervisor(config SupervisorConfig) (*Supervisor, error) {
	config.ConfigPath = strings.TrimSpace(config.ConfigPath)
	if config.ConfigPath == "" {
		return nil, errors.New("socketcontrol: initial config path is required")
	}
	if config.Load == nil {
		config.Load = socketengine.LoadConfigFile
	}
	if config.NewEngine == nil {
		return nil, errors.New("socketcontrol: engine factory is required")
	}
	if config.ShutdownTimeout <= 0 {
		config.ShutdownTimeout = 10 * time.Second
	}
	return &Supervisor{config: config}, nil
}

func (s *Supervisor) Start(ctx context.Context) error {
	if s == nil {
		return errors.New("socketcontrol: nil supervisor")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.ctx != nil {
		s.mu.Unlock()
		return errors.New("socketcontrol: supervisor already started")
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()
	config, plan, digest, err := s.load(s.config.ConfigPath)
	if err != nil {
		return err
	}
	slot, err := s.startSlot(s.ctx, 1, s.config.ConfigPath, config, plan, digest)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.current = slot
	s.mu.Unlock()
	go func() {
		<-s.ctx.Done()
		stopCtx, cancel := context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
		defer cancel()
		_ = s.stopCurrent(stopCtx)
	}()
	return nil
}

func (s *Supervisor) Wait() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	ctx := s.ctx
	s.mu.RUnlock()
	if ctx == nil {
		return errors.New("socketcontrol: supervisor not started")
	}
	<-ctx.Done()
	s.mu.RLock()
	current := s.current
	s.mu.RUnlock()
	if current == nil {
		return nil
	}
	select {
	case <-current.done:
		if err := current.runError(); !normalEngineStop(err) {
			return err
		}
		return nil
	case <-time.After(s.config.ShutdownTimeout):
		return context.DeadlineExceeded
	}
}

func (s *Supervisor) Handler(ctx context.Context, request Request) (any, error) {
	switch request.Action {
	case ActionStatus:
		return s.Status(), nil
	case ActionReload:
		return s.Reload(ctx, request.Config)
	case ActionStop:
		status := s.Status()
		go func() {
			timer := time.NewTimer(25 * time.Millisecond)
			defer timer.Stop()
			<-timer.C
			stopCtx, cancel := context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
			defer cancel()
			_ = s.Stop(stopCtx)
		}()
		return status, nil
	default:
		return nil, ErrInvalid
	}
}

func (s *Supervisor) Status() Status {
	if s == nil {
		return Status{Protocol: ProtocolVersion}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	status := Status{Protocol: ProtocolVersion, ReloadedAt: s.lastReload, LastReloadError: s.lastReloadError, Stopping: s.stopping}
	if s.current == nil {
		return status
	}
	status.Generation = s.current.generation
	status.ConfigPath = s.current.path
	status.ConfigSHA256 = s.current.digest
	status.StartedAt = s.current.startedAt
	status.Plan = s.current.plan
	status.Stats = s.current.engine.Snapshot()
	return status
}

func (s *Supervisor) Reload(ctx context.Context, requestedPath string) (Status, error) {
	if s == nil {
		return Status{}, errors.New("socketcontrol: nil supervisor")
	}
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	s.mu.RLock()
	current := s.current
	root := s.ctx
	s.mu.RUnlock()
	if root == nil || current == nil {
		return Status{}, errors.New("socketcontrol: supervisor not started")
	}
	path := strings.TrimSpace(requestedPath)
	if path == "" {
		path = current.path
	}
	config, plan, digest, err := s.load(path)
	if err != nil {
		s.recordReloadError(err)
		return s.Status(), err
	}
	if digest == current.digest {
		return s.Status(), nil
	}
	generation := current.generation + 1
	var replacement *engineSlot
	if addressesDisjoint(current.plan.Addresses, plan.Addresses) {
		replacement, err = s.startSlot(root, generation, path, config, plan, digest)
		if err == nil {
			stopCtx, cancel := context.WithTimeout(ctxOrBackground(ctx), s.config.ShutdownTimeout)
			stopErr := s.stopSlot(stopCtx, current)
			cancel()
			if stopErr != nil {
				rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
				_ = s.stopSlot(rollbackCtx, replacement)
				rollbackCancel()
				err = fmt.Errorf("retire previous generation: %w", stopErr)
			}
		}
	} else {
		stopCtx, cancel := context.WithTimeout(ctxOrBackground(ctx), s.config.ShutdownTimeout)
		stopErr := s.stopSlot(stopCtx, current)
		cancel()
		if stopErr != nil {
			err = stopErr
		} else {
			replacement, err = s.startSlot(root, generation, path, config, plan, digest)
		}
		if err != nil {
			rollback, rollbackErr := s.startSlot(root, current.generation, current.path, current.config, current.plan, current.digest)
			if rollbackErr == nil {
				s.mu.Lock()
				s.current = rollback
				s.mu.Unlock()
			} else {
				err = fmt.Errorf("reload failed: %v; rollback failed: %w", err, rollbackErr)
			}
		}
	}
	if err != nil {
		s.recordReloadError(err)
		return s.Status(), err
	}
	s.mu.Lock()
	s.current = replacement
	s.lastReload = time.Now()
	s.lastReloadError = ""
	s.mu.Unlock()
	return s.Status(), nil
}

func (s *Supervisor) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.stopping = true
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return s.stopCurrent(ctxOrBackground(ctx))
}

func (s *Supervisor) stopCurrent(ctx context.Context) error {
	s.mu.RLock()
	current := s.current
	s.mu.RUnlock()
	return s.stopSlot(ctx, current)
}

func (s *Supervisor) stopSlot(ctx context.Context, slot *engineSlot) error {
	if slot == nil {
		return nil
	}
	if slot.cancel != nil {
		slot.cancel()
	}
	err := slot.engine.Stop(ctx)
	select {
	case <-slot.done:
		if runErr := slot.runError(); err == nil && !normalEngineStop(runErr) {
			err = runErr
		}
	case <-ctx.Done():
		if err == nil {
			err = ctx.Err()
		}
	}
	return err
}

func (s *Supervisor) load(path string) (socketengine.Config, socketengine.Plan, string, error) {
	config, err := s.config.Load(path)
	if err != nil {
		return socketengine.Config{}, socketengine.Plan{}, "", err
	}
	plan, err := socketengine.Inspect(config)
	if err != nil {
		return socketengine.Config{}, socketengine.Plan{}, "", err
	}
	payload, err := json.Marshal(plan)
	if err != nil {
		return socketengine.Config{}, socketengine.Plan{}, "", err
	}
	sum := sha256.Sum256(payload)
	return config, plan, hex.EncodeToString(sum[:]), nil
}

func (s *Supervisor) startSlot(parent context.Context, generation uint64, path string, config socketengine.Config, plan socketengine.Plan, digest string) (*engineSlot, error) {
	engine, err := s.config.NewEngine(config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	slot := &engineSlot{generation: generation, path: path, config: config, plan: plan, digest: digest, engine: engine, cancel: cancel, done: make(chan struct{}), startedAt: time.Now()}
	go func() {
		slot.setRunError(engine.Run(ctx))
		close(slot.done)
	}()
	select {
	case <-engine.Ready():
		if bootErr := engine.BootError(); bootErr != nil {
			cancel()
			return nil, bootErr
		}
		select {
		case <-slot.done:
			cancel()
			runErr := slot.runError()
			if runErr == nil {
				runErr = errors.New("socketcontrol: engine stopped during startup")
			}
			return nil, runErr
		default:
		}
	case <-slot.done:
		cancel()
		runErr := slot.runError()
		if runErr == nil {
			runErr = errors.New("socketcontrol: engine stopped before ready")
		}
		return nil, runErr
	case <-parent.Done():
		cancel()
		return nil, parent.Err()
	}
	return slot, nil
}

func (s *Supervisor) recordReloadError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.lastReloadError = ""
		return
	}
	s.lastReloadError = err.Error()
}

func addressesDisjoint(left, right []string) bool {
	seen := map[string]bool{}
	for _, address := range left {
		seen[address] = true
	}
	for _, address := range right {
		if seen[address] {
			return false
		}
	}
	return true
}

func normalEngineStop(err error) bool { return err == nil || errors.Is(err, context.Canceled) }
func ctxOrBackground(ctx context.Context) context.Context { if ctx == nil { return context.Background() }; return ctx }
func SortedAddresses(plan socketengine.Plan) []string { addresses := append([]string(nil), plan.Addresses...); sort.Strings(addresses); return addresses }
