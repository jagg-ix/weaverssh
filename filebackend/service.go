package filebackend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

var ErrReadOnly = errors.New("filebackend: read-only backend")

// API is the backend boundary consumed by protocol servers and embedders.
type API interface {
	Describe() Description
	Begin(context.Context, Event) (Pending, error)
	Complete(context.Context, Pending, error, []string)
	Execute(context.Context, Event, []string, func(Backend) error) error
	ObserveQID(relative string, path uint64, version uint32)
	QID(relative string, info os.FileInfo) (uint64, uint32)
	Resolve(relative string) (string, error)
	Close() error
}

type Config struct {
	Backend      Backend
	CoreStore    Store
	Hooks        *Registry
	ReadOnly     bool
	CoreReporter func(error)
}

type Description struct {
	Backend  string       `json:"backend"`
	Root     string       `json:"root"`
	ReadOnly bool         `json:"read_only"`
	Hooks    bool         `json:"hooks"`
	Core     CoreSnapshot `json:"core"`
}

type Pending struct {
	event Event
	start time.Time
}

func (p Pending) Event() Event { return cloneEvent(p.event) }

// Service composes one filesystem backend, durable core, and hook registry.
type Service struct {
	backend      Backend
	core         *Core
	hooks        *Registry
	readOnly     bool
	coreReporter func(error)
}

func New(config Config) (*Service, error) {
	if config.Backend == nil {
		return nil, errors.New("filebackend: backend is required")
	}
	if strings.TrimSpace(config.Backend.Name()) == "" || strings.TrimSpace(config.Backend.Root()) == "" {
		return nil, errors.New("filebackend: invalid backend identity")
	}
	core, err := NewCore(config.CoreStore)
	if err != nil {
		return nil, fmt.Errorf("filebackend: initialize core: %w", err)
	}
	return &Service{
		backend: config.Backend, core: core, hooks: config.Hooks,
		readOnly: config.ReadOnly, coreReporter: config.CoreReporter,
	}, nil
}

func NewOSService(root string, readOnly bool, store Store, hooks *Registry) (*Service, error) {
	backend, err := NewOSBackend(root)
	if err != nil {
		return nil, err
	}
	return New(Config{Backend: backend, CoreStore: store, Hooks: hooks, ReadOnly: readOnly})
}

func (s *Service) Describe() Description {
	if s == nil {
		return Description{}
	}
	return Description{
		Backend: s.backend.Name(), Root: s.backend.Root(), ReadOnly: s.readOnly,
		Hooks: s.hooks != nil && !s.hooks.Empty(), Core: s.core.Snapshot(),
	}
}

func (s *Service) Resolve(relative string) (string, error) {
	if s == nil || s.backend == nil {
		return "", errors.New("filebackend: incomplete service")
	}
	return s.backend.Resolve(relative)
}

func (s *Service) QID(relative string, info os.FileInfo) (uint64, uint32) {
	if s == nil || s.core == nil {
		version := uint32(0)
		if info != nil {
			version = uint32(info.ModTime().Unix())
		}
		return stablePathID(relative), version
	}
	return s.core.QID(relative, info)
}

func (s *Service) ObserveQID(relative string, path uint64, version uint32) {
	if s == nil || s.core == nil {
		return
	}
	if err := s.core.ObserveQID(relative, path, version); err != nil {
		s.reportCore(err)
	}
}

// Begin reserves a durable operation ID, runs enforce-capable before hooks, and
// applies the service read-only policy before any filesystem callback executes.
func (s *Service) Begin(ctx context.Context, event Event) (Pending, error) {
	if s == nil || s.backend == nil || s.core == nil {
		return Pending{}, errors.New("filebackend: incomplete service")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	id, err := s.core.NextID()
	if err != nil {
		return Pending{}, fmt.Errorf("filebackend: reserve operation ID: %w", err)
	}
	start := time.Now()
	event.Version = EventVersion
	event.ID = id
	event.Phase = PhaseBefore
	event.ReadOnly = s.readOnly
	event.OccurredAtUnixNano = start.UnixNano()
	normalized, err := normalizeEvent(event)
	if err != nil {
		return Pending{}, err
	}
	pending := Pending{event: normalized, start: start}
	if err := s.hooks.Run(ctx, normalized); err != nil {
		s.Complete(ctx, pending, err, nil)
		return Pending{}, err
	}
	if s.readOnly && eventMutates(normalized) {
		s.Complete(ctx, pending, ErrReadOnly, nil)
		return Pending{}, ErrReadOnly
	}
	return pending, nil
}

// Complete records the final operation state and runs after/error hooks.
func (s *Service) Complete(ctx context.Context, pending Pending, operationErr error, mutationPaths []string) {
	if s == nil || pending.start.IsZero() {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	final := pending.event
	final.DurationNanos = time.Since(pending.start).Nanoseconds()
	if operationErr != nil {
		final.Phase = PhaseError
		final.Error = operationErr.Error()
		mutationPaths = nil
	} else {
		final.Phase = PhaseAfter
		final.Error = ""
	}
	s.record(final, mutationPaths)
	_ = s.hooks.Run(ctx, final)
}

// Execute is the synchronous convenience form of Begin and Complete.
func (s *Service) Execute(ctx context.Context, event Event, mutationPaths []string, operation func(Backend) error) error {
	if operation == nil {
		return errors.New("filebackend: operation callback is required")
	}
	pending, err := s.Begin(ctx, event)
	if err != nil {
		return err
	}
	operationErr := operation(s.backend)
	s.Complete(ctx, pending, operationErr, mutationPaths)
	return operationErr
}

func eventMutates(event Event) bool {
	switch event.Operation {
	case OperationCreate, OperationWrite, OperationRemove,
		OperationPrepareReplace, OperationCommitReplace, OperationAbortReplace:
		return true
	case OperationOpen:
		const (
			openAccessMask uint32 = 0x03
			openTruncate   uint32 = 0x10
		)
		return event.Mode&openAccessMask != 0 || event.Mode&openTruncate != 0
	default:
		return false
	}
}

func (s *Service) record(event Event, mutationPaths []string) {
	if s == nil || s.core == nil {
		return
	}
	if err := s.core.Record(event, mutationPaths...); err != nil {
		s.reportCore(err)
	}
}

func (s *Service) reportCore(err error) {
	if err == nil || s == nil || s.coreReporter == nil {
		return
	}
	defer func() { _ = recover() }()
	s.coreReporter(err)
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	failures := []error{}
	if s.core != nil {
		if err := s.core.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	if closer, ok := s.backend.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
