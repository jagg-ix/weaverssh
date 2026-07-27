package filebackend

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const EventVersion = "weaverssh.file-backend-event.v1"

const (
	maxHooks          = 128
	maxEventPathBytes = 4 << 10
	maxEventError     = 4 << 10
	maxEventAttrs     = 24
	maxAttrKey        = 64
	maxAttrValue      = 1 << 10
)

type Operation string

const (
	OperationAttach        Operation = "attach"
	OperationWalk          Operation = "walk"
	OperationOpen          Operation = "open"
	OperationCreate        Operation = "create"
	OperationRead          Operation = "read"
	OperationWrite         Operation = "write"
	OperationClunk         Operation = "clunk"
	OperationRemove        Operation = "remove"
	OperationStat          Operation = "stat"
	OperationReadDir       Operation = "readdir"
	OperationPrepareReplace Operation = "replace.prepare"
	OperationCommitReplace  Operation = "replace.commit"
	OperationAbortReplace   Operation = "replace.abort"
)

func (o Operation) valid() bool {
	switch o {
	case OperationAttach, OperationWalk, OperationOpen, OperationCreate,
		OperationRead, OperationWrite, OperationClunk, OperationRemove,
		OperationStat, OperationReadDir, OperationPrepareReplace,
		OperationCommitReplace, OperationAbortReplace:
		return true
	default:
		return false
	}
}

type Phase string

const (
	PhaseBefore Phase = "before"
	PhaseAfter  Phase = "after"
	PhaseError  Phase = "error"
)

type Mode string

const (
	ModeObserve Mode = "observe"
	ModeEnforce Mode = "enforce"
)

// Event describes one bounded filesystem operation. Paths are export-relative;
// absolute host paths and file payload bytes are never included.
type Event struct {
	Version            string            `json:"version"`
	ID                 uint64            `json:"id"`
	Operation          Operation         `json:"operation"`
	Phase              Phase             `json:"phase"`
	Path               string            `json:"path,omitempty"`
	SecondaryPath      string            `json:"secondary_path,omitempty"`
	Offset             uint64            `json:"offset,omitempty"`
	Size               uint64            `json:"size,omitempty"`
	Mode               uint32            `json:"file_mode,omitempty"`
	Directory          bool              `json:"directory,omitempty"`
	ReadOnly           bool              `json:"read_only,omitempty"`
	OccurredAtUnixNano int64             `json:"occurred_at_unix_nano"`
	DurationNanos      int64             `json:"duration_nanos,omitempty"`
	Error              string            `json:"error,omitempty"`
	Attributes         map[string]string `json:"attributes,omitempty"`
}

type Handler func(context.Context, Event) error

type Hook struct {
	Operation   Operation
	Phase       Phase
	Priority    int
	Mode        Mode
	Timeout     time.Duration
	MaxParallel int
	Handler     Handler
}

type Failure struct {
	Operation Operation
	Phase     Phase
	Mode      Mode
	Err       error
}

type Reporter func(Failure)

type registeredHook struct {
	hook      Hook
	order     uint64
	semaphore chan struct{}
}

// Registry runs matching hooks in stable priority and registration order.
type Registry struct {
	mu        sync.RWMutex
	hooks     map[Operation]map[Phase][]registeredHook
	nextOrder uint64
	reporter  Reporter
}

func NewRegistry(reporter Reporter) *Registry {
	return &Registry{hooks: make(map[Operation]map[Phase][]registeredHook), reporter: reporter}
}

func (r *Registry) Register(hook Hook) error {
	if r == nil {
		return errors.New("filebackend: nil hook registry")
	}
	normalized, err := normalizeHook(hook)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, phases := range r.hooks {
		for _, entries := range phases {
			count += len(entries)
		}
	}
	if count >= maxHooks {
		return fmt.Errorf("filebackend: hook registry exceeds %d hooks", maxHooks)
	}
	if r.hooks[normalized.Operation] == nil {
		r.hooks[normalized.Operation] = make(map[Phase][]registeredHook)
	}
	r.nextOrder++
	entry := registeredHook{
		hook: normalized, order: r.nextOrder,
		semaphore: make(chan struct{}, normalized.MaxParallel),
	}
	list := append(r.hooks[normalized.Operation][normalized.Phase], entry)
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].hook.Priority != list[j].hook.Priority {
			return list[i].hook.Priority < list[j].hook.Priority
		}
		return list[i].order < list[j].order
	})
	r.hooks[normalized.Operation][normalized.Phase] = list
	return nil
}

func (r *Registry) Empty() bool {
	if r == nil {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, phases := range r.hooks {
		for _, entries := range phases {
			if len(entries) > 0 {
				return false
			}
		}
	}
	return true
}

func (r *Registry) Run(ctx context.Context, event Event) error {
	if r == nil {
		return nil
	}
	normalized, err := normalizeEvent(event)
	if err != nil {
		return err
	}
	r.mu.RLock()
	entries := append([]registeredHook(nil), r.hooks[normalized.Operation][normalized.Phase]...)
	reporter := r.reporter
	r.mu.RUnlock()
	for _, entry := range entries {
		err := invokeHook(ctx, entry, normalized)
		if err == nil {
			continue
		}
		failure := Failure{Operation: normalized.Operation, Phase: normalized.Phase, Mode: entry.hook.Mode, Err: err}
		reportFailure(reporter, failure)
		if entry.hook.Mode == ModeEnforce {
			return fmt.Errorf("filebackend: %s %s hook vetoed operation: %w", normalized.Operation, normalized.Phase, err)
		}
	}
	return nil
}

func invokeHook(parent context.Context, entry registeredHook, event Event) error {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, entry.hook.Timeout)
	defer cancel()
	select {
	case entry.semaphore <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	result := make(chan error, 1)
	go func() {
		defer func() {
			<-entry.semaphore
			if recovered := recover(); recovered != nil {
				result <- fmt.Errorf("panic: %v", recovered)
			}
		}()
		result <- entry.hook.Handler(ctx, cloneEvent(event))
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func normalizeHook(raw Hook) (Hook, error) {
	if !raw.Operation.valid() {
		return Hook{}, fmt.Errorf("filebackend: invalid hook operation %q", raw.Operation)
	}
	if raw.Phase == "" {
		raw.Phase = PhaseBefore
	}
	if raw.Phase != PhaseBefore && raw.Phase != PhaseAfter && raw.Phase != PhaseError {
		return Hook{}, fmt.Errorf("filebackend: invalid hook phase %q", raw.Phase)
	}
	if raw.Handler == nil {
		return Hook{}, errors.New("filebackend: hook handler is required")
	}
	if raw.Mode == "" {
		raw.Mode = ModeObserve
	}
	if raw.Mode != ModeObserve && raw.Mode != ModeEnforce {
		return Hook{}, fmt.Errorf("filebackend: invalid hook mode %q", raw.Mode)
	}
	if raw.Mode == ModeEnforce && raw.Phase != PhaseBefore {
		return Hook{}, errors.New("filebackend: enforce hooks are valid only in the before phase")
	}
	if raw.Timeout <= 0 {
		raw.Timeout = 2 * time.Second
	}
	if raw.Timeout > time.Minute {
		return Hook{}, errors.New("filebackend: hook timeout exceeds one minute")
	}
	if raw.MaxParallel <= 0 {
		raw.MaxParallel = 1
	}
	if raw.MaxParallel > 64 {
		return Hook{}, errors.New("filebackend: hook max_parallel exceeds 64")
	}
	return raw, nil
}

func normalizeEvent(raw Event) (Event, error) {
	if raw.Version == "" {
		raw.Version = EventVersion
	}
	if raw.Version != EventVersion || !raw.Operation.valid() {
		return Event{}, errors.New("filebackend: invalid hook event")
	}
	if raw.Phase != PhaseBefore && raw.Phase != PhaseAfter && raw.Phase != PhaseError {
		return Event{}, errors.New("filebackend: invalid hook event phase")
	}
	if raw.OccurredAtUnixNano == 0 {
		raw.OccurredAtUnixNano = time.Now().UnixNano()
	}
	for _, path := range []string{raw.Path, raw.SecondaryPath} {
		if len(path) > maxEventPathBytes || containsControl(path) || strings.IndexByte(path, 0) >= 0 {
			return Event{}, errors.New("filebackend: invalid hook event path")
		}
	}
	if len(raw.Error) > maxEventError || containsControl(raw.Error) {
		return Event{}, errors.New("filebackend: invalid hook event error")
	}
	if len(raw.Attributes) > maxEventAttrs {
		return Event{}, errors.New("filebackend: too many hook attributes")
	}
	raw.Attributes = cloneStrings(raw.Attributes)
	for key, value := range raw.Attributes {
		if key == "" || key != strings.TrimSpace(key) || len(key) > maxAttrKey || len(value) > maxAttrValue || containsControl(key) || containsControl(value) {
			return Event{}, errors.New("filebackend: invalid hook attribute")
		}
	}
	return raw, nil
}

func cloneEvent(event Event) Event {
	event.Attributes = cloneStrings(event.Attributes)
	return event
}

func cloneStrings(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func reportFailure(reporter Reporter, failure Failure) {
	if reporter == nil {
		return
	}
	defer func() { _ = recover() }()
	reporter(failure)
}
