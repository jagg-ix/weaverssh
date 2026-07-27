// Package extension provides deterministic, bounded extension hooks for the
// authenticated weaverssh session lifecycle. Hooks may observe operations or
// veto them, but they do not grant capabilities or bypass existing policy.
package extension

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

const (
	EventVersion          = "weaverssh.extension-event.v1"
	maxExtensions         = 128
	maxHooksPerExtension  = 64
	maxEventMetadataBytes = 64 << 20
	maxEventStringBytes   = 4 << 10
	maxEventAttributes    = 32
	maxAttributeKeyBytes  = 64
	maxAttributeValueBytes = 1 << 10
)

// Point identifies a stable lifecycle boundary exposed to extensions.
type Point string

const (
	PointSessionReady     Point = "session.ready"
	PointSessionClosed    Point = "session.closed"
	PointTargetOpened     Point = "target.opened"
	PointTargetAuthorized Point = "target.authorized"
	PointTargetForwarding Point = "target.forwarding"
)

func (p Point) valid() bool {
	switch p {
	case PointSessionReady, PointSessionClosed, PointTargetOpened, PointTargetAuthorized, PointTargetForwarding:
		return true
	default:
		return false
	}
}

// Mode controls how a hook failure affects the operation that invoked it.
type Mode string

const (
	// ModeObserve reports a failure and allows the operation to continue.
	ModeObserve Mode = "observe"
	// ModeEnforce reports a failure and vetoes the operation.
	ModeEnforce Mode = "enforce"
)

// Event is the bounded, non-secret input supplied to a hook. Stream metadata is
// represented by its size and SHA-256 digest rather than raw bytes.
type Event struct {
	Version            string            `json:"version"`
	Point              Point             `json:"point"`
	OccurredAtUnixNano int64             `json:"occurred_at_unix_nano"`
	SessionBinding     string            `json:"session_binding,omitempty"`
	LocalNode          string            `json:"local_node,omitempty"`
	PeerNode           string            `json:"peer_node,omitempty"`
	TargetNode         string            `json:"target_node,omitempty"`
	Service            string            `json:"service,omitempty"`
	ServiceID          uint16            `json:"service_id,omitempty"`
	MetadataBytes      int               `json:"metadata_bytes,omitempty"`
	MetadataSHA256     string            `json:"metadata_sha256,omitempty"`
	Attributes         map[string]string `json:"attributes,omitempty"`
}

// NewEvent constructs an event with the current timestamp.
func NewEvent(point Point) Event {
	return Event{Version: EventVersion, Point: point, OccurredAtUnixNano: time.Now().UnixNano()}
}

// Handler processes one immutable event snapshot.
type Handler func(context.Context, Event) error

// Hook binds a handler to one lifecycle point.
type Hook struct {
	Point       Point
	Priority    int
	Mode        Mode
	Timeout     time.Duration
	MaxParallel int
	Handler     Handler
}

// Descriptor identifies one extension independently from its hooks.
type Descriptor struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

// Definition is registered atomically. Duplicate extension names are rejected.
type Definition struct {
	Descriptor Descriptor
	Hooks      []Hook
}

// Failure describes one hook failure delivered to a Reporter.
type Failure struct {
	Extension Descriptor
	Point     Point
	Mode      Mode
	Err       error
}

// Reporter receives observe-mode failures and enforce-mode vetoes. It must not
// panic or block indefinitely.
type Reporter func(Failure)

type registeredHook struct {
	descriptor Descriptor
	hook       Hook
	order      uint64
	semaphore  chan struct{}
}

// Registry stores extensions and runs their hooks in stable priority and
// registration order. Registration is safe before or during session startup.
type Registry struct {
	mu          sync.RWMutex
	descriptors map[string]Descriptor
	hooks       map[Point][]registeredHook
	nextOrder   uint64
	reporter    Reporter
}

// NewRegistry constructs an empty registry.
func NewRegistry(reporter Reporter) *Registry {
	return &Registry{
		descriptors: make(map[string]Descriptor),
		hooks:       make(map[Point][]registeredHook),
		reporter:    reporter,
	}
}

// SetReporter replaces the failure reporter.
func (r *Registry) SetReporter(reporter Reporter) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.reporter = reporter
	r.mu.Unlock()
}

// Register validates and atomically installs one extension.
func (r *Registry) Register(definition Definition) error {
	if r == nil {
		return errors.New("extension: nil registry")
	}
	descriptor, err := normalizeDescriptor(definition.Descriptor)
	if err != nil {
		return err
	}
	if len(definition.Hooks) == 0 || len(definition.Hooks) > maxHooksPerExtension {
		return fmt.Errorf("extension %s: hook count must be between 1 and %d", descriptor.Name, maxHooksPerExtension)
	}
	normalized := make([]Hook, len(definition.Hooks))
	for i, hook := range definition.Hooks {
		normalized[i], err = normalizeHook(hook)
		if err != nil {
			return fmt.Errorf("extension %s hook %d: %w", descriptor.Name, i, err)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.descriptors == nil {
		r.descriptors = make(map[string]Descriptor)
	}
	if r.hooks == nil {
		r.hooks = make(map[Point][]registeredHook)
	}
	if _, exists := r.descriptors[descriptor.Name]; exists {
		return fmt.Errorf("extension: duplicate extension %q", descriptor.Name)
	}
	if len(r.descriptors) >= maxExtensions {
		return fmt.Errorf("extension: registry exceeds %d extensions", maxExtensions)
	}
	r.descriptors[descriptor.Name] = descriptor
	for _, hook := range normalized {
		r.nextOrder++
		entry := registeredHook{
			descriptor: descriptor,
			hook:       hook,
			order:      r.nextOrder,
			semaphore:  make(chan struct{}, hook.MaxParallel),
		}
		r.hooks[hook.Point] = append(r.hooks[hook.Point], entry)
		sort.SliceStable(r.hooks[hook.Point], func(i, j int) bool {
			left, right := r.hooks[hook.Point][i], r.hooks[hook.Point][j]
			if left.hook.Priority != right.hook.Priority {
				return left.hook.Priority < right.hook.Priority
			}
			return left.order < right.order
		})
	}
	return nil
}

// Extensions returns registered descriptors in stable name order.
func (r *Registry) Extensions() []Descriptor {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	out := make([]Descriptor, 0, len(r.descriptors))
	for _, descriptor := range r.descriptors {
		out = append(out, descriptor)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Empty reports whether no extensions are registered.
func (r *Registry) Empty() bool {
	return r == nil || len(r.Extensions()) == 0
}

// Run invokes hooks for event.Point. Observe-mode failures are reported and
// ignored. Enforce-mode failures are reported and returned to the caller.
func (r *Registry) Run(ctx context.Context, event Event) error {
	if r == nil {
		return nil
	}
	normalized, err := normalizeEvent(event)
	if err != nil {
		return err
	}
	r.mu.RLock()
	hooks := append([]registeredHook(nil), r.hooks[normalized.Point]...)
	reporter := r.reporter
	r.mu.RUnlock()
	for _, hook := range hooks {
		hookErr := invoke(ctx, hook, normalized)
		if hookErr == nil {
			continue
		}
		failure := Failure{Extension: hook.descriptor, Point: normalized.Point, Mode: hook.hook.Mode, Err: hookErr}
		report(reporter, failure)
		if hook.hook.Mode == ModeEnforce {
			return fmt.Errorf("extension %s vetoed %s: %w", hook.descriptor.Name, normalized.Point, hookErr)
		}
	}
	return nil
}

func invoke(parent context.Context, registered registeredHook, event Event) error {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, registered.hook.Timeout)
	defer cancel()
	select {
	case registered.semaphore <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	result := make(chan error, 1)
	go func() {
		defer func() {
			<-registered.semaphore
			if recovered := recover(); recovered != nil {
				result <- fmt.Errorf("panic: %v", recovered)
			}
		}()
		result <- registered.hook.Handler(ctx, cloneEvent(event))
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func report(reporter Reporter, failure Failure) {
	if reporter == nil {
		return
	}
	defer func() { _ = recover() }()
	reporter(failure)
}

func normalizeDescriptor(raw Descriptor) (Descriptor, error) {
	raw.Name = strings.TrimSpace(raw.Name)
	raw.Version = strings.TrimSpace(raw.Version)
	raw.Description = strings.TrimSpace(raw.Description)
	if !validName(raw.Name) {
		return Descriptor{}, fmt.Errorf("extension: invalid name %q", raw.Name)
	}
	if raw.Version == "" || len(raw.Version) > 64 || containsControl(raw.Version) {
		return Descriptor{}, errors.New("extension: invalid version")
	}
	if len(raw.Description) > 512 || containsControl(raw.Description) {
		return Descriptor{}, errors.New("extension: invalid description")
	}
	return raw, nil
}

func normalizeHook(raw Hook) (Hook, error) {
	if !raw.Point.valid() {
		return Hook{}, fmt.Errorf("invalid hook point %q", raw.Point)
	}
	if raw.Handler == nil {
		return Hook{}, errors.New("missing hook handler")
	}
	if raw.Mode == "" {
		raw.Mode = ModeObserve
	}
	if raw.Mode != ModeObserve && raw.Mode != ModeEnforce {
		return Hook{}, fmt.Errorf("invalid hook mode %q", raw.Mode)
	}
	if raw.Timeout <= 0 {
		raw.Timeout = 2 * time.Second
	}
	if raw.Timeout > time.Minute {
		return Hook{}, errors.New("hook timeout exceeds one minute")
	}
	if raw.MaxParallel <= 0 {
		raw.MaxParallel = 1
	}
	if raw.MaxParallel > 64 {
		return Hook{}, errors.New("hook max_parallel exceeds 64")
	}
	return raw, nil
}

func normalizeEvent(raw Event) (Event, error) {
	if raw.Version == "" {
		raw.Version = EventVersion
	}
	if raw.Version != EventVersion || !raw.Point.valid() {
		return Event{}, errors.New("extension: invalid event")
	}
	if raw.OccurredAtUnixNano == 0 {
		raw.OccurredAtUnixNano = time.Now().UnixNano()
	}
	if raw.MetadataBytes < 0 || raw.MetadataBytes > maxEventMetadataBytes {
		return Event{}, errors.New("extension: invalid metadata size")
	}
	for _, value := range []string{raw.SessionBinding, raw.LocalNode, raw.PeerNode, raw.TargetNode, raw.Service} {
		if len(value) > maxEventStringBytes || containsControl(value) {
			return Event{}, errors.New("extension: invalid event string")
		}
	}
	if raw.MetadataSHA256 != "" && !isSHA256Hex(raw.MetadataSHA256) {
		return Event{}, errors.New("extension: invalid metadata digest")
	}
	if len(raw.Attributes) > maxEventAttributes {
		return Event{}, errors.New("extension: too many event attributes")
	}
	raw.Attributes = cloneStrings(raw.Attributes)
	for key, value := range raw.Attributes {
		if key != strings.TrimSpace(key) || key == "" || len(key) > maxAttributeKeyBytes || len(value) > maxAttributeValueBytes || containsControl(key) || containsControl(value) {
			return Event{}, errors.New("extension: invalid event attribute")
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

func validName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, r := range value {
		if unicode.IsLower(r) || unicode.IsDigit(r) || (index > 0 && (r == '.' || r == '_' || r == '-')) {
			continue
		}
		return false
	}
	return true
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
