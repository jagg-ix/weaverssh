// Package eventdelivery supplies an opt-in delivery boundary, not a policy
// evaluator or a globally exactly-once executor. Authorization is independent
// of the event and is rechecked by the host's canonical authority adapter.
package eventdelivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
)

type Kind string

const (
	HandlerInvocation Kind = "handler-invocation"
	TransferRun       Kind = "transfer-run"
	WebhookDelivery   Kind = "webhook-delivery"
)

// Route is resolved configuration from the host, never from an event payload.
// Generation changes whenever any desired field changes. The target is a
// configured resource ID; this package does not interpret it as a URL or command.
type Route struct {
	Scope       string
	ID          string
	Generation  uint64
	Enabled     bool
	Kind        Kind
	Target      string
	Authority   string
	MaxAttempts int
}

// Occurrence has no action, target, grant, secret, or desired-state field.
// ID is a durable event/occurrence identity assigned by the producer. The host
// must resolve its tenant/scope; matching strings are not authentication.
type Occurrence struct {
	Scope      string
	ID         string
	RouteID    string
	Generation uint64
	Parameters map[string]string
}

// Request freezes the configured route, occurrence and delivery key. An
// executor gets a value copy and a copy of parameters, not mutable desired state.
type Request struct {
	route      Route
	occurrence string
	key        string
	parameters map[string]string
}

func (r Request) Route() Route           { return r.route }
func (r Request) OccurrenceID() string   { return r.occurrence }
func (r Request) DeliveryKey() string    { return r.key }
func (r Request) Parameters() map[string]string { return clone(r.parameters) }

type Grant struct {
	Authority  string
	Generation uint64
}

type State string
type Outcome string

const (
	Pending        State = "pending"
	Running        State = "running"
	Succeeded      State = "succeeded"
	DeadLetter     State = "dead-letter"
	OutcomeUnknown State = "outcome-unknown"

	NotAttempted     Outcome = "not-attempted"
	Success          Outcome = "success"
	RetryableFailure Outcome = "retryable-failure"
	PermanentFailure Outcome = "permanent-failure"
	Unknown          Outcome = "unknown"
)

var (
	ErrInvalid     = errors.New("eventdelivery: invalid configuration or occurrence")
	ErrBusy        = errors.New("eventdelivery: an attempt is in progress")
	ErrTerminal    = errors.New("eventdelivery: delivery requires operator review")
	ErrRefused     = errors.New("eventdelivery: current configuration or authority refused")
	ErrEvidence    = errors.New("eventdelivery: required evidence was not acknowledged")
	ErrUnknown     = errors.New("eventdelivery: effect outcome is unknown")
)

// Evidence is payload-free: providers cannot turn their response into desired
// state, authority, or tenant-visible secrets. Adapters must durably acknowledge
// started BEFORE the effect and outcome/refused AFTER the observation.
type Evidence struct {
	DeliveryKey        string
	Scope              string
	RouteID            string
	RouteGeneration    uint64
	OccurrenceID       string
	AuthorityGeneration uint64
	Attempt            int
	Stage              string
	State              State
	Outcome            Outcome
	Reason             string
}

// Adapters are host-owned. In Inetgarden Authorize must call the canonical
// OCaml authority/policy boundary, not trust an event field or a cached grant.
// Execute must apply grant fencing at its actual effect boundary. Resolver and
// authorizer observations here are not an atomic distributed revocation fence.
type Adapters struct {
	CurrentRoute func(context.Context, string, string) (Route, error)
	Authorize    func(context.Context, Request) (Grant, error)
	Execute      func(context.Context, Request, Grant) (Outcome, error)
	Record       func(context.Context, Evidence) error
}

type Snapshot struct {
	DeliveryKey        string
	State              State
	Attempts           int
	AuthorityGeneration uint64
	ObservedOutcome    Outcome
	Reason             string
}

// Delivery serializes only this instance. A durable host still needs intent
// storage, claims/fencing, attempt recovery and a dead-letter consumer. Multiple
// instances or explicit transfer replay may repeat an effect with the same key.
type Delivery struct {
	mu       sync.Mutex
	request  Request
	adapters Adapters
	snapshot Snapshot
}

func token(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
			!(c >= '0' && c <= '9') && c != '-' && c != '_' && c != '.' &&
			c != ':' && c != '/' && c != '~' {
			return false
		}
	}
	return true
}

func validate(route Route, occurrence Occurrence) error {
	if !token(route.Scope) || !token(route.ID) || !token(route.Target) || !token(route.Authority) ||
		!token(occurrence.ID) || route.Generation == 0 || !route.Enabled ||
		route.MaxAttempts < 1 || route.MaxAttempts > 1024 || occurrence.Scope != route.Scope ||
		occurrence.RouteID != route.ID || occurrence.Generation != route.Generation {
		return ErrInvalid
	}
	switch route.Kind {
	case HandlerInvocation, TransferRun, WebhookDelivery:
	default:
		return ErrInvalid
	}
	if len(occurrence.Parameters) > 64 {
		return ErrInvalid
	}
	for key, value := range occurrence.Parameters {
		if !token(key) || len(value) > 4096 {
			return ErrInvalid
		}
	}
	return nil
}

// StableKey uses an unambiguous, versioned JSON tuple. Retry count, provider
// responses and event parameters are intentionally excluded. A new route
// generation is a new delivery identity, not a retry of the old configuration.
func StableKey(route Route, occurrence Occurrence) (string, error) {
	if err := validate(route, occurrence); err != nil {
		return "", err
	}
	tuple := []string{"eventdelivery/v1", route.Scope, route.ID,
		strconv.FormatUint(route.Generation, 10), string(route.Kind), route.Target,
		route.Authority, occurrence.ID}
	encoded, err := json.Marshal(tuple)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "ed1_" + hex.EncodeToString(digest[:]), nil
}

func New(route Route, occurrence Occurrence, adapters Adapters) (*Delivery, error) {
	key, err := StableKey(route, occurrence)
	if err != nil {
		return nil, err
	}
	if adapters.CurrentRoute == nil || adapters.Authorize == nil || adapters.Execute == nil || adapters.Record == nil {
		return nil, ErrInvalid
	}
	request := Request{route: route, occurrence: occurrence.ID, key: key, parameters: clone(occurrence.Parameters)}
	return &Delivery{request: request, adapters: adapters,
		snapshot: Snapshot{DeliveryKey: key, State: Pending, ObservedOutcome: NotAttempted}}, nil
}

func clone(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func (d *Delivery) Snapshot() Snapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.snapshot
}

func (d *Delivery) set(state State, outcome Outcome, reason string) Snapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.snapshot.State, d.snapshot.ObservedOutcome, d.snapshot.Reason = state, outcome, reason
	return d.snapshot
}

func (d *Delivery) evidence(stage string, state State, outcome Outcome, reason string, attempt int) Evidence {
	s := d.Snapshot()
	r := d.request.route
	return Evidence{DeliveryKey: d.request.key, Scope: r.Scope, RouteID: r.ID,
		RouteGeneration: r.Generation, OccurrenceID: d.request.occurrence,
		AuthorityGeneration: s.AuthorityGeneration, Attempt: attempt,
		Stage: stage, State: state, Outcome: outcome, Reason: reason}
}

func (d *Delivery) refuse(ctx context.Context, reason string, cause error) (Snapshot, error) {
	s := d.Snapshot()
	if err := d.adapters.Record(ctx, d.evidence("refused", DeadLetter, NotAttempted, reason, s.Attempts)); err != nil {
		return d.set(OutcomeUnknown, NotAttempted, "evidence-unavailable"), ErrEvidence
	}
	return d.set(DeadLetter, NotAttempted, reason), cause
}

// Attempt performs at most one effect. Only an explicit RetryableFailure makes
// another attempt available. Ambiguous errors stop for review; success stops
// retry. Existing replay APIs are not changed, and receiver deduplication is not
// claimed. The host supplies scheduling/backoff and durable dispatch claims.
func (d *Delivery) Attempt(ctx context.Context) (Snapshot, error) {
	d.mu.Lock()
	s := d.snapshot
	switch s.State {
	case Running:
		d.mu.Unlock()
		return s, ErrBusy
	case Succeeded:
		d.mu.Unlock()
		return s, nil
	case DeadLetter, OutcomeUnknown:
		d.mu.Unlock()
		return s, ErrTerminal
	}
	d.snapshot.State = Running
	d.mu.Unlock()
	// An adapter panic cannot leave a retryable delivery. Preserve the panic for
	// its caller while fencing this instance as unknown; no success is fabricated.
	defer func() {
		d.mu.Lock()
		if d.snapshot.State == Running {
			d.snapshot.State, d.snapshot.ObservedOutcome, d.snapshot.Reason = OutcomeUnknown, Unknown, "adapter-interrupted"
		}
		d.mu.Unlock()
	}()
	if err := ctx.Err(); err != nil {
		return d.refuse(ctx, "cancelled", err)
	}
	if s.Attempts >= d.request.route.MaxAttempts {
		return d.refuse(ctx, "attempt-limit", ErrTerminal)
	}
	current, err := d.adapters.CurrentRoute(ctx, d.request.route.Scope, d.request.route.ID)
	if err != nil || current != d.request.route {
		return d.refuse(ctx, "route-disabled-or-stale", ErrRefused)
	}
	grant, err := d.adapters.Authorize(ctx, d.request)
	if err != nil || grant.Authority != d.request.route.Authority || grant.Generation == 0 {
		return d.refuse(ctx, "authority-refused", ErrRefused)
	}
	if s.AuthorityGeneration != 0 && grant.Generation != s.AuthorityGeneration {
		return d.refuse(ctx, "authority-generation-changed", ErrRefused)
	}
	d.mu.Lock()
	d.snapshot.AuthorityGeneration = grant.Generation
	d.mu.Unlock()
	number := s.Attempts + 1
	if err := d.adapters.Record(ctx, d.evidence("started", Running, NotAttempted, "", number)); err != nil {
		return d.set(OutcomeUnknown, NotAttempted, "evidence-unavailable"), ErrEvidence
	}
	if err := ctx.Err(); err != nil {
		return d.refuse(ctx, "cancelled-before-effect", err)
	}
	d.mu.Lock()
	d.snapshot.Attempts = number
	d.mu.Unlock()
	outcome, execErr := d.adapters.Execute(ctx, d.request, grant)
	if execErr != nil {
		outcome = Unknown // a transport error says nothing about whether an effect happened
	}
	state, reason := OutcomeUnknown, "effect-outcome-unknown"
	switch outcome {
	case Success:
		state, reason = Succeeded, ""
	case RetryableFailure:
		if number < d.request.route.MaxAttempts {
			state, reason = Pending, "retryable-failure"
		} else {
			state, reason = DeadLetter, "attempt-limit"
		}
	case PermanentFailure:
		state, reason = DeadLetter, "permanent-failure"
	default:
		outcome = Unknown
	}
	if err := d.adapters.Record(ctx, d.evidence("outcome", state, outcome, reason, number)); err != nil {
		return d.set(OutcomeUnknown, outcome, "outcome-evidence-unavailable"), ErrEvidence
	}
	s = d.set(state, outcome, reason)
	if state == OutcomeUnknown {
		return s, ErrUnknown
	}
	return s, nil
}
