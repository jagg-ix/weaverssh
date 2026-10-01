package eventdelivery

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type fixture struct {
	route       Route
	occurrence  Occurrence
	grant       Grant
	authErr     error
	recordErrAt string
	calls       int
	authCalls   int
	requests    []Request
	evidence    []Evidence
	outcomes    []Outcome
	execute     func(context.Context, Request, Grant) (Outcome, error)
}

func setup() *fixture {
	return &fixture{
		route: Route{Scope: "tenant:one", ID: "route:one", Generation: 2, Enabled: true,
			Kind: TransferRun, Target: "transfer:configured", Authority: "service:worker", MaxAttempts: 3},
		occurrence: Occurrence{Scope: "tenant:one", ID: "event:one", RouteID: "route:one", Generation: 2,
			Parameters: map[string]string{"target": "hostile-target", "action": "hostile-action", "authority": "admin"}},
		grant: Grant{Authority: "service:worker", Generation: 7},
	}
}

func (f *fixture) adapters() Adapters {
	return Adapters{
		CurrentRoute: func(ctx context.Context, scope, id string) (Route, error) {
			if scope != f.route.Scope || id != f.route.ID {
				return Route{}, errors.New("not found")
			}
			return f.route, nil
		},
		Authorize: func(ctx context.Context, r Request) (Grant, error) {
			f.authCalls++
			return f.grant, f.authErr
		},
		Execute: func(ctx context.Context, r Request, g Grant) (Outcome, error) {
			f.calls++
			f.requests = append(f.requests, r)
			if f.execute != nil {
				return f.execute(ctx, r, g)
			}
			if len(f.outcomes) > 0 {
				outcome := f.outcomes[0]
				f.outcomes = f.outcomes[1:]
				return outcome, nil
			}
			return Success, nil
		},
		Record: func(ctx context.Context, e Evidence) error {
			f.evidence = append(f.evidence, e)
			if e.Stage == f.recordErrAt {
				return errors.New("storage unavailable: private diagnostic")
			}
			return nil
		},
	}
}

func (f *fixture) delivery(t *testing.T) *Delivery {
	t.Helper()
	d, err := New(f.route, f.occurrence, f.adapters())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestEventCannotChooseActionTargetOrAuthority(t *testing.T) {
	f := setup()
	d := f.delivery(t)
	f.occurrence.Parameters["target"] = "changed-after-construction"
	s, err := d.Attempt(context.Background())
	if err != nil || s.State != Succeeded || f.calls != 1 {
		t.Fatalf("snapshot=%+v err=%v calls=%d", s, err, f.calls)
	}
	r := f.requests[0]
	if r.Route().Target != "transfer:configured" || r.Route().Kind != TransferRun || r.Route().Authority != "service:worker" {
		t.Fatal("event chose a configured field")
	}
	if r.Parameters()["target"] != "hostile-target" {
		t.Fatal("occurrence parameters were not snapshotted")
	}
	p := r.Parameters()
	p["target"] = "executor-mutated"
	if r.Parameters()["target"] != "hostile-target" {
		t.Fatal("executor mutated the stored occurrence")
	}
	if len(f.evidence) != 2 || f.evidence[0].Stage != "started" || f.evidence[1].Stage != "outcome" {
		t.Fatal("effect was not bracketed by evidence")
	}
	encoded, err := json.Marshal(f.evidence)
	if err != nil || strings.Contains(string(encoded), "hostile-target") || strings.Contains(string(encoded), "hostile-action") {
		t.Fatal("event payload leaked into evidence")
	}
}

func TestEventCannotGrantRuntimeAuthority(t *testing.T) {
	f := setup()
	f.authErr = errors.New("independent authority refuses the event's admin claim")
	d := f.delivery(t)
	s, err := d.Attempt(context.Background())
	if !errors.Is(err, ErrRefused) || s.State != DeadLetter || f.calls != 0 || f.authCalls != 1 {
		t.Fatalf("event claim became runtime authority: %+v err=%v", s, err)
	}
}

func TestRetryPreservesDeliveryKeyAndSuccessStopsRetry(t *testing.T) {
	f := setup()
	f.outcomes = []Outcome{RetryableFailure, Success}
	d := f.delivery(t)
	for _, expected := range []State{Pending, Succeeded, Succeeded} {
		s, err := d.Attempt(context.Background())
		if err != nil || s.State != expected {
			t.Fatalf("snapshot=%+v err=%v want=%s", s, err, expected)
		}
	}
	if f.calls != 2 || f.authCalls != 2 || len(f.requests) != 2 || f.requests[0].DeliveryKey() != f.requests[1].DeliveryKey() {
		t.Fatal("retry changed its key, skipped authority, or repeated success")
	}
	for _, e := range f.evidence {
		if e.DeliveryKey != d.Snapshot().DeliveryKey {
			t.Fatal("evidence changed delivery key")
		}
	}
}

func TestRevocationAndGenerationChangeStopRetry(t *testing.T) {
	for _, change := range []string{"revoked", "generation", "authority", "zero-generation"} {
		t.Run(change, func(t *testing.T) {
			f := setup()
			f.outcomes = []Outcome{RetryableFailure}
			d := f.delivery(t)
			if _, err := d.Attempt(context.Background()); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "revoked":
				f.authErr = errors.New("revoked")
			case "generation":
				f.grant.Generation++
			case "authority":
				f.grant.Authority = "service:other"
			case "zero-generation":
				f.grant.Generation = 0
			}
			s, err := d.Attempt(context.Background())
			if !errors.Is(err, ErrRefused) || s.State != DeadLetter || f.calls != 1 || f.authCalls != 2 {
				t.Fatalf("retry not refused: %+v err=%v calls=%d", s, err, f.calls)
			}
		})
	}
}

func TestDisabledStaleOrRewrittenRouteStopsDispatch(t *testing.T) {
	for _, change := range []string{"disabled", "generation", "target", "kind", "authority", "attempt-limit"} {
		t.Run(change, func(t *testing.T) {
			f := setup()
			f.outcomes = []Outcome{RetryableFailure}
			d := f.delivery(t)
			if _, err := d.Attempt(context.Background()); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "disabled":
				f.route.Enabled = false
			case "generation":
				f.route.Generation++
			case "target":
				f.route.Target = "transfer:other"
			case "kind":
				f.route.Kind = WebhookDelivery
			case "authority":
				f.route.Authority = "service:other"
			case "attempt-limit":
				f.route.MaxAttempts++
			}
			s, err := d.Attempt(context.Background())
			if !errors.Is(err, ErrRefused) || s.State != DeadLetter || f.calls != 1 || f.authCalls != 1 {
				t.Fatalf("changed route ran: %+v err=%v", s, err)
			}
		})
	}
}

func TestEvidenceFailureCannotBecomeSuccessOrRetry(t *testing.T) {
	for _, stage := range []string{"started", "outcome"} {
		t.Run(stage, func(t *testing.T) {
			f := setup()
			f.recordErrAt = stage
			d := f.delivery(t)
			s, err := d.Attempt(context.Background())
			if !errors.Is(err, ErrEvidence) || s.State != OutcomeUnknown {
				t.Fatalf("evidence failure hidden: %+v err=%v", s, err)
			}
			want := 0
			if stage == "outcome" {
				want = 1
				if s.ObservedOutcome != Success {
					t.Fatal("actual observed success was discarded")
				}
			}
			if _, err := d.Attempt(context.Background()); !errors.Is(err, ErrTerminal) || f.calls != want {
				t.Fatal("unrecorded outcome was replayed")
			}
		})
	}
}

func TestAttemptLimitAndPermanentFailureDeadLetter(t *testing.T) {
	for _, outcome := range []Outcome{RetryableFailure, PermanentFailure} {
		f := setup()
		f.route.MaxAttempts = 1
		f.outcomes = []Outcome{outcome}
		d := f.delivery(t)
		s, err := d.Attempt(context.Background())
		if err != nil || s.State != DeadLetter || s.Attempts != 1 {
			t.Fatalf("limit/permanent outcome not terminal: %+v err=%v", s, err)
		}
		if _, err := d.Attempt(context.Background()); !errors.Is(err, ErrTerminal) || f.calls != 1 {
			t.Fatal("terminal failure ran again")
		}
		if f.evidence[len(f.evidence)-1].State != DeadLetter {
			t.Fatal("dead letter was not evidenced")
		}
	}
}

func TestUnknownResponseOrTransportFailureCannotRewriteDesiredState(t *testing.T) {
	for _, outcome := range []Outcome{Unknown, Outcome("grant-admin"), Success} {
		f := setup()
		original := f.route
		f.execute = func(ctx context.Context, r Request, g Grant) (Outcome, error) {
			if outcome == Success {
				return Success, errors.New("response lost after effect")
			}
			return outcome, nil
		}
		d := f.delivery(t)
		s, err := d.Attempt(context.Background())
		if !errors.Is(err, ErrUnknown) || s.State != OutcomeUnknown || f.route != original || f.requests[0].Route() != original {
			t.Fatalf("ambiguous response changed authority/desired state: %+v err=%v", s, err)
		}
		if _, err := d.Attempt(context.Background()); !errors.Is(err, ErrTerminal) || f.calls != 1 {
			t.Fatal("ambiguous effect was automatically retried")
		}
	}
}

func TestConcurrentAttemptCannotExecuteSameInstanceTwice(t *testing.T) {
	f := setup()
	started, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	f.execute = func(ctx context.Context, r Request, g Grant) (Outcome, error) {
		close(started)
		<-finish
		return Success, nil
	}
	d := f.delivery(t)
	go func() {
		defer close(done)
		if _, err := d.Attempt(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	<-started
	if _, err := d.Attempt(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("concurrent delivery was not fenced")
	}
	close(finish)
	<-done
	if f.calls != 1 || d.Snapshot().State != Succeeded {
		t.Fatal("concurrent call duplicated the effect")
	}
}

func TestAdapterPanicLeavesUnknownNotRetryable(t *testing.T) {
	f := setup()
	f.execute = func(ctx context.Context, r Request, g Grant) (Outcome, error) { panic("adapter interrupted") }
	d := f.delivery(t)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("adapter panic was hidden")
			}
		}()
		_, _ = d.Attempt(context.Background())
	}()
	if d.Snapshot().State != OutcomeUnknown || d.Snapshot().ObservedOutcome != Unknown {
		t.Fatal("panic left delivery retryable or claimed a known effect outcome")
	}
	if _, err := d.Attempt(context.Background()); !errors.Is(err, ErrTerminal) || f.calls != 1 {
		t.Fatal("interrupted adapter was replayed")
	}
}

func TestKeyIsStableUnambiguousAndScoped(t *testing.T) {
	f := setup()
	one, err := StableKey(f.route, f.occurrence)
	if err != nil {
		t.Fatal(err)
	}
	f.occurrence.Parameters["target"] = "different-data"
	two, err := StableKey(f.route, f.occurrence)
	if err != nil || one != two {
		t.Fatal("parameters changed delivery identity")
	}
	for _, change := range []string{"tenant", "occurrence", "generation", "target"} {
		g := setup()
		switch change {
		case "tenant":
			g.route.Scope, g.occurrence.Scope = "tenant:two", "tenant:two"
		case "occurrence":
			g.occurrence.ID = "event:two"
		case "generation":
			g.route.Generation++
			g.occurrence.Generation++
		case "target":
			g.route.Target = "transfer:two"
		}
		key, err := StableKey(g.route, g.occurrence)
		if err != nil || key == one {
			t.Fatalf("%s not distinguished", change)
		}
	}
	left, right := setup(), setup()
	left.route.ID, left.occurrence.RouteID, left.occurrence.ID = "a.b", "a.b", "c"
	right.route.ID, right.occurrence.RouteID, right.occurrence.ID = "a", "a", "b.c"
	a, _ := StableKey(left.route, left.occurrence)
	b, _ := StableKey(right.route, right.occurrence)
	if a == b {
		t.Fatal("delimiter ambiguity collided")
	}
}

// Pin the versioned tuple encoding for future native/browser adapters. Equality
// between two calls alone would miss an accidental protocol-format change.
func TestStableKeyProtocolVector(t *testing.T) {
	f := setup()
	got, err := StableKey(f.route, f.occurrence)
	if err != nil || got != "ed1_5d0dc4ae2e53a0270d59a326e911d65be7cf7160a1d78405f626a03bb90a119d" {
		t.Fatalf("delivery key protocol changed: key=%q err=%v", got, err)
	}
}

func TestNewFailsClosedForMissingAdaptersAndWrongScope(t *testing.T) {
	f := setup()
	for _, name := range []string{"route", "authority", "execute", "evidence"} {
		a := f.adapters()
		switch name {
		case "route":
			a.CurrentRoute = nil
		case "authority":
			a.Authorize = nil
		case "execute":
			a.Execute = nil
		case "evidence":
			a.Record = nil
		}
		if _, err := New(f.route, f.occurrence, a); !errors.Is(err, ErrInvalid) {
			t.Fatalf("missing %s adapter accepted", name)
		}
	}
	for _, change := range []string{"scope", "stale", "disabled", "unbounded", "zero-attempts", "control-character"} {
		g := setup()
		switch change {
		case "scope":
			g.occurrence.Scope = "tenant:other"
		case "stale":
			g.occurrence.Generation++
		case "disabled":
			g.route.Enabled = false
		case "unbounded":
			g.route.MaxAttempts = 1025
		case "zero-attempts":
			g.route.MaxAttempts = 0
		case "control-character":
			g.occurrence.ID = "event:one\nforged"
		}
		if _, err := New(g.route, g.occurrence, g.adapters()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid %s input accepted", change)
		}
	}
}

func TestCancellationAfterEvidencePreventsTheEffect(t *testing.T) {
	f := setup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := f.adapters()
	a.Record = func(ctx context.Context, e Evidence) error {
		f.evidence = append(f.evidence, e)
		if e.Stage == "started" {
			cancel()
		}
		return nil
	}
	d, err := New(f.route, f.occurrence, a)
	if err != nil {
		t.Fatal(err)
	}
	s, err := d.Attempt(ctx)
	if !errors.Is(err, context.Canceled) || f.calls != 0 || s.Attempts != 0 || s.State != DeadLetter {
		t.Fatalf("cancelled effect ran: %+v err=%v", s, err)
	}
}

func TestExplicitReplayDoesNotClaimGlobalIdempotency(t *testing.T) {
	f := setup()
	one, two := f.delivery(t), f.delivery(t)
	_, _ = one.Attempt(context.Background())
	_, _ = two.Attempt(context.Background())
	if f.calls != 2 || one.Snapshot().DeliveryKey != two.Snapshot().DeliveryKey {
		t.Fatal("new instances/replay must not be presented as receiver-side exactly-once delivery")
	}
}
