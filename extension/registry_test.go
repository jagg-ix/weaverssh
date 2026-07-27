package extension

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRegistryOrdersHooksAndObservesFailures(t *testing.T) {
	var mu sync.Mutex
	var order []string
	var failures []Failure
	registry := NewRegistry(func(failure Failure) {
		mu.Lock()
		defer mu.Unlock()
		failures = append(failures, failure)
	})
	register := func(name string, priority int, fail bool) {
		t.Helper()
		err := registry.Register(Definition{
			Descriptor: Descriptor{Name: name, Version: "1"},
			Hooks: []Hook{{
				Point: PointTargetOpened, Priority: priority, Mode: ModeObserve,
				Handler: func(context.Context, Event) error {
					mu.Lock()
					order = append(order, name)
					mu.Unlock()
					if fail {
						return errors.New("observed")
					}
					return nil
				},
			}},
		})
		if err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}
	register("late", 20, false)
	register("early", -10, true)
	register("middle", 0, false)

	if err := registry.Run(context.Background(), NewEvent(PointTargetOpened)); err != nil {
		t.Fatalf("observe hook vetoed operation: %v", err)
	}
	if want := []string{"early", "middle", "late"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("order=%v want=%v", order, want)
	}
	if len(failures) != 1 || failures[0].Extension.Name != "early" || failures[0].Mode != ModeObserve {
		t.Fatalf("failures=%v", failures)
	}
}

func TestRegistryEnforceVetoes(t *testing.T) {
	registry := NewRegistry(nil)
	if err := registry.Register(Definition{
		Descriptor: Descriptor{Name: "policy", Version: "1"},
		Hooks: []Hook{{
			Point: PointTargetAuthorized, Mode: ModeEnforce,
			Handler: func(context.Context, Event) error { return errors.New("denied") },
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Run(context.Background(), NewEvent(PointTargetAuthorized)); err == nil {
		t.Fatal("expected enforce hook veto")
	}
}

func TestRegistryBoundsHungHookConcurrency(t *testing.T) {
	registry := NewRegistry(nil)
	block := make(chan struct{})
	if err := registry.Register(Definition{
		Descriptor: Descriptor{Name: "bounded", Version: "1"},
		Hooks: []Hook{{
			Point: PointSessionReady, Mode: ModeEnforce, Timeout: 20 * time.Millisecond, MaxParallel: 1,
			Handler: func(context.Context, Event) error {
				<-block
				return nil
			},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Run(context.Background(), NewEvent(PointSessionReady)); err == nil {
		t.Fatal("expected first timeout")
	}
	start := time.Now()
	if err := registry.Run(context.Background(), NewEvent(PointSessionReady)); err == nil {
		t.Fatal("expected bounded semaphore timeout")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("second invocation was not bounded: %v", elapsed)
	}
	close(block)
}

func TestRegistryRejectsDuplicateExtension(t *testing.T) {
	registry := NewRegistry(nil)
	definition := Definition{
		Descriptor: Descriptor{Name: "audit", Version: "1"},
		Hooks: []Hook{{Point: PointSessionReady, Handler: func(context.Context, Event) error { return nil }}},
	}
	if err := registry.Register(definition); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(definition); err == nil {
		t.Fatal("expected duplicate rejection")
	}
}

func TestRegistryRejectsUnboundedDefinitions(t *testing.T) {
	registry := NewRegistry(nil)
	if err := registry.Register(Definition{Descriptor: Descriptor{Name: "empty", Version: "1"}}); err == nil {
		t.Fatal("expected empty-hook rejection")
	}
	hooks := make([]Hook, maxHooksPerExtension+1)
	for index := range hooks {
		hooks[index] = Hook{Point: PointSessionReady, Handler: func(context.Context, Event) error { return nil }}
	}
	if err := registry.Register(Definition{Descriptor: Descriptor{Name: "oversized", Version: "1"}, Hooks: hooks}); err == nil {
		t.Fatal("expected hook-count rejection")
	}
}

func TestRegistryRejectsOversizedEvent(t *testing.T) {
	registry := NewRegistry(nil)
	event := NewEvent(PointTargetOpened)
	event.Attributes = map[string]string{"oversized": strings.Repeat("x", maxAttributeValueBytes+1)}
	if err := registry.Run(context.Background(), event); err == nil {
		t.Fatal("expected oversized event rejection")
	}
}
