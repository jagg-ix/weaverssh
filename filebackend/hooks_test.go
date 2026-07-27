package filebackend

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestRegistryOrdersHooksAndReportsObserveFailures(t *testing.T) {
	var mu sync.Mutex
	order := []string{}
	failures := []Failure{}
	registry := NewRegistry(func(failure Failure) {
		mu.Lock()
		failures = append(failures, failure)
		mu.Unlock()
	})
	register := func(name string, priority int, fail bool) {
		t.Helper()
		if err := registry.Register(Hook{
			Operation: OperationWrite, Phase: PhaseBefore, Priority: priority, Mode: ModeObserve,
			Handler: func(context.Context, Event) error {
				mu.Lock()
				order = append(order, name)
				mu.Unlock()
				if fail {
					return errors.New("observed")
				}
				return nil
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	register("late", 20, false)
	register("early", -10, true)
	register("middle", 0, false)
	if err := registry.Run(context.Background(), Event{Operation: OperationWrite, Phase: PhaseBefore, Path: "file"}); err != nil {
		t.Fatalf("observe hook vetoed operation: %v", err)
	}
	if want := []string{"early", "middle", "late"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("order=%v want=%v", order, want)
	}
	if len(failures) != 1 || failures[0].Mode != ModeObserve {
		t.Fatalf("failures=%v", failures)
	}
}

func TestRegistryEnforceVetoesBeforeOnly(t *testing.T) {
	registry := NewRegistry(nil)
	if err := registry.Register(Hook{
		Operation: OperationRemove, Phase: PhaseBefore, Mode: ModeEnforce,
		Handler: func(context.Context, Event) error { return errors.New("denied") },
	}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Run(context.Background(), Event{Operation: OperationRemove, Phase: PhaseBefore, Path: "file"}); err == nil {
		t.Fatal("expected enforce veto")
	}
	if err := registry.Register(Hook{
		Operation: OperationRemove, Phase: PhaseAfter, Mode: ModeEnforce,
		Handler: func(context.Context, Event) error { return nil },
	}); err == nil {
		t.Fatal("expected enforce-after registration rejection")
	}
}

func TestRegistryBoundsHungHookConcurrency(t *testing.T) {
	registry := NewRegistry(nil)
	block := make(chan struct{})
	if err := registry.Register(Hook{
		Operation: OperationRead, Phase: PhaseBefore, Mode: ModeEnforce,
		Timeout: 20 * time.Millisecond, MaxParallel: 1,
		Handler: func(context.Context, Event) error {
			<-block
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Run(context.Background(), Event{Operation: OperationRead, Phase: PhaseBefore}); err == nil {
		t.Fatal("expected first timeout")
	}
	start := time.Now()
	if err := registry.Run(context.Background(), Event{Operation: OperationRead, Phase: PhaseBefore}); err == nil {
		t.Fatal("expected bounded admission timeout")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("second invocation was not bounded: %v", elapsed)
	}
	close(block)
}
