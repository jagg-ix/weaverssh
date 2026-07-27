package app

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestReconnectPolicyDelayIsBounded(t *testing.T) {
	policy := ReconnectPolicy{MinDelay: time.Second, MaxDelay: 5 * time.Second}
	want := []time.Duration{0, time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}
	for failures, expected := range want {
		if actual := policy.Delay(uint(failures)); actual != expected {
			t.Fatalf("failures=%d delay=%s want=%s", failures, actual, expected)
		}
	}
}

func TestRunReconnectLoopRetriesUntilCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	err := RunReconnectLoop(ctx, true, ReconnectPolicy{
		MinDelay: time.Millisecond,
		MaxDelay: time.Millisecond,
		Jitter:   0,
	}, func(context.Context) error {
		if attempts.Add(1) == 3 {
			cancel()
		}
		return errors.New("transport failed")
	}, nil)
	if err != nil {
		t.Fatalf("RunReconnectLoop: %v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts=%d want=3", got)
	}
}

func TestRunReconnectLoopOneShotReturnsAttemptError(t *testing.T) {
	want := errors.New("failed")
	err := RunReconnectLoop(context.Background(), false, ReconnectPolicy{}, func(context.Context) error {
		return want
	}, nil)
	if !errors.Is(err, want) {
		t.Fatalf("error=%v want=%v", err, want)
	}
}
