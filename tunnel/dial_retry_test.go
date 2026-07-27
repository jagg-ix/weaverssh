package tunnel

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestDialWithPolicyRetriesBeforeSuccess(t *testing.T) {
	var attempts int
	var sleeps []time.Duration

	conn, err := dialWithPolicy(
		"tcp",
		"127.0.0.1:1",
		RetryPolicy{
			MaxAttempts:    3,
			InitialBackoff: 5 * time.Millisecond,
			MaxBackoff:     20 * time.Millisecond,
			Sleep: func(d time.Duration) {
				sleeps = append(sleeps, d)
			},
		},
		func(network, address string) (net.Conn, error) {
			attempts++
			if attempts < 3 {
				return nil, errors.New("temporary dial failure")
			}
			return &net.TCPConn{}, nil
		},
	)

	if err != nil {
		t.Fatalf("dialWithPolicy returned error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected connection")
	}
	if attempts != 3 {
		t.Fatalf("attempts=%d want 3", attempts)
	}
	if len(sleeps) != 2 || sleeps[0] != 5*time.Millisecond || sleeps[1] != 10*time.Millisecond {
		t.Fatalf("sleeps=%v want [5ms 10ms]", sleeps)
	}
}

func TestDialWithPolicyFailsClosedOnNonRecoverableError(t *testing.T) {
	terminalErr := errors.New("authorization denied")
	var attempts int

	_, err := dialWithPolicy(
		"tcp",
		"127.0.0.1:1",
		RetryPolicy{
			MaxAttempts:    3,
			InitialBackoff: time.Millisecond,
			Sleep:          func(time.Duration) {},
			IsRecoverable: func(err error) bool {
				return !errors.Is(err, terminalErr)
			},
		},
		func(network, address string) (net.Conn, error) {
			attempts++
			return nil, terminalErr
		},
	)

	if err == nil {
		t.Fatal("expected non-recoverable dial error")
	}
	if attempts != 1 {
		t.Fatalf("attempts=%d want 1", attempts)
	}
}

func TestDialWithPolicyFailsClosedOnNilConnection(t *testing.T) {
	var attempts int

	_, err := dialWithPolicy(
		"tcp",
		"127.0.0.1:1",
		RetryPolicy{
			MaxAttempts:    2,
			InitialBackoff: time.Millisecond,
			Sleep:          func(time.Duration) {},
		},
		func(network, address string) (net.Conn, error) {
			attempts++
			return nil, nil
		},
	)

	if err == nil {
		t.Fatal("expected nil connection to fail closed")
	}
	if attempts != 2 {
		t.Fatalf("attempts=%d want 2", attempts)
	}
}
