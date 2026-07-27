package tunnel

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWebSocketClientRetriesWithMonotoneBackoff(t *testing.T) {
	client := NewWebSocketClient("example.test/ws")
	var attempts int
	var sleeps []time.Duration

	err := client.connectWithPolicy(
		RetryPolicy{
			MaxAttempts:    3,
			InitialBackoff: 10 * time.Millisecond,
			MaxBackoff:     100 * time.Millisecond,
			Sleep: func(d time.Duration) {
				sleeps = append(sleeps, d)
			},
		},
		func(url string, header http.Header) (*websocket.Conn, *http.Response, error) {
			attempts++
			if attempts < 3 {
				return nil, nil, errors.New("temporary dial failure")
			}
			return &websocket.Conn{}, nil, nil
		},
	)

	if err != nil {
		t.Fatalf("connectWithPolicy returned error: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts=%d want 3", attempts)
	}
	if len(sleeps) != 2 || sleeps[0] != 10*time.Millisecond || sleeps[1] != 20*time.Millisecond {
		t.Fatalf("sleeps=%v want [10ms 20ms]", sleeps)
	}
}

func TestWebSocketClientStopsOnNonRecoverableError(t *testing.T) {
	client := NewWebSocketClient("ws://example.test/ws")
	var attempts int
	terminalErr := errors.New("bad auth")

	err := client.connectWithPolicy(
		RetryPolicy{
			MaxAttempts:    3,
			InitialBackoff: time.Millisecond,
			Sleep:          func(time.Duration) {},
			IsRecoverable: func(err error) bool {
				return !errors.Is(err, terminalErr)
			},
		},
		func(url string, header http.Header) (*websocket.Conn, *http.Response, error) {
			attempts++
			return nil, nil, terminalErr
		},
	)

	if err == nil {
		t.Fatal("expected non-recoverable error")
	}
	if attempts != 1 {
		t.Fatalf("attempts=%d want 1", attempts)
	}
}

func TestRetryBackoffCapsAtMaxBackoff(t *testing.T) {
	policy := RetryPolicy{
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     25 * time.Millisecond,
	}

	if got := retryBackoff(policy, 1); got != 10*time.Millisecond {
		t.Fatalf("attempt 1 backoff=%v want 10ms", got)
	}
	if got := retryBackoff(policy, 2); got != 20*time.Millisecond {
		t.Fatalf("attempt 2 backoff=%v want 20ms", got)
	}
	if got := retryBackoff(policy, 3); got != 25*time.Millisecond {
		t.Fatalf("attempt 3 backoff=%v want 25ms cap", got)
	}
}
