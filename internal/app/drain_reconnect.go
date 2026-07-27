package app

import (
	"fmt"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

type drainReconnectOutcome string

const (
	drainReconnectRecovered  drainReconnectOutcome = "recoveredService"
	drainReconnectDegraded   drainReconnectOutcome = "degradedRelay"
	drainReconnectFailClosed drainReconnectOutcome = "failClosed"
)

type websocketRelaySession interface {
	ReadMessage() (int, []byte, error)
	WriteMessage(int, []byte) error
	Close() error
}

type agentWebSocketSession struct {
	ws   *websocket.Conn
	conn net.Conn
}

func (s *agentWebSocketSession) ReadMessage() (int, []byte, error) {
	return s.ws.ReadMessage()
}

func (s *agentWebSocketSession) WriteMessage(messageType int, data []byte) error {
	return s.ws.WriteMessage(messageType, data)
}

func (s *agentWebSocketSession) Close() error {
	var firstErr error
	if s.ws != nil {
		firstErr = s.ws.Close()
	}
	if s.conn != nil {
		if err := s.conn.Close(); firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type reconnectWebSocketFunc func() (websocketRelaySession, error)

type drainReconnectPolicy struct {
	MaxReconnects  int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Sleep          func(time.Duration)
	Authenticated  func() bool
	AllowDegraded  bool
}

type drainReconnectDecision struct {
	Outcome   drainReconnectOutcome
	Accepted  int64
	Delivered int64
	Buffered  int64
	Attempts  int
	Audit     []string
	Err       error
}

func defaultDrainReconnectPolicy() drainReconnectPolicy {
	return drainReconnectPolicy{
		MaxReconnects:  2,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     time.Second,
		Authenticated:  func() bool { return true },
	}
}

func normalizeDrainReconnectPolicy(policy drainReconnectPolicy) drainReconnectPolicy {
	defaults := defaultDrainReconnectPolicy()
	if policy.MaxReconnects <= 0 {
		policy.MaxReconnects = defaults.MaxReconnects
	}
	if policy.InitialBackoff <= 0 {
		policy.InitialBackoff = defaults.InitialBackoff
	}
	if policy.MaxBackoff <= 0 {
		policy.MaxBackoff = defaults.MaxBackoff
	}
	if policy.Sleep == nil {
		policy.Sleep = time.Sleep
	}
	if policy.Authenticated == nil {
		policy.Authenticated = defaults.Authenticated
	}
	return policy
}

func drainReconnectBackoff(policy drainReconnectPolicy, attempt int) time.Duration {
	if attempt <= 1 {
		return policy.InitialBackoff
	}
	backoff := policy.InitialBackoff
	for i := 1; i < attempt; i++ {
		backoff *= 2
		if backoff >= policy.MaxBackoff {
			return policy.MaxBackoff
		}
	}
	return backoff
}

func clonePayloads(payloads [][]byte) ([][]byte, int64) {
	cloned := make([][]byte, 0, len(payloads))
	var accepted int64
	for _, payload := range payloads {
		if len(payload) == 0 {
			continue
		}
		copyPayload := append([]byte(nil), payload...)
		cloned = append(cloned, copyPayload)
		accepted += int64(len(copyPayload))
	}
	return cloned, accepted
}

func recoverBufferedWebSocketSession(
	current websocketRelaySession,
	policy drainReconnectPolicy,
	reconnect reconnectWebSocketFunc,
	payloads [][]byte,
) (websocketRelaySession, drainReconnectDecision) {
	policy = normalizeDrainReconnectPolicy(policy)
	bufferedPayloads, accepted := clonePayloads(payloads)
	decision := drainReconnectDecision{
		Outcome:  drainReconnectFailClosed,
		Accepted: accepted,
		Buffered: accepted,
		Audit:    []string{"faultDetected", "drainStarted"},
	}

	for range bufferedPayloads {
		decision.Audit = append(decision.Audit, "drainChunk")
	}
	// Runtime drain means the bytes are now copied into local custody before any
	// reconnect/degraded decision is allowed.
	decision.Audit = append(decision.Audit, "drainComplete")

	if current != nil {
		_ = current.Close()
	}
	if reconnect == nil {
		decision.Audit = append(decision.Audit, "reconnectExhausted", "failClosed", "auditFailClosed")
		decision.Err = fmt.Errorf("reconnect unavailable")
		return nil, decision
	}
	if !policy.Authenticated() {
		decision.Audit = append(decision.Audit, "authRevoked", "failClosed", "auditFailClosed")
		decision.Err = fmt.Errorf("reconnect denied: authentication is not valid")
		return nil, decision
	}

	var lastErr error
	for attempt := 1; attempt <= policy.MaxReconnects; attempt++ {
		decision.Attempts = attempt
		next, err := reconnect()
		if err != nil {
			lastErr = err
			if attempt < policy.MaxReconnects {
				policy.Sleep(drainReconnectBackoff(policy, attempt))
			}
			continue
		}

		delivered := int64(0)
		for _, payload := range bufferedPayloads {
			if err := next.WriteMessage(websocket.BinaryMessage, payload); err != nil {
				lastErr = err
				_ = next.Close()
				next = nil
				break
			}
			delivered += int64(len(payload))
		}
		if next == nil {
			if attempt < policy.MaxReconnects {
				policy.Sleep(drainReconnectBackoff(policy, attempt))
			}
			continue
		}

		decision.Outcome = drainReconnectRecovered
		decision.Delivered = delivered
		decision.Buffered = accepted - delivered
		decision.Audit = append(decision.Audit, "reconnectSucceeded", "auditRecovered")
		return next, decision
	}

	if policy.AllowDegraded && policy.Authenticated() && accepted == 0 {
		decision.Outcome = drainReconnectDegraded
		decision.Buffered = 0
		decision.Audit = append(decision.Audit, "degradedRelay")
		return nil, decision
	}

	decision.Audit = append(decision.Audit, "reconnectExhausted", "failClosed", "auditFailClosed")
	decision.Err = fmt.Errorf("reconnect exhausted after %d attempts: %w", policy.MaxReconnects, lastErr)
	return nil, decision
}
