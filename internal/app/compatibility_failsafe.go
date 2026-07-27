package app

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

type CompatibilityAction string

const (
	CompatibilityRecovered      CompatibilityAction = "recoveredService"
	CompatibilityRetryUpgrade   CompatibilityAction = "retryUpgrade"
	CompatibilityFallbackRawX11 CompatibilityAction = "fallbackRawX11"
	CompatibilityQuarantinePeer CompatibilityAction = "quarantinePeer"
)

type CompatibilityFailsafePolicy struct {
	MaxUpgradeAttempts  int
	InitialBackoff      time.Duration
	MaxBackoff          time.Duration
	AttemptTimeout      time.Duration
	AllowRawX11Fallback bool
	Sleep               func(time.Duration)
}

type CompatibilityDecision struct {
	Action        CompatibilityAction
	Attempts      int
	Authenticated bool
	Audit         []string
	Err           error
}

type websocketUpgradeFunc func(net.Conn) (*websocket.Conn, error)

func defaultCompatibilityFailsafePolicy() CompatibilityFailsafePolicy {
	return CompatibilityFailsafePolicy{
		MaxUpgradeAttempts: 3,
		InitialBackoff:     25 * time.Millisecond,
		MaxBackoff:         250 * time.Millisecond,
		AttemptTimeout:     5 * time.Second,
	}
}

func normalizeCompatibilityFailsafePolicy(policy CompatibilityFailsafePolicy) CompatibilityFailsafePolicy {
	defaults := defaultCompatibilityFailsafePolicy()
	if policy.MaxUpgradeAttempts <= 0 {
		policy.MaxUpgradeAttempts = defaults.MaxUpgradeAttempts
	}
	if policy.InitialBackoff <= 0 {
		policy.InitialBackoff = defaults.InitialBackoff
	}
	if policy.MaxBackoff <= 0 {
		policy.MaxBackoff = defaults.MaxBackoff
	}
	if policy.AttemptTimeout <= 0 {
		policy.AttemptTimeout = defaults.AttemptTimeout
	}
	if policy.Sleep == nil {
		policy.Sleep = time.Sleep
	}
	return policy
}

func compatibilityBackoff(policy CompatibilityFailsafePolicy, attempt int) time.Duration {
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

func newCompatibilityDecision(action CompatibilityAction, attempts int, authenticated bool, audit []string, err error) CompatibilityDecision {
	copiedAudit := append([]string(nil), audit...)
	return CompatibilityDecision{
		Action:        action,
		Attempts:      attempts,
		Authenticated: authenticated,
		Audit:         copiedAudit,
		Err:           err,
	}
}

func upgradeToWebSocketWithFailsafe(
	client *ClientConnection,
	policy CompatibilityFailsafePolicy,
	upgrade websocketUpgradeFunc,
) (*websocket.Conn, CompatibilityDecision) {
	policy = normalizeCompatibilityFailsafePolicy(policy)
	if upgrade == nil {
		upgrade = upgradeToWebSocket
	}

	authenticated := client != nil && client.authenticated
	audit := []string{"compatProbe"}
	if !authenticated {
		audit = append(audit, "quarantinePeer", "auditFailClosed")
		return nil, newCompatibilityDecision(
			CompatibilityQuarantinePeer,
			0,
			false,
			audit,
			fmt.Errorf("websocket upgrade denied: unauthenticated peer"),
		)
	}

	var lastErr error
	for attempt := 1; attempt <= policy.MaxUpgradeAttempts; attempt++ {
		if client.conn != nil && policy.AttemptTimeout > 0 {
			if err := client.conn.SetDeadline(time.Now().Add(policy.AttemptTimeout)); err != nil {
				audit = append(audit, "deadlineSetFailed", "quarantinePeer", "auditFailClosed")
				return nil, newCompatibilityDecision(CompatibilityQuarantinePeer, attempt, true, audit, err)
			}
		}

		ws, err := upgrade(client.conn)
		if client.conn != nil {
			_ = client.conn.SetDeadline(time.Time{})
		}
		if err == nil && ws != nil {
			audit = append(audit, "retryUpgradeSucceeded", "auditRecovered")
			return ws, newCompatibilityDecision(CompatibilityRecovered, attempt, true, audit, nil)
		}
		if err == nil {
			err = fmt.Errorf("websocket upgrade returned nil connection")
		}

		lastErr = err
		audit = append(audit, "compatDeviation", "retryUpgradeFailed")
		if attempt < policy.MaxUpgradeAttempts {
			audit = append(audit, "backoffScheduled")
			policy.Sleep(compatibilityBackoff(policy, attempt))
		}
	}

	if policy.AllowRawX11Fallback {
		audit = append(audit, "fallbackRawX11", "fallbackAuthenticated", "degradedRelay", "auditDegraded")
		return nil, newCompatibilityDecision(CompatibilityFallbackRawX11, policy.MaxUpgradeAttempts, true, audit, lastErr)
	}

	audit = append(audit, "quarantinePeer", "auditFailClosed")
	return nil, newCompatibilityDecision(CompatibilityQuarantinePeer, policy.MaxUpgradeAttempts, true, audit, lastErr)
}

func logCompatibilityDecision(prefix string, decision CompatibilityDecision) {
	if decision.Err != nil {
		log.Printf("%s action=%s attempts=%d authenticated=%v err=%v audit=%v",
			prefix, decision.Action, decision.Attempts, decision.Authenticated, decision.Err, decision.Audit)
		return
	}
	log.Printf("%s action=%s attempts=%d authenticated=%v audit=%v",
		prefix, decision.Action, decision.Attempts, decision.Authenticated, decision.Audit)
}

func authenticatedRawX11FallbackDecision(client *ClientConnection) CompatibilityDecision {
	authenticated := client != nil && client.authenticated
	audit := []string{"compatProbe", "compatDeviation"}
	if authenticated {
		audit = append(audit, "fallbackRawX11", "fallbackAuthenticated", "degradedRelay", "auditDegraded")
		return newCompatibilityDecision(CompatibilityFallbackRawX11, 0, true, audit, nil)
	}
	audit = append(audit, "quarantinePeer", "auditFailClosed")
	return newCompatibilityDecision(
		CompatibilityQuarantinePeer,
		0,
		false,
		audit,
		fmt.Errorf("raw X11 fallback denied: unauthenticated peer"),
	)
}
