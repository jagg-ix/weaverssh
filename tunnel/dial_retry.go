package tunnel

import (
	"fmt"
	"net"
)

type NetDialFunc func(network, address string) (net.Conn, error)

func DialWithPolicy(network, address string, policy RetryPolicy) (net.Conn, error) {
	return dialWithPolicy(network, address, policy, net.Dial)
}

func dialWithPolicy(network, address string, policy RetryPolicy, dial NetDialFunc) (net.Conn, error) {
	policy = normalizeRetryPolicy(policy)
	var lastErr error

	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		conn, err := dial(network, address)
		if err == nil && conn != nil {
			return conn, nil
		}
		if err == nil {
			err = fmt.Errorf("dial returned nil connection")
		}

		lastErr = err
		if policy.IsRecoverable != nil && !policy.IsRecoverable(err) {
			return nil, fmt.Errorf("dial %s %s failed: non-recoverable after attempt %d/%d: %w",
				network, address, attempt, policy.MaxAttempts, err)
		}
		if attempt < policy.MaxAttempts {
			policy.Sleep(retryBackoff(policy, attempt))
		}
	}

	return nil, fmt.Errorf("dial %s %s failed after %d attempts: %w",
		network, address, policy.MaxAttempts, lastErr)
}
