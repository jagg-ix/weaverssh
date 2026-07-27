package socketcontrol

import (
	"context"
	"errors"
	"time"
)

// WaitRuntime waits for supervisor shutdown or an unexpected exit of the active
// engine generation. Unlike the original Wait method, it does not depend only
// on parent-context cancellation. When a generation exits during Reload, it
// waits for the serialized reload transaction before deciding whether that exit
// was terminal.
func (s *Supervisor) WaitRuntime() error {
	if s == nil {
		return nil
	}
	for {
		s.mu.RLock()
		root := s.ctx
		current := s.current
		stopping := s.stopping
		timeout := s.config.ShutdownTimeout
		s.mu.RUnlock()
		if root == nil {
			return errors.New("socketcontrol: supervisor not started")
		}
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		if current == nil {
			select {
			case <-root.Done():
				return nil
			case <-time.After(10 * time.Millisecond):
				continue
			}
		}

		select {
		case <-root.Done():
			select {
			case <-current.done:
				if err := current.runError(); !normalEngineStop(err) {
					return err
				}
				return nil
			case <-time.After(timeout):
				return context.DeadlineExceeded
			}
		case <-current.done:
			// A planned reload may stop the old generation before publishing the
			// replacement. Serialize behind it, then re-read the active slot.
			s.reloadMu.Lock()
			s.reloadMu.Unlock()
			s.mu.RLock()
			replacement := s.current
			stopping = s.stopping
			rootErr := s.ctx.Err()
			s.mu.RUnlock()
			if replacement != nil && replacement != current {
				continue
			}
			err := current.runError()
			if stopping || rootErr != nil {
				if !normalEngineStop(err) {
					return err
				}
				return nil
			}
			if err == nil || errors.Is(err, context.Canceled) {
				return errors.New("socketcontrol: active engine stopped unexpectedly")
			}
			return err
		}
	}
}
