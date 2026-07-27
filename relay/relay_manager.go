package relay

import (
	"sync"
	"time"
)

// RelayManager manages multiple relays
type RelayManager struct {
	relays        map[string]*Relay
	mu            sync.RWMutex
	cleanupTicker *time.Ticker
	done          chan struct{}
	closeOnce     sync.Once
}

// NewRelayManager creates a new relay manager
func NewRelayManager() *RelayManager {
	manager := &RelayManager{
		relays: make(map[string]*Relay),
		done:   make(chan struct{}),
	}

	// Start cleanup routine
	manager.cleanupTicker = time.NewTicker(5 * time.Minute)
	go func() {
		for {
			select {
			case <-manager.cleanupTicker.C:
				manager.cleanupInactiveRelays()
			case <-manager.done:
				return
			}
		}
	}()

	return manager
}

// AddRelay adds a relay to the manager
func (m *RelayManager) AddRelay(id string, relay *Relay) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.relays[id] = relay
}

// GetRelay retrieves a relay by ID
func (m *RelayManager) GetRelay(id string) (*Relay, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	relay, ok := m.relays[id]
	return relay, ok
}

// RemoveRelay removes a relay from the manager
func (m *RelayManager) RemoveRelay(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.relays, id)
}

// cleanupInactiveRelays removes inactive relays
func (m *RelayManager) cleanupInactiveRelays() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, relay := range m.relays {
		if relay.isReapable() {
			delete(m.relays, id)
		}
	}
}

// GetActiveRelayCount returns the number of active relays
func (m *RelayManager) GetActiveRelayCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, relay := range m.relays {
		_, _, _, _, isActive := relay.GetStats()
		if isActive {
			count++
		}
	}

	return count
}

// GetTotalStats returns total bytes sent and received across all relays
func (m *RelayManager) GetTotalStats() (int64, int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var totalSent, totalReceived int64

	for _, relay := range m.relays {
		_, _, sent, received, _ := relay.GetStats()
		totalSent += sent
		totalReceived += received
	}

	return totalSent, totalReceived
}

// Close shuts down the relay manager
func (m *RelayManager) Close() {
	m.closeOnce.Do(func() {
		if m.cleanupTicker != nil {
			m.cleanupTicker.Stop()
		}
		if m.done != nil {
			close(m.done)
		}
	})
}
