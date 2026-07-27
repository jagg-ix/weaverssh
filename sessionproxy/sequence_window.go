package sessionproxy

import "sync"

// sequenceWindow accepts each positive sequence at most once while permitting
// reordering within the latest 64 packets.
type sequenceWindow struct {
	mu      sync.Mutex
	highest uint64
	seen    uint64
}

func (w *sequenceWindow) Accept(sequence uint64) bool {
	if sequence == 0 {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.highest == 0 {
		w.highest = sequence
		w.seen = 1
		return true
	}
	if sequence > w.highest {
		shift := sequence - w.highest
		if shift >= 64 {
			w.seen = 1
		} else {
			w.seen = (w.seen << shift) | 1
		}
		w.highest = sequence
		return true
	}
	delta := w.highest - sequence
	if delta >= 64 {
		return false
	}
	mask := uint64(1) << delta
	if w.seen&mask != 0 {
		return false
	}
	w.seen |= mask
	return true
}
