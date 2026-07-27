package storageadapter

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

type memoryStore struct {
	mu       sync.RWMutex
	values   map[string][]byte
	closed   bool
	openedAt time.Time
	lastErr  string
}

func openMemory(context.Context, Config) (Store, error) {
	return &memoryStore{values: map[string][]byte{}, openedAt: time.Now().UTC()}, nil
}

func (store *memoryStore) Name() string { return "memory" }
func (store *memoryStore) Capabilities() Capabilities {
	return Capabilities{Transactions: true, AtomicBatch: true, CompareAndSwap: true, OrderedScan: true}
}
func (store *memoryStore) Get(_ context.Context, key []byte) ([]byte, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return nil, ErrClosed
	}
	value, ok := store.values[string(key)]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), value...), nil
}
func (store *memoryStore) Scan(_ context.Context, options ScanOptions) ([]Entry, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return nil, ErrClosed
	}
	keys := make([]string, 0, len(store.values))
	for key := range store.values {
		keyBytes := []byte(key)
		if !bytes.HasPrefix(keyBytes, options.Prefix) || len(options.After) > 0 && bytes.Compare(keyBytes, options.After) <= 0 {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > options.Limit {
		keys = keys[:options.Limit]
	}
	out := make([]Entry, 0, len(keys))
	for _, key := range keys {
		out = append(out, Entry{Key: []byte(key), Value: append([]byte(nil), store.values[key]...)})
	}
	return out, nil
}
func (store *memoryStore) Update(ctx context.Context, fn func(Tx) error) error {
	if fn == nil {
		return errors.New("storageadapter: update callback is required")
	}
	select {
	case <-ctxOrBackground(ctx).Done():
		return ctxOrBackground(ctx).Err()
	default:
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return ErrClosed
	}
	working := cloneValues(store.values)
	tx := &mapTx{values: working}
	if err := fn(tx); err != nil {
		store.lastErr = err.Error()
		return err
	}
	store.values = working
	store.lastErr = ""
	return nil
}
func (store *memoryStore) Snapshot() Snapshot {
	store.mu.RLock()
	defer store.mu.RUnlock()
	var total uint64
	for key, value := range store.values {
		total += uint64(len(key) + len(value))
	}
	return Snapshot{Engine: store.Name(), Capabilities: store.Capabilities(), Entries: uint64(len(store.values)), Bytes: total, OpenedAt: store.openedAt, LastError: store.lastErr}
}
func (store *memoryStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	store.values = nil
	return nil
}

type mapTx struct{ values map[string][]byte }
func (tx *mapTx) Get(key []byte) ([]byte, error) {
	value, ok := tx.values[string(key)]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), value...), nil
}
func (tx *mapTx) Put(key, value []byte) error {
	if len(key) == 0 {
		return errors.New("storageadapter: empty key")
	}
	tx.values[string(key)] = append([]byte(nil), value...)
	return nil
}
func (tx *mapTx) Delete(key []byte) error {
	if len(key) == 0 {
		return errors.New("storageadapter: empty key")
	}
	delete(tx.values, string(key))
	return nil
}
func (tx *mapTx) CompareAndSwap(key, oldValue, newValue []byte) error {
	current, exists := tx.values[string(key)]
	if oldValue == nil {
		if exists {
			return ErrConflict
		}
	} else if !exists || !bytes.Equal(current, oldValue) {
		return ErrConflict
	}
	if newValue == nil {
		delete(tx.values, string(key))
		return nil
	}
	tx.values[string(key)] = append([]byte(nil), newValue...)
	return nil
}
func cloneValues(values map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(values))
	for key, value := range values {
		out[key] = append([]byte(nil), value...)
	}
	return out
}
