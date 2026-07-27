package storageadapter

import (
	"bytes"
	"context"
	"errors"
)

type boundedStore struct {
	Store
	config Config
}

func (store *boundedStore) Get(ctx context.Context, key []byte) ([]byte, error) {
	if err := store.validateKey(key); err != nil {
		return nil, err
	}
	value, err := store.Store.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if len(value) > store.config.MaxValueBytes {
		return nil, errors.New("storageadapter: stored value exceeds configured bound")
	}
	return append([]byte(nil), value...), nil
}

func (store *boundedStore) Scan(ctx context.Context, options ScanOptions) ([]Entry, error) {
	if len(options.Prefix) > store.config.MaxKeyBytes || len(options.After) > store.config.MaxKeyBytes {
		return nil, errors.New("storageadapter: scan key exceeds configured bound")
	}
	if options.Limit <= 0 || options.Limit > 10000 {
		return nil, errors.New("storageadapter: scan limit must be 1..10000")
	}
	entries, err := store.Store.Scan(ctx, options)
	if err != nil {
		return nil, err
	}
	for index := range entries {
		if err := store.validateKey(entries[index].Key); err != nil {
			return nil, err
		}
		if len(entries[index].Value) > store.config.MaxValueBytes {
			return nil, errors.New("storageadapter: scanned value exceeds configured bound")
		}
		entries[index].Key = append([]byte(nil), entries[index].Key...)
		entries[index].Value = append([]byte(nil), entries[index].Value...)
	}
	return entries, nil
}

func (store *boundedStore) Update(ctx context.Context, fn func(Tx) error) error {
	if fn == nil {
		return errors.New("storageadapter: update callback is required")
	}
	if store.config.ReadOnly {
		return ErrReadOnly
	}
	return store.Store.Update(ctx, func(tx Tx) error {
		return fn(&boundedTx{Tx: tx, config: store.config})
	})
}

func (store *boundedStore) Snapshot() Snapshot {
	snapshot := store.Store.Snapshot()
	snapshot.Namespace = store.config.Namespace
	if store.config.ReadOnly {
		snapshot.Capabilities.ReadOnly = true
	}
	return snapshot
}

func (store *boundedStore) validateKey(key []byte) error {
	if len(key) == 0 || len(key) > store.config.MaxKeyBytes {
		return errors.New("storageadapter: key exceeds configured bound or is empty")
	}
	return nil
}

type boundedTx struct {
	Tx
	config Config
}

func (tx *boundedTx) Get(key []byte) ([]byte, error) {
	if len(key) == 0 || len(key) > tx.config.MaxKeyBytes {
		return nil, errors.New("storageadapter: key exceeds configured bound or is empty")
	}
	value, err := tx.Tx.Get(key)
	if err != nil {
		return nil, err
	}
	if len(value) > tx.config.MaxValueBytes {
		return nil, errors.New("storageadapter: value exceeds configured bound")
	}
	return append([]byte(nil), value...), nil
}

func (tx *boundedTx) Put(key, value []byte) error {
	if len(key) == 0 || len(key) > tx.config.MaxKeyBytes || len(value) > tx.config.MaxValueBytes {
		return errors.New("storageadapter: key or value exceeds configured bound")
	}
	return tx.Tx.Put(key, value)
}

func (tx *boundedTx) Delete(key []byte) error {
	if len(key) == 0 || len(key) > tx.config.MaxKeyBytes {
		return errors.New("storageadapter: key exceeds configured bound or is empty")
	}
	return tx.Tx.Delete(key)
}

func (tx *boundedTx) CompareAndSwap(key, oldValue, newValue []byte) error {
	if len(key) == 0 || len(key) > tx.config.MaxKeyBytes || len(oldValue) > tx.config.MaxValueBytes || len(newValue) > tx.config.MaxValueBytes {
		return errors.New("storageadapter: compare-and-swap input exceeds configured bound")
	}
	return tx.Tx.CompareAndSwap(key, oldValue, newValue)
}

type namespaceStore struct {
	Store
	namespace []byte
}

func (store *namespaceStore) Name() string { return store.Store.Name() }
func (store *namespaceStore) Capabilities() Capabilities { return store.Store.Capabilities() }

func (store *namespaceStore) Get(ctx context.Context, key []byte) ([]byte, error) {
	if err := validateLogicalKey(key); err != nil {
		return nil, err
	}
	return store.Store.Get(ctx, store.key(key))
}

func (store *namespaceStore) Scan(ctx context.Context, options ScanOptions) ([]Entry, error) {
	inner := ScanOptions{Prefix: store.key(options.Prefix), Limit: options.Limit}
	if len(options.After) > 0 {
		inner.After = store.key(options.After)
	}
	entries, err := store.Store.Scan(ctx, inner)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if !bytes.HasPrefix(entry.Key, store.namespace) {
			continue
		}
		logical := entry.Key[len(store.namespace):]
		if len(logical) == 0 {
			return nil, errors.New("storageadapter: provider returned empty namespaced key")
		}
		entry.Key = append([]byte(nil), logical...)
		out = append(out, entry)
	}
	return out, nil
}

func (store *namespaceStore) Update(ctx context.Context, fn func(Tx) error) error {
	if fn == nil {
		return errors.New("storageadapter: update callback is required")
	}
	return store.Store.Update(ctx, func(tx Tx) error {
		return fn(&namespaceTx{Tx: tx, namespace: store.namespace})
	})
}

func (store *namespaceStore) Snapshot() Snapshot {
	snapshot := store.Store.Snapshot()
	snapshot.Namespace = string(bytes.TrimSuffix(store.namespace, []byte("/")))
	return snapshot
}

func (store *namespaceStore) key(key []byte) []byte {
	out := make([]byte, 0, len(store.namespace)+len(key))
	out = append(out, store.namespace...)
	out = append(out, key...)
	return out
}

type namespaceTx struct {
	Tx
	namespace []byte
}

func (tx *namespaceTx) key(key []byte) []byte {
	out := make([]byte, 0, len(tx.namespace)+len(key))
	out = append(out, tx.namespace...)
	return append(out, key...)
}
func (tx *namespaceTx) Get(key []byte) ([]byte, error) {
	if err := validateLogicalKey(key); err != nil { return nil, err }
	return tx.Tx.Get(tx.key(key))
}
func (tx *namespaceTx) Put(key, value []byte) error {
	if err := validateLogicalKey(key); err != nil { return err }
	return tx.Tx.Put(tx.key(key), value)
}
func (tx *namespaceTx) Delete(key []byte) error {
	if err := validateLogicalKey(key); err != nil { return err }
	return tx.Tx.Delete(tx.key(key))
}
func (tx *namespaceTx) CompareAndSwap(key, oldValue, newValue []byte) error {
	if err := validateLogicalKey(key); err != nil { return err }
	return tx.Tx.CompareAndSwap(tx.key(key), oldValue, newValue)
}

func validateLogicalKey(key []byte) error {
	if len(key) == 0 {
		return errors.New("storageadapter: logical key is empty")
	}
	return nil
}
