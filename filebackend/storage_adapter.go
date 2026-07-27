package filebackend

import (
	"context"
	"errors"

	"weaverssh/storageadapter"
)

// AdapterStore exposes any storageadapter.Store through the established
// filebackend.Store contract used by the metadata core.
type AdapterStore struct {
	store storageadapter.Store
}

func NewAdapterStore(store storageadapter.Store) (*AdapterStore, error) {
	if store == nil {
		return nil, errors.New("filebackend: storage adapter is required")
	}
	return &AdapterStore{store: store}, nil
}

func OpenAdapterStore(ctx context.Context, config storageadapter.Config) (*AdapterStore, error) {
	store, err := storageadapter.Open(ctx, config)
	if err != nil {
		return nil, err
	}
	adapter, err := NewAdapterStore(store)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	return adapter, nil
}

func (store *AdapterStore) Name() string {
	if store == nil || store.store == nil {
		return ""
	}
	return store.store.Name()
}

func (store *AdapterStore) Get(key []byte) ([]byte, error) {
	if store == nil || store.store == nil {
		return nil, errors.New("filebackend: incomplete storage adapter")
	}
	value, err := store.store.Get(context.Background(), key)
	if errors.Is(err, storageadapter.ErrNotFound) {
		return nil, ErrNotFound
	}
	return value, err
}

func (store *AdapterStore) Put(key, value []byte) error {
	return store.Write([]BatchEntry{{Key: key, Value: value}})
}

func (store *AdapterStore) Delete(key []byte) error {
	return store.Write([]BatchEntry{{Key: key, Delete: true}})
}

func (store *AdapterStore) Write(entries []BatchEntry) error {
	if store == nil || store.store == nil {
		return errors.New("filebackend: incomplete storage adapter")
	}
	return store.store.Update(context.Background(), func(tx storageadapter.Tx) error {
		for _, entry := range entries {
			if len(entry.Key) == 0 {
				return errors.New("filebackend: empty core key")
			}
			if entry.Delete {
				if err := tx.Delete(entry.Key); err != nil {
					return err
				}
				continue
			}
			if err := tx.Put(entry.Key, entry.Value); err != nil {
				return err
			}
		}
		return nil
	})
}

func (store *AdapterStore) Close() error {
	if store == nil || store.store == nil {
		return nil
	}
	return store.store.Close()
}

func (store *AdapterStore) Snapshot() storageadapter.Snapshot {
	if store == nil || store.store == nil {
		return storageadapter.Snapshot{}
	}
	return store.store.Snapshot()
}
