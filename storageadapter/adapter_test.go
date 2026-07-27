package storageadapter

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestMemoryNamespaceTransactionsAndScan(t *testing.T) {
	store, err := Open(context.Background(), Config{Engine: "memory", Namespace: "tenant/a"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Update(context.Background(), func(tx Tx) error {
		if err := tx.Put([]byte("items/2"), []byte("two")); err != nil { return err }
		if err := tx.Put([]byte("items/1"), []byte("one")); err != nil { return err }
		return tx.CompareAndSwap([]byte("state"), nil, []byte("v1"))
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := store.Scan(context.Background(), ScanOptions{Prefix: []byte("items/"), Limit: 10})
	if err != nil || len(entries) != 2 || string(entries[0].Key) != "items/1" {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	if err := store.Update(context.Background(), func(tx Tx) error {
		return tx.CompareAndSwap([]byte("state"), []byte("wrong"), []byte("v2"))
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	value, err := store.Get(context.Background(), []byte("state"))
	if err != nil || string(value) != "v1" {
		t.Fatalf("value=%q err=%v", value, err)
	}
}

func TestFileStorePersistsCommittedTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "storage.json")
	config := Config{Engine: "file", Path: path, Namespace: "policy"}
	store, err := Open(context.Background(), config)
	if err != nil { t.Fatal(err) }
	if err := store.Update(context.Background(), func(tx Tx) error {
		return tx.Put([]byte("active"), []byte("revision-a"))
	}); err != nil { t.Fatal(err) }
	if err := store.Close(); err != nil { t.Fatal(err) }
	store, err = Open(context.Background(), config)
	if err != nil { t.Fatal(err) }
	defer store.Close()
	value, err := store.Get(context.Background(), []byte("active"))
	if err != nil || string(value) != "revision-a" {
		t.Fatalf("value=%q err=%v", value, err)
	}
}

func TestRegistrySupportsAdditionalEngine(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register("custom", openMemory); err != nil { t.Fatal(err) }
	store, err := registry.Open(context.Background(), Config{Engine: "custom"})
	if err != nil { t.Fatal(err) }
	defer store.Close()
	if store.Name() != "memory" { t.Fatalf("name=%s", store.Name()) }
	if err := registry.Register("custom", openMemory); err == nil {
		t.Fatal("duplicate registration accepted")
	}
}

func TestReadOnlyWrapperRejectsUpdates(t *testing.T) {
	store, err := Open(context.Background(), Config{Engine: "memory", ReadOnly: true})
	if err != nil { t.Fatal(err) }
	defer store.Close()
	if err := store.Update(context.Background(), func(Tx) error { return nil }); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("err=%v", err)
	}
}
