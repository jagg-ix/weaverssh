//go:build rocksdb && cgo

package rocksdb

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"weaverssh/storageadapter"
)

func TestRocksDBProviderContract(t *testing.T) {
	store, err := open(context.Background(), storageadapter.Config{Engine: "rocksdb", Path: filepath.Join(t.TempDir(), "rocks")})
	if err != nil { t.Fatal(err) }
	defer store.Close()
	if err := store.Update(context.Background(), func(tx storageadapter.Tx) error {
		if err := tx.Put([]byte("a/2"), []byte("two")); err != nil { return err }
		if err := tx.Put([]byte("a/1"), []byte("one")); err != nil { return err }
		return tx.CompareAndSwap([]byte("state"), nil, []byte("v1"))
	}); err != nil { t.Fatal(err) }
	entries, err := store.Scan(context.Background(), storageadapter.ScanOptions{Prefix: []byte("a/"), Limit: 10})
	if err != nil || len(entries) != 2 || string(entries[0].Key) != "a/1" { t.Fatalf("entries=%+v err=%v", entries, err) }
	if err := store.Update(context.Background(), func(tx storageadapter.Tx) error {
		return tx.CompareAndSwap([]byte("state"), []byte("bad"), []byte("v2"))
	}); !errors.Is(err, storageadapter.ErrConflict) { t.Fatalf("err=%v", err) }
}
