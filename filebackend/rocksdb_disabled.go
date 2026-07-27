//go:build !rocksdb || !cgo

package filebackend

type RocksDBStore struct{}

func OpenRocksDB(string) (*RocksDBStore, error) { return nil, ErrRocksDBUnavailable }

// The stub still implements Store so that call sites which assign an opened
// RocksDB handle to a Store compile without the rocksdb+cgo build tags. Because
// OpenRocksDB always returns ErrRocksDBUnavailable here, these methods are never
// reached at runtime.
func (*RocksDBStore) Name() string                     { return "rocksdb" }
func (*RocksDBStore) Get(key []byte) ([]byte, error)   { return nil, ErrRocksDBUnavailable }
func (*RocksDBStore) Put(key, value []byte) error      { return ErrRocksDBUnavailable }
func (*RocksDBStore) Delete(key []byte) error          { return ErrRocksDBUnavailable }
func (*RocksDBStore) Write(entries []BatchEntry) error { return ErrRocksDBUnavailable }
func (*RocksDBStore) Close() error                     { return nil }
