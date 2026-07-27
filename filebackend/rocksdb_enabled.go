//go:build rocksdb && cgo

package filebackend

/*
#cgo pkg-config: rocksdb
#include <stdlib.h>
#include <rocksdb/c.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"
)

const maxRocksDBCoreValueBytes = 1 << 20

var emptyRocksDBByte byte

// RocksDBStore uses the official RocksDB C API. File payloads are not stored in
// RocksDB; this store is used only by the file-service metadata core.
type RocksDBStore struct {
	mu     sync.RWMutex
	db     *C.rocksdb_t
	read   *C.rocksdb_readoptions_t
	write  *C.rocksdb_writeoptions_t
	path   string
	closed bool
}

// OpenRocksDB opens or creates a RocksDB core. Writes use synchronous WAL mode.
func OpenRocksDB(path string) (*RocksDBStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("filebackend: RocksDB path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("filebackend: resolve RocksDB path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		return nil, fmt.Errorf("filebackend: create RocksDB parent: %w", err)
	}
	options := C.rocksdb_options_create()
	if options == nil {
		return nil, errors.New("filebackend: create RocksDB options")
	}
	defer C.rocksdb_options_destroy(options)
	C.rocksdb_options_set_create_if_missing(options, 1)
	C.rocksdb_options_set_paranoid_checks(options, 1)
	cpath := C.CString(absolute)
	defer C.free(unsafe.Pointer(cpath))
	var cerr *C.char
	db := C.rocksdb_open(options, cpath, &cerr)
	if err := rocksDBError(cerr); err != nil {
		return nil, fmt.Errorf("filebackend: open RocksDB: %w", err)
	}
	if db == nil {
		return nil, errors.New("filebackend: RocksDB returned a nil database")
	}
	read := C.rocksdb_readoptions_create()
	write := C.rocksdb_writeoptions_create()
	if read == nil || write == nil {
		if read != nil {
			C.rocksdb_readoptions_destroy(read)
		}
		if write != nil {
			C.rocksdb_writeoptions_destroy(write)
		}
		C.rocksdb_close(db)
		return nil, errors.New("filebackend: create RocksDB read/write options")
	}
	C.rocksdb_writeoptions_set_sync(write, 1)
	return &RocksDBStore{db: db, read: read, write: write, path: absolute}, nil
}

func (s *RocksDBStore) Name() string { return "rocksdb" }

func (s *RocksDBStore) Get(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("filebackend: empty RocksDB key")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.db == nil {
		return nil, errors.New("filebackend: RocksDB store closed")
	}
	var valueLength C.size_t
	var cerr *C.char
	value := C.rocksdb_get(s.db, s.read, bytePointer(key), C.size_t(len(key)), &valueLength, &cerr)
	if err := rocksDBError(cerr); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, ErrNotFound
	}
	defer C.rocksdb_free(unsafe.Pointer(value))
	if uint64(valueLength) > maxRocksDBCoreValueBytes {
		return nil, fmt.Errorf("filebackend: RocksDB core value exceeds %d bytes", maxRocksDBCoreValueBytes)
	}
	return C.GoBytes(unsafe.Pointer(value), C.int(valueLength)), nil
}

func (s *RocksDBStore) Put(key, value []byte) error {
	return s.Write([]BatchEntry{{Key: key, Value: value}})
}

func (s *RocksDBStore) Delete(key []byte) error {
	return s.Write([]BatchEntry{{Key: key, Delete: true}})
}

func (s *RocksDBStore) Write(entries []BatchEntry) error {
	if len(entries) == 0 {
		return nil
	}
	for _, entry := range entries {
		if len(entry.Key) == 0 {
			return errors.New("filebackend: empty RocksDB key")
		}
		if len(entry.Value) > maxRocksDBCoreValueBytes {
			return fmt.Errorf("filebackend: RocksDB core value exceeds %d bytes", maxRocksDBCoreValueBytes)
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.db == nil {
		return errors.New("filebackend: RocksDB store closed")
	}
	batch := C.rocksdb_writebatch_create()
	if batch == nil {
		return errors.New("filebackend: create RocksDB write batch")
	}
	defer C.rocksdb_writebatch_destroy(batch)
	for _, entry := range entries {
		if entry.Delete {
			C.rocksdb_writebatch_delete(batch, bytePointer(entry.Key), C.size_t(len(entry.Key)))
			continue
		}
		C.rocksdb_writebatch_put(
			batch,
			bytePointer(entry.Key), C.size_t(len(entry.Key)),
			bytePointer(entry.Value), C.size_t(len(entry.Value)),
		)
	}
	var cerr *C.char
	C.rocksdb_write(s.db, s.write, batch, &cerr)
	return rocksDBError(cerr)
}

func (s *RocksDBStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.read != nil {
		C.rocksdb_readoptions_destroy(s.read)
		s.read = nil
	}
	if s.write != nil {
		C.rocksdb_writeoptions_destroy(s.write)
		s.write = nil
	}
	if s.db != nil {
		C.rocksdb_close(s.db)
		s.db = nil
	}
	return nil
}

func bytePointer(value []byte) *C.char {
	if len(value) == 0 {
		return (*C.char)(unsafe.Pointer(&emptyRocksDBByte))
	}
	return (*C.char)(unsafe.Pointer(&value[0]))
}

func rocksDBError(value *C.char) error {
	if value == nil {
		return nil
	}
	message := C.GoString(value)
	C.rocksdb_free(unsafe.Pointer(value))
	return errors.New(message)
}
