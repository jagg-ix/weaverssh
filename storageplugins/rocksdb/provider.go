//go:build rocksdb && cgo

package rocksdb

/*
#cgo pkg-config: rocksdb
#include <stdlib.h>
#include <rocksdb/c.h>
*/
import "C"

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"weaverssh/storageadapter"
)

const maxValueBytes = 128 << 20
var emptyByte byte

type store struct {
	mu       sync.Mutex
	db       *C.rocksdb_t
	read     *C.rocksdb_readoptions_t
	write    *C.rocksdb_writeoptions_t
	path     string
	closed   bool
	readOnly bool
	openedAt time.Time
	lastErr  string
}

func init() { _ = storageadapter.Register("rocksdb", open) }

func open(_ context.Context, config storageadapter.Config) (storageadapter.Store, error) {
	path := strings.TrimSpace(config.Path)
	if path == "" { return nil, errors.New("storage rocksdb: path is required") }
	absolute, err := filepath.Abs(path)
	if err != nil { return nil, err }
	if !config.ReadOnly {
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil { return nil, err }
	}
	options := C.rocksdb_options_create()
	if options == nil { return nil, errors.New("storage rocksdb: create options") }
	defer C.rocksdb_options_destroy(options)
	C.rocksdb_options_set_create_if_missing(options, boolInt(!config.ReadOnly))
	C.rocksdb_options_set_paranoid_checks(options, 1)
	cpath := C.CString(absolute)
	defer C.free(unsafe.Pointer(cpath))
	var message *C.char
	var db *C.rocksdb_t
	if config.ReadOnly {
		db = C.rocksdb_open_for_read_only(options, cpath, 0, &message)
	} else {
		db = C.rocksdb_open(options, cpath, &message)
	}
	if err := rocksError(message); err != nil { return nil, err }
	if db == nil { return nil, errors.New("storage rocksdb: nil database") }
	read := C.rocksdb_readoptions_create()
	write := C.rocksdb_writeoptions_create()
	if read == nil || write == nil {
		if read != nil { C.rocksdb_readoptions_destroy(read) }
		if write != nil { C.rocksdb_writeoptions_destroy(write) }
		C.rocksdb_close(db)
		return nil, errors.New("storage rocksdb: create read/write options")
	}
	C.rocksdb_writeoptions_set_sync(write, 1)
	return &store{db: db, read: read, write: write, path: absolute, readOnly: config.ReadOnly, openedAt: time.Now().UTC()}, nil
}

func (s *store) Name() string { return "rocksdb" }
func (s *store) Capabilities() storageadapter.Capabilities {
	return storageadapter.Capabilities{Transactions: true, AtomicBatch: true, CompareAndSwap: true, OrderedScan: true, Durable: true, ReadOnly: s.readOnly}
}
func (s *store) Get(_ context.Context, key []byte) ([]byte, error) {
	s.mu.Lock(); defer s.mu.Unlock()
	return s.getLocked(key)
}
func (s *store) Scan(_ context.Context, options storageadapter.ScanOptions) ([]storageadapter.Entry, error) {
	s.mu.Lock(); defer s.mu.Unlock()
	if s.closed || s.db == nil { return nil, storageadapter.ErrClosed }
	iterator := C.rocksdb_create_iterator(s.db, s.read)
	if iterator == nil { return nil, errors.New("storage rocksdb: create iterator") }
	defer C.rocksdb_iter_destroy(iterator)
	start := options.Prefix
	if len(options.After) > 0 { start = options.After }
	C.rocksdb_iter_seek(iterator, bytePointer(start), C.size_t(len(start)))
	out := make([]storageadapter.Entry, 0, options.Limit)
	for C.rocksdb_iter_valid(iterator) != 0 && len(out) < options.Limit {
		var keyLength C.size_t
		keyPointer := C.rocksdb_iter_key(iterator, &keyLength)
		key := C.GoBytes(unsafe.Pointer(keyPointer), C.int(keyLength))
		if len(options.After) > 0 && bytes.Compare(key, options.After) <= 0 {
			C.rocksdb_iter_next(iterator)
			continue
		}
		if len(options.Prefix) > 0 && !bytes.HasPrefix(key, options.Prefix) { break }
		var valueLength C.size_t
		valuePointer := C.rocksdb_iter_value(iterator, &valueLength)
		if uint64(valueLength) > maxValueBytes { return nil, errors.New("storage rocksdb: value exceeds bound") }
		value := C.GoBytes(unsafe.Pointer(valuePointer), C.int(valueLength))
		out = append(out, storageadapter.Entry{Key: key, Value: value})
		C.rocksdb_iter_next(iterator)
	}
	var message *C.char
	C.rocksdb_iter_get_error(iterator, &message)
	if err := rocksError(message); err != nil { return nil, err }
	return out, nil
}
func (s *store) Update(ctx context.Context, fn func(storageadapter.Tx) error) error {
	if fn == nil { return errors.New("storage rocksdb: update callback is required") }
	if s.readOnly { return storageadapter.ErrReadOnly }
	ctx = contextOrBackground(ctx)
	select { case <-ctx.Done(): return ctx.Err(); default: }
	s.mu.Lock(); defer s.mu.Unlock()
	if s.closed || s.db == nil { return storageadapter.ErrClosed }
	tx := &transaction{store: s, writes: map[string]*[]byte{}}
	if err := fn(tx); err != nil { s.lastErr = err.Error(); return err }
	batch := C.rocksdb_writebatch_create()
	if batch == nil { return errors.New("storage rocksdb: create batch") }
	defer C.rocksdb_writebatch_destroy(batch)
	for key, value := range tx.writes {
		keyBytes := []byte(key)
		if value == nil {
			C.rocksdb_writebatch_delete(batch, bytePointer(keyBytes), C.size_t(len(keyBytes)))
			continue
		}
		C.rocksdb_writebatch_put(batch, bytePointer(keyBytes), C.size_t(len(keyBytes)), bytePointer(*value), C.size_t(len(*value)))
	}
	var message *C.char
	C.rocksdb_write(s.db, s.write, batch, &message)
	if err := rocksError(message); err != nil { s.lastErr = err.Error(); return err }
	s.lastErr = ""
	return nil
}
func (s *store) Snapshot() storageadapter.Snapshot {
	s.mu.Lock(); defer s.mu.Unlock()
	return storageadapter.Snapshot{Engine: s.Name(), Capabilities: s.Capabilities(), OpenedAt: s.openedAt, LastError: s.lastErr}
}
func (s *store) Close() error {
	if s == nil { return nil }
	s.mu.Lock(); defer s.mu.Unlock()
	if s.closed { return nil }
	s.closed = true
	if s.read != nil { C.rocksdb_readoptions_destroy(s.read); s.read = nil }
	if s.write != nil { C.rocksdb_writeoptions_destroy(s.write); s.write = nil }
	if s.db != nil { C.rocksdb_close(s.db); s.db = nil }
	return nil
}
func (s *store) getLocked(key []byte) ([]byte, error) {
	if s.closed || s.db == nil { return nil, storageadapter.ErrClosed }
	var length C.size_t
	var message *C.char
	value := C.rocksdb_get(s.db, s.read, bytePointer(key), C.size_t(len(key)), &length, &message)
	if err := rocksError(message); err != nil { return nil, err }
	if value == nil { return nil, storageadapter.ErrNotFound }
	defer C.rocksdb_free(unsafe.Pointer(value))
	if uint64(length) > maxValueBytes { return nil, errors.New("storage rocksdb: value exceeds bound") }
	return C.GoBytes(unsafe.Pointer(value), C.int(length)), nil
}

type transaction struct {
	store  *store
	writes map[string]*[]byte
}
func (tx *transaction) Get(key []byte) ([]byte, error) {
	if value, exists := tx.writes[string(key)]; exists {
		if value == nil { return nil, storageadapter.ErrNotFound }
		return append([]byte(nil), (*value)...), nil
	}
	return tx.store.getLocked(key)
}
func (tx *transaction) Put(key, value []byte) error {
	copyValue := append([]byte(nil), value...)
	tx.writes[string(key)] = &copyValue
	return nil
}
func (tx *transaction) Delete(key []byte) error { tx.writes[string(key)] = nil; return nil }
func (tx *transaction) CompareAndSwap(key, oldValue, newValue []byte) error {
	current, err := tx.Get(key)
	if oldValue == nil {
		if err == nil { return storageadapter.ErrConflict }
		if !errors.Is(err, storageadapter.ErrNotFound) { return err }
	} else if err != nil || !bytes.Equal(current, oldValue) {
		return storageadapter.ErrConflict
	}
	if newValue == nil { return tx.Delete(key) }
	return tx.Put(key, newValue)
}

func bytePointer(value []byte) *C.char {
	if len(value) == 0 { return (*C.char)(unsafe.Pointer(&emptyByte)) }
	return (*C.char)(unsafe.Pointer(&value[0]))
}
func rocksError(value *C.char) error {
	if value == nil { return nil }
	message := C.GoString(value)
	C.rocksdb_free(unsafe.Pointer(value))
	return errors.New("storage rocksdb: " + message)
}
func boolInt(value bool) C.uchar { if value { return 1 }; return 0 }
func contextOrBackground(ctx context.Context) context.Context { if ctx == nil { return context.Background() }; return ctx }
