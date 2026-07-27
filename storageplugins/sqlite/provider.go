//go:build sqlite && cgo

package sqlite

/*
#cgo pkg-config: sqlite3
#include <stdlib.h>
#include <sqlite3.h>

static unsigned char wv_empty_blob;
static int wv_bind_blob(sqlite3_stmt *stmt, int index, const void *value, int length) {
	if (value == NULL && length == 0) value = &wv_empty_blob;
	return sqlite3_bind_blob(stmt, index, value, length, SQLITE_TRANSIENT);
}
*/
import "C"

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"weaverssh/storageadapter"
)

const schema = `CREATE TABLE IF NOT EXISTS weaverssh_kv (
  key BLOB PRIMARY KEY NOT NULL,
  value BLOB NOT NULL
) WITHOUT ROWID;`

type store struct {
	mu       sync.Mutex
	db       *C.sqlite3
	path     string
	closed   bool
	readOnly bool
	openedAt time.Time
	lastErr  string
}

func init() { _ = storageadapter.Register("sqlite", open) }

func open(_ context.Context, config storageadapter.Config) (storageadapter.Store, error) {
	path := strings.TrimSpace(config.Path)
	if path == "" { return nil, errors.New("storage sqlite: path is required") }
	absolute, err := filepath.Abs(path)
	if err != nil { return nil, err }
	if !config.ReadOnly {
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil { return nil, err }
	}
	flags := C.int(C.SQLITE_OPEN_FULLMUTEX | C.SQLITE_OPEN_URI)
	if config.ReadOnly { flags |= C.SQLITE_OPEN_READONLY } else { flags |= C.SQLITE_OPEN_READWRITE | C.SQLITE_OPEN_CREATE }
	cpath := C.CString(absolute)
	defer C.free(unsafe.Pointer(cpath))
	var db *C.sqlite3
	if code := C.sqlite3_open_v2(cpath, &db, flags, nil); code != C.SQLITE_OK {
		message := sqliteMessage(db, code)
		if db != nil { C.sqlite3_close_v2(db) }
		return nil, errors.New(message)
	}
	result := &store{db: db, path: absolute, readOnly: config.ReadOnly, openedAt: time.Now().UTC()}
	busy := 5000
	if raw := strings.TrimSpace(config.Options["busy_timeout_ms"]); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > 60000 {
			_ = result.Close()
			return nil, errors.New("storage sqlite: busy_timeout_ms must be 0..60000")
		}
		busy = parsed
	}
	C.sqlite3_busy_timeout(db, C.int(busy))
	if !config.ReadOnly {
		for _, statement := range []string{"PRAGMA journal_mode=WAL;", "PRAGMA synchronous=FULL;", schema} {
			if err := result.exec(statement); err != nil { _ = result.Close(); return nil, err }
		}
	}
	return result, nil
}

func (s *store) Name() string { return "sqlite" }
func (s *store) Capabilities() storageadapter.Capabilities {
	return storageadapter.Capabilities{Transactions: true, AtomicBatch: true, CompareAndSwap: true, OrderedScan: true, Durable: true, ReadOnly: s.readOnly}
}
func (s *store) Get(_ context.Context, key []byte) ([]byte, error) {
	s.mu.Lock(); defer s.mu.Unlock(); return s.getLocked(key)
}
func (s *store) Scan(_ context.Context, options storageadapter.ScanOptions) ([]storageadapter.Entry, error) {
	s.mu.Lock(); defer s.mu.Unlock()
	if s.closed || s.db == nil { return nil, storageadapter.ErrClosed }
	statement, err := s.prepare(`SELECT key, value FROM weaverssh_kv
WHERE (?1 = X'' OR substr(key, 1, length(?1)) = ?1)
  AND (?2 = X'' OR key > ?2)
ORDER BY key LIMIT ?3`)
	if err != nil { return nil, err }
	defer C.sqlite3_finalize(statement)
	if err := bindBlob(statement, 1, options.Prefix); err != nil { return nil, err }
	if err := bindBlob(statement, 2, options.After); err != nil { return nil, err }
	if code := C.sqlite3_bind_int(statement, 3, C.int(options.Limit)); code != C.SQLITE_OK { return nil, s.codeError(code) }
	entries := make([]storageadapter.Entry, 0, options.Limit)
	for {
		code := C.sqlite3_step(statement)
		if code == C.SQLITE_DONE { break }
		if code != C.SQLITE_ROW { return nil, s.codeError(code) }
		entries = append(entries, storageadapter.Entry{Key: columnBlob(statement, 0), Value: columnBlob(statement, 1)})
	}
	return entries, nil
}
func (s *store) Update(ctx context.Context, fn func(storageadapter.Tx) error) error {
	if fn == nil { return errors.New("storage sqlite: update callback is required") }
	if s.readOnly { return storageadapter.ErrReadOnly }
	if ctx == nil { ctx = context.Background() }
	s.mu.Lock(); defer s.mu.Unlock()
	if s.closed || s.db == nil { return storageadapter.ErrClosed }
	select { case <-ctx.Done(): return ctx.Err(); default: }
	if err := s.execLocked("BEGIN IMMEDIATE;"); err != nil { return err }
	if err := fn(&transaction{store: s}); err != nil {
		_ = s.execLocked("ROLLBACK;"); s.lastErr = err.Error(); return err
	}
	if err := s.execLocked("COMMIT;"); err != nil {
		_ = s.execLocked("ROLLBACK;"); s.lastErr = err.Error(); return err
	}
	s.lastErr = ""
	return nil
}
func (s *store) Snapshot() storageadapter.Snapshot {
	s.mu.Lock(); defer s.mu.Unlock()
	snapshot := storageadapter.Snapshot{Engine: s.Name(), Capabilities: s.Capabilities(), OpenedAt: s.openedAt, LastError: s.lastErr}
	if s.closed || s.db == nil { return snapshot }
	statement, err := s.prepare("SELECT count(*), coalesce(sum(length(key)+length(value)),0) FROM weaverssh_kv")
	if err != nil { snapshot.LastError = err.Error(); return snapshot }
	defer C.sqlite3_finalize(statement)
	if C.sqlite3_step(statement) == C.SQLITE_ROW {
		snapshot.Entries = uint64(C.sqlite3_column_int64(statement, 0))
		snapshot.Bytes = uint64(C.sqlite3_column_int64(statement, 1))
	}
	return snapshot
}
func (s *store) Close() error {
	if s == nil { return nil }
	s.mu.Lock(); defer s.mu.Unlock()
	if s.closed { return nil }
	s.closed = true
	if s.db != nil {
		if code := C.sqlite3_close_v2(s.db); code != C.SQLITE_OK { return s.codeError(code) }
		s.db = nil
	}
	return nil
}

func (s *store) getLocked(key []byte) ([]byte, error) {
	if s.closed || s.db == nil { return nil, storageadapter.ErrClosed }
	statement, err := s.prepare("SELECT value FROM weaverssh_kv WHERE key=?1")
	if err != nil { return nil, err }
	defer C.sqlite3_finalize(statement)
	if err := bindBlob(statement, 1, key); err != nil { return nil, err }
	code := C.sqlite3_step(statement)
	if code == C.SQLITE_DONE { return nil, storageadapter.ErrNotFound }
	if code != C.SQLITE_ROW { return nil, s.codeError(code) }
	return columnBlob(statement, 0), nil
}
func (s *store) putLocked(key, value []byte) error {
	statement, err := s.prepare("INSERT INTO weaverssh_kv(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
	if err != nil { return err }
	defer C.sqlite3_finalize(statement)
	if err := bindBlob(statement, 1, key); err != nil { return err }
	if err := bindBlob(statement, 2, value); err != nil { return err }
	if code := C.sqlite3_step(statement); code != C.SQLITE_DONE { return s.codeError(code) }
	return nil
}
func (s *store) deleteLocked(key []byte) error {
	statement, err := s.prepare("DELETE FROM weaverssh_kv WHERE key=?1")
	if err != nil { return err }
	defer C.sqlite3_finalize(statement)
	if err := bindBlob(statement, 1, key); err != nil { return err }
	if code := C.sqlite3_step(statement); code != C.SQLITE_DONE { return s.codeError(code) }
	return nil
}
func (s *store) exec(statement string) error { s.mu.Lock(); defer s.mu.Unlock(); return s.execLocked(statement) }
func (s *store) execLocked(statement string) error {
	cstatement := C.CString(statement)
	defer C.free(unsafe.Pointer(cstatement))
	var message *C.char
	code := C.sqlite3_exec(s.db, cstatement, nil, nil, &message)
	if message != nil { defer C.sqlite3_free(unsafe.Pointer(message)) }
	if code != C.SQLITE_OK {
		if message != nil { return errors.New(C.GoString(message)) }
		return s.codeError(code)
	}
	return nil
}
func (s *store) prepare(query string) (*C.sqlite3_stmt, error) {
	cquery := C.CString(query)
	defer C.free(unsafe.Pointer(cquery))
	var statement *C.sqlite3_stmt
	if code := C.sqlite3_prepare_v2(s.db, cquery, -1, &statement, nil); code != C.SQLITE_OK { return nil, s.codeError(code) }
	return statement, nil
}
func (s *store) codeError(code C.int) error { return errors.New(sqliteMessage(s.db, code)) }

type transaction struct{ store *store }
func (tx *transaction) Get(key []byte) ([]byte, error) { return tx.store.getLocked(key) }
func (tx *transaction) Put(key, value []byte) error { return tx.store.putLocked(key, value) }
func (tx *transaction) Delete(key []byte) error { return tx.store.deleteLocked(key) }
func (tx *transaction) CompareAndSwap(key, oldValue, newValue []byte) error {
	current, err := tx.Get(key)
	if oldValue == nil {
		if err == nil { return storageadapter.ErrConflict }
		if !errors.Is(err, storageadapter.ErrNotFound) { return err }
	} else if err != nil || !bytes.Equal(current, oldValue) { return storageadapter.ErrConflict }
	if newValue == nil { return tx.Delete(key) }
	return tx.Put(key, newValue)
}

func bindBlob(statement *C.sqlite3_stmt, index int, value []byte) error {
	var pointer unsafe.Pointer
	if len(value) > 0 { pointer = unsafe.Pointer(&value[0]) }
	if code := C.wv_bind_blob(statement, C.int(index), pointer, C.int(len(value))); code != C.SQLITE_OK {
		return fmt.Errorf("storage sqlite: bind failed with code %d", int(code))
	}
	return nil
}
func columnBlob(statement *C.sqlite3_stmt, column int) []byte {
	length := C.sqlite3_column_bytes(statement, C.int(column))
	if length <= 0 { return []byte{} }
	return C.GoBytes(C.sqlite3_column_blob(statement, C.int(column)), length)
}
func sqliteMessage(db *C.sqlite3, code C.int) string {
	if db != nil { return "storage sqlite: " + C.GoString(C.sqlite3_errmsg(db)) }
	return fmt.Sprintf("storage sqlite: error code %d", int(code))
}
