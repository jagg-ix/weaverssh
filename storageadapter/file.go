package storageadapter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const fileStoreVersion = "weaverssh.storage-file.v1"

type fileDocument struct {
	Version string            `json:"version"`
	Values  map[string]string `json:"values"`
}

type fileStore struct {
	mu       sync.RWMutex
	path     string
	values   map[string][]byte
	closed   bool
	openedAt time.Time
	lastErr  string
}

func openFile(_ context.Context, config Config) (Store, error) {
	path := strings.TrimSpace(config.Path)
	if path == "" {
		return nil, errors.New("storageadapter: file engine requires path")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		return nil, err
	}
	store := &fileStore{path: filepath.Clean(absolute), values: map[string][]byte{}, openedAt: time.Now().UTC()}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *fileStore) Name() string { return "file" }
func (store *fileStore) Capabilities() Capabilities {
	return Capabilities{Transactions: true, AtomicBatch: true, CompareAndSwap: true, OrderedScan: true, Durable: true}
}
func (store *fileStore) Get(_ context.Context, key []byte) ([]byte, error) {
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
func (store *fileStore) Scan(_ context.Context, options ScanOptions) ([]Entry, error) {
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
func (store *fileStore) Update(ctx context.Context, fn func(Tx) error) error {
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
	if err := fn(&mapTx{values: working}); err != nil {
		store.lastErr = err.Error()
		return err
	}
	if err := store.persist(working); err != nil {
		store.lastErr = err.Error()
		return err
	}
	store.values = working
	store.lastErr = ""
	return nil
}
func (store *fileStore) Snapshot() Snapshot {
	store.mu.RLock()
	defer store.mu.RUnlock()
	var total uint64
	for key, value := range store.values {
		total += uint64(len(key) + len(value))
	}
	return Snapshot{Engine: store.Name(), Capabilities: store.Capabilities(), Entries: uint64(len(store.values)), Bytes: total, OpenedAt: store.openedAt, LastError: store.lastErr}
}
func (store *fileStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.closed = true
	store.values = nil
	return nil
}
func (store *fileStore) load() error {
	payload, err := os.ReadFile(store.path)
	if os.IsNotExist(err) {
		return store.persist(store.values)
	}
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > 256<<20 {
		return errors.New("storageadapter: invalid file-store size")
	}
	var document fileDocument
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	if document.Version != fileStoreVersion {
		return fmt.Errorf("storageadapter: unsupported file-store version %q", document.Version)
	}
	values := make(map[string][]byte, len(document.Values))
	for encodedKey, encodedValue := range document.Values {
		key, err := base64.RawStdEncoding.DecodeString(encodedKey)
		if err != nil || len(key) == 0 {
			return errors.New("storageadapter: corrupt file-store key")
		}
		value, err := base64.RawStdEncoding.DecodeString(encodedValue)
		if err != nil {
			return errors.New("storageadapter: corrupt file-store value")
		}
		values[string(key)] = value
	}
	store.values = values
	return nil
}
func (store *fileStore) persist(values map[string][]byte) error {
	document := fileDocument{Version: fileStoreVersion, Values: make(map[string]string, len(values))}
	for key, value := range values {
		document.Values[base64.RawStdEncoding.EncodeToString([]byte(key))] = base64.RawStdEncoding.EncodeToString(value)
	}
	payload, err := json.Marshal(document)
	if err != nil {
		return err
	}
	if len(payload) > 256<<20 {
		return errors.New("storageadapter: file-store exceeds 256 MiB")
	}
	directory := filepath.Dir(store.path)
	temporary, err := os.CreateTemp(directory, ".storage-next-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := replaceFile(temporaryPath, store.path); err != nil {
		return err
	}
	committed = true
	if directoryHandle, err := os.Open(directory); err == nil {
		_ = directoryHandle.Sync()
		_ = directoryHandle.Close()
	}
	return nil
}

func replaceFile(source, destination string) error {
	if err := os.Rename(source, destination); err == nil {
		return nil
	}
	if removeErr := os.Remove(destination); removeErr != nil && !os.IsNotExist(removeErr) {
		return removeErr
	}
	return os.Rename(source, destination)
}
