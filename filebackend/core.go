package filebackend

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

var ErrNotFound = errors.New("filebackend: core key not found")

type BatchEntry struct {
	Key    []byte
	Value  []byte
	Delete bool
}

type Store interface {
	Name() string
	Get(key []byte) ([]byte, error)
	Put(key, value []byte) error
	Delete(key []byte) error
	Write(entries []BatchEntry) error
	Close() error
}

type MemoryStore struct {
	mu     sync.RWMutex
	closed bool
	values map[string][]byte
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{values: make(map[string][]byte)} }
func (s *MemoryStore) Name() string { return "memory" }
func (s *MemoryStore) Get(key []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("filebackend: nil memory store")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, errors.New("filebackend: memory store closed")
	}
	value, ok := s.values[string(key)]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), value...), nil
}
func (s *MemoryStore) Put(key, value []byte) error {
	return s.Write([]BatchEntry{{Key: key, Value: value}})
}
func (s *MemoryStore) Delete(key []byte) error {
	return s.Write([]BatchEntry{{Key: key, Delete: true}})
}
func (s *MemoryStore) Write(entries []BatchEntry) error {
	if s == nil {
		return errors.New("filebackend: nil memory store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("filebackend: memory store closed")
	}
	for _, entry := range entries {
		if len(entry.Key) == 0 {
			return errors.New("filebackend: empty core key")
		}
		if entry.Delete {
			delete(s.values, string(entry.Key))
			continue
		}
		s.values[string(entry.Key)] = append([]byte(nil), entry.Value...)
	}
	return nil
}
func (s *MemoryStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	s.values = nil
	s.mu.Unlock()
	return nil
}

type Core struct {
	mu        sync.Mutex
	store     Store
	sequence  uint64
	counts    map[Operation]uint64
	errors    uint64
	lastError string
}

type CoreSnapshot struct {
	Store         string               `json:"store"`
	Sequence      uint64               `json:"sequence"`
	Operations    map[Operation]uint64 `json:"operations"`
	Errors        uint64               `json:"errors"`
	LastCoreError string               `json:"last_core_error,omitempty"`
}

func NewCore(store Store) (*Core, error) {
	if store == nil {
		store = NewMemoryStore()
	}
	core := &Core{store: store, counts: make(map[Operation]uint64)}
	if value, err := readUint64(store, []byte("state/sequence")); err == nil {
		core.sequence = value
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	for _, operation := range allOperations() {
		if value, err := readUint64(store, counterKey(operation)); err == nil {
			core.counts[operation] = value
		} else if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}
	if value, err := readUint64(store, []byte("state/errors")); err == nil {
		core.errors = value
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return core, nil
}

func (c *Core) StoreName() string {
	if c == nil || c.store == nil {
		return ""
	}
	return c.store.Name()
}

func (c *Core) NextID() (uint64, error) {
	if c == nil || c.store == nil {
		return 0, errors.New("filebackend: incomplete core")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sequence++
	if err := c.store.Put([]byte("state/sequence"), encodeUint64(c.sequence)); err != nil {
		c.sequence--
		c.lastError = err.Error()
		return 0, err
	}
	return c.sequence, nil
}

func (c *Core) ObserveQID(relative string, path uint64, version uint32) error {
	if c == nil || c.store == nil {
		return errors.New("filebackend: incomplete core")
	}
	if path == 0 {
		return errors.New("filebackend: invalid zero QID path")
	}
	relative = canonicalRelative(relative)
	value := make([]byte, 12)
	binary.LittleEndian.PutUint64(value[:8], path)
	binary.LittleEndian.PutUint32(value[8:], version)
	c.mu.Lock()
	defer c.mu.Unlock()
	current, err := readUint32(c.store, versionKey(relative))
	if errors.Is(err, ErrNotFound) {
		current = 0
	} else if err != nil {
		c.lastError = err.Error()
		return err
	}
	if current < version {
		current = version
	}
	if current == 0 {
		current = 1
	}
	entries := []BatchEntry{
		{Key: qidKey(relative), Value: value},
		{Key: versionKey(relative), Value: encodeUint32(current)},
	}
	if err := c.store.Write(entries); err != nil {
		c.lastError = err.Error()
		return err
	}
	c.lastError = ""
	return nil
}

func (c *Core) QID(relative string, info os.FileInfo) (uint64, uint32) {
	relative = canonicalRelative(relative)
	pathID := stablePathID(relative)
	version := uint32(0)
	if info != nil {
		version = uint32(info.ModTime().Unix())
	}
	if c == nil || c.store == nil {
		return pathID, version
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if observed, err := c.store.Get(qidKey(relative)); err == nil {
		if len(observed) != 12 {
			c.lastError = "filebackend: corrupt observed QID value"
		} else {
			pathID = binary.LittleEndian.Uint64(observed[:8])
			version = binary.LittleEndian.Uint32(observed[8:])
		}
	} else if !errors.Is(err, ErrNotFound) {
		c.lastError = err.Error()
	}
	key := versionKey(relative)
	stored, err := readUint32(c.store, key)
	if err == nil {
		if stored > version {
			version = stored
		}
	} else if errors.Is(err, ErrNotFound) {
		if version == 0 {
			version = 1
		}
		if putErr := c.store.Put(key, encodeUint32(version)); putErr != nil {
			c.lastError = putErr.Error()
		}
	} else {
		c.lastError = err.Error()
	}
	return pathID, version
}

func (c *Core) Record(event Event, mutationPaths ...string) error {
	if c == nil || c.store == nil {
		return errors.New("filebackend: incomplete core")
	}
	normalized, err := normalizeEvent(event)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	newCount := c.counts[normalized.Operation] + 1
	newErrors := c.errors
	entries := []BatchEntry{
		{Key: counterKey(normalized.Operation), Value: encodeUint64(newCount)},
		{Key: []byte("event/last"), Value: payload},
	}
	if normalized.Phase == PhaseError {
		newErrors++
		entries = append(entries, BatchEntry{Key: []byte("state/errors"), Value: encodeUint64(newErrors)})
	}
	seen := make(map[string]bool)
	for _, raw := range mutationPaths {
		relative := canonicalRelative(raw)
		if seen[relative] {
			continue
		}
		seen[relative] = true
		key := versionKey(relative)
		current, readErr := readUint32(c.store, key)
		if errors.Is(readErr, ErrNotFound) {
			current = 0
		} else if readErr != nil {
			c.lastError = readErr.Error()
			return readErr
		}
		current++
		if current == 0 {
			current = 1
		}
		entries = append(entries, BatchEntry{Key: key, Value: encodeUint32(current)})
	}
	if err := c.store.Write(entries); err != nil {
		c.lastError = err.Error()
		return err
	}
	c.counts[normalized.Operation] = newCount
	c.errors = newErrors
	c.lastError = ""
	return nil
}

func (c *Core) Snapshot() CoreSnapshot {
	if c == nil {
		return CoreSnapshot{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	counts := make(map[Operation]uint64, len(c.counts))
	for operation, count := range c.counts {
		counts[operation] = count
	}
	return CoreSnapshot{Store: c.StoreName(), Sequence: c.sequence, Operations: counts, Errors: c.errors, LastCoreError: c.lastError}
}

func (c *Core) Close() error {
	if c == nil || c.store == nil {
		return nil
	}
	return c.store.Close()
}

func qidKey(relative string) []byte {
	digest := sha256.Sum256([]byte("qid-observed\x00" + canonicalRelative(relative)))
	return []byte("qid/observed/" + fmt.Sprintf("%x", digest[:]))
}

func versionKey(relative string) []byte {
	digest := sha256.Sum256([]byte("qid-version\x00" + canonicalRelative(relative)))
	return []byte("qid/version/" + fmt.Sprintf("%x", digest[:]))
}

func counterKey(operation Operation) []byte { return []byte("counter/" + string(operation)) }

func stablePathID(relative string) uint64 {
	digest := sha256.Sum256([]byte("qid-path\x00" + canonicalRelative(relative)))
	value := binary.LittleEndian.Uint64(digest[:8])
	if value == 0 {
		return 1
	}
	return value
}

func canonicalRelative(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	value = strings.TrimPrefix(value, "/")
	if value == "." {
		return ""
	}
	return value
}

func readUint64(store Store, key []byte) (uint64, error) {
	value, err := store.Get(key)
	if err != nil {
		return 0, err
	}
	if len(value) != 8 {
		return 0, errors.New("filebackend: corrupt uint64 core value")
	}
	return binary.LittleEndian.Uint64(value), nil
}
func readUint32(store Store, key []byte) (uint32, error) {
	value, err := store.Get(key)
	if err != nil {
		return 0, err
	}
	if len(value) != 4 {
		return 0, errors.New("filebackend: corrupt uint32 core value")
	}
	return binary.LittleEndian.Uint32(value), nil
}
func encodeUint64(value uint64) []byte {
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, value)
	return out
}
func encodeUint32(value uint32) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, value)
	return out
}

func allOperations() []Operation {
	out := []Operation{
		OperationAttach, OperationWalk, OperationOpen, OperationCreate,
		OperationRead, OperationWrite, OperationClunk, OperationRemove,
		OperationStat, OperationReadDir, OperationPrepareReplace,
		OperationCommitReplace, OperationAbortReplace,
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
