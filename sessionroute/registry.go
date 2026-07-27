// Package sessionroute coordinates adjacent dynamic sessions owned by separate
// local wv processes. The registry is local IPC metadata only; routed payloads
// remain inside authenticated SSH/X11-derived WebSocket sessions.
package sessionroute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionbroker"
)

const (
	RegistryVersion = "weaverssh.route-registry.v1"
	maxRegistryBytes = 1 << 20
)

var (
	ErrNoRoute       = errors.New("sessionroute: no adjacent route")
	ErrInvalidEntry  = errors.New("sessionroute: invalid registry entry")
	ErrRegistryBusy  = errors.New("sessionroute: registry lock timeout")
	ErrTargetLocal   = errors.New("sessionroute: target is local")
	ErrTargetUnknown = errors.New("sessionroute: target is outside signed topology")
)

// Entry describes one live local broker connected to one adjacent signed node.
type Entry struct {
	Version     string    `json:"version"`
	Binding     string    `json:"binding"`
	Socket      string    `json:"socket"`
	LocalNode   string    `json:"local_node"`
	PeerNode    string    `json:"peer_node"`
	ChainID     string    `json:"chain_id"`
	ChainSHA256 string    `json:"chain_sha256"`
	Topology    []string  `json:"topology"`
	LocalIndex  int       `json:"local_index"`
	PeerIndex   int       `json:"peer_index"`
	PID         int       `json:"pid"`
	StartedAt   time.Time `json:"started_at"`
}

// Registry is the atomic on-disk representation shared by parent attach and
// recursive child session-host processes on one operating-system user account.
type Registry struct {
	Version string  `json:"version"`
	Entries []Entry `json:"entries"`
}

// Store manages one user-private registry file.
type Store struct {
	Path        string
	LockTimeout time.Duration
}

// DefaultPath returns a route registry beside the existing broker state.
func DefaultPath() (string, error) {
	_, statePath, err := sessionbroker.DefaultPaths()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(statePath), "routes.json"), nil
}

func (s Store) path() (string, error) {
	path := strings.TrimSpace(s.Path)
	if path != "" {
		return path, nil
	}
	return DefaultPath()
}

// Register atomically inserts or replaces the entry with the same binding.
func (s Store) Register(ctx context.Context, entry Entry) error {
	entry = normalizeEntry(entry)
	if err := validateEntry(entry); err != nil {
		return err
	}
	return s.mutate(ctx, func(registry *Registry) {
		entries := registry.Entries[:0]
		for _, existing := range registry.Entries {
			if strings.TrimSpace(existing.Binding) != entry.Binding {
				entries = append(entries, existing)
			}
		}
		registry.Entries = append(entries, entry)
	})
}

// Remove deletes one binding. Missing registries and bindings are harmless.
func (s Store) Remove(ctx context.Context, binding string) error {
	binding = strings.TrimSpace(binding)
	if binding == "" {
		return nil
	}
	return s.mutate(ctx, func(registry *Registry) {
		entries := registry.Entries[:0]
		for _, entry := range registry.Entries {
			if strings.TrimSpace(entry.Binding) != binding {
				entries = append(entries, entry)
			}
		}
		registry.Entries = entries
	})
}

// Snapshot returns validated entries in stable binding order.
func (s Store) Snapshot() (Registry, error) {
	path, err := s.path()
	if err != nil {
		return Registry{}, err
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Registry{Version: RegistryVersion}, nil
		}
		return Registry{}, err
	}
	if len(payload) > maxRegistryBytes {
		return Registry{}, errors.New("sessionroute: registry is too large")
	}
	var registry Registry
	if err := json.Unmarshal(payload, &registry); err != nil {
		return Registry{}, fmt.Errorf("sessionroute: decode registry: %w", err)
	}
	if registry.Version != RegistryVersion {
		return Registry{}, fmt.Errorf("sessionroute: unsupported registry version %q", registry.Version)
	}
	validated := make([]Entry, 0, len(registry.Entries))
	for _, entry := range registry.Entries {
		entry = normalizeEntry(entry)
		if validateEntry(entry) == nil {
			validated = append(validated, entry)
		}
	}
	sort.Slice(validated, func(i, j int) bool { return validated[i].Binding < validated[j].Binding })
	registry.Entries = validated
	return registry, nil
}

// Current returns the entry for one binding.
func (s Store) Current(binding string) (Entry, error) {
	registry, err := s.Snapshot()
	if err != nil {
		return Entry{}, err
	}
	binding = strings.TrimSpace(binding)
	for _, entry := range registry.Entries {
		if entry.Binding == binding {
			return entry, nil
		}
	}
	return Entry{}, fmt.Errorf("%w: binding=%s", ErrNoRoute, binding)
}

// ResolveAdjacent selects the newest adjacent session in the direction of target.
// currentBinding is excluded so an incoming stream can never be reflected into
// the same mux from which it arrived.
func (s Store) ResolveAdjacent(currentBinding string, nodeContext authproof.NodeContext, target string) (Entry, string, int, error) {
	nodeContext = nodeContext.Normalized()
	if err := nodeContext.Validate(); err != nil {
		return Entry{}, "", -1, err
	}
	currentIndex := indexOf(nodeContext.Nodes, nodeContext.CurrentNode)
	targetNode, targetIndex, err := ResolveNode(nodeContext, target)
	if err != nil {
		return Entry{}, "", -1, err
	}
	if targetIndex == currentIndex {
		return Entry{}, targetNode, targetIndex, ErrTargetLocal
	}
	desiredPeer := currentIndex - 1
	if targetIndex > currentIndex {
		desiredPeer = currentIndex + 1
	}
	registry, err := s.Snapshot()
	if err != nil {
		return Entry{}, "", -1, err
	}
	currentBinding = strings.TrimSpace(currentBinding)
	var candidates []Entry
	for _, entry := range registry.Entries {
		if entry.Binding == currentBinding || entry.LocalNode != nodeContext.CurrentNode ||
			entry.ChainID != nodeContext.ChainID || entry.ChainSHA256 != nodeContext.ChainSHA256 ||
			!sameStrings(entry.Topology, nodeContext.Nodes) || entry.LocalIndex != currentIndex ||
			entry.PeerIndex != desiredPeer {
			continue
		}
		candidates = append(candidates, entry)
	}
	if len(candidates) == 0 {
		return Entry{}, targetNode, targetIndex, fmt.Errorf("%w: local=%s target=%s direction_peer_index=%d", ErrNoRoute, nodeContext.CurrentNode, targetNode, desiredPeer)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].StartedAt.After(candidates[j].StartedAt) })
	return candidates[0], targetNode, targetIndex, nil
}

// ResolveNode resolves only topology-defined relative names. It never treats
// "origin" or SSH user@host syntax specially.
func ResolveNode(ctx authproof.NodeContext, raw string) (string, int, error) {
	ctx = ctx.Normalized()
	current := indexOf(ctx.Nodes, ctx.CurrentNode)
	name := strings.TrimSpace(raw)
	switch strings.ToLower(name) {
	case "self", "local", "here", "this", "current", ".":
		name = ctx.CurrentNode
	case "previous", "prev":
		if current <= 0 {
			return "", -1, ErrTargetUnknown
		}
		name = ctx.Nodes[current-1]
	case "next":
		if current < 0 || current+1 >= len(ctx.Nodes) {
			return "", -1, ErrTargetUnknown
		}
		name = ctx.Nodes[current+1]
	case "endpoint", "last", "remote":
		if len(ctx.Nodes) == 0 {
			return "", -1, ErrTargetUnknown
		}
		name = ctx.Nodes[len(ctx.Nodes)-1]
	}
	index := indexOf(ctx.Nodes, name)
	if index < 0 {
		return "", -1, fmt.Errorf("%w: %s", ErrTargetUnknown, name)
	}
	return name, index, nil
}

func (s Store) mutate(ctx context.Context, apply func(*Registry)) error {
	path, err := s.path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	unlock, err := acquireLock(ctx, path+".lock", s.LockTimeout)
	if err != nil {
		return err
	}
	defer unlock()
	registry, err := s.Snapshot()
	if err != nil {
		return err
	}
	registry.Version = RegistryVersion
	apply(&registry)
	payload, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if len(payload) > maxRegistryBytes {
		return errors.New("sessionroute: registry is too large")
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".routes-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempName)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temp.Write(payload); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return err
	}
	committed = true
	return nil
}

// acquireLock uses an operating-system file lock. The lock file is persistent,
// but the kernel lock is released automatically if the owner exits or crashes.
func acquireLock(ctx context.Context, path string, timeout time.Duration) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		locked, lockErr := tryLockFile(file)
		if lockErr != nil {
			_ = file.Close()
			return nil, lockErr
		}
		if locked {
			if err := file.Truncate(0); err != nil {
				_ = unlockFile(file)
				_ = file.Close()
				return nil, err
			}
			if _, err := file.Seek(0, 0); err != nil {
				_ = unlockFile(file)
				_ = file.Close()
				return nil, err
			}
			if _, err := fmt.Fprintf(file, "%d\n", os.Getpid()); err != nil {
				_ = unlockFile(file)
				_ = file.Close()
				return nil, err
			}
			_ = file.Sync()
			var once sync.Once
			return func() {
				once.Do(func() {
					_ = unlockFile(file)
					_ = file.Close()
				})
			}, nil
		}
		if time.Now().After(deadline) {
			_ = file.Close()
			return nil, ErrRegistryBusy
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func normalizeEntry(entry Entry) Entry {
	if entry.Version == "" {
		entry.Version = RegistryVersion
	}
	entry.Binding = strings.TrimSpace(entry.Binding)
	entry.Socket = strings.TrimSpace(entry.Socket)
	entry.LocalNode = strings.TrimSpace(entry.LocalNode)
	entry.PeerNode = strings.TrimSpace(entry.PeerNode)
	entry.ChainID = strings.TrimSpace(entry.ChainID)
	entry.ChainSHA256 = strings.ToLower(strings.TrimSpace(entry.ChainSHA256))
	entry.Topology = append([]string(nil), entry.Topology...)
	for index := range entry.Topology {
		entry.Topology[index] = strings.TrimSpace(entry.Topology[index])
	}
	return entry
}

func validateEntry(entry Entry) error {
	if entry.Version != RegistryVersion || entry.Binding == "" || entry.Socket == "" || entry.LocalNode == "" ||
		entry.PeerNode == "" || entry.ChainID == "" || len(entry.ChainSHA256) != 64 || len(entry.Topology) < 2 ||
		entry.PID <= 0 || entry.StartedAt.IsZero() {
		return ErrInvalidEntry
	}
	if entry.LocalIndex < 0 || entry.PeerIndex < 0 || entry.LocalIndex >= len(entry.Topology) || entry.PeerIndex >= len(entry.Topology) ||
		entry.Topology[entry.LocalIndex] != entry.LocalNode || entry.Topology[entry.PeerIndex] != entry.PeerNode ||
		abs(entry.LocalIndex-entry.PeerIndex) != 1 {
		return ErrInvalidEntry
	}
	return nil
}

func indexOf(values []string, want string) int {
	for index, value := range values {
		if value == want {
			return index
		}
	}
	return -1
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
