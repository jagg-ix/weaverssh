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
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionbroker"
	"weaverssh/sessionlink"
)

const (
	LeaseRegistryVersion  = "weaverssh.route-leases.v1"
	maxLeaseRegistryBytes = 1 << 20
)

// LeaseEntry publishes one stable logical adjacency. Binding identifies the
// current transport only; LinkID is the replacement key and Generation fences
// delayed cleanup from older transports.
type LeaseEntry struct {
	Version     string                  `json:"version"`
	LinkID      sessionlink.ID          `json:"link_id"`
	TransportID sessionlink.TransportID `json:"transport_id"`
	Generation  uint64                  `json:"generation"`
	Binding     string                  `json:"binding"`
	Socket      string                  `json:"socket"`
	LocalNode   string                  `json:"local_node"`
	PeerNode    string                  `json:"peer_node"`
	ChainID     string                  `json:"chain_id"`
	ChainSHA256 string                  `json:"chain_sha256"`
	Topology    []string                `json:"topology"`
	LocalIndex  int                     `json:"local_index"`
	PeerIndex   int                     `json:"peer_index"`
	PID         int                     `json:"pid"`
	StartedAt   time.Time               `json:"started_at"`
	UpdatedAt   time.Time               `json:"updated_at"`
	LeaseUntil  time.Time               `json:"lease_until"`
}

func (e LeaseEntry) Token() sessionlink.Token {
	return sessionlink.Token{LinkID: e.LinkID, TransportID: e.TransportID, Generation: e.Generation}
}

func (e LeaseEntry) LegacyEntry() Entry {
	return Entry{
		Version: RegistryVersion, Binding: e.Binding, Socket: e.Socket,
		LocalNode: e.LocalNode, PeerNode: e.PeerNode, ChainID: e.ChainID,
		ChainSHA256: e.ChainSHA256, Topology: append([]string(nil), e.Topology...),
		LocalIndex: e.LocalIndex, PeerIndex: e.PeerIndex, PID: e.PID,
		StartedAt: e.StartedAt,
	}
}

type LeaseRegistry struct {
	Version string       `json:"version"`
	Entries []LeaseEntry `json:"entries"`
}

// LeaseStore is the generation-aware route registry. Path is independent from
// the legacy binding registry so mixed-version local processes fail closed
// rather than misinterpreting each other's JSON.
type LeaseStore struct {
	Path        string
	LockTimeout time.Duration
	Now         func() time.Time
}

func DefaultLeasePath() (string, error) {
	_, statePath, err := sessionbroker.DefaultPaths()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(statePath), "route-leases.json"), nil
}

// ResolveLeasePath maps the existing --route-registry option to a separate
// generation-aware file. Empty input selects the per-user default.
func ResolveLeasePath(routeRegistryPath string) (string, error) {
	routeRegistryPath = strings.TrimSpace(routeRegistryPath)
	if routeRegistryPath == "" {
		return DefaultLeasePath()
	}
	return routeRegistryPath + ".leases", nil
}

func (s LeaseStore) path() (string, error) {
	if path := strings.TrimSpace(s.Path); path != "" {
		return path, nil
	}
	return DefaultLeasePath()
}

func (s LeaseStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func NewLeaseEntry(
	ctx authproof.NodeContext,
	binding, socket, peerNode string,
	pid int,
	startedAt time.Time,
	token sessionlink.Token,
	leaseUntil time.Time,
) (LeaseEntry, error) {
	ctx = ctx.Normalized()
	if err := ctx.Validate(); err != nil {
		return LeaseEntry{}, err
	}
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	descriptor := sessionlink.Descriptor{
		ChainSHA256: ctx.ChainSHA256,
		Topology:    append([]string(nil), ctx.Nodes...),
		LocalNode:   ctx.CurrentNode,
		PeerNode:    strings.TrimSpace(peerNode),
	}
	linkID, err := sessionlink.DeriveID(descriptor)
	if err != nil {
		return LeaseEntry{}, err
	}
	if token.LinkID != linkID || sessionlink.ValidateTransportID(token.TransportID) != nil || token.Generation == 0 {
		return LeaseEntry{}, sessionlink.ErrGenerationMismatch
	}
	entry := normalizeLeaseEntry(LeaseEntry{
		Version: LeaseRegistryVersion, LinkID: token.LinkID, TransportID: token.TransportID,
		Generation: token.Generation, Binding: binding, Socket: socket,
		LocalNode: ctx.CurrentNode, PeerNode: peerNode, ChainID: ctx.ChainID,
		ChainSHA256: ctx.ChainSHA256, Topology: append([]string(nil), ctx.Nodes...),
		LocalIndex: indexOf(ctx.Nodes, ctx.CurrentNode), PeerIndex: indexOf(ctx.Nodes, strings.TrimSpace(peerNode)),
		PID: pid, StartedAt: startedAt, UpdatedAt: startedAt, LeaseUntil: leaseUntil,
	})
	if err := validateLeaseEntry(entry, startedAt); err != nil {
		return LeaseEntry{}, err
	}
	return entry, nil
}

// Register inserts or replaces one logical adjacency. An older generation can
// never overwrite a newer one.
func (s LeaseStore) Register(ctx context.Context, entry LeaseEntry) error {
	now := s.now()
	entry = normalizeLeaseEntry(entry)
	if err := validateLeaseEntry(entry, now); err != nil {
		return err
	}
	return s.mutate(ctx, func(registry *LeaseRegistry) error {
		entries := registry.Entries[:0]
		for _, existing := range registry.Entries {
			existing = normalizeLeaseEntry(existing)
			if expiredLease(existing, now) || validateLeaseEntry(existing, now) != nil {
				continue
			}
			if existing.LinkID != entry.LinkID {
				entries = append(entries, existing)
				continue
			}
			if existing.Generation > entry.Generation {
				return sessionlink.ErrGenerationMismatch
			}
			if existing.Generation == entry.Generation && existing.TransportID != entry.TransportID {
				return sessionlink.ErrGenerationMismatch
			}
		}
		registry.Entries = append(entries, entry)
		return nil
	})
}

func (s LeaseStore) Renew(ctx context.Context, token sessionlink.Token, leaseUntil time.Time) error {
	now := s.now()
	if leaseUntil.IsZero() || !leaseUntil.After(now) || leaseUntil.Sub(now) > sessionlink.MaxLease {
		return sessionlink.ErrInvalidLease
	}
	return s.mutate(ctx, func(registry *LeaseRegistry) error {
		found := false
		entries := registry.Entries[:0]
		for _, entry := range registry.Entries {
			entry = normalizeLeaseEntry(entry)
			if expiredLease(entry, now) || validateLeaseEntry(entry, now) != nil {
				continue
			}
			if entry.LinkID == token.LinkID {
				if entry.TransportID != token.TransportID || entry.Generation != token.Generation {
					return sessionlink.ErrGenerationMismatch
				}
				entry.LeaseUntil = leaseUntil
				entry.UpdatedAt = now
				found = true
			}
			entries = append(entries, entry)
		}
		registry.Entries = entries
		if !found {
			return ErrNoRoute
		}
		return nil
	})
}

// Remove deletes only the exact transport generation. Stale cleanup is
// harmless after a replacement has been registered.
func (s LeaseStore) Remove(ctx context.Context, token sessionlink.Token) error {
	now := s.now()
	return s.mutate(ctx, func(registry *LeaseRegistry) error {
		entries := registry.Entries[:0]
		for _, entry := range registry.Entries {
			entry = normalizeLeaseEntry(entry)
			if expiredLease(entry, now) || validateLeaseEntry(entry, now) != nil {
				continue
			}
			if entry.LinkID == token.LinkID && entry.TransportID == token.TransportID && entry.Generation == token.Generation {
				continue
			}
			entries = append(entries, entry)
		}
		registry.Entries = entries
		return nil
	})
}

// ResetLink removes every generation for one logical adjacency. Callers must
// own the stable broker socket for that link before invoking it; this is the
// process-restart recovery path when an old process crashed with an unexpired
// lease and its in-memory generation counter was lost.
func (s LeaseStore) ResetLink(ctx context.Context, linkID sessionlink.ID) error {
	if sessionlink.ValidateID(linkID) != nil {
		return sessionlink.ErrInvalidDescriptor
	}
	now := s.now()
	return s.mutate(ctx, func(registry *LeaseRegistry) error {
		entries := registry.Entries[:0]
		for _, entry := range registry.Entries {
			entry = normalizeLeaseEntry(entry)
			if expiredLease(entry, now) || validateLeaseEntry(entry, now) != nil || entry.LinkID == linkID {
				continue
			}
			entries = append(entries, entry)
		}
		registry.Entries = entries
		return nil
	})
}

func (s LeaseStore) Snapshot() (LeaseRegistry, error) {
	path, err := s.path()
	if err != nil {
		return LeaseRegistry{}, err
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return LeaseRegistry{Version: LeaseRegistryVersion}, nil
		}
		return LeaseRegistry{}, err
	}
	if len(payload) > maxLeaseRegistryBytes {
		return LeaseRegistry{}, errors.New("sessionroute: lease registry is too large")
	}
	var registry LeaseRegistry
	if err := json.Unmarshal(payload, &registry); err != nil {
		return LeaseRegistry{}, fmt.Errorf("sessionroute: decode lease registry: %w", err)
	}
	if registry.Version != LeaseRegistryVersion {
		return LeaseRegistry{}, fmt.Errorf("sessionroute: unsupported lease registry version %q", registry.Version)
	}
	now := s.now()
	validated := make([]LeaseEntry, 0, len(registry.Entries))
	for _, entry := range registry.Entries {
		entry = normalizeLeaseEntry(entry)
		if expiredLease(entry, now) || validateLeaseEntry(entry, now) != nil {
			continue
		}
		validated = append(validated, entry)
	}
	sort.Slice(validated, func(i, j int) bool {
		if validated[i].LinkID == validated[j].LinkID {
			return validated[i].Generation > validated[j].Generation
		}
		return validated[i].LinkID < validated[j].LinkID
	})
	registry.Entries = validated
	return registry, nil
}

func (s LeaseStore) ResolveAdjacent(currentBinding string, nodeContext authproof.NodeContext, target string) (LeaseEntry, string, int, error) {
	nodeContext = nodeContext.Normalized()
	if err := nodeContext.Validate(); err != nil {
		return LeaseEntry{}, "", -1, err
	}
	currentIndex := indexOf(nodeContext.Nodes, nodeContext.CurrentNode)
	targetNode, targetIndex, err := ResolveNode(nodeContext, target)
	if err != nil {
		return LeaseEntry{}, "", -1, err
	}
	if targetIndex == currentIndex {
		return LeaseEntry{}, targetNode, targetIndex, ErrTargetLocal
	}
	desiredPeer := currentIndex - 1
	if targetIndex > currentIndex {
		desiredPeer = currentIndex + 1
	}
	registry, err := s.Snapshot()
	if err != nil {
		return LeaseEntry{}, "", -1, err
	}
	currentBinding = strings.TrimSpace(currentBinding)
	var candidates []LeaseEntry
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
		return LeaseEntry{}, targetNode, targetIndex, fmt.Errorf("%w: local=%s target=%s direction_peer_index=%d", ErrNoRoute, nodeContext.CurrentNode, targetNode, desiredPeer)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Generation == candidates[j].Generation {
			return candidates[i].UpdatedAt.After(candidates[j].UpdatedAt)
		}
		return candidates[i].Generation > candidates[j].Generation
	})
	return candidates[0], targetNode, targetIndex, nil
}

func (s LeaseStore) mutate(ctx context.Context, apply func(*LeaseRegistry) error) error {
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

	registry, err := s.snapshotUnlocked(path)
	if err != nil {
		return err
	}
	registry.Version = LeaseRegistryVersion
	if err := apply(&registry); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if len(payload) > maxLeaseRegistryBytes {
		return errors.New("sessionroute: lease registry is too large")
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".route-leases-*")
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

func (s LeaseStore) snapshotUnlocked(path string) (LeaseRegistry, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return LeaseRegistry{Version: LeaseRegistryVersion}, nil
		}
		return LeaseRegistry{}, err
	}
	if len(payload) > maxLeaseRegistryBytes {
		return LeaseRegistry{}, errors.New("sessionroute: lease registry is too large")
	}
	var registry LeaseRegistry
	if err := json.Unmarshal(payload, &registry); err != nil {
		return LeaseRegistry{}, fmt.Errorf("sessionroute: decode lease registry: %w", err)
	}
	if registry.Version != LeaseRegistryVersion {
		return LeaseRegistry{}, fmt.Errorf("sessionroute: unsupported lease registry version %q", registry.Version)
	}
	return registry, nil
}

func normalizeLeaseEntry(entry LeaseEntry) LeaseEntry {
	if entry.Version == "" {
		entry.Version = LeaseRegistryVersion
	}
	entry.LinkID = sessionlink.ID(strings.TrimSpace(string(entry.LinkID)))
	entry.TransportID = sessionlink.TransportID(strings.TrimSpace(string(entry.TransportID)))
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

func validateLeaseEntry(entry LeaseEntry, now time.Time) error {
	if entry.Version != LeaseRegistryVersion || sessionlink.ValidateID(entry.LinkID) != nil ||
		sessionlink.ValidateTransportID(entry.TransportID) != nil || entry.Generation == 0 ||
		entry.Binding == "" || entry.Socket == "" || entry.LocalNode == "" || entry.PeerNode == "" ||
		entry.ChainID == "" || len(entry.ChainSHA256) != 64 || len(entry.Topology) < 2 ||
		entry.PID <= 0 || entry.StartedAt.IsZero() || entry.UpdatedAt.IsZero() || entry.LeaseUntil.IsZero() {
		return ErrInvalidEntry
	}
	if !entry.LeaseUntil.After(now) || entry.LeaseUntil.Sub(now) > sessionlink.MaxLease {
		return sessionlink.ErrInvalidLease
	}
	if entry.LocalIndex < 0 || entry.PeerIndex < 0 || entry.LocalIndex >= len(entry.Topology) || entry.PeerIndex >= len(entry.Topology) ||
		entry.Topology[entry.LocalIndex] != entry.LocalNode || entry.Topology[entry.PeerIndex] != entry.PeerNode ||
		abs(entry.LocalIndex-entry.PeerIndex) != 1 {
		return ErrInvalidEntry
	}
	descriptor := sessionlink.Descriptor{ChainSHA256: entry.ChainSHA256, Topology: entry.Topology, LocalNode: entry.LocalNode, PeerNode: entry.PeerNode}
	linkID, err := sessionlink.DeriveID(descriptor)
	if err != nil || linkID != entry.LinkID {
		return ErrInvalidEntry
	}
	return nil
}

func expiredLease(entry LeaseEntry, now time.Time) bool {
	return entry.LeaseUntil.IsZero() || !now.Before(entry.LeaseUntil)
}
