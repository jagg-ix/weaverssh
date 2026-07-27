package apicontract

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

var ErrContractNotFound = errors.New("apicontract: contract not found")

// Provider is the transport-neutral runtime surface used by HTTP, session,
// event, gRPC, or other adapters to discover and retrieve published contracts.
type Provider interface {
	Catalog(context.Context) (Catalog, error)
	Lock(context.Context) (Lock, error)
	List(context.Context) ([]LockedEntry, error)
	Read(context.Context, string, string) ([]byte, LockedEntry, error)
}

// FileProvider validates the complete catalog at construction time and then
// exposes immutable snapshots. Contract bytes are read and re-hashed on every
// Read so post-start file replacement is detected against the validated lock.
type FileProvider struct {
	mu      sync.RWMutex
	catalog Catalog
	lock    Lock
	byKey   map[string]Contract
	latest  map[string]string
}

func OpenFileProvider(ctx context.Context, catalogPath string, registry *Registry) (*FileProvider, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if registry == nil {
		registry = NewRegistry()
	}
	catalog, err := LoadCatalogFile(catalogPath)
	if err != nil {
		return nil, err
	}
	lock, err := registry.ValidateCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	provider := &FileProvider{catalog: cloneCatalog(catalog), lock: cloneLock(lock), byKey: map[string]Contract{}, latest: map[string]string{}}
	for _, contract := range catalog.Contracts {
		key := contract.ID + "@" + contract.Version
		provider.byKey[key] = cloneContract(contract)
		if current := provider.latest[contract.ID]; current == "" || compareVersion(contract.Version, current) > 0 {
			provider.latest[contract.ID] = contract.Version
		}
	}
	return provider, nil
}

func (provider *FileProvider) Catalog(ctx context.Context) (Catalog, error) {
	if provider == nil {
		return Catalog{}, errors.New("apicontract: provider unavailable")
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return Catalog{}, err
		}
	}
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	return cloneCatalog(provider.catalog), nil
}

func (provider *FileProvider) Lock(ctx context.Context) (Lock, error) {
	if provider == nil {
		return Lock{}, errors.New("apicontract: provider unavailable")
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return Lock{}, err
		}
	}
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	return cloneLock(provider.lock), nil
}

func (provider *FileProvider) List(ctx context.Context) ([]LockedEntry, error) {
	lock, err := provider.Lock(ctx)
	if err != nil {
		return nil, err
	}
	return lock.Contracts, nil
}

func (provider *FileProvider) Read(ctx context.Context, id, version string) ([]byte, LockedEntry, error) {
	if provider == nil {
		return nil, LockedEntry{}, errors.New("apicontract: provider unavailable")
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, LockedEntry{}, err
		}
	}
	id = strings.TrimSpace(id)
	version = strings.TrimSpace(version)
	if !validToken(id, 128) {
		return nil, LockedEntry{}, errors.New("apicontract: invalid contract id")
	}
	provider.mu.RLock()
	if version == "" {
		version = provider.latest[id]
	}
	contract, exists := provider.byKey[id+"@"+version]
	entry, locked := lockedEntry(provider.lock, id, version)
	provider.mu.RUnlock()
	if !exists || !locked {
		return nil, LockedEntry{}, fmt.Errorf("%w: %s@%s", ErrContractNotFound, id, version)
	}
	payload, err := readContract(contract.Path)
	if err != nil {
		return nil, LockedEntry{}, err
	}
	if sha256Hex(payload) != entry.SHA256 {
		return nil, LockedEntry{}, errors.New("apicontract: contract bytes changed after provider initialization")
	}
	return append([]byte(nil), payload...), cloneLockedEntry(entry), nil
}

func lockedEntry(lock Lock, id, version string) (LockedEntry, bool) {
	for _, entry := range lock.Contracts {
		if entry.ID == id && entry.Version == version {
			return entry, true
		}
	}
	return LockedEntry{}, false
}

func cloneCatalog(catalog Catalog) Catalog {
	catalog.Contracts = append([]Contract(nil), catalog.Contracts...)
	for index := range catalog.Contracts {
		catalog.Contracts[index] = cloneContract(catalog.Contracts[index])
	}
	return catalog
}

func cloneContract(contract Contract) Contract {
	contract.Transports = append([]string(nil), contract.Transports...)
	contract.MediaTypes = append([]string(nil), contract.MediaTypes...)
	if contract.Labels != nil {
		labels := make(map[string]string, len(contract.Labels))
		for key, value := range contract.Labels {
			labels[key] = value
		}
		contract.Labels = labels
	}
	return contract
}

func cloneLock(lock Lock) Lock {
	lock.Contracts = append([]LockedEntry(nil), lock.Contracts...)
	for index := range lock.Contracts {
		lock.Contracts[index] = cloneLockedEntry(lock.Contracts[index])
	}
	return lock
}

func cloneLockedEntry(entry LockedEntry) LockedEntry {
	entry.Symbols = append([]string(nil), entry.Symbols...)
	return entry
}

var _ Provider = (*FileProvider)(nil)
