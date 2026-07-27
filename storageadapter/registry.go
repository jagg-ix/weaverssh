package storageadapter

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

var globalRegistry = NewRegistry()

type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

func NewRegistry() *Registry {
	return &Registry{factories: map[string]Factory{}}
}

func Register(name string, factory Factory) error {
	return globalRegistry.Register(name, factory)
}

func Open(ctx context.Context, config Config) (Store, error) {
	return globalRegistry.Open(ctx, config)
}

func Engines() []string { return globalRegistry.Engines() }

func (registry *Registry) Register(name string, factory Factory) error {
	if registry == nil {
		return errors.New("storageadapter: nil registry")
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if !validToken(name, 64) || factory == nil {
		return errors.New("storageadapter: invalid engine registration")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.factories[name]; exists {
		return fmt.Errorf("storageadapter: engine %q already registered", name)
	}
	registry.factories[name] = factory
	return nil
}

func (registry *Registry) Open(ctx context.Context, config Config) (Store, error) {
	if registry == nil {
		return nil, errors.New("storageadapter: nil registry")
	}
	normalized, err := config.Normalize()
	if err != nil {
		return nil, err
	}
	registry.mu.RLock()
	factory := registry.factories[normalized.Engine]
	registry.mu.RUnlock()
	if factory == nil {
		return nil, fmt.Errorf("%w: %s", ErrEngineUnavailable, normalized.Engine)
	}
	store, err := factory(ctxOrBackground(ctx), normalized)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf("storageadapter: engine %q returned nil store", normalized.Engine)
	}
	bounded := &boundedStore{Store: store, config: normalized}
	if normalized.Namespace == "" {
		return bounded, nil
	}
	return &namespaceStore{Store: bounded, namespace: []byte(normalized.Namespace + "/")}, nil
}

func (registry *Registry) Engines() []string {
	if registry == nil {
		return nil
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	out := make([]string, 0, len(registry.factories))
	for name := range registry.factories {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func ctxOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func init() {
	_ = Register("memory", openMemory)
	_ = Register("file", openFile)
}
