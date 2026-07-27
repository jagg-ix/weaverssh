package mapreduce

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

const (
	maxPlugins    = 128
	maxStageHooks = 256
)

type Descriptor struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

type MapInput struct {
	JobID      string
	SourceNode string
	TargetNode string
	Labels     map[string]string
	Record     Record
}

type ReduceInput struct {
	JobID      string
	SourceNode string
	TargetNode string
	Labels     map[string]string
	Group      Group
}

type MapFunc func(context.Context, MapInput) ([]Record, error)
type ReduceFunc func(context.Context, ReduceInput) (Record, error)

type MapHook func(context.Context, MapInput, MapFunc) ([]Record, error)
type ReduceHook func(context.Context, ReduceInput, ReduceFunc) (Record, error)

type Plugin struct {
	Descriptor Descriptor
	Map        MapFunc
	Reduce     ReduceFunc
}

type mapHookEntry struct {
	priority int
	order    uint64
	hook     MapHook
}

type reduceHookEntry struct {
	priority int
	order    uint64
	hook     ReduceHook
}

type pluginEntry struct {
	plugin      Plugin
	mapHooks    []mapHookEntry
	reduceHooks []reduceHookEntry
}

// Registry stores map/reduce plugins and middleware hooks. A hook may wrap a
// plugin implementation or implement the stage itself by returning without
// calling next.
type Registry struct {
	mu        sync.RWMutex
	plugins   map[string]*pluginEntry
	nextOrder uint64
}

func NewRegistry() *Registry { return &Registry{plugins: make(map[string]*pluginEntry)} }

func (r *Registry) RegisterPlugin(plugin Plugin) error {
	if r == nil {
		return errors.New("mapreduce: nil registry")
	}
	normalized, err := normalizePlugin(plugin)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.plugins == nil {
		r.plugins = make(map[string]*pluginEntry)
	}
	if len(r.plugins) >= maxPlugins {
		return fmt.Errorf("mapreduce: plugin limit %d exceeded", maxPlugins)
	}
	if _, exists := r.plugins[normalized.Descriptor.Name]; exists {
		return fmt.Errorf("mapreduce: plugin %q already registered", normalized.Descriptor.Name)
	}
	r.plugins[normalized.Descriptor.Name] = &pluginEntry{plugin: normalized}
	return nil
}

func (r *Registry) RegisterMapHook(plugin string, priority int, hook MapHook) error {
	if r == nil || hook == nil {
		return errors.New("mapreduce: invalid map hook")
	}
	plugin = strings.TrimSpace(plugin)
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.plugins[plugin]
	if !ok {
		return fmt.Errorf("%w: %s", ErrPluginNotFound, plugin)
	}
	if len(entry.mapHooks) >= maxStageHooks {
		return fmt.Errorf("mapreduce: map hook limit %d exceeded", maxStageHooks)
	}
	r.nextOrder++
	entry.mapHooks = append(entry.mapHooks, mapHookEntry{priority: priority, order: r.nextOrder, hook: hook})
	sort.SliceStable(entry.mapHooks, func(i, j int) bool {
		if entry.mapHooks[i].priority != entry.mapHooks[j].priority {
			return entry.mapHooks[i].priority < entry.mapHooks[j].priority
		}
		return entry.mapHooks[i].order < entry.mapHooks[j].order
	})
	return nil
}

func (r *Registry) RegisterReduceHook(plugin string, priority int, hook ReduceHook) error {
	if r == nil || hook == nil {
		return errors.New("mapreduce: invalid reduce hook")
	}
	plugin = strings.TrimSpace(plugin)
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.plugins[plugin]
	if !ok {
		return fmt.Errorf("%w: %s", ErrPluginNotFound, plugin)
	}
	if len(entry.reduceHooks) >= maxStageHooks {
		return fmt.Errorf("mapreduce: reduce hook limit %d exceeded", maxStageHooks)
	}
	r.nextOrder++
	entry.reduceHooks = append(entry.reduceHooks, reduceHookEntry{priority: priority, order: r.nextOrder, hook: hook})
	sort.SliceStable(entry.reduceHooks, func(i, j int) bool {
		if entry.reduceHooks[i].priority != entry.reduceHooks[j].priority {
			return entry.reduceHooks[i].priority < entry.reduceHooks[j].priority
		}
		return entry.reduceHooks[i].order < entry.reduceHooks[j].order
	})
	return nil
}

func (r *Registry) Descriptions() []PluginDescription {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]PluginDescription, 0, len(names))
	for _, name := range names {
		entry := r.plugins[name]
		out = append(out, PluginDescription{
			Name:      entry.plugin.Descriptor.Name,
			Version:   entry.plugin.Descriptor.Version,
			HasMap:    entry.plugin.Map != nil || len(entry.mapHooks) > 0,
			HasReduce: entry.plugin.Reduce != nil || len(entry.reduceHooks) > 0,
			MapHooks:  len(entry.mapHooks), ReduceHooks: len(entry.reduceHooks),
		})
	}
	return out
}

func (r *Registry) Empty() bool {
	if r == nil {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.plugins) == 0
}

func (r *Registry) Map(ctx context.Context, plugin string, input MapInput) ([]Record, error) {
	base, hooks, err := r.mapChain(plugin)
	if err != nil {
		return nil, err
	}
	next := base
	if next == nil {
		next = func(context.Context, MapInput) ([]Record, error) { return nil, ErrMapUnavailable }
	}
	for i := len(hooks) - 1; i >= 0; i-- {
		current := hooks[i].hook
		downstream := next
		next = func(ctx context.Context, input MapInput) ([]Record, error) { return current(ctx, input, downstream) }
	}
	return next(ctx, input)
}

func (r *Registry) Reduce(ctx context.Context, plugin string, input ReduceInput) (Record, error) {
	base, hooks, err := r.reduceChain(plugin)
	if err != nil {
		return Record{}, err
	}
	next := base
	if next == nil {
		next = func(context.Context, ReduceInput) (Record, error) { return Record{}, ErrReduceUnavailable }
	}
	for i := len(hooks) - 1; i >= 0; i-- {
		current := hooks[i].hook
		downstream := next
		next = func(ctx context.Context, input ReduceInput) (Record, error) { return current(ctx, input, downstream) }
	}
	return next(ctx, input)
}

func (r *Registry) mapChain(plugin string) (MapFunc, []mapHookEntry, error) {
	if r == nil {
		return nil, nil, ErrPluginNotFound
	}
	plugin = strings.TrimSpace(plugin)
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.plugins[plugin]
	if !ok {
		return nil, nil, fmt.Errorf("%w: %s", ErrPluginNotFound, plugin)
	}
	return entry.plugin.Map, append([]mapHookEntry(nil), entry.mapHooks...), nil
}

func (r *Registry) reduceChain(plugin string) (ReduceFunc, []reduceHookEntry, error) {
	if r == nil {
		return nil, nil, ErrPluginNotFound
	}
	plugin = strings.TrimSpace(plugin)
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.plugins[plugin]
	if !ok {
		return nil, nil, fmt.Errorf("%w: %s", ErrPluginNotFound, plugin)
	}
	return entry.plugin.Reduce, append([]reduceHookEntry(nil), entry.reduceHooks...), nil
}

func normalizePlugin(raw Plugin) (Plugin, error) {
	out := raw
	out.Descriptor.Name = strings.TrimSpace(out.Descriptor.Name)
	out.Descriptor.Version = strings.TrimSpace(out.Descriptor.Version)
	out.Descriptor.Description = strings.TrimSpace(out.Descriptor.Description)
	if !validName(out.Descriptor.Name) || out.Descriptor.Version == "" || len(out.Descriptor.Version) > 64 || len(out.Descriptor.Description) > 1024 {
		return Plugin{}, errors.New("mapreduce: invalid plugin descriptor")
	}
	if out.Map == nil && out.Reduce == nil {
		return Plugin{}, errors.New("mapreduce: plugin requires map or reduce implementation")
	}
	return out, nil
}
