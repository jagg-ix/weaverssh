// Package containerstream routes bounded vfs://container references to
// pluggable orchestration adapters without coupling VFS callers to a specific
// container runtime or scheduler.
package containerstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const (
	// SchemePrefix is the reserved VFS namespace for orchestration streams.
	SchemePrefix = "vfs://container/"
	maxURILength = 8 << 10
	maxOptions   = 32
)

var (
	providerNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	targetPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]*$`)
	optionNamePattern   = regexp.MustCompile(`^[a-z][a-z0-9._-]*$`)
)

// Request is the provider-neutral form of a container VFS reference.
// Endpoint is a logical WeaverSSH/orchestration node, TargetID is the pod,
// container, or allocation identifier, and FilePath is absolute inside it.
type Request struct {
	URI          string            `json:"uri"`
	Endpoint     string            `json:"endpoint"`
	TargetID     string            `json:"target_id"`
	FilePath     string            `json:"file_path"`
	ProviderHint string            `json:"provider_hint,omitempty"`
	Options      map[string]string `json:"options,omitempty"`
}

// ParseURI parses the homogeneous form
// vfs://container/ENDPOINT/TARGET/ABSOLUTE/PATH. A provider can be selected
// explicitly with ?provider=NAME; all other bounded query values are passed as
// adapter options.
func ParseURI(raw string) (Request, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxURILength {
		return Request{}, errors.New("containerstream: URI is empty or exceeds 8 KiB")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return Request{}, fmt.Errorf("containerstream: parse URI: %w", err)
	}
	if parsed.Scheme != "vfs" || parsed.Host != "container" || parsed.User != nil || parsed.Fragment != "" {
		return Request{}, fmt.Errorf("containerstream: expected %sENDPOINT/TARGET/PATH", SchemePrefix)
	}

	segments, err := decodePathSegments(parsed.EscapedPath())
	if err != nil {
		return Request{}, err
	}
	if len(segments) < 3 {
		return Request{}, fmt.Errorf("containerstream: URI requires endpoint, target, and file path")
	}
	if !targetPattern.MatchString(segments[0]) {
		return Request{}, fmt.Errorf("containerstream: unsafe endpoint %q", segments[0])
	}
	if !targetPattern.MatchString(segments[1]) {
		return Request{}, fmt.Errorf("containerstream: unsafe target %q", segments[1])
	}
	filePath := path.Clean("/" + strings.Join(segments[2:], "/"))
	if filePath == "/" || len(filePath) > 4096 || strings.ContainsAny(filePath, "\x00\r\n") {
		return Request{}, errors.New("containerstream: invalid container file path")
	}

	values := parsed.Query()
	if len(values) > maxOptions {
		return Request{}, errors.New("containerstream: too many URI options")
	}
	request := Request{
		URI:      raw,
		Endpoint: segments[0],
		TargetID: segments[1],
		FilePath: filePath,
		Options:  map[string]string{},
	}
	for key, entries := range values {
		if !optionNamePattern.MatchString(key) || len(entries) != 1 {
			return Request{}, fmt.Errorf("containerstream: invalid or repeated option %q", key)
		}
		value := strings.TrimSpace(entries[0])
		if value == "" || len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
			return Request{}, fmt.Errorf("containerstream: invalid value for option %q", key)
		}
		if key == "provider" {
			value = normalizeProviderName(value)
			if !providerNamePattern.MatchString(value) {
				return Request{}, fmt.Errorf("containerstream: invalid provider hint %q", value)
			}
			request.ProviderHint = value
			continue
		}
		request.Options[key] = value
	}
	if len(request.Options) == 0 {
		request.Options = nil
	}
	return request, nil
}

func decodePathSegments(escaped string) ([]string, error) {
	escaped = strings.TrimPrefix(escaped, "/")
	parts := strings.Split(escaped, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil {
			return nil, fmt.Errorf("containerstream: decode path: %w", err)
		}
		if decoded == "" || decoded == "." {
			continue
		}
		if decoded == ".." || strings.ContainsAny(decoded, "/\\\x00\r\n") {
			return nil, errors.New("containerstream: path escapes or changes URI segment boundaries")
		}
		out = append(out, decoded)
	}
	return out, nil
}

// Provider opens a read stream from a target managed by one orchestration
// stack. Implementations must return promptly when ctx is cancelled.
type Provider interface {
	Name() string
	OpenContainerStream(context.Context, Request) (io.ReadCloser, error)
}

// Registry holds stream providers by stable name. It is safe for concurrent
// discovery and request routing and can be extended by applications.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
	aliases   map[string]string
}

func NewRegistry() *Registry {
	return &Registry{providers: map[string]Provider{}, aliases: map[string]string{}}
}

func (r *Registry) Register(provider Provider, aliases ...string) error {
	if r == nil || provider == nil {
		return errors.New("containerstream: invalid provider registration")
	}
	name := normalizeProviderName(provider.Name())
	if !providerNamePattern.MatchString(name) {
		return fmt.Errorf("containerstream: invalid provider name %q", provider.Name())
	}
	normalizedAliases := make([]string, len(aliases))
	for index, alias := range aliases {
		alias = normalizeProviderName(alias)
		if !providerNamePattern.MatchString(alias) || alias == name {
			return fmt.Errorf("containerstream: invalid provider alias %q", alias)
		}
		normalizedAliases[index] = alias
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[name]; exists {
		return fmt.Errorf("containerstream: provider %q is already registered", name)
	}
	for _, alias := range normalizedAliases {
		if _, exists := r.providers[alias]; exists {
			return fmt.Errorf("containerstream: alias %q conflicts with a provider", alias)
		}
		if existing, exists := r.aliases[alias]; exists && existing != name {
			return fmt.Errorf("containerstream: alias %q is already registered", alias)
		}
	}
	r.providers[name] = provider
	for _, alias := range normalizedAliases {
		r.aliases[alias] = name
	}
	return nil
}

func (r *Registry) MustRegister(provider Provider, aliases ...string) {
	if err := r.Register(provider, aliases...); err != nil {
		panic(err)
	}
}

// Replace swaps a provider implementation while preserving its registered
// aliases. Embedders use this to install a socket/API or hybrid fast path under
// a built-in provider name.
func (r *Registry) Replace(provider Provider) error {
	if r == nil || provider == nil {
		return errors.New("containerstream: invalid replacement provider")
	}
	name := normalizeProviderName(provider.Name())
	if !providerNamePattern.MatchString(name) {
		return fmt.Errorf("containerstream: invalid provider name %q", provider.Name())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[name]; !exists {
		return fmt.Errorf("containerstream: provider %q is not registered", name)
	}
	r.providers[name] = provider
	return nil
}

func (r *Registry) Provider(name string) (Provider, bool) {
	if r == nil {
		return nil, false
	}
	name = normalizeProviderName(name)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if canonical, ok := r.aliases[name]; ok {
		name = canonical
	}
	provider, ok := r.providers[name]
	return provider, ok
}

func (r *Registry) Names() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.providers))
	for name := range r.providers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func normalizeProviderName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func safeAdapterToken(name, value string) (string, error) {
	value = strings.TrimSpace(value)
	if !targetPattern.MatchString(value) {
		return "", fmt.Errorf("containerstream: unsafe %s %q", name, value)
	}
	return value, nil
}
