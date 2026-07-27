package apicontract

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type Summary struct {
	Symbols []string
}

type Validator interface {
	Kind() Kind
	Validate(context.Context, Contract, []byte) (Summary, error)
}

type ValidatorFunc struct {
	ContractKind Kind
	ValidateFunc func(context.Context, Contract, []byte) (Summary, error)
}

func (validator ValidatorFunc) Kind() Kind { return validator.ContractKind }
func (validator ValidatorFunc) Validate(ctx context.Context, contract Contract, payload []byte) (Summary, error) {
	if validator.ValidateFunc == nil {
		return Summary{}, errors.New("apicontract: validator function unavailable")
	}
	return validator.ValidateFunc(ctx, contract, payload)
}

type Registry struct {
	mu         sync.RWMutex
	validators map[Kind]Validator
}

func NewRegistry() *Registry {
	registry := &Registry{validators: map[Kind]Validator{}}
	registry.MustRegister(jsonDescriptionValidator{kind: KindOpenAPI, versionField: "openapi", expectedPrefix: "3."})
	registry.MustRegister(jsonDescriptionValidator{kind: KindOpenRPC, versionField: "openrpc", expectedPrefix: "1."})
	registry.MustRegister(jsonDescriptionValidator{kind: KindAsyncAPI, versionField: "asyncapi", expectedPrefix: "3."})
	registry.MustRegister(jsonDescriptionValidator{kind: KindJSONSchema, versionField: "$schema", expectedPrefix: "https://json-schema.org/draft/2020-12/"})
	registry.MustRegister(protobufSourceValidator{})
	registry.MustRegister(descriptorValidator{})
	return registry
}

func (registry *Registry) Register(validator Validator) error {
	if registry == nil || validator == nil || !validator.Kind().valid() {
		return errors.New("apicontract: invalid validator")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.validators[validator.Kind()]; exists {
		return fmt.Errorf("apicontract: validator already registered for %s", validator.Kind())
	}
	registry.validators[validator.Kind()] = validator
	return nil
}

func (registry *Registry) MustRegister(validator Validator) {
	if err := registry.Register(validator); err != nil {
		panic(err)
	}
}

func (registry *Registry) ValidateCatalog(ctx context.Context, catalog Catalog) (Lock, error) {
	if registry == nil {
		return Lock{}, errors.New("apicontract: nil registry")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := catalog.Validate(); err != nil {
		return Lock{}, err
	}
	root := commonContractRoot(catalog.Contracts)
	entries := make([]LockedEntry, 0, len(catalog.Contracts))
	for _, contract := range catalog.Contracts {
		if err := ctx.Err(); err != nil {
			return Lock{}, err
		}
		payload, err := readContract(contract.Path)
		if err != nil {
			return Lock{}, fmt.Errorf("apicontract: %s@%s: %w", contract.ID, contract.Version, err)
		}
		registry.mu.RLock()
		validator := registry.validators[contract.Kind]
		registry.mu.RUnlock()
		if validator == nil {
			return Lock{}, fmt.Errorf("apicontract: no validator for %s", contract.Kind)
		}
		summary, err := validator.Validate(ctx, contract, payload)
		if err != nil {
			return Lock{}, fmt.Errorf("apicontract: %s@%s: %w", contract.ID, contract.Version, err)
		}
		path := contract.Path
		if root != "" {
			if relative, relErr := filepath.Rel(root, contract.Path); relErr == nil {
				path = relative
			}
		}
		entries = append(entries, LockedEntry{
			ID: contract.ID, Version: contract.Version, Kind: contract.Kind,
			Path: filepath.ToSlash(path), Stability: contract.Stability,
			Compatibility: contract.Compatibility, SHA256: sha256Hex(payload),
			Symbols: normalizeSymbols(summary.Symbols),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ID != entries[j].ID {
			return entries[i].ID < entries[j].ID
		}
		return compareVersion(entries[i].Version, entries[j].Version) < 0
	})
	catalogDigest, err := digestCatalog(catalog)
	if err != nil {
		return Lock{}, err
	}
	return Lock{Version: LockVersion, CatalogName: catalog.Name, Revision: catalog.Revision, CatalogSHA256: catalogDigest, Contracts: entries}, nil
}

func readContract(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > MaxContractSize {
		return nil, errors.New("contract must be a bounded regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, MaxContractSize+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxContractSize {
		return nil, errors.New("contract exceeds 64 MiB")
	}
	return payload, nil
}

func digestCatalog(catalog Catalog) (string, error) {
	portable := cloneCatalog(catalog)
	root := commonContractRoot(portable.Contracts)
	for index := range portable.Contracts {
		if root != "" {
			if relative, err := filepath.Rel(root, portable.Contracts[index].Path); err == nil {
				portable.Contracts[index].Path = filepath.ToSlash(relative)
			}
		}
	}
	payload, err := json.Marshal(portable)
	if err != nil {
		return "", err
	}
	return sha256Hex(payload), nil
}

func commonContractRoot(contracts []Contract) string {
	if len(contracts) == 0 {
		return ""
	}
	root := filepath.Dir(contracts[0].Path)
	for _, contract := range contracts[1:] {
		candidate := filepath.Dir(contract.Path)
		for root != "." && root != string(filepath.Separator) {
			relative, err := filepath.Rel(root, candidate)
			if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				break
			}
			parent := filepath.Dir(root)
			if parent == root {
				break
			}
			root = parent
		}
	}
	return root
}

func normalizeSymbols(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func DecodeLock(reader io.Reader) (Lock, error) {
	if reader == nil {
		return Lock{}, errors.New("apicontract: nil lock reader")
	}
	payload, err := io.ReadAll(io.LimitReader(reader, MaxCatalogSize+1))
	if err != nil {
		return Lock{}, err
	}
	if len(payload) > MaxCatalogSize {
		return Lock{}, errors.New("apicontract: lock exceeds 4 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var lock Lock
	if err := decoder.Decode(&lock); err != nil {
		return Lock{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Lock{}, errors.New("apicontract: trailing lock data")
	}
	if err := lock.Validate(); err != nil {
		return Lock{}, err
	}
	return lock, nil
}

func (lock Lock) Validate() error {
	if lock.Version != LockVersion || !validToken(lock.CatalogName, 128) || !validVersion(lock.Revision) || !validSHA256(lock.CatalogSHA256) {
		return errors.New("apicontract: invalid lock metadata")
	}
	if len(lock.Contracts) == 0 || len(lock.Contracts) > 4096 {
		return errors.New("apicontract: invalid lock contract count")
	}
	seen := map[string]struct{}{}
	for _, entry := range lock.Contracts {
		key := entry.ID + "@" + entry.Version
		if !validToken(entry.ID, 128) || !validVersion(entry.Version) || !entry.Kind.valid() || !entry.Stability.valid() || !entry.Compatibility.valid() || !validSHA256(entry.SHA256) || entry.Path == "" || filepath.IsAbs(entry.Path) {
			return fmt.Errorf("apicontract: invalid lock entry %s", key)
		}
		clean := filepath.Clean(filepath.FromSlash(entry.Path))
		if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("apicontract: lock path escapes root for %s", key)
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("apicontract: duplicate lock entry %s", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func EncodeLock(writer io.Writer, lock Lock) error {
	if writer == nil {
		return errors.New("apicontract: nil lock writer")
	}
	if err := lock.Validate(); err != nil {
		return err
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(lock)
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}
