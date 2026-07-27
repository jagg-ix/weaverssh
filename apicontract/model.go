// Package apicontract manages versioned, transport-neutral API description files.
package apicontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	CatalogVersion  = "weaverssh.api-contract-catalog.v1"
	LockVersion     = "weaverssh.api-contract-lock.v1"
	MaxCatalogSize  = 4 << 20
	MaxContractSize = 64 << 20
)

type Kind string

const (
	KindOpenAPI            Kind = "openapi"
	KindOpenRPC            Kind = "openrpc"
	KindAsyncAPI           Kind = "asyncapi"
	KindJSONSchema         Kind = "json-schema"
	KindProtobuf           Kind = "protobuf"
	KindProtobufDescriptor Kind = "protobuf-descriptor"
)

type Stability string

const (
	StabilityExperimental Stability = "experimental"
	StabilityBeta         Stability = "beta"
	StabilityStable       Stability = "stable"
	StabilityDeprecated   Stability = "deprecated"
)

type Compatibility string

const (
	CompatibilityNone     Compatibility = "none"
	CompatibilityBackward Compatibility = "backward"
	CompatibilityForward  Compatibility = "forward"
	CompatibilityFull     Compatibility = "full"
)

type Catalog struct {
	Version   string     `json:"version"`
	Name      string     `json:"name"`
	Revision  string     `json:"revision"`
	Contracts []Contract `json:"contracts"`
}

type Contract struct {
	ID            string            `json:"id"`
	Version       string            `json:"contract_version"`
	Kind          Kind              `json:"kind"`
	Path          string            `json:"path"`
	Stability     Stability         `json:"stability"`
	Compatibility Compatibility     `json:"compatibility"`
	Supersedes    string            `json:"supersedes,omitempty"`
	Owner         string            `json:"owner,omitempty"`
	Transports    []string          `json:"transports,omitempty"`
	MediaTypes    []string          `json:"media_types,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
}

type Lock struct {
	Version       string        `json:"version"`
	CatalogName   string        `json:"catalog_name"`
	Revision      string        `json:"revision"`
	CatalogSHA256 string        `json:"catalog_sha256"`
	Contracts     []LockedEntry `json:"contracts"`
}

type LockedEntry struct {
	ID            string        `json:"id"`
	Version       string        `json:"contract_version"`
	Kind          Kind          `json:"kind"`
	Path          string        `json:"path"`
	Stability     Stability     `json:"stability"`
	Compatibility Compatibility `json:"compatibility"`
	SHA256        string        `json:"sha256"`
	Symbols       []string      `json:"symbols,omitempty"`
}

func LoadCatalogFile(path string) (Catalog, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Catalog{}, errors.New("apicontract: catalog path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Catalog{}, err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return Catalog{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > MaxCatalogSize {
		return Catalog{}, errors.New("apicontract: catalog must be a bounded regular non-symlink file")
	}
	file, err := os.Open(absolute)
	if err != nil {
		return Catalog{}, err
	}
	defer file.Close()
	catalog, err := DecodeCatalog(file)
	if err != nil {
		return Catalog{}, err
	}
	base := filepath.Dir(absolute)
	for index := range catalog.Contracts {
		contractPath := catalog.Contracts[index].Path
		if !filepath.IsAbs(contractPath) {
			contractPath = filepath.Join(base, contractPath)
		}
		catalog.Contracts[index].Path = filepath.Clean(contractPath)
	}
	return catalog, nil
}

func DecodeCatalog(reader io.Reader) (Catalog, error) {
	if reader == nil {
		return Catalog{}, errors.New("apicontract: nil catalog reader")
	}
	payload, err := io.ReadAll(io.LimitReader(reader, MaxCatalogSize+1))
	if err != nil {
		return Catalog{}, err
	}
	if len(payload) > MaxCatalogSize {
		return Catalog{}, errors.New("apicontract: catalog exceeds 4 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var catalog Catalog
	if err := decoder.Decode(&catalog); err != nil {
		return Catalog{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Catalog{}, errors.New("apicontract: trailing catalog data")
	}
	if err := catalog.Validate(); err != nil {
		return Catalog{}, err
	}
	return catalog, nil
}

func (catalog Catalog) Validate() error {
	if catalog.Version != CatalogVersion {
		return errors.New("apicontract: unsupported catalog version")
	}
	if !validToken(catalog.Name, 128) || !validVersion(catalog.Revision) {
		return errors.New("apicontract: invalid catalog name or revision")
	}
	if len(catalog.Contracts) == 0 || len(catalog.Contracts) > 4096 {
		return errors.New("apicontract: catalog requires 1..4096 contracts")
	}
	seen := map[string]struct{}{}
	known := map[string]struct{}{}
	for index := range catalog.Contracts {
		contract := &catalog.Contracts[index]
		contract.ID = strings.TrimSpace(contract.ID)
		contract.Version = strings.TrimSpace(contract.Version)
		contract.Path = strings.TrimSpace(contract.Path)
		contract.Owner = strings.TrimSpace(contract.Owner)
		contract.Supersedes = strings.TrimSpace(contract.Supersedes)
		if !validToken(contract.ID, 128) || !validVersion(contract.Version) || contract.Path == "" || len(contract.Path) > 4096 || strings.ContainsAny(contract.Path, "\x00\r\n") {
			return fmt.Errorf("apicontract: invalid contract at index %d", index)
		}
		if !contract.Kind.valid() || !contract.Stability.valid() || !contract.Compatibility.valid() {
			return fmt.Errorf("apicontract: invalid contract classification for %s", contract.ID)
		}
		key := contract.ID + "@" + contract.Version
		if _, exists := seen[key]; exists {
			return fmt.Errorf("apicontract: duplicate contract %s", key)
		}
		seen[key] = struct{}{}
		known[key] = struct{}{}
		if contract.Supersedes != "" && !validReference(contract.Supersedes) {
			return fmt.Errorf("apicontract: invalid supersedes reference for %s", contract.ID)
		}
		var err error
		contract.Transports, err = validateStringList("transport", contract.Transports, 32)
		if err != nil {
			return fmt.Errorf("apicontract: %s: %w", contract.ID, err)
		}
		contract.MediaTypes, err = validateStringList("media type", contract.MediaTypes, 32)
		if err != nil {
			return fmt.Errorf("apicontract: %s: %w", contract.ID, err)
		}
		if len(contract.Labels) > 64 {
			return fmt.Errorf("apicontract: metadata exceeds limits for %s", contract.ID)
		}
		for key, value := range contract.Labels {
			if !validToken(key, 128) || len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
				return fmt.Errorf("apicontract: invalid label %q", key)
			}
		}
	}
	for _, contract := range catalog.Contracts {
		if contract.Supersedes == "" {
			continue
		}
		if _, exists := known[contract.Supersedes]; !exists {
			return fmt.Errorf("apicontract: superseded contract %s is not present in catalog", contract.Supersedes)
		}
		if strings.HasPrefix(contract.Supersedes, contract.ID+"@") && contract.Supersedes == contract.ID+"@"+contract.Version {
			return fmt.Errorf("apicontract: contract %s cannot supersede itself", contract.ID)
		}
	}
	return nil
}

func (kind Kind) valid() bool {
	switch kind {
	case KindOpenAPI, KindOpenRPC, KindAsyncAPI, KindJSONSchema, KindProtobuf, KindProtobufDescriptor:
		return true
	default:
		return false
	}
}

func (stability Stability) valid() bool {
	switch stability {
	case StabilityExperimental, StabilityBeta, StabilityStable, StabilityDeprecated:
		return true
	default:
		return false
	}
}

func (compatibility Compatibility) valid() bool {
	switch compatibility {
	case CompatibilityNone, CompatibilityBackward, CompatibilityForward, CompatibilityFull:
		return true
	default:
		return false
	}
}

func validToken(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maximum {
		return false
	}
	for _, char := range value {
		if !(char == '-' || char == '_' || char == '.' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func validVersion(value string) bool {
	return validToken(value, 128) && strings.ContainsAny(value, "0123456789")
}

func validReference(value string) bool {
	parts := strings.Split(value, "@")
	return len(parts) == 2 && validToken(parts[0], 128) && validVersion(parts[1])
}

func validateStringList(name string, values []string, maximum int) ([]string, error) {
	if len(values) > maximum {
		return nil, fmt.Errorf("%s list exceeds %d entries", name, maximum)
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("invalid %s", name)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}
