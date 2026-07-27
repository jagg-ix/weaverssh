package apicontract

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

type jsonDescriptionValidator struct {
	kind           Kind
	versionField   string
	expectedPrefix string
}

func (validator jsonDescriptionValidator) Kind() Kind { return validator.kind }
func (validator jsonDescriptionValidator) Validate(_ context.Context, _ Contract, payload []byte) (Summary, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return Summary{}, fmt.Errorf("builtin %s validator requires the JSON representation: %w", validator.kind, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Summary{}, errors.New("description contains trailing JSON")
	}
	version, ok := document[validator.versionField].(string)
	if !ok || !strings.HasPrefix(version, validator.expectedPrefix) {
		return Summary{}, fmt.Errorf("missing or unsupported %s version", validator.versionField)
	}
	symbols, err := extractJSONSymbols(validator.kind, document)
	if err != nil {
		return Summary{}, err
	}
	return Summary{Symbols: symbols}, nil
}

func extractJSONSymbols(kind Kind, document map[string]any) ([]string, error) {
	var symbols []string
	switch kind {
	case KindOpenAPI:
		paths, ok := object(document["paths"])
		if !ok {
			return nil, errors.New("OpenAPI document requires paths")
		}
		for path, raw := range paths {
			operations, _ := object(raw)
			for method := range operations {
				method = strings.ToLower(method)
				if isHTTPMethod(method) {
					symbols = append(symbols, "operation:"+strings.ToUpper(method)+" "+path)
				}
			}
		}
		symbols = append(symbols, componentSymbols(document, "schema")...)
	case KindOpenRPC:
		methods, ok := document["methods"].([]any)
		if !ok {
			return nil, errors.New("OpenRPC document requires methods")
		}
		for _, raw := range methods {
			method, _ := object(raw)
			if name, ok := method["name"].(string); ok && strings.TrimSpace(name) != "" {
				symbols = append(symbols, "method:"+name)
			}
		}
		symbols = append(symbols, componentSymbols(document, "schema")...)
	case KindAsyncAPI:
		channels, ok := object(document["channels"])
		if !ok {
			return nil, errors.New("AsyncAPI document requires channels")
		}
		for channel := range channels {
			symbols = append(symbols, "channel:"+channel)
		}
		if operations, ok := object(document["operations"]); ok {
			for operation := range operations {
				symbols = append(symbols, "operation:"+operation)
			}
		}
		symbols = append(symbols, componentSymbols(document, "message")...)
		symbols = append(symbols, componentSymbols(document, "schema")...)
	case KindJSONSchema:
		if identifier, ok := document["$id"].(string); ok && identifier != "" {
			symbols = append(symbols, "schema-id:"+identifier)
		}
		if title, ok := document["title"].(string); ok && title != "" {
			symbols = append(symbols, "schema:"+title)
		}
		if properties, ok := object(document["properties"]); ok {
			for name := range properties {
				symbols = append(symbols, "property:"+name)
			}
		}
		for _, key := range []string{"$defs", "definitions"} {
			if definitions, ok := object(document[key]); ok {
				for name := range definitions {
					symbols = append(symbols, "schema:"+name)
				}
			}
		}
	}
	return normalizeSymbols(symbols), nil
}

func componentSymbols(document map[string]any, prefix string) []string {
	components, ok := object(document["components"])
	if !ok {
		return nil
	}
	var key string
	switch prefix {
	case "schema":
		key = "schemas"
	case "message":
		key = "messages"
	default:
		return nil
	}
	values, ok := object(components[key])
	if !ok {
		return nil
	}
	symbols := make([]string, 0, len(values))
	for name := range values {
		symbols = append(symbols, prefix+":"+name)
	}
	return symbols
}

func object(value any) (map[string]any, bool) {
	result, ok := value.(map[string]any)
	return result, ok
}

func isHTTPMethod(value string) bool {
	switch value {
	case "get", "put", "post", "delete", "options", "head", "patch", "trace", "query":
		return true
	default:
		return false
	}
}

type protobufSourceValidator struct{}

func (protobufSourceValidator) Kind() Kind { return KindProtobuf }
func (protobufSourceValidator) Validate(_ context.Context, _ Contract, payload []byte) (Summary, error) {
	text := stripProtoComments(string(payload))
	proto3 := regexp.MustCompile(`(?m)^\s*syntax\s*=\s*"proto3"\s*;`).MatchString(text)
	edition := regexp.MustCompile(`(?m)^\s*edition\s*=\s*"(2023|2024)"\s*;`).MatchString(text)
	if !proto3 && !edition {
		return Summary{}, errors.New("protobuf source must declare proto3 syntax or edition 2023/2024")
	}
	packageName := ""
	if match := regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z_][A-Za-z0-9_.]*)\s*;`).FindStringSubmatch(text); len(match) == 2 {
		packageName = match[1]
	}
	var symbols []string
	patterns := []struct {
		prefix string
		re     *regexp.Regexp
	}{
		{"message:", regexp.MustCompile(`(?m)^\s*message\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{`)},
		{"enum:", regexp.MustCompile(`(?m)^\s*enum\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{`)},
		{"service:", regexp.MustCompile(`(?m)^\s*service\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{`)},
		{"rpc:", regexp.MustCompile(`(?m)\brpc\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)},
	}
	for _, pattern := range patterns {
		for _, match := range pattern.re.FindAllStringSubmatch(text, -1) {
			name := match[1]
			if packageName != "" {
				name = packageName + "." + name
			}
			symbols = append(symbols, pattern.prefix+name)
		}
	}
	if len(symbols) == 0 {
		return Summary{}, errors.New("protobuf source declares no messages, enums, services, or RPCs")
	}
	sort.Strings(symbols)
	return Summary{Symbols: symbols}, nil
}

func stripProtoComments(value string) string {
	block := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(value, "")
	return regexp.MustCompile(`(?m)//.*$`).ReplaceAllString(block, "")
}

type descriptorValidator struct{}

func (descriptorValidator) Kind() Kind { return KindProtobufDescriptor }
func (descriptorValidator) Validate(_ context.Context, _ Contract, payload []byte) (Summary, error) {
	if len(payload) == 0 {
		return Summary{}, errors.New("protobuf descriptor set is empty")
	}
	return Summary{}, nil
}
