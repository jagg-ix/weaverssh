package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON data")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func readStrictJSONFile(path string, target any) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("configuration file path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return decodeStrictJSON(data, target)
}

func marshalJSONArtifact(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func emitJSONArtifact(writer io.Writer, value any) error {
	data, err := marshalJSONArtifact(value)
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

// writeJSONArtifact writes a complete JSON artifact through a same-directory
// temporary file. Existing output is rejected unless replace is true.
func writeJSONArtifact(path string, value any, mode os.FileMode, replace bool) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("output path is required")
	}
	if !replace {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; use --force or --in-place", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	data, err := marshalJSONArtifact(value)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".wv-config-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

type commaListFlag []string

func (f *commaListFlag) String() string { return strings.Join(*f, ",") }

func (f *commaListFlag) Set(raw string) error {
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			*f = append(*f, item)
		}
	}
	return nil
}

func normalizedUniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

// splitLeadingOperands lets commands accept either GNU-style flags first or
// the common `command PATH --flag` form supported by the rest of wv.
func splitLeadingOperands(args []string, maximum int) ([]string, []string) {
	leading := make([]string, 0, maximum)
	index := 0
	for index < len(args) && len(leading) < maximum && !strings.HasPrefix(args[index], "-") {
		leading = append(leading, args[index])
		index++
	}
	return leading, args[index:]
}
