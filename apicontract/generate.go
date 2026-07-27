package apicontract

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	MaxGeneratedFiles = 4096
	MaxGeneratedBytes = 64 << 20
)

type GenerationRequest struct {
	Contract  Contract
	Payload   []byte
	OutputDir string
	Options   map[string]string
}

type GeneratedFile struct {
	Path    string
	Content []byte
	Mode    os.FileMode
}

type Generator interface {
	Name() string
	Kind() Kind
	Generate(context.Context, GenerationRequest) ([]GeneratedFile, error)
}

type GenerationRegistry struct {
	mu         sync.RWMutex
	generators map[string]Generator
}

func NewGenerationRegistry() *GenerationRegistry {
	return &GenerationRegistry{generators: map[string]Generator{}}
}

func (registry *GenerationRegistry) Register(generator Generator) error {
	if registry == nil || generator == nil || !validToken(generator.Name(), 128) || !generator.Kind().valid() {
		return errors.New("apicontract: invalid generator")
	}
	key := string(generator.Kind()) + "/" + generator.Name()
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.generators[key]; exists {
		return fmt.Errorf("apicontract: duplicate generator %s", key)
	}
	registry.generators[key] = generator
	return nil
}

func (registry *GenerationRegistry) Generate(ctx context.Context, name string, request GenerationRequest) ([]string, error) {
	if registry == nil {
		return nil, errors.New("apicontract: nil generation registry")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	key := string(request.Contract.Kind) + "/" + strings.TrimSpace(name)
	registry.mu.RLock()
	generator := registry.generators[key]
	registry.mu.RUnlock()
	if generator == nil {
		return nil, fmt.Errorf("apicontract: generator %s is not registered", key)
	}
	output, err := filepath.Abs(strings.TrimSpace(request.OutputDir))
	if err != nil || strings.TrimSpace(request.OutputDir) == "" {
		return nil, errors.New("apicontract: output directory is required")
	}
	if err := os.MkdirAll(output, 0o700); err != nil {
		return nil, err
	}
	request.OutputDir = output
	files, err := generator.Generate(ctx, request)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 || len(files) > MaxGeneratedFiles {
		return nil, errors.New("apicontract: generator returned an invalid file count")
	}
	total := 0
	seen := map[string]struct{}{}
	for index := range files {
		path, err := safeGeneratedPath(output, files[index].Path)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[path]; exists {
			return nil, fmt.Errorf("apicontract: duplicate generated path %s", path)
		}
		seen[path] = struct{}{}
		files[index].Path = path
		total += len(files[index].Content)
		if total > MaxGeneratedBytes {
			return nil, errors.New("apicontract: generated output exceeds 64 MiB")
		}
		if files[index].Mode == 0 {
			files[index].Mode = 0o600
		}
		if files[index].Mode.Perm()&0o022 != 0 {
			return nil, errors.New("apicontract: generated files may not be group/world writable")
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	written := make([]string, 0, len(files))
	for _, file := range files {
		if err := writeGeneratedFile(file); err != nil {
			return written, err
		}
		written = append(written, file.Path)
	}
	return written, nil
}

func safeGeneratedPath(root, relative string) (string, error) {
	relative = filepath.Clean(strings.TrimSpace(relative))
	if relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("apicontract: generated path escapes output directory")
	}
	path := filepath.Join(root, relative)
	resolved, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	check, err := filepath.Rel(root, resolved)
	if err != nil || check == ".." || strings.HasPrefix(check, ".."+string(filepath.Separator)) {
		return "", errors.New("apicontract: generated path escapes output directory")
	}
	return resolved, nil
}

func writeGeneratedFile(file GeneratedFile) error {
	if err := os.MkdirAll(filepath.Dir(file.Path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(file.Path), ".api-generated-")
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
	if err := temporary.Chmod(file.Mode.Perm()); err != nil {
		return err
	}
	if _, err := temporary.Write(file.Content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if _, err := os.Lstat(file.Path); err == nil {
		return fmt.Errorf("apicontract: generated file already exists: %s", file.Path)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(temporaryPath, file.Path); err != nil {
		return err
	}
	committed = true
	return nil
}
