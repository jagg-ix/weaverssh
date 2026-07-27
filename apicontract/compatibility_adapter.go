package apicontract

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

type Revision struct {
	Contract Contract
	Payload  []byte
	Summary  Summary
}

type DeepCompatibilityResult struct {
	Compatible bool     `json:"compatible"`
	Reasons    []string `json:"reasons,omitempty"`
}

type CompatibilityChecker interface {
	Name() string
	Kind() Kind
	Compare(context.Context, Revision, Revision) (DeepCompatibilityResult, error)
}

type CompatibilityCheckerFunc struct {
	CheckerName string
	ContractKind Kind
	CompareFunc func(context.Context, Revision, Revision) (DeepCompatibilityResult, error)
}

func (checker CompatibilityCheckerFunc) Name() string { return checker.CheckerName }
func (checker CompatibilityCheckerFunc) Kind() Kind   { return checker.ContractKind }
func (checker CompatibilityCheckerFunc) Compare(ctx context.Context, previous, current Revision) (DeepCompatibilityResult, error) {
	if checker.CompareFunc == nil {
		return DeepCompatibilityResult{}, errors.New("apicontract: compatibility checker function unavailable")
	}
	return checker.CompareFunc(ctx, previous, current)
}

type CompatibilityRegistry struct {
	mu       sync.RWMutex
	checkers map[string]CompatibilityChecker
}

func NewCompatibilityRegistry() *CompatibilityRegistry {
	return &CompatibilityRegistry{checkers: map[string]CompatibilityChecker{}}
}

func (registry *CompatibilityRegistry) Register(checker CompatibilityChecker) error {
	if registry == nil || checker == nil || !validToken(checker.Name(), 128) || !checker.Kind().valid() {
		return errors.New("apicontract: invalid compatibility checker")
	}
	key := string(checker.Kind()) + "/" + checker.Name()
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.checkers[key]; exists {
		return fmt.Errorf("apicontract: duplicate compatibility checker %s", key)
	}
	registry.checkers[key] = checker
	return nil
}

func (registry *CompatibilityRegistry) Compare(ctx context.Context, name string, previous, current Revision) (DeepCompatibilityResult, error) {
	if registry == nil {
		return DeepCompatibilityResult{}, errors.New("apicontract: nil compatibility registry")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if previous.Contract.Kind != current.Contract.Kind {
		return DeepCompatibilityResult{}, errors.New("apicontract: cannot compare different contract kinds")
	}
	key := string(current.Contract.Kind) + "/" + name
	registry.mu.RLock()
	checker := registry.checkers[key]
	registry.mu.RUnlock()
	if checker == nil {
		return DeepCompatibilityResult{}, fmt.Errorf("apicontract: compatibility checker %s is not registered", key)
	}
	result, err := checker.Compare(ctx, cloneRevision(previous), cloneRevision(current))
	if err != nil {
		return DeepCompatibilityResult{}, err
	}
	for _, reason := range result.Reasons {
		if reason == "" || len(reason) > 4096 {
			return DeepCompatibilityResult{}, errors.New("apicontract: invalid compatibility reason")
		}
	}
	return result, nil
}

func cloneRevision(revision Revision) Revision {
	revision.Contract = cloneContract(revision.Contract)
	revision.Payload = append([]byte(nil), revision.Payload...)
	revision.Summary.Symbols = append([]string(nil), revision.Summary.Symbols...)
	return revision
}
