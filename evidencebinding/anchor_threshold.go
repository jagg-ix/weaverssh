package evidencebinding

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var ErrAnchorThreshold = errors.New("evidence anchor threshold not met")

type AnchorThresholdPolicy struct {
	providers map[string]AnchorProvider
	threshold int
}

type AnchorThresholdReport struct {
	Required  int               `json:"required"`
	Valid     int               `json:"valid"`
	Providers []string          `json:"providers"`
	Failures  map[string]string `json:"failures,omitempty"`
}

func NewAnchorThresholdPolicy(providers []AnchorProvider, threshold int) (AnchorThresholdPolicy, error) {
	if threshold <= 0 || threshold > len(providers) {
		return AnchorThresholdPolicy{}, ErrAnchorThreshold
	}
	policy := AnchorThresholdPolicy{providers: make(map[string]AnchorProvider, len(providers)), threshold: threshold}
	for _, provider := range providers {
		if provider == nil {
			return AnchorThresholdPolicy{}, ErrInvalidAnchor
		}
		name := strings.TrimSpace(provider.Name())
		if name == "" {
			return AnchorThresholdPolicy{}, ErrInvalidAnchor
		}
		if _, exists := policy.providers[name]; exists {
			return AnchorThresholdPolicy{}, fmt.Errorf("%w: duplicate provider %s", ErrInvalidAnchor, name)
		}
		policy.providers[name] = provider
	}
	return policy, nil
}

func (p AnchorThresholdPolicy) Anchor(ctx context.Context, head Head) ([]AnchorReceipt, error) {
	if _, err := NewAnchorStatement(head); err != nil {
		return nil, err
	}
	names := p.providerNames()
	receipts := make([]AnchorReceipt, 0, len(names))
	var failures []error
	for _, name := range names {
		receipt, err := p.providers[name].Anchor(ctx, head)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
			continue
		}
		if err := receipt.ValidateFor(name, head); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
			continue
		}
		receipts = append(receipts, receipt)
	}
	if len(receipts) < p.threshold {
		return receipts, errors.Join(append([]error{ErrAnchorThreshold}, failures...)...)
	}
	return receipts, nil
}

func (p AnchorThresholdPolicy) Verify(ctx context.Context, head Head, receipts []AnchorReceipt) (AnchorThresholdReport, error) {
	report := AnchorThresholdReport{Required: p.threshold, Failures: make(map[string]string)}
	if _, err := NewAnchorStatement(head); err != nil {
		return report, err
	}
	seen := make(map[string]struct{}, len(receipts))
	for _, receipt := range receipts {
		name := strings.TrimSpace(receipt.Provider)
		if name == "" {
			report.Failures["<empty>"] = ErrInvalidAnchor.Error()
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			report.Failures[name] = "duplicate provider receipt"
			continue
		}
		seen[name] = struct{}{}
		provider, ok := p.providers[name]
		if !ok {
			report.Failures[name] = "provider is not configured"
			continue
		}
		if err := provider.Verify(ctx, head, receipt); err != nil {
			report.Failures[name] = err.Error()
			continue
		}
		report.Valid++
		report.Providers = append(report.Providers, name)
	}
	sort.Strings(report.Providers)
	if len(report.Failures) == 0 {
		report.Failures = nil
	}
	if report.Valid < p.threshold {
		return report, ErrAnchorThreshold
	}
	return report, nil
}

func (p AnchorThresholdPolicy) providerNames() []string {
	names := make([]string, 0, len(p.providers))
	for name := range p.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
