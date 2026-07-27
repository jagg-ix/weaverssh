package mapreduce

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

type Rule struct {
	Name           string            `json:"name"`
	Effect         Effect            `json:"effect"`
	SourceNodes    []string          `json:"source_nodes"`
	SourceRoles    []string          `json:"source_roles,omitempty"`
	TargetNodes    []string          `json:"target_nodes"`
	Plugins        []string          `json:"plugins"`
	Operations     []Operation       `json:"operations"`
	RequiredLabels map[string]string `json:"required_labels,omitempty"`
	Limits         Limits            `json:"limits,omitempty"`
}

type Policy struct {
	Version string `json:"version"`
	Default Effect `json:"default"`
	Rules   []Rule `json:"rules"`

	digest string
}

func ParsePolicy(data []byte) (*Policy, error) {
	var policy Policy
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("mapreduce: trailing policy data")
	}
	return NewPolicy(policy)
}

func NewPolicy(raw Policy) (*Policy, error) {
	normalized, err := normalizePolicy(raw)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	normalized.digest = hex.EncodeToString(sum[:])
	return &normalized, nil
}

func (p *Policy) SHA256() string {
	if p == nil {
		return ""
	}
	return p.digest
}

func (p *Policy) Evaluate(inv Invocation) (DecisionSummary, error) {
	if p == nil {
		return DecisionSummary{}, fmt.Errorf("%w: no policy", ErrDenied)
	}
	inv.SourceNode = strings.TrimSpace(inv.SourceNode)
	inv.TargetNode = strings.TrimSpace(inv.TargetNode)
	inv.Plugin = strings.TrimSpace(inv.Plugin)
	inv.SourceRole = strings.TrimSpace(inv.SourceRole)
	inv.Labels = cloneLabels(inv.Labels)
	if !validNodeName(inv.SourceNode) || !validNodeName(inv.TargetNode) || !inv.Operation.Valid() || !validName(inv.Plugin) {
		return DecisionSummary{}, ErrInvalidRequest
	}
	if err := validateLabels(inv.Labels); err != nil {
		return DecisionSummary{}, err
	}
	if inv.Items < 0 || inv.InputBytes < 0 || inv.RequestedParallel < 0 || inv.RequestedTimeoutMillis < 0 || inv.Fanout < 0 {
		return DecisionSummary{}, ErrInvalidRequest
	}

	matchingAllow := make([]Rule, 0)
	matchingNames := make([]string, 0)
	for _, rule := range p.Rules {
		if !ruleMatches(rule, inv) {
			continue
		}
		if rule.Effect == EffectDeny {
			return DecisionSummary{Allowed: false, RuleNames: []string{rule.Name}, PolicySHA256: p.digest}, fmt.Errorf("%w: rule %s", ErrDenied, rule.Name)
		}
		matchingAllow = append(matchingAllow, rule)
		matchingNames = append(matchingNames, rule.Name)
	}
	if len(matchingAllow) == 0 {
		return DecisionSummary{Allowed: false, PolicySHA256: p.digest}, ErrDenied
	}
	effective := HardLimits()
	for _, rule := range matchingAllow {
		effective = minLimits(effective, normalizeRuleLimits(rule.Limits))
	}
	decision := DecisionSummary{Allowed: true, RuleNames: matchingNames, Limits: effective, PolicySHA256: p.digest}
	if err := checkInvocationLimits(inv, effective); err != nil {
		decision.Allowed = false
		return decision, err
	}
	return decision, nil
}

func normalizePolicy(raw Policy) (Policy, error) {
	out := raw
	if out.Version == "" {
		out.Version = PolicyVersion
	}
	if out.Version != PolicyVersion {
		return Policy{}, fmt.Errorf("mapreduce: unsupported policy version %q", out.Version)
	}
	if out.Default == "" {
		out.Default = EffectDeny
	}
	if out.Default != EffectDeny {
		return Policy{}, errors.New("mapreduce: policy default must be deny")
	}
	if len(out.Rules) == 0 || len(out.Rules) > 256 {
		return Policy{}, errors.New("mapreduce: policy requires 1..256 rules")
	}
	seen := make(map[string]bool)
	for index := range out.Rules {
		rule, err := normalizeRule(out.Rules[index])
		if err != nil {
			return Policy{}, fmt.Errorf("mapreduce: rule %d: %w", index, err)
		}
		if seen[rule.Name] {
			return Policy{}, fmt.Errorf("mapreduce: duplicate rule %q", rule.Name)
		}
		seen[rule.Name] = true
		out.Rules[index] = rule
	}
	return out, nil
}

func normalizeRule(raw Rule) (Rule, error) {
	out := raw
	out.Name = strings.TrimSpace(out.Name)
	if !validName(out.Name) {
		return Rule{}, errors.New("invalid rule name")
	}
	if out.Effect != EffectAllow && out.Effect != EffectDeny {
		return Rule{}, errors.New("effect must be allow or deny")
	}
	var err error
	if out.SourceNodes, err = normalizeNodePatterns(out.SourceNodes); err != nil {
		return Rule{}, fmt.Errorf("source_nodes: %w", err)
	}
	if out.TargetNodes, err = normalizeNodePatterns(out.TargetNodes); err != nil {
		return Rule{}, fmt.Errorf("target_nodes: %w", err)
	}
	if out.Plugins, err = normalizePluginPatterns(out.Plugins); err != nil {
		return Rule{}, fmt.Errorf("plugins: %w", err)
	}
	if len(out.SourceNodes) == 0 || len(out.TargetNodes) == 0 || len(out.Plugins) == 0 {
		return Rule{}, errors.New("source_nodes, target_nodes, and plugins are required")
	}
	out.SourceRoles = normalizeRoles(out.SourceRoles)
	if len(raw.SourceRoles) > 0 && len(out.SourceRoles) == 0 {
		return Rule{}, errors.New("invalid source_roles")
	}
	if len(out.Operations) == 0 {
		return Rule{}, errors.New("operations are required")
	}
	seenOps := map[Operation]bool{}
	operations := make([]Operation, 0, len(out.Operations))
	for _, operation := range out.Operations {
		if !operation.Valid() {
			return Rule{}, fmt.Errorf("invalid operation %q", operation)
		}
		if !seenOps[operation] {
			seenOps[operation] = true
			operations = append(operations, operation)
		}
	}
	sort.Slice(operations, func(i, j int) bool { return operations[i] < operations[j] })
	out.Operations = operations
	out.RequiredLabels = cloneLabels(out.RequiredLabels)
	if err := validateLabels(out.RequiredLabels); err != nil {
		return Rule{}, err
	}
	if out.Effect == EffectAllow {
		normalized := normalizeRuleLimits(out.Limits)
		if err := validateLimits(normalized); err != nil {
			return Rule{}, err
		}
		out.Limits = normalized
	} else {
		out.Limits = Limits{}
	}
	return out, nil
}

func normalizeNodePatterns(raw []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if value != "*" && !validNodeName(value) {
			return nil, fmt.Errorf("invalid node pattern %q", value)
		}
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out, nil
}

func normalizePluginPatterns(raw []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if value != "*" && !validName(value) {
			return nil, fmt.Errorf("invalid plugin pattern %q", value)
		}
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out, nil
}

func normalizeRoles(raw []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, role := range raw {
		role = strings.ToLower(strings.TrimSpace(role))
		switch role {
		case "origin", "intermediate", "endpoint", "single":
			if !seen[role] {
				seen[role] = true
				out = append(out, role)
			}
		}
	}
	sort.Strings(out)
	return out
}

func normalizeRuleLimits(raw Limits) Limits {
	hard := HardLimits()
	out := raw
	if out.MaxItems <= 0 { out.MaxItems = hard.MaxItems }
	if out.MaxInputBytes <= 0 { out.MaxInputBytes = hard.MaxInputBytes }
	if out.MaxOutputRecords <= 0 { out.MaxOutputRecords = hard.MaxOutputRecords }
	if out.MaxOutputBytes <= 0 { out.MaxOutputBytes = hard.MaxOutputBytes }
	if out.MaxParallel <= 0 { out.MaxParallel = hard.MaxParallel }
	if out.MaxFanout <= 0 { out.MaxFanout = hard.MaxFanout }
	if out.MaxDurationMillis <= 0 { out.MaxDurationMillis = hard.MaxDurationMillis }
	if out.MaxValuesPerKey <= 0 { out.MaxValuesPerKey = hard.MaxValuesPerKey }
	return out
}

func validateLimits(limits Limits) error {
	hard := HardLimits()
	if limits.MaxItems <= 0 || limits.MaxItems > hard.MaxItems || limits.MaxInputBytes <= 0 || limits.MaxInputBytes > hard.MaxInputBytes ||
		limits.MaxOutputRecords <= 0 || limits.MaxOutputRecords > hard.MaxOutputRecords || limits.MaxOutputBytes <= 0 || limits.MaxOutputBytes > hard.MaxOutputBytes ||
		limits.MaxParallel <= 0 || limits.MaxParallel > hard.MaxParallel || limits.MaxFanout <= 0 || limits.MaxFanout > hard.MaxFanout ||
		limits.MaxDurationMillis <= 0 || limits.MaxDurationMillis > hard.MaxDurationMillis || limits.MaxValuesPerKey <= 0 || limits.MaxValuesPerKey > hard.MaxValuesPerKey {
		return errors.New("mapreduce: rule limits exceed hard limits")
	}
	return nil
}

func ruleMatches(rule Rule, inv Invocation) bool {
	if !matchPattern(rule.SourceNodes, inv.SourceNode) || !matchPattern(rule.TargetNodes, inv.TargetNode) || !matchPattern(rule.Plugins, inv.Plugin) {
		return false
	}
	if len(rule.SourceRoles) > 0 && !containsString(rule.SourceRoles, inv.SourceRole) { return false }
	foundOp := false
	for _, operation := range rule.Operations { if operation == inv.Operation { foundOp = true; break } }
	if !foundOp { return false }
	for key, value := range rule.RequiredLabels { if inv.Labels[key] != value { return false } }
	return true
}

func matchPattern(patterns []string, value string) bool {
	for _, pattern := range patterns { if pattern == "*" || pattern == value { return true } }
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values { if value == want { return true } }
	return false
}

func minLimits(a, b Limits) Limits {
	return Limits{
		MaxItems: minInt(a.MaxItems, b.MaxItems), MaxInputBytes: minInt64(a.MaxInputBytes, b.MaxInputBytes),
		MaxOutputRecords: minInt(a.MaxOutputRecords, b.MaxOutputRecords), MaxOutputBytes: minInt64(a.MaxOutputBytes, b.MaxOutputBytes),
		MaxParallel: minInt(a.MaxParallel, b.MaxParallel), MaxFanout: minInt(a.MaxFanout, b.MaxFanout),
		MaxDurationMillis: minInt64(a.MaxDurationMillis, b.MaxDurationMillis), MaxValuesPerKey: minInt(a.MaxValuesPerKey, b.MaxValuesPerKey),
	}
}

func checkInvocationLimits(inv Invocation, limits Limits) error {
	switch {
	case inv.Items > limits.MaxItems:
		return fmt.Errorf("%w: items %d > %d", ErrLimitExceeded, inv.Items, limits.MaxItems)
	case inv.InputBytes > limits.MaxInputBytes:
		return fmt.Errorf("%w: input bytes %d > %d", ErrLimitExceeded, inv.InputBytes, limits.MaxInputBytes)
	case inv.RequestedParallel > limits.MaxParallel:
		return fmt.Errorf("%w: parallel %d > %d", ErrLimitExceeded, inv.RequestedParallel, limits.MaxParallel)
	case inv.Fanout > limits.MaxFanout:
		return fmt.Errorf("%w: fanout %d > %d", ErrLimitExceeded, inv.Fanout, limits.MaxFanout)
	case inv.RequestedTimeoutMillis > limits.MaxDurationMillis:
		return fmt.Errorf("%w: timeout %d > %d", ErrLimitExceeded, inv.RequestedTimeoutMillis, limits.MaxDurationMillis)
	default:
		return nil
	}
}

func minInt(a, b int) int { if a < b { return a }; return b }
func minInt64(a, b int64) int64 { if a < b { return a }; return b }
