package terminalsession

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"weaverssh/containerstream"
)

const (
	PolicyVersion  = "weaverssh.terminal-policy.v1"
	MaxPolicyBytes = 1 << 20
)

var (
	actionNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	termNamePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]{0,127}$`)
)

type Policy struct {
	Version string         `json:"version"`
	Default string         `json:"default"`
	Actions []ActionPolicy `json:"actions"`
}

// ActionPolicy maps a public action name to a fixed executable and constrains
// every authenticated source and orchestration target that may use it.
type ActionPolicy struct {
	Name          string              `json:"name"`
	Executable    string              `json:"executable"`
	FixedArgs     []string            `json:"fixed_args,omitempty"`
	Environment   map[string]string   `json:"environment,omitempty"`
	Principals    []string            `json:"principals"`
	Sources       []string            `json:"sources"`
	Endpoints     []string            `json:"endpoints"`
	Targets       []string            `json:"targets"`
	Providers     []string            `json:"providers"`
	Options       map[string][]string `json:"options,omitempty"`
	MaxArgs       int                 `json:"max_args,omitempty"`
	MaxStdinBytes int64               `json:"max_stdin_bytes,omitempty"`
	Timeout       string              `json:"timeout,omitempty"`
	DetachTTL     string              `json:"detach_ttl,omitempty"`
	ReplayBytes   int                 `json:"replay_bytes,omitempty"`
	Recording     RecordingMode       `json:"recording,omitempty"`
}

type policyAction struct {
	policy  ActionPolicy
	timeout time.Duration
	ttl     time.Duration
}

type PolicyAuthorizer struct{ actions map[string]policyAction }

func ParsePolicy(data []byte) (Policy, error) {
	if len(data) == 0 || len(data) > MaxPolicyBytes {
		return Policy{}, errors.New("terminalsession: invalid policy size")
	}
	var policy Policy
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("terminalsession: decode policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Policy{}, errors.New("terminalsession: trailing policy data")
	}
	if policy.Version != PolicyVersion || strings.ToLower(strings.TrimSpace(policy.Default)) != "deny" || len(policy.Actions) == 0 {
		return Policy{}, errors.New("terminalsession: policy must be version weaverssh.terminal-policy.v1 with default deny and at least one action")
	}
	seen := make(map[string]bool, len(policy.Actions))
	for index := range policy.Actions {
		action := &policy.Actions[index]
		action.Name = strings.TrimSpace(action.Name)
		action.Executable = strings.TrimSpace(action.Executable)
		if !actionNamePattern.MatchString(action.Name) || seen[action.Name] || !path.IsAbs(action.Executable) || path.Clean(action.Executable) != action.Executable || action.Executable == "/" || strings.ContainsAny(action.Executable, "\\\x00\r\n") {
			return Policy{}, fmt.Errorf("terminalsession: invalid or duplicate action %q", action.Name)
		}
		seen[action.Name] = true
		if err := validatePolicyAction(*action); err != nil {
			return Policy{}, fmt.Errorf("terminalsession: action %s: %w", action.Name, err)
		}
	}
	return policy, nil
}

func LoadPolicyFile(path string) (Policy, error) {
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return Policy{}, err
	}
	return ParsePolicy(data)
}

func NewPolicyAuthorizer(policy Policy) (*PolicyAuthorizer, error) {
	canonical, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	normalized, err := ParsePolicy(canonical)
	if err != nil {
		return nil, err
	}
	authorizer := &PolicyAuthorizer{actions: make(map[string]policyAction, len(normalized.Actions))}
	for _, action := range normalized.Actions {
		timeout, _ := parsePolicyDuration(action.Timeout, 0, 24*time.Hour)
		ttl, _ := parsePolicyDuration(action.DetachTTL, defaultDetachTTL, maxDetachTTL)
		authorizer.actions[action.Name] = policyAction{policy: action, timeout: timeout, ttl: ttl}
	}
	return authorizer, nil
}

func (a *PolicyAuthorizer) AuthorizeOpen(_ context.Context, identity Identity, request OpenRequest) (Grant, error) {
	target, err := containerstream.ParseURI(request.TargetURI)
	if err != nil {
		return Grant{}, ErrDenied
	}
	process, action, err := a.authorizeProcess(identity, target, containerstream.StartRequest{
		Action: request.Action, Args: request.Args, Environment: request.Environment, TTY: true,
	}, request.Term)
	if err != nil {
		return Grant{}, err
	}
	return Grant{
		Process: process, DetachTTL: action.ttl,
		ReplayBytes: policyReplayBytes(action.policy), RecordingMode: policyRecording(action.policy),
	}, nil
}

// AuthorizeContainerProcess lets ProcessManager reuse the same final-node,
// named-action policy for streaming Exec RPC and ProcessFS. Authenticated
// provenance is supplied out-of-band by the broker and cannot be overridden by
// the start request.
func (a *PolicyAuthorizer) AuthorizeContainerProcess(_ context.Context, identity containerstream.ProcessIdentity, target containerstream.Request, request containerstream.StartRequest) (containerstream.ProcessSpec, error) {
	process, _, err := a.authorizeProcess(Identity{
		Principal: identity.Principal, SourceNode: identity.SourceNode,
		SourceBinding: identity.SourceBinding, ChainSHA256: identity.ChainSHA256,
	}, target, request, "")
	if err != nil {
		return containerstream.ProcessSpec{}, fmt.Errorf("%w: %v", containerstream.ErrProcessPermission, err)
	}
	return process, err
}

func (a *PolicyAuthorizer) authorizeProcess(identity Identity, target containerstream.Request, request containerstream.StartRequest, term string) (containerstream.ProcessSpec, policyAction, error) {
	if a == nil || identity.Validate() != nil {
		return containerstream.ProcessSpec{}, policyAction{}, ErrDenied
	}
	action, ok := a.actions[strings.TrimSpace(request.Action)]
	if !ok || !actionAllows(action.policy, identity, target) || len(request.Environment) != 0 {
		return containerstream.ProcessSpec{}, policyAction{}, ErrDenied
	}
	maxArgs := action.policy.MaxArgs
	if maxArgs == 0 {
		maxArgs = 16
	}
	if len(request.Args) > maxArgs || 1+len(action.policy.FixedArgs)+len(request.Args) > containerstream.MaxProcessArgs {
		return containerstream.ProcessSpec{}, policyAction{}, ErrDenied
	}
	for _, argument := range request.Args {
		if len(argument) > containerstream.MaxProcessArgument || strings.ContainsAny(argument, "\x00\r\n") {
			return containerstream.ProcessSpec{}, policyAction{}, ErrDenied
		}
	}
	environment := cloneEnvironment(action.policy.Environment)
	if term != "" {
		if !request.TTY || !termNamePattern.MatchString(term) {
			return containerstream.ProcessSpec{}, policyAction{}, ErrDenied
		}
		if _, fixed := environment["TERM"]; !fixed {
			if environment == nil {
				environment = make(map[string]string)
			}
			environment["TERM"] = term
		}
	}
	argv := append(append([]string(nil), action.policy.FixedArgs...), request.Args...)
	argv = append([]string{action.policy.Executable}, argv...)
	maxStdin := action.policy.MaxStdinBytes
	if maxStdin == 0 {
		maxStdin = defaultMaxStdin
	}
	return containerstream.ProcessSpec{
		Argv: argv, Environment: environment, TTY: request.TTY,
		Timeout: action.timeout, MaxStdinBytes: maxStdin,
	}, action, nil
}

func policyReplayBytes(action ActionPolicy) int {
	if action.ReplayBytes == 0 {
		return defaultReplayBytes
	}
	return action.ReplayBytes
}

func policyRecording(action ActionPolicy) RecordingMode {
	if action.Recording == "" {
		return RecordingOff
	}
	return action.Recording
}

func (a *PolicyAuthorizer) AuthorizeReattach(_ context.Context, identity Identity, snapshot Snapshot) error {
	if a == nil {
		return ErrDenied
	}
	action, ok := a.actions[snapshot.Action]
	if !ok {
		return ErrDenied
	}
	target, err := containerstream.ParseURI(snapshot.TargetURI)
	if err != nil || !actionAllows(action.policy, identity, target) {
		return ErrDenied
	}
	return nil
}

func validatePolicyAction(action ActionPolicy) error {
	if len(action.Executable) > containerstream.MaxProcessArgument {
		return errors.New("executable is too long")
	}
	if len(action.FixedArgs) > containerstream.MaxProcessArgs-1 {
		return errors.New("too many fixed arguments")
	}
	for _, argument := range action.FixedArgs {
		if len(argument) > containerstream.MaxProcessArgument || strings.ContainsAny(argument, "\x00\r\n") {
			return errors.New("invalid fixed argument")
		}
	}
	if len(action.Principals) == 0 || len(action.Sources) == 0 || len(action.Endpoints) == 0 || len(action.Targets) == 0 || len(action.Providers) == 0 {
		return errors.New("principals, sources, endpoints, targets, and providers are required")
	}
	for label, values := range map[string][]string{
		"principals": action.Principals, "sources": action.Sources, "endpoints": action.Endpoints,
		"targets": action.Targets, "providers": action.Providers,
	} {
		if err := validatePolicyValues(label, values); err != nil {
			return err
		}
	}
	if action.MaxArgs < 0 || action.MaxArgs > containerstream.MaxProcessArgs-1 || action.MaxStdinBytes < 0 || action.MaxStdinBytes > containerstream.MaxProcessStdin {
		return errors.New("invalid argument or stdin limit")
	}
	if action.ReplayBytes < 0 || action.ReplayBytes > maxReplayBytes {
		return errors.New("invalid replay limit")
	}
	if action.Recording != "" && action.Recording != RecordingOff && action.Recording != RecordingBestEffort && action.Recording != RecordingRequired {
		return errors.New("invalid recording mode")
	}
	if _, err := parsePolicyDuration(action.Timeout, 0, 24*time.Hour); err != nil {
		return fmt.Errorf("invalid timeout: %w", err)
	}
	if _, err := parsePolicyDuration(action.DetachTTL, defaultDetachTTL, maxDetachTTL); err != nil {
		return fmt.Errorf("invalid detach TTL: %w", err)
	}
	if len(action.Environment) > 64 {
		return errors.New("too many environment entries")
	}
	totalEnvironment := 0
	for name, value := range action.Environment {
		if !safeEnvironmentName(name) || strings.ContainsAny(value, "\x00\r\n") || credentialEnvironmentName(name) {
			return fmt.Errorf("invalid environment entry %q", name)
		}
		totalEnvironment += len(name) + len(value) + 1
	}
	if totalEnvironment > containerstream.MaxProcessEnvironment {
		return errors.New("environment is too large")
	}
	for name, values := range action.Options {
		if !safeOptionName(name) || len(values) == 0 {
			return fmt.Errorf("invalid option policy %q", name)
		}
		if err := validatePolicyValues("option "+name, values); err != nil {
			return err
		}
	}
	return nil
}

func actionAllows(action ActionPolicy, identity Identity, target containerstream.Request) bool {
	if !matchesPolicyValue(action.Principals, identity.Principal) || !matchesPolicyValue(action.Sources, identity.SourceNode) ||
		!matchesPolicyValue(action.Endpoints, target.Endpoint) || !matchesPolicyValue(action.Targets, target.TargetID) {
		return false
	}
	provider := target.ProviderHint
	if provider == "" {
		provider = "auto"
	}
	if !matchesPolicyValue(action.Providers, provider) {
		return false
	}
	for name, value := range target.Options {
		allowed, ok := action.Options[name]
		if !ok || !matchesPolicyValue(allowed, value) {
			return false
		}
	}
	return true
}

func validatePolicyValues(label string, values []string) error {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") || seen[value] {
			return fmt.Errorf("invalid or duplicate %s value", label)
		}
		seen[value] = true
	}
	return nil
}

func matchesPolicyValue(values []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, value := range values {
		if value == "*" || strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func parsePolicyDuration(raw string, defaultValue, maximum time.Duration) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return defaultValue, nil
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || parsed <= 0 || parsed > maximum {
		return 0, errors.New("duration is outside the allowed range")
	}
	return parsed, nil
}

func cloneEnvironment(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for name, value := range input {
		out[name] = value
	}
	return out
}

func safeEnvironmentName(name string) bool {
	if name == "" || (name[0] != '_' && (name[0] < 'A' || name[0] > 'Z') && (name[0] < 'a' || name[0] > 'z')) {
		return false
	}
	for _, character := range name[1:] {
		if character != '_' && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func credentialEnvironmentName(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	return upper == "SSH_AUTH_SOCK" || upper == "GPG_AGENT_INFO" || strings.Contains(upper, "TOKEN") ||
		strings.Contains(upper, "SECRET") || strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "CREDENTIAL") || strings.Contains(upper, "PRIVATE_KEY")
}

func safeOptionName(name string) bool {
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, character := range name[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

// SortedActionNames exposes only policy identifiers for status/reporting.
func (a *PolicyAuthorizer) SortedActionNames() []string {
	if a == nil {
		return nil
	}
	out := make([]string, 0, len(a.actions))
	for name := range a.actions {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
