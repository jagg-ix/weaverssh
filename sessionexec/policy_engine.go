package sessionexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	ProtocolVersion      = "weaverssh.exec.v1"
	OpenProtocolVersion  = "weaverssh.exec-open.v1"
	PolicyVersion        = "weaverssh.exec-policy.v1"
	MaxOpenMetadataBytes = 4096
	MaxMessageBytes      = 16 << 20
	MaxArgs              = 64
	MaxArgBytes          = 4096
	MaxInputBytes        = 4 << 20
	MaxOutputBytes       = 8 << 20
)

var (
	ErrInvalidRequest = errors.New("sessionexec: invalid request")
	ErrDenied         = errors.New("sessionexec: denied")
	ErrActionNotFound = errors.New("sessionexec: action not found")
	ErrLimitExceeded  = errors.New("sessionexec: limit exceeded")
)

type OpenMetadata struct {
	Protocol      string `json:"protocol"`
	TargetNode    string `json:"target_node"`
	SourceNode    string `json:"source_node,omitempty"`
	SourceBinding string `json:"source_binding,omitempty"`
	ChainSHA256   string `json:"chain_sha256,omitempty"`
}

type Request struct {
	Protocol      string   `json:"protocol"`
	ID            string   `json:"id"`
	Action        string   `json:"action"`
	Args          []string `json:"args,omitempty"`
	Stdin         []byte   `json:"stdin,omitempty"`
	TimeoutMillis int64    `json:"timeout_millis,omitempty"`
}

type ResponseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type Response struct {
	Protocol        string         `json:"protocol"`
	ID              string         `json:"id"`
	ExitCode        int            `json:"exit_code"`
	Stdout          []byte         `json:"stdout,omitempty"`
	Stderr          []byte         `json:"stderr,omitempty"`
	StdoutTruncated bool           `json:"stdout_truncated,omitempty"`
	StderrTruncated bool           `json:"stderr_truncated,omitempty"`
	Error           *ResponseError `json:"error,omitempty"`
}

type Policy struct {
	Version string         `json:"version"`
	Default string         `json:"default"`
	Actions []ActionPolicy `json:"actions"`
}

type ActionPolicy struct {
	Name           string            `json:"name"`
	Executable     string            `json:"executable"`
	FixedArgs      []string          `json:"fixed_args,omitempty"`
	WorkDir        string            `json:"workdir,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	Sources        []string          `json:"sources"`
	Timeout        string            `json:"timeout,omitempty"`
	MaxParallel    int               `json:"max_parallel,omitempty"`
	MaxArgs        int               `json:"max_args,omitempty"`
	MaxStdinBytes  int               `json:"max_stdin_bytes,omitempty"`
	MaxStdoutBytes int               `json:"max_stdout_bytes,omitempty"`
	MaxStderrBytes int               `json:"max_stderr_bytes,omitempty"`
}

type actionRuntime struct {
	policy  ActionPolicy
	timeout time.Duration
	sem     chan struct{}
}
type Engine struct {
	topology    []string
	chainSHA256 string
	currentNode string
	actions     map[string]*actionRuntime
}

type EngineConfig struct {
	Topology    []string
	ChainSHA256 string
	CurrentNode string
	Policy      Policy
}

func ParsePolicy(data []byte) (Policy, error) {
	var p Policy
	if err := decodeStrict(data, &p); err != nil {
		return Policy{}, err
	}
	if p.Version != PolicyVersion || strings.ToLower(strings.TrimSpace(p.Default)) != "deny" {
		return Policy{}, errors.New("sessionexec: policy must use version weaverssh.exec-policy.v1 and default deny")
	}
	if len(p.Actions) == 0 {
		return Policy{}, errors.New("sessionexec: policy has no actions")
	}
	seen := map[string]bool{}
	for i := range p.Actions {
		a := &p.Actions[i]
		a.Name = strings.TrimSpace(a.Name)
		a.Executable = strings.TrimSpace(a.Executable)
		a.WorkDir = strings.TrimSpace(a.WorkDir)
		if !validName(a.Name) || seen[a.Name] {
			return Policy{}, fmt.Errorf("sessionexec: invalid or duplicate action %q", a.Name)
		}
		seen[a.Name] = true
		if !filepath.IsAbs(a.Executable) {
			return Policy{}, fmt.Errorf("sessionexec: action %s executable must be absolute", a.Name)
		}
		if a.WorkDir != "" && !filepath.IsAbs(a.WorkDir) {
			return Policy{}, fmt.Errorf("sessionexec: action %s workdir must be absolute", a.Name)
		}
		if len(a.Sources) == 0 {
			return Policy{}, fmt.Errorf("sessionexec: action %s has no sources", a.Name)
		}
		for _, source := range a.Sources {
			if !validName(source) && source != "*" {
				return Policy{}, fmt.Errorf("sessionexec: action %s has invalid source %q", a.Name, source)
			}
		}
		if len(a.FixedArgs) > MaxArgs {
			return Policy{}, fmt.Errorf("sessionexec: action %s has too many fixed args", a.Name)
		}
		for _, arg := range a.FixedArgs {
			if len(arg) > MaxArgBytes || strings.IndexByte(arg, 0) >= 0 {
				return Policy{}, fmt.Errorf("sessionexec: action %s has invalid fixed arg", a.Name)
			}
		}
		for key, value := range a.Env {
			if !validEnvKey(key) || strings.IndexByte(value, 0) >= 0 || len(value) > 32<<10 {
				return Policy{}, fmt.Errorf("sessionexec: action %s has invalid environment", a.Name)
			}
			upper := strings.ToUpper(key)
			if upper == "SSH_AUTH_SOCK" || upper == "GPG_AGENT_INFO" || strings.Contains(upper, "TOKEN") || strings.Contains(upper, "SECRET") || strings.Contains(upper, "PASSWORD") {
				return Policy{}, fmt.Errorf("sessionexec: action %s environment key %s is credential-like", a.Name, key)
			}
		}
		if _, _, _, _, _, _, err := limits(*a); err != nil {
			return Policy{}, err
		}
	}
	return p, nil
}

func LoadPolicyFile(path string) (Policy, error) {
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return Policy{}, err
	}
	return ParsePolicy(data)
}

func NewEngine(config EngineConfig) (*Engine, error) {
	chain := strings.ToLower(strings.TrimSpace(config.ChainSHA256))
	current := strings.TrimSpace(config.CurrentNode)
	if len(chain) != 64 || indexOf(config.Topology, current) < 0 {
		return nil, errors.New("sessionexec: invalid topology")
	}
	e := &Engine{topology: append([]string(nil), config.Topology...), chainSHA256: chain, currentNode: current, actions: map[string]*actionRuntime{}}
	for _, action := range config.Policy.Actions {
		timeout, maxParallel, _, _, _, _, err := limits(action)
		if err != nil {
			return nil, err
		}
		e.actions[action.Name] = &actionRuntime{policy: action, timeout: timeout, sem: make(chan struct{}, maxParallel)}
	}
	return e, nil
}

func limits(a ActionPolicy) (time.Duration, int, int, int, int, int, error) {
	timeout := 30 * time.Second
	if strings.TrimSpace(a.Timeout) != "" {
		parsed, err := time.ParseDuration(a.Timeout)
		if err != nil || parsed <= 0 || parsed > 24*time.Hour {
			return 0, 0, 0, 0, 0, 0, fmt.Errorf("sessionexec: action %s has invalid timeout", a.Name)
		}
		timeout = parsed
	}
	maxParallel := a.MaxParallel
	if maxParallel == 0 {
		maxParallel = 4
	}
	if maxParallel < 1 || maxParallel > 1024 {
		return 0, 0, 0, 0, 0, 0, fmt.Errorf("sessionexec: action %s has invalid max_parallel", a.Name)
	}
	maxArgs := a.MaxArgs
	if maxArgs == 0 {
		maxArgs = 16
	}
	if maxArgs < 0 || maxArgs > MaxArgs {
		return 0, 0, 0, 0, 0, 0, fmt.Errorf("sessionexec: action %s has invalid max_args", a.Name)
	}
	maxIn := a.MaxStdinBytes
	if maxIn == 0 {
		maxIn = 1 << 20
	}
	if maxIn < 0 || maxIn > MaxInputBytes {
		return 0, 0, 0, 0, 0, 0, fmt.Errorf("sessionexec: action %s has invalid stdin limit", a.Name)
	}
	maxOut := a.MaxStdoutBytes
	if maxOut == 0 {
		maxOut = 1 << 20
	}
	if maxOut < 1 || maxOut > MaxOutputBytes {
		return 0, 0, 0, 0, 0, 0, fmt.Errorf("sessionexec: action %s has invalid stdout limit", a.Name)
	}
	maxErr := a.MaxStderrBytes
	if maxErr == 0 {
		maxErr = 256 << 10
	}
	if maxErr < 1 || maxErr > MaxOutputBytes {
		return 0, 0, 0, 0, 0, 0, fmt.Errorf("sessionexec: action %s has invalid stderr limit", a.Name)
	}
	return timeout, maxParallel, maxArgs, maxIn, maxOut, maxErr, nil
}

func NewOpenMetadata(target string) ([]byte, error) {
	m := OpenMetadata{Protocol: OpenProtocolVersion, TargetNode: strings.TrimSpace(target)}
	if !validName(m.TargetNode) {
		return nil, errors.New("sessionexec: invalid target")
	}
	return json.Marshal(m)
}
func ParseOpenMetadata(raw []byte) (OpenMetadata, error) {
	if len(raw) == 0 || len(raw) > MaxOpenMetadataBytes {
		return OpenMetadata{}, errors.New("sessionexec: invalid open metadata size")
	}
	var m OpenMetadata
	if err := decodeStrict(raw, &m); err != nil {
		return OpenMetadata{}, err
	}
	m.Protocol = strings.TrimSpace(m.Protocol)
	m.TargetNode = strings.TrimSpace(m.TargetNode)
	m.SourceNode = strings.TrimSpace(m.SourceNode)
	m.SourceBinding = strings.TrimSpace(m.SourceBinding)
	m.ChainSHA256 = strings.ToLower(strings.TrimSpace(m.ChainSHA256))
	if m.Protocol != OpenProtocolVersion || !validName(m.TargetNode) {
		return OpenMetadata{}, errors.New("sessionexec: invalid open metadata")
	}
	return m, nil
}
func IsOpenMetadata(raw []byte) bool {
	m, err := ParseOpenMetadata(raw)
	return err == nil && m.Protocol == OpenProtocolVersion
}
func BindSource(raw []byte, source, binding, chain, target string) ([]byte, error) {
	m, err := ParseOpenMetadata(raw)
	if err != nil {
		return nil, err
	}
	chain = strings.ToLower(strings.TrimSpace(chain))
	if m.SourceNode == "" && m.SourceBinding == "" && m.ChainSHA256 == "" {
		m.SourceNode = strings.TrimSpace(source)
		m.SourceBinding = strings.TrimSpace(binding)
		m.ChainSHA256 = chain
	} else if m.ChainSHA256 != chain {
		return nil, errors.New("sessionexec: forwarded provenance chain mismatch")
	}
	m.TargetNode = strings.TrimSpace(target)
	if !validName(m.SourceNode) || !validName(m.TargetNode) || m.SourceBinding == "" || len(m.SourceBinding) > 512 || len(m.ChainSHA256) != 64 {
		return nil, errors.New("sessionexec: invalid broker provenance")
	}
	return json.Marshal(m)
}

func (e *Engine) Execute(ctx context.Context, metadata OpenMetadata, req Request) (Response, error) {
	if e == nil {
		return Response{}, errors.New("sessionexec: nil engine")
	}
	if metadata.TargetNode != e.currentNode || metadata.ChainSHA256 != e.chainSHA256 || indexOf(e.topology, metadata.SourceNode) < 0 {
		return Response{}, ErrDenied
	}
	req = normalizeRequest(req)
	if err := validateRequest(req); err != nil {
		return Response{}, err
	}
	runtime, ok := e.actions[req.Action]
	if !ok {
		return Response{}, ErrActionNotFound
	}
	if !sourceAllowed(runtime.policy.Sources, metadata.SourceNode) {
		return Response{}, ErrDenied
	}
	timeout, _, maxArgs, maxIn, maxOut, maxErr, _ := limits(runtime.policy)
	if len(req.Args) > maxArgs || len(req.Stdin) > maxIn {
		return Response{}, ErrLimitExceeded
	}
	for _, arg := range req.Args {
		if len(arg) > MaxArgBytes || strings.IndexByte(arg, 0) >= 0 {
			return Response{}, ErrInvalidRequest
		}
	}
	if req.TimeoutMillis > 0 {
		requested := time.Duration(req.TimeoutMillis) * time.Millisecond
		if requested < timeout {
			timeout = requested
		}
	}
	select {
	case runtime.sem <- struct{}{}:
		defer func() { <-runtime.sem }()
	case <-ctx.Done():
		return Response{}, ctx.Err()
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	argv := append(append([]string(nil), runtime.policy.FixedArgs...), req.Args...)
	cmd := exec.CommandContext(runCtx, runtime.policy.Executable, argv...)
	cmd.Dir = runtime.policy.WorkDir
	cmd.Env = explicitEnv(runtime.policy.Env)
	cmd.Stdin = bytes.NewReader(req.Stdin)
	stdout := &cappedBuffer{max: maxOut}
	stderr := &cappedBuffer{max: maxErr}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		exitCode = -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		}
	}
	response := Response{Protocol: ProtocolVersion, ID: req.ID, ExitCode: exitCode, Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), StdoutTruncated: stdout.truncated, StderrTruncated: stderr.truncated}
	if runCtx.Err() != nil {
		return response, runCtx.Err()
	}
	if stdout.truncated || stderr.truncated {
		return response, ErrLimitExceeded
	}
	if err != nil {
		return response, fmt.Errorf("sessionexec: command exited %d", exitCode)
	}
	return response, nil
}
