package rules

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	PipelineVersion         = "weaverssh.rules.pipeline.v1"
	DefaultSystemRulesDir   = "/etc/weaverssh/rules.d"
	DefaultSystemRulesFile  = "/etc/weaverssh/rules.json"
	DefaultUserRulesDir     = ".config/weaverssh/rules.d"
	DefaultNodeRulesDir     = "/etc/weaverssh/nodes/{node}/rules.d"
	DefaultNodeRulesFile    = "/etc/weaverssh/nodes/{node}/rules.json"
	DefaultUserNodeRulesDir = ".config/weaverssh/nodes/{node}/rules.d"
)

type StageConfig struct {
	Name          string   `json:"name"`
	Required      bool     `json:"required,omitempty"`
	TerminalDeny  *bool    `json:"terminal_deny,omitempty"`
	TerminalAllow *bool    `json:"terminal_allow,omitempty"`
	Paths         []string `json:"paths,omitempty"`
}

type PipelineConfig struct {
	Version string        `json:"version"`
	NodeID  string        `json:"node_id,omitempty"`
	Stages  []StageConfig `json:"stages"`
}

type RuleSetSource struct {
	Stage   string  `json:"stage"`
	Path    string  `json:"path"`
	RuleSet RuleSet `json:"-"`
}

type StageDecision struct {
	Stage    string   `json:"stage"`
	Path     string   `json:"path,omitempty"`
	Required bool     `json:"required,omitempty"`
	Skipped  bool     `json:"skipped,omitempty"`
	Decision Decision `json:"decision,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

type PipelineDecision struct {
	Version string            `json:"version"`
	Allowed bool              `json:"allowed"`
	Action  Action            `json:"action"`
	Reason  string            `json:"reason,omitempty"`
	Topic   string            `json:"topic,omitempty"`
	Fields  map[string]string `json:"fields,omitempty"`
	Stages  []StageDecision   `json:"stages"`
	Final   Decision          `json:"final"`
}

func DefaultPipelineConfig() PipelineConfig {
	return PipelineConfig{
		Version: PipelineVersion,
		Stages: []StageConfig{
			{Name: "system", Paths: []string{filepath.Join(DefaultSystemRulesDir, "*.json"), DefaultSystemRulesFile}, TerminalDeny: boolPtr(true)},
			{Name: "user", Paths: []string{filepath.Join("~", DefaultUserRulesDir, "*.json")}, TerminalDeny: boolPtr(true)},
		},
	}
}

func DefaultRemoteNodePipelineConfig(nodeID string) (PipelineConfig, error) {
	nodeID, err := CleanNodeID(nodeID)
	if err != nil {
		return PipelineConfig{}, err
	}
	return PipelineConfig{
		Version: PipelineVersion,
		NodeID:  nodeID,
		Stages: []StageConfig{
			{Name: "system", Paths: []string{filepath.Join(DefaultSystemRulesDir, "*.json"), DefaultSystemRulesFile}, TerminalDeny: boolPtr(true)},
			{Name: "remote-node", Paths: []string{filepath.Join(DefaultNodeRulesDir, "*.json"), DefaultNodeRulesFile}, TerminalDeny: boolPtr(true)},
			{Name: "user-node", Paths: []string{filepath.Join("~", DefaultUserNodeRulesDir, "*.json")}, TerminalDeny: boolPtr(true)},
			{Name: "user", Paths: []string{filepath.Join("~", DefaultUserRulesDir, "*.json")}, TerminalDeny: boolPtr(true)},
		},
	}, nil
}

func LoadPipeline(r io.Reader) (PipelineConfig, error) {
	var cfg PipelineConfig
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return PipelineConfig{}, err
	}
	return cfg.Normalize()
}

func LoadPipelineFile(path string) (PipelineConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return PipelineConfig{}, err
	}
	defer f.Close()
	return LoadPipeline(f)
}

func (cfg PipelineConfig) Normalize() (PipelineConfig, error) {
	cfg.Version = strings.TrimSpace(cfg.Version)
	if cfg.Version == "" {
		cfg.Version = PipelineVersion
	}
	if cfg.Version != PipelineVersion {
		return cfg, fmt.Errorf("unsupported pipeline version %q", cfg.Version)
	}
	if strings.TrimSpace(cfg.NodeID) != "" {
		nodeID, err := CleanNodeID(cfg.NodeID)
		if err != nil {
			return cfg, err
		}
		cfg.NodeID = nodeID
	}
	if len(cfg.Stages) == 0 {
		cfg = DefaultPipelineConfig()
	}
	for i := range cfg.Stages {
		cfg.Stages[i].Name = strings.TrimSpace(cfg.Stages[i].Name)
		if cfg.Stages[i].Name == "" {
			return cfg, fmt.Errorf("stage %d name is required", i)
		}
		cfg.Stages[i].Paths = cleanList(cfg.Stages[i].Paths)
		if len(cfg.Stages[i].Paths) == 0 && cfg.Stages[i].Required {
			return cfg, fmt.Errorf("required stage %q has no paths", cfg.Stages[i].Name)
		}
	}
	return cfg, nil
}

func (cfg PipelineConfig) LoadRuleSets() ([]RuleSetSource, []StageDecision, error) {
	cfg, err := cfg.Normalize()
	if err != nil {
		return nil, nil, err
	}
	var sources []RuleSetSource
	var skipped []StageDecision
	for _, stage := range cfg.Stages {
		paths, err := resolveRulePaths(stage.Paths, cfg.NodeID)
		if err != nil {
			return nil, nil, fmt.Errorf("stage %q: %w", stage.Name, err)
		}
		if len(paths) == 0 {
			msg := "no rule files found"
			if stage.Required {
				return nil, nil, fmt.Errorf("stage %q required but %s", stage.Name, msg)
			}
			skipped = append(skipped, StageDecision{Stage: stage.Name, Required: stage.Required, Skipped: true, Reason: msg})
			continue
		}
		for _, path := range paths {
			if err := validatePolicyFile(path); err != nil {
				return nil, nil, fmt.Errorf("stage %q file %s: %w", stage.Name, path, err)
			}
			rs, err := LoadFile(path)
			if err != nil {
				return nil, nil, fmt.Errorf("stage %q file %s: %w", stage.Name, path, err)
			}
			sources = append(sources, RuleSetSource{Stage: stage.Name, Path: path, RuleSet: rs})
		}
	}
	return sources, skipped, nil
}

func (cfg PipelineConfig) Evaluate(input Input) (PipelineDecision, error) {
	cfg, err := cfg.Normalize()
	if err != nil {
		return PipelineDecision{}, err
	}
	input = inputWithNodeFacts(input, cfg.NodeID)
	input = input.Normalized()
	decision := PipelineDecision{Version: PipelineVersion, Topic: input.Topic, Fields: copyMap(input.Facts)}
	var evaluated bool
	for _, stage := range cfg.Stages {
		paths, err := resolveRulePaths(stage.Paths, cfg.NodeID)
		if err != nil {
			return decision, fmt.Errorf("stage %q: %w", stage.Name, err)
		}
		if len(paths) == 0 {
			msg := "no rule files found"
			if stage.Required {
				return decision, fmt.Errorf("stage %q required but %s", stage.Name, msg)
			}
			decision.Stages = append(decision.Stages, StageDecision{Stage: stage.Name, Required: stage.Required, Skipped: true, Reason: msg})
			continue
		}
		for _, path := range paths {
			if err := validatePolicyFile(path); err != nil {
				return decision, fmt.Errorf("stage %q file %s: %w", stage.Name, path, err)
			}
			rs, err := LoadFile(path)
			if err != nil {
				return decision, fmt.Errorf("stage %q file %s: %w", stage.Name, path, err)
			}
			d, err := rs.Evaluate(input)
			if err != nil {
				return decision, fmt.Errorf("stage %q file %s: %w", stage.Name, path, err)
			}
			evaluated = true
			decision.Stages = append(decision.Stages, StageDecision{Stage: stage.Name, Path: path, Required: stage.Required, Decision: d})
			input = inputAfterDecision(input, d)
			decision.Final = d
			decision.Allowed = d.Allowed
			decision.Action = d.Action
			decision.Reason = d.Reason
			decision.Topic = input.Topic
			decision.Fields = copyMap(input.Facts)
			if stageStops(stage, d) {
				return decision, nil
			}
		}
	}
	if !evaluated {
		final := Decision{Version: EngineVersion, Action: ActionDeny, Allowed: false, Reason: "no pipeline rules evaluated", Topic: input.Topic, Fields: copyMap(input.Facts)}
		decision.Final = final
		decision.Allowed = false
		decision.Action = ActionDeny
		decision.Reason = final.Reason
		decision.Topic = input.Topic
		decision.Fields = copyMap(input.Facts)
	}
	return decision, nil
}

func (cfg PipelineConfig) EvaluateNode(nodeID string, input Input) (PipelineDecision, error) {
	nodeID, err := CleanNodeID(nodeID)
	if err != nil {
		return PipelineDecision{}, err
	}
	cfg.NodeID = nodeID
	return cfg.Evaluate(inputWithNodeFacts(input, nodeID))
}

func (a *API) EvaluatePipeline(cfg PipelineConfig, input Input) (PipelineDecision, error) {
	return cfg.Evaluate(input)
}

func (a *API) LoadPipelineFile(path string) (PipelineConfig, error) {
	return LoadPipelineFile(path)
}

func inputAfterDecision(input Input, d Decision) Input {
	topic := d.Topic
	if strings.TrimSpace(topic) == "" {
		topic = input.Topic
	}
	facts := copyMap(input.Facts)
	for k, v := range d.Fields {
		if facts == nil {
			facts = map[string]string{}
		}
		facts[k] = v
	}
	for k, v := range d.SetFields {
		if facts == nil {
			facts = map[string]string{}
		}
		facts[k] = v
	}
	if topic != "" {
		if facts == nil {
			facts = map[string]string{}
		}
		facts["topic"] = topic
	}
	return NewInput(topic, facts)
}

func stageStops(stage StageConfig, d Decision) bool {
	switch d.Action {
	case ActionDeny, ActionDrop:
		return boolValue(stage.TerminalDeny, true)
	case ActionAllow:
		return boolValue(stage.TerminalAllow, false)
	default:
		return false
	}
}

func resolveRulePaths(patterns []string, nodeID string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, pattern := range patterns {
		pattern = expandRulePathForNode(pattern, nodeID)
		pattern = expandRulePath(pattern)
		if pattern == "" {
			continue
		}
		matches, err := resolveOneRulePath(pattern)
		if err != nil {
			return nil, err
		}
		for _, path := range matches {
			clean := filepath.Clean(path)
			if !seen[clean] {
				seen[clean] = true
				out = append(out, clean)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func resolveOneRulePath(pattern string) ([]string, error) {
	if strings.ContainsAny(pattern, "*?[") {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		sort.Strings(matches)
		return existingFiles(matches), nil
	}
	info, err := os.Stat(pattern)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		matches, err := filepath.Glob(filepath.Join(pattern, "*.json"))
		if err != nil {
			return nil, err
		}
		sort.Strings(matches)
		return existingFiles(matches), nil
	}
	return []string{pattern}, nil
}

func existingFiles(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			out = append(out, path)
		}
	}
	return out
}

func expandRulePath(pattern string) string {
	pattern = strings.TrimSpace(os.ExpandEnv(pattern))
	if pattern == "" {
		return ""
	}
	if pattern == "~" || strings.HasPrefix(pattern, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if pattern == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(pattern, "~/"))
		}
	}
	return filepath.Clean(pattern)
}

func expandRulePathForNode(pattern, nodeID string) string {
	pattern = strings.ReplaceAll(pattern, "{node}", nodeID)
	pattern = strings.ReplaceAll(pattern, "${node}", nodeID)
	pattern = strings.ReplaceAll(pattern, "${WEAVERSSH_NODE_ID}", nodeID)
	return pattern
}

func validatePolicyFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("policy file symlinks are rejected")
	}
	if !isDefaultSystemPolicyPath(path) {
		return nil
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("system policy file must not be group/world writable")
	}
	if ok, known := systemPolicyOwnerOK(info); known && !ok {
		return fmt.Errorf("system policy file must be owned by root/admin")
	}
	return nil
}

func isDefaultSystemPolicyPath(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	clean := filepath.Clean(abs)
	for _, root := range []string{"/etc/weaverssh", "/Library/Application Support/weaverssh"} {
		root = filepath.Clean(root)
		if clean == root || strings.HasPrefix(clean, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func CleanNodeID(nodeID string) (string, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return "", fmt.Errorf("node id is required")
	}
	if nodeID == "." || nodeID == ".." || strings.Contains(nodeID, "/") || strings.Contains(nodeID, "\\") {
		return "", fmt.Errorf("node id %q is not path-safe", nodeID)
	}
	for _, r := range nodeID {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return "", fmt.Errorf("node id %q contains unsupported character %q", nodeID, r)
		}
	}
	return nodeID, nil
}

func inputWithNodeFacts(input Input, nodeID string) Input {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return input
	}
	facts := copyMap(input.Facts)
	if facts == nil {
		facts = map[string]string{}
	}
	facts["node.id"] = nodeID
	facts["remote.node_id"] = nodeID
	facts["api.node_id"] = nodeID
	return NewInput(input.Topic, facts)
}

func boolPtr(v bool) *bool { return &v }

func boolValue(v *bool, fallback bool) bool {
	if v == nil {
		return fallback
	}
	return *v
}
