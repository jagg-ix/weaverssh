package rules

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

const DefaultRuleSetName = "default"

var (
	ErrRuleSetNotFound      = errors.New("ruleset not found")
	ErrRuleSetAlreadyExists = errors.New("ruleset already exists")
)

type APIConfig struct {
	DefaultName string             `json:"default_name,omitempty"`
	RuleSets    map[string]RuleSet `json:"rulesets,omitempty"`
}

type API struct {
	mu          sync.RWMutex
	defaultName string
	rulesets    map[string]RuleSet
}

type Contract struct {
	Version       string   `json:"version"`
	DefaultName   string   `json:"default_name"`
	DefaultAction Action   `json:"default_action"`
	Evaluation    string   `json:"evaluation"`
	Actions       []string `json:"actions"`
	Operators     []string `json:"operators"`
	InputFacts    []string `json:"input_facts"`
	Safety        []string `json:"safety"`
}

func NewAPI(cfg APIConfig) (*API, error) {
	defaultName := cleanRuleSetName(cfg.DefaultName)
	if defaultName == "" {
		defaultName = DefaultRuleSetName
	}
	api := &API{defaultName: defaultName, rulesets: map[string]RuleSet{}}
	for name, rs := range cfg.RuleSets {
		if err := api.Put(name, rs); err != nil {
			return nil, err
		}
	}
	return api, nil
}

func MustNewAPI(cfg APIConfig) *API {
	api, err := NewAPI(cfg)
	if err != nil {
		panic(err)
	}
	return api
}

func (a *API) DefaultName() string {
	if a == nil {
		return DefaultRuleSetName
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.defaultName == "" {
		return DefaultRuleSetName
	}
	return a.defaultName
}

func (a *API) SetDefaultName(name string) error {
	if a == nil {
		return fmt.Errorf("rules API is nil")
	}
	name = cleanRuleSetName(name)
	if name == "" {
		return fmt.Errorf("default ruleset name is required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.rulesets[name]; !ok {
		return fmt.Errorf("%w: %s", ErrRuleSetNotFound, name)
	}
	a.defaultName = name
	return nil
}

func (a *API) Register(name string, rs RuleSet) error {
	if a == nil {
		return fmt.Errorf("rules API is nil")
	}
	name = cleanRuleSetName(name)
	if name == "" {
		name = a.DefaultName()
	}
	normalized, err := rs.Normalize()
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.rulesets[name]; exists {
		return fmt.Errorf("%w: %s", ErrRuleSetAlreadyExists, name)
	}
	a.rulesets[name] = cloneRuleSet(normalized)
	return nil
}

func (a *API) Put(name string, rs RuleSet) error {
	if a == nil {
		return fmt.Errorf("rules API is nil")
	}
	name = cleanRuleSetName(name)
	if name == "" {
		name = a.DefaultName()
	}
	normalized, err := rs.Normalize()
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rulesets[name] = cloneRuleSet(normalized)
	return nil
}

func (a *API) Load(name string, r io.Reader) error {
	rs, err := Load(r)
	if err != nil {
		return err
	}
	return a.Put(name, rs)
}

func (a *API) LoadFile(name string, path string) error {
	rs, err := LoadFile(path)
	if err != nil {
		return err
	}
	return a.Put(name, rs)
}

func (a *API) RuleSet(name string) (RuleSet, bool) {
	if a == nil {
		return RuleSet{}, false
	}
	name = cleanRuleSetName(name)
	if name == "" {
		name = a.DefaultName()
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	rs, ok := a.rulesets[name]
	if !ok {
		return RuleSet{}, false
	}
	return cloneRuleSet(rs), true
}

func (a *API) Names() []string {
	if a == nil {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	names := make([]string, 0, len(a.rulesets))
	for name := range a.rulesets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (a *API) Remove(name string) bool {
	if a == nil {
		return false
	}
	name = cleanRuleSetName(name)
	if name == "" {
		name = a.DefaultName()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.rulesets[name]; !ok {
		return false
	}
	delete(a.rulesets, name)
	return true
}

func (a *API) Evaluate(input Input) (Decision, error) {
	return a.EvaluateNamed("", input)
}

func (a *API) EvaluateNamed(name string, input Input) (Decision, error) {
	if a == nil {
		return Decision{}, fmt.Errorf("rules API is nil")
	}
	name = cleanRuleSetName(name)
	if name == "" {
		name = a.DefaultName()
	}
	a.mu.RLock()
	rs, ok := a.rulesets[name]
	a.mu.RUnlock()
	if !ok {
		return Decision{}, fmt.Errorf("%w: %s", ErrRuleSetNotFound, name)
	}
	return rs.Evaluate(input)
}

func (a *API) Contract() Contract {
	defaultName := DefaultRuleSetName
	if a != nil {
		defaultName = a.DefaultName()
	}
	return Contract{
		Version:       EngineVersion,
		DefaultName:   defaultName,
		DefaultAction: ActionDeny,
		Evaluation:    "ordered first-match",
		Actions:       SortedActionStrings(),
		Operators:     SortedOperatorStrings(),
		InputFacts: []string{
			"topic", "hook.point", "event.id", "event.type", "event.component", "event.origin", "event.message", "event.version", "event.at", "field.<name>", "fields.<name>", "<name>",
			"infra.kind", "infra.operation", "infra.path", "infra.view_path", "infra.component", "infra.origin", "infra.protocol", "infra.status", "infra.bytes", "infra.files", "infra.is_dir",
			"file.operation", "file.path", "file.view_path", "file.protocol", "file.status", "file.bytes", "file.files", "file.is_dir",
		},
		Safety: []string{
			"rulesets are deterministic and evaluated in JSON order",
			"a ruleset defaults to deny when no rule matches unless default_action is explicitly changed",
			"runtime adapters must opt in by registering the ruleset as hooks; MQTT never loads executable code",
		},
	}
}

func cleanRuleSetName(name string) string {
	return strings.TrimSpace(name)
}

func cloneRuleSet(rs RuleSet) RuleSet {
	out := rs
	out.Rules = make([]Rule, len(rs.Rules))
	for i, rule := range rs.Rules {
		out.Rules[i] = rule
		out.Rules[i].SetFields = copyMap(rule.SetFields)
		out.Rules[i].Tags = append([]string(nil), rule.Tags...)
		out.Rules[i].When = cloneCondition(rule.When)
	}
	return out
}

func cloneCondition(c Condition) Condition {
	out := c
	out.Values = append([]string(nil), c.Values...)
	out.All = cloneConditions(c.All)
	out.Any = cloneConditions(c.Any)
	if c.Not != nil {
		cloned := cloneCondition(*c.Not)
		out.Not = &cloned
	}
	return out
}

func cloneConditions(in []Condition) []Condition {
	if len(in) == 0 {
		return nil
	}
	out := make([]Condition, len(in))
	for i := range in {
		out[i] = cloneCondition(in[i])
	}
	return out
}
