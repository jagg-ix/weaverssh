package rules

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const EngineVersion = "weaverssh.rules.v1"

type Action string

const (
	ActionAllow   Action = "allow"
	ActionDeny    Action = "deny"
	ActionDrop    Action = "drop"
	ActionRewrite Action = "rewrite"
	ActionTag     Action = "tag"
	ActionAudit   Action = "audit"
)

type Operator string

const (
	OpEquals       Operator = "equals"
	OpNotEquals    Operator = "not_equals"
	OpIn           Operator = "in"
	OpNotIn        Operator = "not_in"
	OpContains     Operator = "contains"
	OpPrefix       Operator = "prefix"
	OpSuffix       Operator = "suffix"
	OpGlob         Operator = "glob"
	OpMatches      Operator = "matches"
	OpTopicMatches Operator = "topic_matches"
	OpExists       Operator = "exists"
	OpAbsent       Operator = "absent"
	OpGT           Operator = "gt"
	OpGTE          Operator = "gte"
	OpLT           Operator = "lt"
	OpLTE          Operator = "lte"
	OpCIDRContains Operator = "cidr_contains"
)

// Input is the normalized fact set the rule engine evaluates. The engine is
// intentionally string-based so CLI tools, JSON logs, MQTT events, and small
// agents can feed it without generated bindings.
type Input struct {
	Topic string            `json:"topic,omitempty"`
	Facts map[string]string `json:"facts,omitempty"`
}

type RuleSet struct {
	Version       string `json:"version"`
	DefaultAction Action `json:"default_action,omitempty"`
	Rules         []Rule `json:"rules"`
}

type Rule struct {
	ID           string            `json:"id"`
	Description  string            `json:"description,omitempty"`
	When         Condition         `json:"when,omitempty"`
	Action       Action            `json:"action"`
	Reason       string            `json:"reason,omitempty"`
	SetFields    map[string]string `json:"set_fields,omitempty"`
	RewriteTopic string            `json:"rewrite_topic,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
}

// Condition is either a compound condition (all/any/not) or one atomic
// comparison. Empty Condition{} is true, which makes unconditional final rules
// explicit and compact.
type Condition struct {
	All    []Condition `json:"all,omitempty"`
	Any    []Condition `json:"any,omitempty"`
	Not    *Condition  `json:"not,omitempty"`
	Field  string      `json:"field,omitempty"`
	Op     Operator    `json:"op,omitempty"`
	Value  string      `json:"value,omitempty"`
	Values []string    `json:"values,omitempty"`
}

type Decision struct {
	Version   string            `json:"version"`
	Matched   bool              `json:"matched"`
	RuleID    string            `json:"rule_id,omitempty"`
	Action    Action            `json:"action"`
	Allowed   bool              `json:"allowed"`
	Reason    string            `json:"reason,omitempty"`
	Topic     string            `json:"topic,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
	SetFields map[string]string `json:"set_fields,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
}

func NewInput(topic string, facts map[string]string) Input {
	input := Input{Topic: strings.TrimSpace(topic), Facts: map[string]string{}}
	for k, v := range facts {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		input.Facts[k] = v
	}
	if input.Topic != "" {
		input.Facts["topic"] = input.Topic
	}
	if len(input.Facts) == 0 {
		input.Facts = nil
	}
	return input
}

func (i Input) Normalized() Input {
	return NewInput(i.Topic, i.Facts)
}

func (i Input) Value(field string) (string, bool) {
	field = strings.TrimSpace(field)
	if field == "" {
		return "", false
	}
	if field == "topic" {
		return strings.TrimSpace(i.Topic), strings.TrimSpace(i.Topic) != ""
	}
	if i.Facts == nil {
		return "", false
	}
	v, ok := i.Facts[field]
	return v, ok
}

func Load(r io.Reader) (RuleSet, error) {
	var rs RuleSet
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rs); err != nil {
		return RuleSet{}, err
	}
	return rs.Normalize()
}

func LoadFile(name string) (RuleSet, error) {
	f, err := os.Open(name)
	if err != nil {
		return RuleSet{}, err
	}
	defer f.Close()
	return Load(f)
}

func (rs RuleSet) Normalize() (RuleSet, error) {
	rs.Version = strings.TrimSpace(rs.Version)
	if rs.Version == "" {
		rs.Version = EngineVersion
	}
	if rs.Version != EngineVersion {
		return rs, fmt.Errorf("unsupported rules version %q", rs.Version)
	}
	rs.DefaultAction = normalizeAction(rs.DefaultAction)
	if rs.DefaultAction == "" {
		rs.DefaultAction = ActionDeny
	}
	if !validAction(rs.DefaultAction) {
		return rs, fmt.Errorf("unsupported default action %q", rs.DefaultAction)
	}
	for i := range rs.Rules {
		r, err := rs.Rules[i].Normalize(i)
		if err != nil {
			return rs, err
		}
		rs.Rules[i] = r
	}
	return rs, nil
}

func (r Rule) Normalize(index int) (Rule, error) {
	r.ID = strings.TrimSpace(r.ID)
	if r.ID == "" {
		return r, fmt.Errorf("rule %d id is required", index)
	}
	r.Description = strings.TrimSpace(r.Description)
	r.Action = normalizeAction(r.Action)
	if r.Action == "" {
		r.Action = ActionDeny
	}
	if !validAction(r.Action) {
		return r, fmt.Errorf("rule %q has unsupported action %q", r.ID, r.Action)
	}
	r.Reason = strings.TrimSpace(r.Reason)
	r.RewriteTopic = strings.TrimSpace(r.RewriteTopic)
	if r.Action == ActionRewrite && r.RewriteTopic == "" {
		return r, fmt.Errorf("rule %q rewrite action requires rewrite_topic", r.ID)
	}
	if r.Action != ActionRewrite && r.RewriteTopic != "" {
		return r, fmt.Errorf("rule %q rewrite_topic is only valid with rewrite action", r.ID)
	}
	if err := r.When.Validate(); err != nil {
		return r, fmt.Errorf("rule %q condition: %w", r.ID, err)
	}
	r.SetFields = cleanMap(r.SetFields)
	r.Tags = cleanList(r.Tags)
	return r, nil
}

func (rs RuleSet) Evaluate(input Input) (Decision, error) {
	normalized, err := rs.Normalize()
	if err != nil {
		return Decision{}, err
	}
	input = input.Normalized()
	for _, rule := range normalized.Rules {
		matched, err := rule.When.Match(input)
		if err != nil {
			return Decision{}, fmt.Errorf("rule %q evaluation: %w", rule.ID, err)
		}
		if matched {
			return rule.decision(input), nil
		}
	}
	return Decision{
		Version: EngineVersion,
		Matched: false,
		Action:  normalized.DefaultAction,
		Allowed: actionAllowed(normalized.DefaultAction),
		Reason:  "no rule matched",
		Topic:   input.Topic,
		Fields:  copyMap(input.Facts),
	}, nil
}

func (r Rule) decision(input Input) Decision {
	fields := copyMap(input.Facts)
	for k, v := range r.SetFields {
		if fields == nil {
			fields = map[string]string{}
		}
		fields[k] = v
	}
	topic := input.Topic
	if r.Action == ActionRewrite {
		topic = r.RewriteTopic
	}
	reason := r.Reason
	if reason == "" {
		reason = "matched rule " + r.ID
	}
	return Decision{
		Version:   EngineVersion,
		Matched:   true,
		RuleID:    r.ID,
		Action:    r.Action,
		Allowed:   actionAllowed(r.Action),
		Reason:    reason,
		Topic:     topic,
		Fields:    fields,
		SetFields: copyMap(r.SetFields),
		Tags:      append([]string(nil), r.Tags...),
	}
}

func (c Condition) Validate() error {
	compound := 0
	if len(c.All) > 0 {
		compound++
		for i := range c.All {
			if err := c.All[i].Validate(); err != nil {
				return fmt.Errorf("all[%d]: %w", i, err)
			}
		}
	}
	if len(c.Any) > 0 {
		compound++
		for i := range c.Any {
			if err := c.Any[i].Validate(); err != nil {
				return fmt.Errorf("any[%d]: %w", i, err)
			}
		}
	}
	if c.Not != nil {
		compound++
		if err := c.Not.Validate(); err != nil {
			return fmt.Errorf("not: %w", err)
		}
	}
	atomic := strings.TrimSpace(c.Field) != "" || strings.TrimSpace(string(c.Op)) != "" || c.Value != "" || len(c.Values) > 0
	if compound > 0 && atomic {
		return fmt.Errorf("condition cannot mix all/any/not with field comparison")
	}
	if compound > 1 {
		return fmt.Errorf("condition can use only one of all, any, or not")
	}
	if !atomic {
		return nil
	}
	op := normalizeOperator(c.Op)
	field := strings.TrimSpace(c.Field)
	if field == "" && op != OpTopicMatches {
		return fmt.Errorf("field is required")
	}
	if !validOperator(op) {
		return fmt.Errorf("unsupported operator %q", c.Op)
	}
	switch op {
	case OpExists, OpAbsent:
		return nil
	case OpIn, OpNotIn:
		if len(normalizedValues(c)) == 0 {
			return fmt.Errorf("operator %s requires value or values", op)
		}
	case OpTopicMatches, OpGlob, OpMatches, OpCIDRContains, OpEquals, OpNotEquals, OpContains, OpPrefix, OpSuffix, OpGT, OpGTE, OpLT, OpLTE:
		if c.Value == "" {
			return fmt.Errorf("operator %s requires value", op)
		}
	}
	return nil
}

func (c Condition) Match(input Input) (bool, error) {
	input = input.Normalized()
	if len(c.All) > 0 {
		for _, sub := range c.All {
			ok, err := sub.Match(input)
			if err != nil || !ok {
				return ok, err
			}
		}
		return true, nil
	}
	if len(c.Any) > 0 {
		for _, sub := range c.Any {
			ok, err := sub.Match(input)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}
	if c.Not != nil {
		ok, err := c.Not.Match(input)
		return !ok, err
	}
	if strings.TrimSpace(c.Field) == "" && strings.TrimSpace(string(c.Op)) == "" && c.Value == "" && len(c.Values) == 0 {
		return true, nil
	}
	op := normalizeOperator(c.Op)
	field := strings.TrimSpace(c.Field)
	if field == "" && op == OpTopicMatches {
		field = "topic"
	}
	actual, exists := input.Value(field)
	return evalAtomic(op, actual, exists, c)
}

func evalAtomic(op Operator, actual string, exists bool, c Condition) (bool, error) {
	switch op {
	case OpExists:
		return exists && actual != "", nil
	case OpAbsent:
		return !exists || actual == "", nil
	}
	if !exists {
		return false, nil
	}
	switch op {
	case OpEquals:
		return actual == c.Value, nil
	case OpNotEquals:
		return actual != c.Value, nil
	case OpIn:
		return contains(normalizedValues(c), actual), nil
	case OpNotIn:
		return !contains(normalizedValues(c), actual), nil
	case OpContains:
		return strings.Contains(actual, c.Value), nil
	case OpPrefix:
		return strings.HasPrefix(actual, c.Value), nil
	case OpSuffix:
		return strings.HasSuffix(actual, c.Value), nil
	case OpGlob:
		return path.Match(c.Value, actual)
	case OpMatches:
		return regexp.MatchString(c.Value, actual)
	case OpTopicMatches:
		return topicMatches(c.Value, actual), nil
	case OpGT, OpGTE, OpLT, OpLTE:
		return compareNumber(op, actual, c.Value)
	case OpCIDRContains:
		return cidrContains(c.Value, actual)
	default:
		return false, fmt.Errorf("unsupported operator %q", op)
	}
}

func compareNumber(op Operator, actualText, wantText string) (bool, error) {
	actual, err := strconv.ParseFloat(strings.TrimSpace(actualText), 64)
	if err != nil {
		return false, fmt.Errorf("field value %q is not numeric", actualText)
	}
	want, err := strconv.ParseFloat(strings.TrimSpace(wantText), 64)
	if err != nil {
		return false, fmt.Errorf("rule value %q is not numeric", wantText)
	}
	switch op {
	case OpGT:
		return actual > want, nil
	case OpGTE:
		return actual >= want, nil
	case OpLT:
		return actual < want, nil
	case OpLTE:
		return actual <= want, nil
	default:
		return false, fmt.Errorf("unsupported numeric operator %q", op)
	}
}

func cidrContains(cidr, ipText string) (bool, error) {
	ip := net.ParseIP(strings.TrimSpace(ipText))
	if ip == nil {
		return false, fmt.Errorf("field value %q is not an IP address", ipText)
	}
	_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return false, err
	}
	return network.Contains(ip), nil
}

func Actions() []Action {
	return []Action{ActionAllow, ActionDeny, ActionDrop, ActionRewrite, ActionTag, ActionAudit}
}

func Operators() []Operator {
	return []Operator{OpEquals, OpNotEquals, OpIn, OpNotIn, OpContains, OpPrefix, OpSuffix, OpGlob, OpMatches, OpTopicMatches, OpExists, OpAbsent, OpGT, OpGTE, OpLT, OpLTE, OpCIDRContains}
}

func ExampleRuleSet() RuleSet {
	return RuleSet{
		Version:       EngineVersion,
		DefaultAction: ActionDeny,
		Rules: []Rule{
			{
				ID:          "allow-internal-runtime-status",
				Description: "allow internal runtime status events",
				When: Condition{All: []Condition{
					{Field: "event.origin", Op: OpEquals, Value: "internal"},
					{Field: "event.component", Op: OpEquals, Value: "runtime"},
					{Field: "event.type", Op: OpEquals, Value: "status"},
				}},
				Action: ActionAllow,
				Reason: "internal status is allowed",
			},
			{
				ID:          "drop-external-auth-faults",
				Description: "drop external authproof fault events before publication",
				When: Condition{All: []Condition{
					{Field: "event.origin", Op: OpEquals, Value: "external"},
					{Field: "event.component", Op: OpEquals, Value: "authproof"},
					{Field: "event.type", Op: OpEquals, Value: "fault"},
				}},
				Action: ActionDrop,
				Reason: "external auth faults require local review before forwarding",
			},
		},
	}
}

func normalizeAction(action Action) Action {
	return Action(strings.TrimSpace(strings.ToLower(string(action))))
}

func validAction(action Action) bool {
	for _, candidate := range Actions() {
		if action == candidate {
			return true
		}
	}
	return false
}

func actionAllowed(action Action) bool {
	switch normalizeAction(action) {
	case ActionAllow, ActionRewrite, ActionTag, ActionAudit:
		return true
	default:
		return false
	}
}

func normalizeOperator(op Operator) Operator {
	value := strings.TrimSpace(strings.ToLower(string(op)))
	switch value {
	case "", "eq", "equals", "==", "=":
		return OpEquals
	case "ne", "neq", "not_eq", "not_equals", "!=":
		return OpNotEquals
	case "in", "one_of":
		return OpIn
	case "not_in", "not-one-of":
		return OpNotIn
	case "contains":
		return OpContains
	case "prefix", "has_prefix":
		return OpPrefix
	case "suffix", "has_suffix":
		return OpSuffix
	case "glob":
		return OpGlob
	case "matches", "regex", "regexp":
		return OpMatches
	case "topic_matches", "mqtt_matches", "mqtt_topic_matches":
		return OpTopicMatches
	case "exists":
		return OpExists
	case "absent", "missing":
		return OpAbsent
	case "gt", ">":
		return OpGT
	case "gte", ">=":
		return OpGTE
	case "lt", "<":
		return OpLT
	case "lte", "<=":
		return OpLTE
	case "cidr_contains":
		return OpCIDRContains
	default:
		return Operator(value)
	}
}

func validOperator(op Operator) bool {
	for _, candidate := range Operators() {
		if op == candidate {
			return true
		}
	}
	return false
}

func normalizedValues(c Condition) []string {
	values := cleanList(c.Values)
	if len(values) == 0 && strings.TrimSpace(c.Value) != "" {
		for _, part := range strings.Split(c.Value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				values = append(values, part)
			}
		}
	}
	return values
}

func cleanMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range in {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func copyMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cleanList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func topicMatches(filter, topic string) bool {
	filter = strings.TrimSpace(filter)
	topic = strings.TrimSpace(topic)
	if filter == "" || topic == "" {
		return false
	}
	filterParts := strings.Split(filter, "/")
	topicParts := strings.Split(topic, "/")
	for i, part := range filterParts {
		if part == "#" {
			return i == len(filterParts)-1
		}
		if i >= len(topicParts) {
			return false
		}
		if part == "+" {
			continue
		}
		if part != topicParts[i] {
			return false
		}
	}
	return len(filterParts) == len(topicParts)
}

func SortedActionStrings() []string {
	items := make([]string, 0, len(Actions()))
	for _, action := range Actions() {
		items = append(items, string(action))
	}
	sort.Strings(items)
	return items
}

func SortedOperatorStrings() []string {
	items := make([]string, 0, len(Operators()))
	for _, op := range Operators() {
		items = append(items, string(op))
	}
	sort.Strings(items)
	return items
}
