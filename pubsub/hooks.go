package pubsub

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const HookAPIVersion = "weaverssh.hooks.v1"

var ErrEventDropped = errors.New("event dropped by hook")

type HookPoint string

type HookAction string

const (
	HookBeforePublish HookPoint = "before_publish"
	HookAfterPublish  HookPoint = "after_publish"
	HookBeforeForward HookPoint = "before_forward"
	HookAfterForward  HookPoint = "after_forward"
	HookOnDelivery    HookPoint = "on_delivery"
	HookOnError       HookPoint = "on_error"

	HookBeforeFileTransfer     HookPoint = "before_file_transfer"
	HookAfterFileTransfer      HookPoint = "after_file_transfer"
	HookOnFileTransferProgress HookPoint = "on_file_transfer_progress"

	HookBeforeFileOperation HookPoint = "before_file_operation"
	HookAfterFileOperation  HookPoint = "after_file_operation"
	HookOnFileOperation     HookPoint = "on_file_operation"

	HookBeforeEnvironmentEvent HookPoint = "before_environment_event"
	HookAfterEnvironmentEvent  HookPoint = "after_environment_event"
	HookOnEnvironmentEvent     HookPoint = "on_environment_event"

	HookBeforeAPICall   HookPoint = "before_api_call"
	HookAfterAPICall    HookPoint = "after_api_call"
	HookOnAPIEvent      HookPoint = "on_api_event"
	HookOnEventConsumed HookPoint = "on_event_consumed"

	HookContinue HookAction = "continue"
	HookDrop     HookAction = "drop"
)

// HookFilter selects events by origin class, component, type, and optional MQTT
// topic filter. Empty fields mean "any". Origin defaults to internal for
// legacy events that do not yet carry an origin field.
type HookFilter struct {
	Origins     []EventOrigin     `json:"origins,omitempty"`
	Components  []string          `json:"components,omitempty"`
	Types       []string          `json:"types,omitempty"`
	TopicFilter string            `json:"topic_filter,omitempty"`
	Fields      map[string]string `json:"fields,omitempty"`
}

type HookInvocation struct {
	Version string    `json:"version"`
	Point   HookPoint `json:"point"`
	Topic   string    `json:"topic,omitempty"`
	Event   Event     `json:"event"`
}

type HookDecision struct {
	Action HookAction        `json:"action"`
	Reason string            `json:"reason,omitempty"`
	Fields map[string]string `json:"fields,omitempty"`
}

type HookResult struct {
	PluginID string     `json:"plugin_id"`
	HookID   string     `json:"hook_id"`
	Action   HookAction `json:"action"`
	Reason   string     `json:"reason,omitempty"`
	Error    string     `json:"error,omitempty"`
}

type HookDispatch struct {
	Version string       `json:"version"`
	Point   HookPoint    `json:"point"`
	Topic   string       `json:"topic,omitempty"`
	EventID string       `json:"event_id"`
	Matched int          `json:"matched"`
	Dropped bool         `json:"dropped"`
	Results []HookResult `json:"results,omitempty"`
}

type HookHandler func(context.Context, HookInvocation) (HookDecision, error)

type Hook struct {
	ID          string      `json:"id"`
	PluginID    string      `json:"plugin_id"`
	Description string      `json:"description,omitempty"`
	Point       HookPoint   `json:"point"`
	Filter      HookFilter  `json:"filter,omitempty"`
	Handler     HookHandler `json:"-"`
}

type PluginManifest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Version     string   `json:"version,omitempty"`
	Kind        string   `json:"kind,omitempty"`
	External    bool     `json:"external,omitempty"`
	Components  []string `json:"components,omitempty"`
	Description string   `json:"description,omitempty"`
}

type Plugin interface {
	Manifest() PluginManifest
	Hooks() []Hook
}

type StaticPlugin struct {
	ManifestData PluginManifest
	HookList     []Hook
}

func (p StaticPlugin) Manifest() PluginManifest { return p.ManifestData }
func (p StaticPlugin) Hooks() []Hook            { return append([]Hook(nil), p.HookList...) }

type HookRegistry struct {
	mu      sync.RWMutex
	plugins map[string]PluginManifest
	hooks   []Hook
}

type EventPublisher interface {
	PublishEvent(prefix string, event Event) (string, error)
}

type HookedEmitter struct {
	Prefix    string
	Publisher EventPublisher
	Hooks     *HookRegistry
}

type HookedEmitResult struct {
	Topic   string       `json:"topic"`
	Dropped bool         `json:"dropped"`
	Before  HookDispatch `json:"before"`
	After   HookDispatch `json:"after"`
}

func KnownHookPoints() []HookPoint {
	return []HookPoint{
		HookBeforePublish, HookAfterPublish, HookBeforeForward, HookAfterForward, HookOnDelivery, HookOnError,
		HookBeforeFileTransfer, HookAfterFileTransfer, HookOnFileTransferProgress,
		HookBeforeFileOperation, HookAfterFileOperation, HookOnFileOperation,
		HookBeforeEnvironmentEvent, HookAfterEnvironmentEvent, HookOnEnvironmentEvent,
		HookBeforeAPICall, HookAfterAPICall, HookOnAPIEvent, HookOnEventConsumed,
	}
}

func ParseHookPoint(value string) (HookPoint, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	for _, point := range KnownHookPoints() {
		if value == string(point) {
			return point, nil
		}
	}
	return "", fmt.Errorf("unsupported hook point %q", value)
}

func NewHookRegistry() *HookRegistry {
	return &HookRegistry{plugins: map[string]PluginManifest{}}
}

func (r *HookRegistry) RegisterPlugin(plugin Plugin) error {
	if r == nil {
		return fmt.Errorf("hook registry is nil")
	}
	if plugin == nil {
		return fmt.Errorf("plugin is nil")
	}
	manifest := plugin.Manifest()
	if strings.TrimSpace(manifest.ID) == "" {
		return fmt.Errorf("plugin id is required")
	}
	r.mu.Lock()
	if _, exists := r.plugins[manifest.ID]; exists {
		r.mu.Unlock()
		return fmt.Errorf("plugin %q already registered", manifest.ID)
	}
	r.plugins[manifest.ID] = manifest
	r.mu.Unlock()
	for _, hook := range plugin.Hooks() {
		if strings.TrimSpace(hook.PluginID) == "" {
			hook.PluginID = manifest.ID
		}
		if err := r.RegisterHook(hook); err != nil {
			return err
		}
	}
	return nil
}

func (r *HookRegistry) RegisterHook(hook Hook) error {
	if r == nil {
		return fmt.Errorf("hook registry is nil")
	}
	if strings.TrimSpace(hook.ID) == "" {
		return fmt.Errorf("hook id is required")
	}
	if strings.TrimSpace(hook.PluginID) == "" {
		return fmt.Errorf("hook plugin id is required")
	}
	if _, err := ParseHookPoint(string(hook.Point)); err != nil {
		return err
	}
	if hook.Handler == nil {
		return fmt.Errorf("hook %q handler is required", hook.ID)
	}
	if err := hook.Filter.Validate(); err != nil {
		return fmt.Errorf("hook %q filter: %w", hook.ID, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.plugins[hook.PluginID]; !ok {
		r.plugins[hook.PluginID] = PluginManifest{ID: hook.PluginID, Kind: "anonymous"}
	}
	for _, existing := range r.hooks {
		if existing.PluginID == hook.PluginID && existing.ID == hook.ID {
			return fmt.Errorf("hook %q already registered for plugin %q", hook.ID, hook.PluginID)
		}
	}
	r.hooks = append(r.hooks, hook)
	return nil
}

func (r *HookRegistry) Dispatch(ctx context.Context, point HookPoint, topic string, event Event) (HookDispatch, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := ParseHookPoint(string(point)); err != nil {
		return HookDispatch{}, err
	}
	event = event.Normalized()
	if err := event.Validate(); err != nil {
		return HookDispatch{}, err
	}
	dispatch := HookDispatch{Version: HookAPIVersion, Point: point, Topic: topic, EventID: event.ID}
	if r == nil {
		return dispatch, nil
	}
	r.mu.RLock()
	hooks := append([]Hook(nil), r.hooks...)
	r.mu.RUnlock()
	for _, hook := range hooks {
		if hook.Point != point || !hook.Filter.Match(topic, event) {
			continue
		}
		dispatch.Matched++
		decision, err := hook.Handler(ctx, HookInvocation{Version: HookAPIVersion, Point: point, Topic: topic, Event: event})
		result := HookResult{PluginID: hook.PluginID, HookID: hook.ID, Action: normalizeHookAction(decision.Action), Reason: decision.Reason}
		if err != nil {
			result.Error = err.Error()
			dispatch.Results = append(dispatch.Results, result)
			return dispatch, err
		}
		switch result.Action {
		case HookContinue:
			dispatch.Results = append(dispatch.Results, result)
		case HookDrop:
			dispatch.Dropped = true
			dispatch.Results = append(dispatch.Results, result)
			return dispatch, nil
		default:
			result.Error = fmt.Sprintf("unsupported hook action %q", decision.Action)
			dispatch.Results = append(dispatch.Results, result)
			return dispatch, fmt.Errorf("hook %q returned unsupported action %q", hook.ID, decision.Action)
		}
		select {
		case <-ctx.Done():
			return dispatch, ctx.Err()
		default:
		}
	}
	return dispatch, nil
}

func (e HookedEmitter) Emit(ctx context.Context, event Event) (HookedEmitResult, error) {
	if e.Publisher == nil {
		return HookedEmitResult{}, fmt.Errorf("event publisher is required")
	}
	event = event.Normalized()
	topic, err := EventTopic(e.Prefix, event.Component, event.Type)
	if err != nil {
		return HookedEmitResult{}, err
	}
	before, err := e.Hooks.Dispatch(ctx, HookBeforePublish, topic, event)
	result := HookedEmitResult{Topic: topic, Before: before}
	if err != nil {
		return result, err
	}
	if before.Dropped {
		result.Dropped = true
		return result, ErrEventDropped
	}
	publishedTopic, err := e.Publisher.PublishEvent(e.Prefix, event)
	if err != nil {
		return result, err
	}
	result.Topic = publishedTopic
	after, err := e.Hooks.Dispatch(ctx, HookAfterPublish, publishedTopic, event)
	result.After = after
	if err != nil {
		return result, err
	}
	return result, nil
}

func (f HookFilter) Validate() error {
	for _, origin := range f.Origins {
		if _, err := ParseEventOrigin(string(origin)); err != nil {
			return err
		}
	}
	if strings.TrimSpace(f.TopicFilter) != "" {
		return ValidateSubscribeTopic(f.TopicFilter)
	}
	for key := range f.Fields {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("hook filter field name is required")
		}
	}
	return nil
}

func (f HookFilter) Match(topic string, event Event) bool {
	event = event.Normalized()
	if len(f.Origins) > 0 && !originIn(event.Origin, f.Origins) {
		return false
	}
	if len(f.Components) > 0 && !stringInFold(event.Component, f.Components) {
		return false
	}
	if len(f.Types) > 0 && !stringInFold(event.Type, f.Types) {
		return false
	}
	if strings.TrimSpace(f.TopicFilter) != "" && !TopicMatches(f.TopicFilter, topic) {
		return false
	}
	for key, want := range f.Fields {
		key = strings.TrimSpace(key)
		got, ok := event.Fields[key]
		if !ok {
			return false
		}
		want = strings.TrimSpace(want)
		if want == "" {
			if strings.TrimSpace(got) == "" {
				return false
			}
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(got), want) {
			return false
		}
	}
	return true
}

func normalizeHookAction(action HookAction) HookAction {
	if action == "" {
		return HookContinue
	}
	return HookAction(strings.TrimSpace(strings.ToLower(string(action))))
}

func originIn(value EventOrigin, values []EventOrigin) bool {
	value = EventOrigin(strings.TrimSpace(strings.ToLower(string(value))))
	for _, candidate := range values {
		if value == EventOrigin(strings.TrimSpace(strings.ToLower(string(candidate)))) {
			return true
		}
	}
	return false
}

func stringInFold(value string, values []string) bool {
	value = strings.TrimSpace(value)
	for _, candidate := range values {
		if strings.EqualFold(value, strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}
