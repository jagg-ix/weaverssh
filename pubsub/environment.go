package pubsub

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

const (
	ComponentEnvironment = "environment"
	EnvironmentEventKind = "environment"
)

type EnvironmentScope string

const (
	EnvironmentScopeSystemChain EnvironmentScope = "system_chain"
	EnvironmentScopeHost        EnvironmentScope = "host"
	EnvironmentScopeConnection  EnvironmentScope = "connection"
	EnvironmentScopeQoS         EnvironmentScope = "qos"
	EnvironmentScopeFilesystem  EnvironmentScope = "filesystem"
	EnvironmentScopeFile        EnvironmentScope = "file"
	EnvironmentScopeData        EnvironmentScope = "data"
)

// EnvironmentEvent is a metadata-only contract for observations or decisions
// about resources outside the core data plane. It intentionally excludes file
// contents, socket payloads, private keys, cookies, and other secrets.
type EnvironmentEvent struct {
	ID            string            `json:"id,omitempty"`
	Scope         EnvironmentScope  `json:"scope"`
	Operation     string            `json:"operation"`
	Component     string            `json:"component,omitempty"`
	Origin        EventOrigin       `json:"origin,omitempty"`
	ChainID       string            `json:"chain_id,omitempty"`
	NodeID        string            `json:"node_id,omitempty"`
	HostID        string            `json:"host_id,omitempty"`
	ConnectionID  string            `json:"connection_id,omitempty"`
	QoSClass      string            `json:"qos_class,omitempty"`
	FilesystemID  string            `json:"filesystem_id,omitempty"`
	Path          string            `json:"path,omitempty"`
	DataClass     string            `json:"data_class,omitempty"`
	Protocol      string            `json:"protocol,omitempty"`
	Direction     string            `json:"direction,omitempty"`
	Status        string            `json:"status,omitempty"`
	Error         string            `json:"error,omitempty"`
	Bytes         int64             `json:"bytes,omitempty"`
	Files         int64             `json:"files,omitempty"`
	LatencyMillis int64             `json:"latency_ms,omitempty"`
	ThroughputBPS int64             `json:"throughput_bps,omitempty"`
	Fields        map[string]string `json:"fields,omitempty"`
}

func KnownEnvironmentScopes() []EnvironmentScope {
	return []EnvironmentScope{
		EnvironmentScopeSystemChain,
		EnvironmentScopeHost,
		EnvironmentScopeConnection,
		EnvironmentScopeQoS,
		EnvironmentScopeFilesystem,
		EnvironmentScopeFile,
		EnvironmentScopeData,
	}
}

func ParseEnvironmentScope(value string) (EnvironmentScope, error) {
	value = strings.TrimSpace(strings.ToLower(strings.ReplaceAll(value, "-", "_")))
	switch value {
	case "chain", "system", "system_chain", "systemchain":
		return EnvironmentScopeSystemChain, nil
	case "host", "node":
		return EnvironmentScopeHost, nil
	case "connection", "conn", "socket", "tunnel":
		return EnvironmentScopeConnection, nil
	case "qos", "quos", "quality_of_service", "quality-of-service":
		return EnvironmentScopeQoS, nil
	case "filesystem", "fs", "vfs":
		return EnvironmentScopeFilesystem, nil
	case "file":
		return EnvironmentScopeFile, nil
	case "data", "payload", "stream":
		return EnvironmentScopeData, nil
	default:
		return "", fmt.Errorf("unsupported environment scope %q", value)
	}
}

func normalizeEnvironmentScope(scope EnvironmentScope) EnvironmentScope {
	parsed, err := ParseEnvironmentScope(string(scope))
	if err != nil {
		return scope
	}
	return parsed
}

func (e EnvironmentEvent) Normalized() EnvironmentEvent {
	e.ID = strings.TrimSpace(e.ID)
	if e.ID == "" {
		e.ID = newID("environment")
	}
	e.Scope = normalizeEnvironmentScope(e.Scope)
	e.Operation = strings.TrimSpace(e.Operation)
	e.Component = strings.TrimSpace(e.Component)
	if e.Component == "" {
		e.Component = ComponentEnvironment
	}
	if strings.TrimSpace(string(e.Origin)) == "" {
		e.Origin = EventOriginExternal
	} else {
		e.Origin = normalizeEventOrigin(e.Origin)
	}
	e.ChainID = strings.TrimSpace(e.ChainID)
	e.NodeID = strings.TrimSpace(e.NodeID)
	e.HostID = strings.TrimSpace(e.HostID)
	e.ConnectionID = strings.TrimSpace(e.ConnectionID)
	e.QoSClass = strings.TrimSpace(e.QoSClass)
	e.FilesystemID = strings.TrimSpace(e.FilesystemID)
	e.Path = strings.TrimSpace(e.Path)
	e.DataClass = strings.TrimSpace(e.DataClass)
	e.Protocol = strings.TrimSpace(e.Protocol)
	e.Direction = strings.TrimSpace(e.Direction)
	e.Status = strings.TrimSpace(e.Status)
	e.Error = strings.TrimSpace(e.Error)
	if e.Bytes < 0 {
		e.Bytes = 0
	}
	if e.Files < 0 {
		e.Files = 0
	}
	if e.LatencyMillis < 0 {
		e.LatencyMillis = 0
	}
	if e.ThroughputBPS < 0 {
		e.ThroughputBPS = 0
	}
	e.Fields = copyFields(e.Fields)
	return e
}

func (e EnvironmentEvent) Validate() error {
	e = e.Normalized()
	if _, err := ParseEnvironmentScope(string(e.Scope)); err != nil {
		return err
	}
	if e.Operation == "" {
		return fmt.Errorf("environment operation is required")
	}
	return nil
}

func (e EnvironmentEvent) FieldsFor() map[string]string {
	e = e.Normalized()
	fields := map[string]string{
		"environment_id": e.ID,
		"kind":           EnvironmentEventKind,
		"scope":          string(e.Scope),
		"operation":      e.Operation,
	}
	add := func(key, value string) {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			fields[key] = value
		}
	}
	add("chain_id", e.ChainID)
	add("node_id", e.NodeID)
	add("host_id", e.HostID)
	add("connection_id", e.ConnectionID)
	add("qos_class", e.QoSClass)
	add("filesystem_id", e.FilesystemID)
	add("path", e.Path)
	add("data_class", e.DataClass)
	add("protocol", e.Protocol)
	add("direction", e.Direction)
	add("status", e.Status)
	add("error", e.Error)
	if e.Bytes > 0 {
		fields["bytes"] = strconv.FormatInt(e.Bytes, 10)
	}
	if e.Files > 0 {
		fields["files"] = strconv.FormatInt(e.Files, 10)
	}
	if e.LatencyMillis > 0 {
		fields["latency_ms"] = strconv.FormatInt(e.LatencyMillis, 10)
	}
	if e.ThroughputBPS > 0 {
		fields["throughput_bps"] = strconv.FormatInt(e.ThroughputBPS, 10)
	}
	for k, v := range e.Fields {
		if _, exists := fields[k]; !exists {
			fields[k] = v
		}
	}
	return fields
}

func EnvironmentEventType(scope EnvironmentScope, operation string) string {
	scope = normalizeEnvironmentScope(scope)
	operation = cleanTopicPart(operation)
	if operation == "" {
		operation = "observed"
	}
	return cleanTopicPart(string(scope) + "_" + operation)
}

func NewEnvironmentEvent(scope EnvironmentScope, operation string, env EnvironmentEvent) Event {
	env.Scope = scope
	env.Operation = operation
	env = env.Normalized()
	message := fmt.Sprintf("environment %s %s", env.Scope, env.Operation)
	return NewEventFrom(env.Origin, EnvironmentEventType(env.Scope, env.Operation), env.Component, message, env.FieldsFor())
}

func (a *API) EmitEnvironmentEvent(ctx context.Context, scope EnvironmentScope, operation string, env EnvironmentEvent) (HookedEmitResult, error) {
	env.Scope = scope
	env.Operation = operation
	if err := env.Validate(); err != nil {
		return HookedEmitResult{}, err
	}
	return a.EmitEvent(ctx, NewEnvironmentEvent(scope, operation, env))
}

func (a *API) DispatchEnvironmentEvent(ctx context.Context, point HookPoint, scope EnvironmentScope, operation string, env EnvironmentEvent) (HookDispatch, error) {
	env.Scope = scope
	env.Operation = operation
	if err := env.Validate(); err != nil {
		return HookDispatch{}, err
	}
	event := NewEnvironmentEvent(scope, operation, env)
	topic, err := a.TopicFor(event)
	if err != nil {
		return HookDispatch{}, err
	}
	return a.Dispatch(ctx, point, topic, event)
}

func (a *API) BeforeEnvironmentEvent(ctx context.Context, scope EnvironmentScope, operation string, env EnvironmentEvent) (HookDispatch, error) {
	return a.DispatchEnvironmentEvent(ctx, HookBeforeEnvironmentEvent, scope, operation, env)
}

func (a *API) AfterEnvironmentEvent(ctx context.Context, scope EnvironmentScope, operation string, env EnvironmentEvent) (HookDispatch, error) {
	return a.DispatchEnvironmentEvent(ctx, HookAfterEnvironmentEvent, scope, operation, env)
}

func (a *API) ObserveEnvironmentEvent(ctx context.Context, scope EnvironmentScope, operation string, env EnvironmentEvent) (HookDispatch, error) {
	return a.DispatchEnvironmentEvent(ctx, HookOnEnvironmentEvent, scope, operation, env)
}

func (a *API) RunEnvironmentOperation(ctx context.Context, scope EnvironmentScope, operation string, env EnvironmentEvent, fn HookedOperation) (HookedOperationResult, error) {
	env.Scope = scope
	env.Operation = operation
	if err := env.Validate(); err != nil {
		return HookedOperationResult{}, err
	}
	event := NewEnvironmentEvent(scope, operation, env)
	topic, err := a.TopicFor(event)
	if err != nil {
		return HookedOperationResult{}, err
	}
	return a.runHookedOperation(ctx, HookBeforeEnvironmentEvent, HookAfterEnvironmentEvent, topic, event, fn)
}

type EnvironmentPluginConfig struct {
	ID          string             `json:"id"`
	Name        string             `json:"name,omitempty"`
	Description string             `json:"description,omitempty"`
	Origins     []EventOrigin      `json:"origins,omitempty"`
	Scopes      []EnvironmentScope `json:"scopes,omitempty"`
	Points      []HookPoint        `json:"points,omitempty"`
	Handler     HookHandler        `json:"-"`
}

func NewEnvironmentPlugin(cfg EnvironmentPluginConfig) (Plugin, error) {
	id := strings.TrimSpace(cfg.ID)
	if id == "" {
		id = "environment"
	}
	if cfg.Handler == nil {
		return nil, fmt.Errorf("environment plugin handler is required")
	}
	origins := cfg.Origins
	if len(origins) == 0 {
		origins = []EventOrigin{EventOriginExternal}
	}
	for _, origin := range origins {
		if _, err := ParseEventOrigin(string(origin)); err != nil {
			return nil, err
		}
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = KnownEnvironmentScopes()
	}
	points := cfg.Points
	if len(points) == 0 {
		points = []HookPoint{HookBeforeEnvironmentEvent, HookOnEnvironmentEvent, HookAfterEnvironmentEvent}
	}
	hooks := make([]Hook, 0, len(scopes)*len(points))
	for _, rawScope := range scopes {
		scope, err := ParseEnvironmentScope(string(rawScope))
		if err != nil {
			return nil, err
		}
		for _, rawPoint := range points {
			point, err := ParseHookPoint(string(rawPoint))
			if err != nil {
				return nil, err
			}
			hooks = append(hooks, Hook{
				ID:          "environment-" + string(scope) + "-" + string(point),
				PluginID:    id,
				Description: "environment " + string(scope) + " hook for " + string(point),
				Point:       point,
				Filter: HookFilter{
					Origins:    origins,
					Components: []string{ComponentEnvironment},
					Fields:     map[string]string{"scope": string(scope)},
				},
				Handler: cfg.Handler,
			})
		}
	}
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		name = "weaverssh environment integration"
	}
	return StaticPlugin{
		ManifestData: PluginManifest{ID: id, Name: name, Version: HookAPIVersion, Kind: "environment", External: true, Components: []string{ComponentEnvironment, "hooks"}, Description: cfg.Description},
		HookList:     hooks,
	}, nil
}
