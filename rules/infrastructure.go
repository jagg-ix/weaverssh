package rules

import (
	"strconv"
	"strings"
)

const (
	InfrastructureKindFile       = "file"
	InfrastructureComponent      = "infrastructure"
	InfrastructureOriginInternal = "internal"
)

// InfrastructureEvent is the rules-facing metadata contract for local
// infrastructure operations. It intentionally carries only metadata so callers
// can evaluate file, socket, adapter, or service events without exposing file
// payloads to policy code.
type InfrastructureEvent struct {
	ID        string            `json:"id,omitempty"`
	Kind      string            `json:"kind,omitempty"`
	Operation string            `json:"operation"`
	Path      string            `json:"path,omitempty"`
	ViewPath  string            `json:"view_path,omitempty"`
	Component string            `json:"component,omitempty"`
	Origin    string            `json:"origin,omitempty"`
	Protocol  string            `json:"protocol,omitempty"`
	Status    string            `json:"status,omitempty"`
	Error     string            `json:"error,omitempty"`
	Bytes     int64             `json:"bytes,omitempty"`
	Files     int64             `json:"files,omitempty"`
	IsDir     bool              `json:"is_dir,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
}

func (e InfrastructureEvent) normalized() InfrastructureEvent {
	e.ID = strings.TrimSpace(e.ID)
	e.Kind = strings.TrimSpace(e.Kind)
	if e.Kind == "" {
		e.Kind = InfrastructureKindFile
	}
	e.Operation = strings.TrimSpace(e.Operation)
	e.Path = strings.TrimSpace(e.Path)
	e.ViewPath = strings.TrimSpace(e.ViewPath)
	e.Component = strings.TrimSpace(e.Component)
	if e.Component == "" {
		e.Component = InfrastructureComponent
	}
	e.Origin = strings.TrimSpace(e.Origin)
	if e.Origin == "" {
		e.Origin = InfrastructureOriginInternal
	}
	e.Protocol = strings.TrimSpace(e.Protocol)
	e.Status = strings.TrimSpace(e.Status)
	e.Error = strings.TrimSpace(e.Error)
	if e.Bytes < 0 {
		e.Bytes = 0
	}
	if e.Files < 0 {
		e.Files = 0
	}
	if len(e.Fields) > 0 {
		fields := make(map[string]string, len(e.Fields))
		for k, v := range e.Fields {
			if key := strings.TrimSpace(k); key != "" {
				fields[key] = v
			}
		}
		e.Fields = fields
	}
	return e
}

// NewInfrastructureInput returns a normalized rules input for infrastructure
// events. File events additionally get file.* aliases because path and
// operation policy is the common case for VFS, transfer, and local-agent code.
func NewInfrastructureInput(topic string, event InfrastructureEvent) Input {
	event = event.normalized()
	facts := map[string]string{
		"topic":           strings.TrimSpace(topic),
		"event.component": event.Component,
		"event.origin":    event.Origin,
		"infra.kind":      event.Kind,
		"infra.operation": event.Operation,
		"infra.component": event.Component,
		"infra.origin":    event.Origin,
	}
	add := func(key, value string) {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			facts[key] = value
		}
	}
	add("infra.id", event.ID)
	add("infra.path", event.Path)
	add("infra.view_path", event.ViewPath)
	add("infra.protocol", event.Protocol)
	add("infra.status", event.Status)
	add("infra.error", event.Error)
	facts["infra.is_dir"] = strconv.FormatBool(event.IsDir)
	if event.Bytes > 0 {
		facts["infra.bytes"] = strconv.FormatInt(event.Bytes, 10)
	}
	if event.Files > 0 {
		facts["infra.files"] = strconv.FormatInt(event.Files, 10)
	}
	if event.Kind == InfrastructureKindFile {
		facts["file.operation"] = event.Operation
		add("file.path", event.Path)
		add("file.view_path", event.ViewPath)
		add("file.protocol", event.Protocol)
		add("file.status", event.Status)
		facts["file.is_dir"] = strconv.FormatBool(event.IsDir)
		if event.Bytes > 0 {
			facts["file.bytes"] = strconv.FormatInt(event.Bytes, 10)
		}
		if event.Files > 0 {
			facts["file.files"] = strconv.FormatInt(event.Files, 10)
		}
	}
	for k, v := range event.Fields {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		facts["field."+key] = v
		facts["fields."+key] = v
		if _, exists := facts[key]; !exists {
			facts[key] = v
		}
	}
	return NewInput(topic, facts)
}

func (a *API) EvaluateInfrastructure(topic string, event InfrastructureEvent) (Decision, error) {
	return a.EvaluateNamedInfrastructure("", topic, event)
}

func (a *API) EvaluateNamedInfrastructure(name string, topic string, event InfrastructureEvent) (Decision, error) {
	return a.EvaluateNamed(name, NewInfrastructureInput(topic, event))
}
