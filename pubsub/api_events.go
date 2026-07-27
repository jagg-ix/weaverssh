package pubsub

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

const ComponentAPI = "api"

type APIEventPhase string

const (
	APIStarted   APIEventPhase = "api_started"
	APICompleted APIEventPhase = "api_completed"
	APIFailed    APIEventPhase = "api_failed"
	APIDenied    APIEventPhase = "api_denied"
)

// APIEvent is metadata for a component API call. It intentionally excludes
// payloads and secrets; hooks/rules receive identity, node, operation, status,
// and caller-provided metadata only.
type APIEvent struct {
	ID        string            `json:"id,omitempty"`
	NodeID    string            `json:"node_id,omitempty"`
	API       string            `json:"api"`
	Operation string            `json:"operation,omitempty"`
	Subject   string            `json:"subject,omitempty"`
	Component string            `json:"component,omitempty"`
	Origin    EventOrigin       `json:"origin,omitempty"`
	Status    string            `json:"status,omitempty"`
	Error     string            `json:"error,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
}

func (e APIEvent) Normalized() APIEvent {
	e.ID = strings.TrimSpace(e.ID)
	if e.ID == "" {
		e.ID = newID("api-event")
	}
	e.NodeID = strings.TrimSpace(e.NodeID)
	e.API = strings.TrimSpace(e.API)
	e.Operation = strings.TrimSpace(e.Operation)
	e.Subject = strings.TrimSpace(e.Subject)
	e.Component = strings.TrimSpace(e.Component)
	if e.Component == "" {
		e.Component = ComponentAPI
	}
	e.Origin = normalizeEventOrigin(e.Origin)
	e.Status = strings.TrimSpace(e.Status)
	e.Error = strings.TrimSpace(e.Error)
	e.Fields = copyFields(e.Fields)
	return e
}

func (e APIEvent) Validate(phase APIEventPhase) error {
	phase = APIEventPhase(strings.TrimSpace(string(phase)))
	if phase == "" {
		return fmt.Errorf("api event phase is required")
	}
	e = e.Normalized()
	if e.API == "" {
		return fmt.Errorf("api name is required")
	}
	return nil
}

func (e APIEvent) FieldsFor(phase APIEventPhase) map[string]string {
	e = e.Normalized()
	fields := map[string]string{
		"api_event_id": e.ID,
		"kind":         "api",
		"phase":        string(phase),
		"api":          e.API,
	}
	if e.NodeID != "" {
		fields["node_id"] = e.NodeID
	}
	if e.Operation != "" {
		fields["operation"] = e.Operation
	}
	if e.Subject != "" {
		fields["subject"] = e.Subject
	}
	if e.Status != "" {
		fields["status"] = e.Status
	}
	if e.Error != "" {
		fields["error"] = e.Error
	}
	for k, v := range e.Fields {
		if _, exists := fields[k]; !exists {
			fields[k] = v
		}
	}
	return fields
}

func NewAPIEvent(phase APIEventPhase, apiEvent APIEvent) Event {
	apiEvent = apiEvent.Normalized()
	message := fmt.Sprintf("api %s %s", strings.TrimSpace(apiEvent.API), strings.TrimSpace(string(phase)))
	return NewEventFrom(apiEvent.Origin, strings.TrimSpace(string(phase)), apiEvent.Component, message, apiEvent.FieldsFor(phase))
}

func (a *API) EmitAPIEvent(ctx context.Context, phase APIEventPhase, apiEvent APIEvent) (HookedEmitResult, error) {
	if err := apiEvent.Validate(phase); err != nil {
		return HookedEmitResult{}, err
	}
	return a.EmitEvent(ctx, NewAPIEvent(phase, apiEvent))
}

func (a *API) DispatchAPIEvent(ctx context.Context, point HookPoint, phase APIEventPhase, apiEvent APIEvent) (HookDispatch, error) {
	if err := apiEvent.Validate(phase); err != nil {
		return HookDispatch{}, err
	}
	event := NewAPIEvent(phase, apiEvent)
	topic, err := a.TopicFor(event)
	if err != nil {
		return HookDispatch{}, err
	}
	return a.Dispatch(ctx, point, topic, event)
}

func (a *API) BeforeAPICall(ctx context.Context, apiEvent APIEvent) (HookDispatch, error) {
	return a.DispatchAPIEvent(ctx, HookBeforeAPICall, APIStarted, apiEvent)
}

func (a *API) AfterAPICall(ctx context.Context, phase APIEventPhase, apiEvent APIEvent) (HookDispatch, error) {
	return a.DispatchAPIEvent(ctx, HookAfterAPICall, phase, apiEvent)
}

func (a *API) ObserveAPIEvent(ctx context.Context, phase APIEventPhase, apiEvent APIEvent) (HookDispatch, error) {
	return a.DispatchAPIEvent(ctx, HookOnAPIEvent, phase, apiEvent)
}

func (a *API) RunAPICall(ctx context.Context, apiEvent APIEvent, fn HookedOperation) (HookedOperationResult, error) {
	if err := apiEvent.Validate(APIStarted); err != nil {
		return HookedOperationResult{}, err
	}
	event := NewAPIEvent(APIStarted, apiEvent)
	topic, err := a.TopicFor(event)
	if err != nil {
		return HookedOperationResult{}, err
	}
	result, err := a.runHookedOperation(ctx, HookBeforeAPICall, HookAfterAPICall, topic, event, fn)
	if result.Dropped {
		denied := apiEvent
		denied.Status = "denied"
		_, _ = a.EmitAPIEvent(ctx, APIDenied, denied)
	}
	if err != nil && err != ErrEventDropped {
		failed := apiEvent
		failed.Status = "failed"
		failed.Error = err.Error()
		_, _ = a.EmitAPIEvent(ctx, APIFailed, failed)
	} else if err == nil {
		completed := apiEvent
		completed.Status = "completed"
		_, _ = a.EmitAPIEvent(ctx, APICompleted, completed)
	}
	return result, err
}

func APIEventFacts(event Event) map[string]string {
	facts := map[string]string{}
	if event.Component != "" {
		facts["api.component"] = event.Component
	}
	aliases := []string{"api_event_id", "phase", "api", "operation", "subject", "node_id", "status", "error"}
	for _, key := range aliases {
		value := strings.TrimSpace(event.Fields[key])
		if value == "" {
			continue
		}
		factKey := strings.TrimPrefix(key, "api_")
		if key == "api" {
			factKey = "name"
		}
		facts["api."+factKey] = value
	}
	if retries := strings.TrimSpace(event.Fields["attempt"]); retries != "" {
		if _, err := strconv.Atoi(retries); err == nil {
			facts["api.attempt"] = retries
		}
	}
	return facts
}
