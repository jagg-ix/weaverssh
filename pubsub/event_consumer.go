package pubsub

import (
	"context"
	"fmt"
	"strings"

	"weaverssh/rules"
)

const EventConsumerVersion = "weaverssh.event_consumer.v1"

// APICallIntent is a data-only request produced by rules after consuming an
// event. It is not executed until a trusted component passes it to an
// APIIntentExecutor.
type APICallIntent struct {
	API       string            `json:"api"`
	Operation string            `json:"operation,omitempty"`
	Subject   string            `json:"subject,omitempty"`
	NodeID    string            `json:"node_id,omitempty"`
	RuleID    string            `json:"rule_id,omitempty"`
	Stage     string            `json:"stage,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// APITrigger is retained as a compatibility alias. Prefer APICallIntent for
// new code because the value is an intent, not an executed trigger.
type APITrigger = APICallIntent

type APIIntentHandler func(context.Context, APICallIntent) error

// APITriggerHandler is retained as a compatibility alias. Prefer
// APIIntentHandler for new code.
type APITriggerHandler = APIIntentHandler

type APIIntentResult struct {
	Intent   APICallIntent `json:"intent"`
	Executed bool          `json:"executed"`
	Error    string        `json:"error,omitempty"`
}

type EventConsumeRequest struct {
	Topic string `json:"topic,omitempty"`
	Event Event  `json:"event"`
}

type EventTriggerPlan struct {
	Version  string                 `json:"version"`
	NodeID   string                 `json:"node_id,omitempty"`
	Topic    string                 `json:"topic"`
	Event    Event                  `json:"event"`
	Decision rules.PipelineDecision `json:"decision"`
	Intents  []APICallIntent        `json:"intents,omitempty"`
}

// EventConsumeResult is retained for existing callers. Prefer EventTriggerPlan
// because consuming an event produces a plan, not an execution result.
type EventConsumeResult = EventTriggerPlan

type EventConsumerConfig struct {
	NodeID   string
	Pipeline rules.PipelineConfig
}

type EventConsumer struct {
	nodeID   string
	pipeline rules.PipelineConfig
}

func NewEventConsumer(cfg EventConsumerConfig) (*EventConsumer, error) {
	nodeID := strings.TrimSpace(cfg.NodeID)
	if nodeID == "" {
		nodeID = strings.TrimSpace(cfg.Pipeline.NodeID)
	}
	if nodeID != "" {
		clean, err := rules.CleanNodeID(nodeID)
		if err != nil {
			return nil, err
		}
		nodeID = clean
	}
	pipeline := cfg.Pipeline
	if pipeline.Version == "" && len(pipeline.Stages) == 0 {
		var err error
		if nodeID != "" {
			pipeline, err = rules.DefaultRemoteNodePipelineConfig(nodeID)
		} else {
			pipeline = rules.DefaultPipelineConfig()
		}
		if err != nil {
			return nil, err
		}
	}
	pipeline.NodeID = nodeID
	var err error
	pipeline, err = pipeline.Normalize()
	if err != nil {
		return nil, err
	}
	return &EventConsumer{nodeID: nodeID, pipeline: pipeline}, nil
}

func (c *EventConsumer) PlanEvent(ctx context.Context, req EventConsumeRequest) (EventTriggerPlan, error) {
	if c == nil {
		return EventTriggerPlan{}, fmt.Errorf("event consumer is nil")
	}
	if ctx == nil {
		return EventTriggerPlan{}, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return EventTriggerPlan{}, err
	}
	event := req.Event.Normalized()
	if err := event.Validate(); err != nil {
		return EventTriggerPlan{}, err
	}
	topic := strings.TrimSpace(req.Topic)
	if topic == "" {
		var err error
		topic, err = EventTopic(DefaultPrefix, event.Component, event.Type)
		if err != nil {
			return EventTriggerPlan{}, err
		}
	}
	input := EventRuleInput(topic, HookOnEventConsumed, event)
	decision, err := c.pipeline.Evaluate(input)
	plan := EventTriggerPlan{Version: EventConsumerVersion, NodeID: c.nodeID, Topic: topic, Event: event, Decision: decision}
	if err != nil {
		return plan, err
	}
	plan.Intents = APICallIntentsFromDecision(decision)
	return plan, nil
}

// Consume is retained for compatibility. It plans only; it never executes API
// intents. New code should call PlanEvent.
func (c *EventConsumer) Consume(ctx context.Context, topic string, event Event) (EventConsumeResult, error) {
	return c.PlanEvent(ctx, EventConsumeRequest{Topic: topic, Event: event})
}

type APIIntentExecutorConfig struct {
	API     *API
	Handler APIIntentHandler
}

type APIIntentExecutor struct {
	api     *API
	handler APIIntentHandler
}

func NewAPIIntentExecutor(cfg APIIntentExecutorConfig) (*APIIntentExecutor, error) {
	if cfg.Handler == nil {
		return nil, fmt.Errorf("api intent handler is required")
	}
	api := cfg.API
	if api == nil {
		api = NewAPI(APIConfig{})
	}
	return &APIIntentExecutor{api: api, handler: cfg.Handler}, nil
}

// TriggerExecutorConfig is retained as a compatibility alias. Prefer
// APIIntentExecutorConfig for new code.
type TriggerExecutorConfig = APIIntentExecutorConfig

// TriggerExecutor is retained as a compatibility alias. Prefer APIIntentExecutor
// for new code.
type TriggerExecutor = APIIntentExecutor

func NewTriggerExecutor(cfg TriggerExecutorConfig) (*TriggerExecutor, error) {
	return NewAPIIntentExecutor(cfg)
}

func (e *APIIntentExecutor) ExecutePlan(ctx context.Context, plan EventTriggerPlan) ([]APIIntentResult, error) {
	if e == nil {
		return nil, fmt.Errorf("trigger executor is nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	results := make([]APIIntentResult, 0, len(plan.Intents))
	if !plan.Decision.Allowed {
		return results, nil
	}
	for _, intent := range plan.Intents {
		result := APIIntentResult{Intent: intent}
		apiEvent := intent.APIEvent()
		_, err := e.api.RunAPICall(ctx, apiEvent, func(ctx context.Context) error {
			return e.handler(ctx, intent)
		})
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			return results, err
		}
		result.Executed = true
		results = append(results, result)
	}
	return results, nil
}

func APICallIntentsFromDecision(decision rules.PipelineDecision) []APICallIntent {
	if !decision.Allowed {
		return nil
	}
	intent := intentFromFields(decision.Fields)
	if intent.API == "" {
		intent = intentFromFields(decision.Final.Fields)
	}
	if intent.API == "" {
		return nil
	}
	intent.RuleID = decision.Final.RuleID
	intent.Reason = decision.Final.Reason
	for i := len(decision.Stages) - 1; i >= 0; i-- {
		if decision.Stages[i].Decision.RuleID == decision.Final.RuleID {
			intent.Stage = decision.Stages[i].Stage
			break
		}
	}
	if intent.NodeID == "" {
		intent.NodeID = decision.Fields["node.id"]
	}
	return []APICallIntent{intent}
}

// APITriggersFromDecision is retained for compatibility. Prefer
// APICallIntentsFromDecision for new code.
func APITriggersFromDecision(decision rules.PipelineDecision) []APITrigger {
	return APICallIntentsFromDecision(decision)
}

func intentFromFields(fields map[string]string) APICallIntent {
	if len(fields) == 0 {
		return APICallIntent{}
	}
	intent := APICallIntent{
		API:       strings.TrimSpace(firstNonEmpty(fields["intent.api"], fields["trigger.api"], fields["api.trigger"])),
		Operation: strings.TrimSpace(firstNonEmpty(fields["intent.operation"], fields["trigger.operation"])),
		Subject:   strings.TrimSpace(firstNonEmpty(fields["intent.subject"], fields["trigger.subject"])),
		NodeID:    strings.TrimSpace(firstNonEmpty(fields["intent.node_id"], fields["trigger.node_id"], fields["node.id"])),
		Fields:    map[string]string{},
	}
	for k, v := range fields {
		switch {
		case strings.HasPrefix(k, "intent.field."):
			intent.Fields[strings.TrimPrefix(k, "intent.field.")] = v
		case strings.HasPrefix(k, "trigger.field."):
			intent.Fields[strings.TrimPrefix(k, "trigger.field.")] = v
		}
	}
	if len(intent.Fields) == 0 {
		intent.Fields = nil
	}
	return intent
}

func (t APICallIntent) APIEvent() APIEvent {
	return APIEvent{
		NodeID:    t.NodeID,
		API:       t.API,
		Operation: t.Operation,
		Subject:   t.Subject,
		Fields:    t.Fields,
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
