package pubsub

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	EventVersion  = "weaverssh.pubsub.v1"
	DefaultPrefix = "weaverssh"
)

// EventOrigin classifies where an event entered the weaverssh event system.
// Internal events come from weaverssh components, external events come from
// adapters/tools outside the data-plane owner, and pubsub events originate in
// the event bus/broker layer itself.
type EventOrigin string

const (
	EventOriginInternal EventOrigin = "internal"
	EventOriginExternal EventOrigin = "external"
	EventOriginPubSub   EventOrigin = "pubsub"
)

// Event is the common payload weaverssh components publish to local subscribers
// or to an MQTT broker. Keep fields stringly typed so CLI, JSON logs, and
// lightweight agents can consume it without generated bindings.
type Event struct {
	Version   string            `json:"version"`
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	Component string            `json:"component"`
	Origin    EventOrigin       `json:"origin,omitempty"`
	Message   string            `json:"message,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
	At        string            `json:"at"`
}

// Message is a broker or local bus delivery with topic and raw payload.
type Message struct {
	Topic   string `json:"topic"`
	Payload []byte `json:"payload"`
}

func NewEvent(eventType, component, message string, fields map[string]string) Event {
	return NewEventFrom(EventOriginInternal, eventType, component, message, fields)
}

func NewEventFrom(origin EventOrigin, eventType, component, message string, fields map[string]string) Event {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return Event{
		Version:   EventVersion,
		ID:        newID(now),
		Type:      strings.TrimSpace(eventType),
		Component: strings.TrimSpace(component),
		Origin:    normalizeEventOrigin(origin),
		Message:   strings.TrimSpace(message),
		Fields:    copyFields(fields),
		At:        now,
	}
}

func (e Event) Validate() error {
	if strings.TrimSpace(e.Version) == "" {
		return fmt.Errorf("event version is required")
	}
	if e.Version != EventVersion {
		return fmt.Errorf("unsupported event version %q", e.Version)
	}
	if strings.TrimSpace(e.Type) == "" {
		return fmt.Errorf("event type is required")
	}
	if strings.TrimSpace(e.Component) == "" {
		return fmt.Errorf("event component is required")
	}
	if strings.TrimSpace(e.ID) == "" {
		return fmt.Errorf("event id is required")
	}
	if strings.TrimSpace(string(e.Origin)) != "" {
		if _, err := ParseEventOrigin(string(e.Origin)); err != nil {
			return err
		}
	}
	if strings.TrimSpace(e.At) == "" {
		return fmt.Errorf("event timestamp is required")
	}
	return nil
}

func (e Event) Normalized() Event {
	e.Type = strings.TrimSpace(e.Type)
	e.Component = strings.TrimSpace(e.Component)
	e.Message = strings.TrimSpace(e.Message)
	e.Origin = normalizeEventOrigin(e.Origin)
	e.Fields = copyFields(e.Fields)
	return e
}

func KnownEventOrigins() []EventOrigin {
	return []EventOrigin{EventOriginInternal, EventOriginExternal, EventOriginPubSub}
}

func ParseEventOrigin(value string) (EventOrigin, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return EventOriginInternal, nil
	}
	for _, origin := range KnownEventOrigins() {
		if value == string(origin) {
			return origin, nil
		}
	}
	return "", fmt.Errorf("unsupported event origin %q", value)
}

func normalizeEventOrigin(origin EventOrigin) EventOrigin {
	parsed, err := ParseEventOrigin(string(origin))
	if err != nil {
		return origin
	}
	return parsed
}

func (e Event) JSON() ([]byte, error) {
	e = e.Normalized()
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

func DecodeEvent(payload []byte) (Event, error) {
	var event Event
	if err := json.Unmarshal(payload, &event); err != nil {
		return Event{}, err
	}
	event = event.Normalized()
	if err := event.Validate(); err != nil {
		return Event{}, err
	}
	return event, nil
}

func EventTopic(prefix, component, eventType string) (string, error) {
	prefix = cleanTopicPart(prefix)
	if prefix == "" {
		prefix = DefaultPrefix
	}
	component = cleanTopicPart(component)
	eventType = cleanTopicPart(eventType)
	if component == "" {
		return "", fmt.Errorf("component is required")
	}
	if eventType == "" {
		return "", fmt.Errorf("event type is required")
	}
	topic := prefix + "/" + component + "/" + eventType
	return topic, ValidatePublishTopic(topic)
}

func ValidatePublishTopic(topic string) error {
	topic = strings.TrimSpace(topic)
	if topic == "" {
		return fmt.Errorf("MQTT topic is required")
	}
	if len(topic) > 65535 {
		return fmt.Errorf("MQTT topic is too long")
	}
	if strings.ContainsAny(topic, "+#") {
		return fmt.Errorf("MQTT publish topic must not contain wildcards")
	}
	for _, part := range strings.Split(topic, "/") {
		if strings.TrimSpace(part) == "" {
			return fmt.Errorf("MQTT topic contains an empty level")
		}
	}
	return nil
}

func ValidateSubscribeTopic(topic string) error {
	topic = strings.TrimSpace(topic)
	if topic == "" {
		return fmt.Errorf("MQTT topic filter is required")
	}
	if len(topic) > 65535 {
		return fmt.Errorf("MQTT topic filter is too long")
	}
	parts := strings.Split(topic, "/")
	for i, part := range parts {
		if strings.Contains(part, "#") && !(part == "#" && i == len(parts)-1) {
			return fmt.Errorf("MQTT # wildcard must occupy the final level")
		}
		if strings.Contains(part, "+") && part != "+" {
			return fmt.Errorf("MQTT + wildcard must occupy a whole level")
		}
	}
	return nil
}

func cleanTopicPart(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, " ", "-")
	value = strings.Trim(value, "/")
	return value
}

func copyFields(fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]string, len(fields))
	for k, v := range fields {
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

func newID(seed string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strings.ReplaceAll(seed, ":", "")
	}
	return hex.EncodeToString(b[:])
}
