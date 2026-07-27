package pubsub

import (
	"context"
	"testing"
	"time"
)

func TestEventTopicAndValidation(t *testing.T) {
	event := NewEvent("status", "runtime", "ready", map[string]string{"plane": "ok"})
	payload, err := event.JSON()
	if err != nil {
		t.Fatalf("event JSON: %v", err)
	}
	decoded, err := DecodeEvent(payload)
	if err != nil {
		t.Fatalf("decode event: %v", err)
	}
	if decoded.Version != EventVersion || decoded.Fields["plane"] != "ok" {
		t.Fatalf("decoded event mismatch: %+v", decoded)
	}
	topic, err := EventTopic("weaverssh", event.Component, event.Type)
	if err != nil {
		t.Fatalf("event topic: %v", err)
	}
	if topic != "weaverssh/runtime/status" {
		t.Fatalf("topic=%q", topic)
	}
	if err := ValidatePublishTopic("weaverssh/+/status"); err == nil {
		t.Fatalf("publish topic with wildcard should be rejected")
	}
	if err := ValidateSubscribeTopic("weaverssh/+/status"); err != nil {
		t.Fatalf("subscribe wildcard should be accepted: %v", err)
	}
}

func TestBusPublishesToMatchingSubscribers(t *testing.T) {
	bus := NewBus()
	ch, cancel, err := bus.Subscribe("weaverssh/relay/#", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if err := bus.Publish("weaverssh/runtime/status", []byte("miss")); err != nil {
		t.Fatal(err)
	}
	if err := bus.Publish("weaverssh/relay/session", []byte("hit")); err != nil {
		t.Fatal(err)
	}
	ctx, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	messages := Collect(ctx, ch, 1)
	if len(messages) != 1 || messages[0].Topic != "weaverssh/relay/session" || string(messages[0].Payload) != "hit" {
		t.Fatalf("unexpected messages: %+v", messages)
	}
}

func TestTopicMatches(t *testing.T) {
	cases := []struct {
		filter string
		topic  string
		want   bool
	}{
		{"weaverssh/#", "weaverssh/runtime/status", true},
		{"weaverssh/+/status", "weaverssh/runtime/status", true},
		{"weaverssh/+/status", "weaverssh/runtime/fault", false},
		{"weaverssh/relay", "weaverssh/relay/session", false},
	}
	for _, tc := range cases {
		if got := TopicMatches(tc.filter, tc.topic); got != tc.want {
			t.Fatalf("TopicMatches(%q,%q)=%t want %t", tc.filter, tc.topic, got, tc.want)
		}
	}
}
