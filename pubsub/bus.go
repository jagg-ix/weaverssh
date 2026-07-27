package pubsub

import (
	"context"
	"sync"
)

// Bus is an in-process pub-sub bus used by components before or without an
// external MQTT broker. It is intentionally small: publishing never blocks on a
// slow subscriber; slow subscribers drop messages and should use a bigger buffer.
type Bus struct {
	mu   sync.RWMutex
	next uint64
	subs map[uint64]subscription
}

type subscription struct {
	filter string
	ch     chan Message
}

func NewBus() *Bus {
	return &Bus{subs: map[uint64]subscription{}}
}

func (b *Bus) Subscribe(filter string, buffer int) (<-chan Message, func(), error) {
	if err := ValidateSubscribeTopic(filter); err != nil {
		return nil, nil, err
	}
	if buffer < 0 {
		buffer = 0
	}
	ch := make(chan Message, buffer)
	b.mu.Lock()
	b.next++
	id := b.next
	b.subs[id] = subscription{filter: filter, ch: ch}
	b.mu.Unlock()
	cancel := func() {
		b.mu.Lock()
		if sub, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(sub.ch)
		}
		b.mu.Unlock()
	}
	return ch, cancel, nil
}

func (b *Bus) Publish(topic string, payload []byte) error {
	if err := ValidatePublishTopic(topic); err != nil {
		return err
	}
	msg := Message{Topic: topic, Payload: append([]byte(nil), payload...)}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, sub := range b.subs {
		if !TopicMatches(sub.filter, topic) {
			continue
		}
		select {
		case sub.ch <- msg:
		default:
		}
	}
	return nil
}

func (b *Bus) PublishEvent(prefix string, event Event) (string, error) {
	payload, err := event.JSON()
	if err != nil {
		return "", err
	}
	topic, err := EventTopic(prefix, event.Component, event.Type)
	if err != nil {
		return "", err
	}
	return topic, b.Publish(topic, payload)
}

func Collect(ctx context.Context, ch <-chan Message, limit int) []Message {
	if limit < 0 {
		limit = 0
	}
	out := []Message{}
	for limit == 0 || len(out) < limit {
		select {
		case <-ctx.Done():
			return out
		case msg, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, msg)
		}
	}
	return out
}

func TopicMatches(filter, topic string) bool {
	fp := splitTopic(filter)
	tp := splitTopic(topic)
	for i, part := range fp {
		if part == "#" {
			return i == len(fp)-1
		}
		if i >= len(tp) {
			return false
		}
		if part == "+" {
			continue
		}
		if part != tp[i] {
			return false
		}
	}
	return len(fp) == len(tp)
}

func splitTopic(topic string) []string {
	if topic == "" {
		return nil
	}
	var parts []string
	start := 0
	for i := 0; i <= len(topic); i++ {
		if i == len(topic) || topic[i] == '/' {
			parts = append(parts, topic[start:i])
			start = i + 1
		}
	}
	return parts
}
