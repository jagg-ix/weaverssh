package pubsub

import (
	"fmt"
	"strings"

	"weaverssh/flowcontrol"
)

const DefaultProtocolBufferTopic = "weaverssh/settings/protocol-buffers/v1"

func ProtocolBufferTopic(prefix string) string {
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix == "" { return DefaultProtocolBufferTopic }
	return prefix + "/settings/protocol-buffers/v1"
}

// PublishProtocolBufferUpdate publishes the exact generation/digest envelope.
// Subscribers must call ApplyProtocolBufferMessage rather than copying fields.
func PublishProtocolBufferUpdate(client interface{ Publish(string, []byte) error }, prefix string, update flowcontrol.BufferUpdate) (string, error) {
	if client == nil { return "", fmt.Errorf("MQTT protocol buffer publisher is required") }
	payload, err := flowcontrol.EncodeBufferUpdate(update)
	if err != nil { return "", err }
	topic := ProtocolBufferTopic(prefix)
	return topic, client.Publish(topic, payload)
}

func ApplyProtocolBufferMessage(coordinator *flowcontrol.BufferCoordinator, message Message, prefix string) (flowcontrol.BufferSnapshot, error) {
	if coordinator == nil { return flowcontrol.BufferSnapshot{}, fmt.Errorf("protocol buffer coordinator is required") }
	if message.Topic != ProtocolBufferTopic(prefix) { return flowcontrol.BufferSnapshot{}, fmt.Errorf("unexpected protocol buffer topic %q", message.Topic) }
	update, err := flowcontrol.DecodeBufferUpdate(message.Payload)
	if err != nil { return flowcontrol.BufferSnapshot{}, err }
	return coordinator.Apply(update)
}
