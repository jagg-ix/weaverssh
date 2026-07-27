package pubsub

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

type rawPacket struct {
	packetType byte
	flags      byte
	payload    []byte
}

func fakeDial(handler func(net.Conn)) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go handler(server)
		return client, nil
	}
}

func readRawPacket(t *testing.T, conn net.Conn) rawPacket {
	t.Helper()
	reader := bufio.NewReader(conn)
	header, err := reader.ReadByte()
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	remaining, err := readRemainingLength(reader)
	if err != nil {
		t.Fatalf("read remaining length: %v", err)
	}
	payload := make([]byte, remaining)
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	return rawPacket{packetType: header >> 4, flags: header & 0x0f, payload: payload}
}

func writeRawPacket(t *testing.T, conn net.Conn, packetType byte, flags byte, payload []byte) {
	t.Helper()
	fixed := []byte{packetType<<4 | flags}
	fixed = append(fixed, encodeRemainingLength(len(payload))...)
	fixed = append(fixed, payload...)
	if _, err := conn.Write(fixed); err != nil {
		t.Fatalf("write packet: %v", err)
	}
}

func TestMQTTPublishQoS0ToFakeBroker(t *testing.T) {
	got := make(chan Message, 1)
	cfg := MQTTConfig{
		Broker:   "mqtt://broker.invalid:1883",
		ClientID: "test-client",
		DialContext: fakeDial(func(conn net.Conn) {
			defer conn.Close()
			pkt := readRawPacket(t, conn)
			if pkt.packetType != mqttConnect {
				t.Fatalf("expected CONNECT, got %d", pkt.packetType)
			}
			writeRawPacket(t, conn, mqttConnAck, 0, []byte{0, 0})
			pkt = readRawPacket(t, conn)
			if pkt.packetType != mqttPublish {
				t.Fatalf("expected PUBLISH, got %d", pkt.packetType)
			}
			msg, err := decodePublish(pkt.flags, pkt.payload)
			if err != nil {
				t.Fatalf("decode publish: %v", err)
			}
			got <- msg
		}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := DialMQTT(ctx, cfg)
	if err != nil {
		t.Fatalf("dial mqtt: %v", err)
	}
	defer client.Close()
	if err := client.Publish("weaverssh/runtime/status", []byte("ready")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	select {
	case msg := <-got:
		if msg.Topic != "weaverssh/runtime/status" || string(msg.Payload) != "ready" {
			t.Fatalf("unexpected message: %+v", msg)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for publish")
	}
}

func TestMQTTSubscribeQoS0FromFakeBroker(t *testing.T) {
	cfg := MQTTConfig{
		Broker:   "mqtt://broker.invalid:1883",
		ClientID: "test-client",
		DialContext: fakeDial(func(conn net.Conn) {
			defer conn.Close()
			pkt := readRawPacket(t, conn)
			if pkt.packetType != mqttConnect {
				t.Fatalf("expected CONNECT, got %d", pkt.packetType)
			}
			writeRawPacket(t, conn, mqttConnAck, 0, []byte{0, 0})
			pkt = readRawPacket(t, conn)
			if pkt.packetType != mqttSubscribe || len(pkt.payload) < 2 {
				t.Fatalf("expected SUBSCRIBE, got %+v", pkt)
			}
			packetID := pkt.payload[:2]
			writeRawPacket(t, conn, mqttSubAck, 0, []byte{packetID[0], packetID[1], 0})
			body := appendUTF8(nil, "weaverssh/runtime/status")
			body = append(body, []byte("ready")...)
			writeRawPacket(t, conn, mqttPublish, 0, body)
		}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := DialMQTT(ctx, cfg)
	if err != nil {
		t.Fatalf("dial mqtt: %v", err)
	}
	defer client.Close()
	messages, err := client.Subscribe(ctx, "weaverssh/#", 1)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if len(messages) != 1 || messages[0].Topic != "weaverssh/runtime/status" || string(messages[0].Payload) != "ready" {
		t.Fatalf("unexpected messages: %+v", messages)
	}
}

func TestParseBrokerDefaults(t *testing.T) {
	addr, network, useTLS, serverName, err := parseBroker("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if addr != "example.com:1883" || network != "tcp" || useTLS || serverName != "example.com" {
		t.Fatalf("unexpected broker parse: addr=%s network=%s tls=%t server=%s", addr, network, useTLS, serverName)
	}
	addr, _, useTLS, _, err = parseBroker("mqtts://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if addr != "example.com:8883" || !useTLS {
		t.Fatalf("unexpected mqtts parse: addr=%s tls=%t", addr, useTLS)
	}
}
