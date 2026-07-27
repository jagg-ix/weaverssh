package pubsub

import (
	"context"
	"testing"
	"time"
)

func TestMQTTBrokerPublishesToSubscriber(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	broker := NewMQTTBroker(MQTTBrokerConfig{Addr: "127.0.0.1:0"})
	if err := broker.Listen(ctx); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer broker.Close()
	go func() { _ = broker.Serve(ctx) }()

	brokerURL := "mqtt://" + broker.Addr()
	sub, err := DialMQTT(ctx, MQTTConfig{Broker: brokerURL, ClientID: "sub", ConnectTimeout: time.Second})
	if err != nil {
		t.Fatalf("Dial subscriber: %v", err)
	}
	defer sub.Close()
	pub, err := DialMQTT(ctx, MQTTConfig{Broker: brokerURL, ClientID: "pub", ConnectTimeout: time.Second})
	if err != nil {
		t.Fatalf("Dial publisher: %v", err)
	}
	defer pub.Close()

	gotCh := make(chan []Message, 1)
	subCtx, subCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer subCancel()
	go func() {
		got, _ := sub.Subscribe(subCtx, "weaverssh/#", 1)
		gotCh <- got
	}()
	time.Sleep(100 * time.Millisecond)
	if err := pub.Publish("weaverssh/runtime/status", []byte("ready")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	got := <-gotCh
	if len(got) != 1 {
		t.Fatalf("message count = %d, want 1", len(got))
	}
	if got[0].Topic != "weaverssh/runtime/status" || string(got[0].Payload) != "ready" {
		t.Fatalf("unexpected message: %+v", got[0])
	}
}

func TestMQTTBrokerStatusPing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	broker := NewMQTTBroker(MQTTBrokerConfig{Addr: "127.0.0.1:0"})
	if err := broker.Listen(ctx); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer broker.Close()
	go func() { _ = broker.Serve(ctx) }()

	client, err := DialMQTT(ctx, MQTTConfig{Broker: "mqtt://" + broker.Addr(), ClientID: "ping", ConnectTimeout: time.Second})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	pingCtx, pingCancel := context.WithTimeout(context.Background(), time.Second)
	defer pingCancel()
	if err := client.Ping(pingCtx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}
