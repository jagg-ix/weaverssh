package pubsub

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"weaverssh/flowcontrol"
)

func TestMQTTBufferFactoryUsesGenerationAndRecycles(t *testing.T) {
	coordinator := flowcontrol.NewDefaultBufferCoordinator()
	factory, err := NewMQTTBufferFactory(coordinator)
	if err != nil { t.Fatal(err) }
	defer factory.Close()

	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		reader := bufio.NewReader(serverConn)
		header, err := reader.ReadByte()
		if err != nil { serverDone <- err; return }
		if header>>4 != mqttConnect { serverDone <- io.ErrUnexpectedEOF; return }
		remaining, err := readRemainingLength(reader)
		if err != nil { serverDone <- err; return }
		if _, err := io.CopyN(io.Discard, reader, int64(remaining)); err != nil { serverDone <- err; return }
		if _, err := serverConn.Write([]byte{mqttConnAck << 4, 2, 0, 0}); err != nil { serverDone <- err; return }
		buffer := make([]byte, 8)
		_, err = serverConn.Read(buffer)
		serverDone <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := factory.Dial(ctx, MQTTConfig{
		Broker: "mqtt://buffer-sync.invalid:1883",
		DialContext: func(context.Context, string, string) (net.Conn, error) { return clientConn, nil },
	})
	if err != nil { t.Fatal(err) }
	initial := coordinator.Current()
	if client.BufferGeneration() != initial.Generation { t.Fatalf("client generation=%d want=%d", client.BufferGeneration(), initial.Generation) }
	if client.MQTTClient.rw.Reader.Size() != initial.Buffers.MQTTReadBufferBytes || client.MQTTClient.rw.Writer.Size() != initial.Buffers.MQTTWriteBufferBytes {
		t.Fatalf("MQTT buffers not aligned: reader=%d writer=%d snapshot=%+v", client.MQTTClient.rw.Reader.Size(), client.MQTTClient.rw.Writer.Size(), initial.Buffers)
	}

	if _, err := coordinator.Update(flowcontrol.ProtocolBuffersFromFrame(64*1024, 4)); err != nil { t.Fatal(err) }
	if err := client.Publish("weaverssh/test", []byte("stale")); err == nil {
		t.Fatal("stale MQTT client remained usable after buffer generation changed")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second): t.Fatal("MQTT client was not recycled")
	}
}
