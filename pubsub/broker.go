package pubsub

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// MQTTBrokerConfig configures the lightweight broker used for lab, system-test,
// and local agent fan-out. It intentionally implements MQTT 3.1.1 QoS 0 only.
type MQTTBrokerConfig struct {
	Addr   string
	Logger func(format string, args ...any)
}

// MQTTBroker is a small MQTT 3.1.1 QoS 0 broker. It is not a replacement for a
// production broker; use it to keep weaverssh event-bus tests self-contained.
type MQTTBroker struct {
	cfg MQTTBrokerConfig

	mu      sync.RWMutex
	ln      net.Listener
	clients map[*mqttBrokerClient]struct{}
}

type mqttBrokerClient struct {
	broker *MQTTBroker
	conn   net.Conn
	rw     *bufio.ReadWriter

	mu            sync.Mutex
	id            string
	subscriptions map[string]struct{}
}

// NewMQTTBroker creates a broker. Call Listen first if the caller needs the
// assigned address, otherwise Serve will listen lazily.
func NewMQTTBroker(cfg MQTTBrokerConfig) *MQTTBroker {
	if strings.TrimSpace(cfg.Addr) == "" {
		cfg.Addr = "127.0.0.1:1883"
	}
	return &MQTTBroker{cfg: cfg, clients: map[*mqttBrokerClient]struct{}{}}
}

func (b *MQTTBroker) logf(format string, args ...any) {
	if b != nil && b.cfg.Logger != nil {
		b.cfg.Logger(format, args...)
	}
}

func (b *MQTTBroker) Listen(ctx context.Context) error {
	if b == nil {
		return fmt.Errorf("MQTT broker is nil")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ln != nil {
		return nil
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", b.cfg.Addr)
	if err != nil {
		return err
	}
	b.ln = ln
	return nil
}

func (b *MQTTBroker) Addr() string {
	if b == nil {
		return ""
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.ln == nil {
		return ""
	}
	return b.ln.Addr().String()
}

func (b *MQTTBroker) Serve(ctx context.Context) error {
	if b == nil {
		return fmt.Errorf("MQTT broker is nil")
	}
	if err := b.Listen(ctx); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = b.Close()
	}()
	for {
		b.mu.RLock()
		ln := b.ln
		b.mu.RUnlock()
		if ln == nil {
			return nil
		}
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		client := &mqttBrokerClient{
			broker:        b,
			conn:          conn,
			rw:            bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
			subscriptions: map[string]struct{}{},
		}
		b.addClient(client)
		go client.serve()
	}
}

func (b *MQTTBroker) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	ln := b.ln
	b.ln = nil
	clients := make([]*mqttBrokerClient, 0, len(b.clients))
	for client := range b.clients {
		clients = append(clients, client)
	}
	b.mu.Unlock()
	for _, client := range clients {
		_ = client.conn.Close()
	}
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func ListenAndServeMQTT(ctx context.Context, cfg MQTTBrokerConfig) error {
	return NewMQTTBroker(cfg).Serve(ctx)
}

func (b *MQTTBroker) addClient(client *mqttBrokerClient) {
	b.mu.Lock()
	b.clients[client] = struct{}{}
	b.mu.Unlock()
	b.logf("client connected remote=%s", client.conn.RemoteAddr())
}

func (b *MQTTBroker) removeClient(client *mqttBrokerClient) {
	b.mu.Lock()
	delete(b.clients, client)
	b.mu.Unlock()
	b.logf("client disconnected id=%s remote=%s", client.id, client.conn.RemoteAddr())
	_ = client.conn.Close()
}

func (b *MQTTBroker) publish(msg Message) {
	b.mu.RLock()
	clients := make([]*mqttBrokerClient, 0, len(b.clients))
	for client := range b.clients {
		clients = append(clients, client)
	}
	b.mu.RUnlock()
	delivered := 0
	for _, client := range clients {
		if client.matches(msg.Topic) {
			if err := client.writePublish(msg.Topic, msg.Payload); err != nil {
				b.logf("deliver failed topic=%s to=%s err=%v", msg.Topic, client.id, err)
				continue
			}
			delivered++
		}
	}
	b.logf("publish topic=%s bytes=%d delivered=%d clients=%d", msg.Topic, len(msg.Payload), delivered, len(clients))
}

func (c *mqttBrokerClient) serve() {
	defer c.broker.removeClient(c)
	for {
		packetType, flags, payload, err := readMQTTPacket(c.rw)
		if err != nil {
			return
		}
		switch packetType {
		case mqttConnect:
			if err := c.handleConnect(payload); err != nil {
				return
			}
		case mqttPublish:
			msg, err := decodePublish(flags, payload)
			if err != nil {
				return
			}
			c.broker.publish(msg)
		case mqttSubscribe:
			if err := c.handleSubscribe(payload); err != nil {
				return
			}
		case mqttPingReq:
			if err := c.writePacket(mqttPingResp, 0, nil); err != nil {
				return
			}
		case mqttDisconnect:
			return
		default:
			return
		}
	}
}

func (c *mqttBrokerClient) handleConnect(payload []byte) error {
	protocol, rest, err := readUTF8(payload)
	if err != nil {
		return err
	}
	if protocol != mqttProtocolName || len(rest) < 4 || rest[0] != 4 {
		return fmt.Errorf("unsupported MQTT CONNECT")
	}
	connectFlags := rest[1]
	rest = rest[4:]
	clientID, rest, err := readUTF8(rest)
	if err != nil {
		return err
	}
	c.id = clientID
	if connectFlags&0x80 != 0 {
		_, rest, err = readUTF8(rest)
		if err != nil {
			return err
		}
	}
	if connectFlags&0x40 != 0 {
		_, rest, err = readUTF8(rest)
		if err != nil {
			return err
		}
	}
	if len(rest) != 0 {
		return fmt.Errorf("MQTT CONNECT has trailing bytes")
	}
	c.broker.logf("connect accepted id=%s remote=%s", c.id, c.conn.RemoteAddr())
	return c.writePacket(mqttConnAck, 0, []byte{0, 0})
}

func (c *mqttBrokerClient) handleSubscribe(payload []byte) error {
	if len(payload) < 3 {
		return io.ErrUnexpectedEOF
	}
	packetID := binary.BigEndian.Uint16(payload[:2])
	rest := payload[2:]
	var filters []string
	for len(rest) > 0 {
		filter, next, err := readUTF8(rest)
		if err != nil {
			return err
		}
		if len(next) < 1 {
			return io.ErrUnexpectedEOF
		}
		if err := ValidateSubscribeTopic(filter); err != nil {
			return err
		}
		filters = append(filters, filter)
		rest = next[1:]
	}
	if len(filters) == 0 {
		return fmt.Errorf("MQTT SUBSCRIBE has no filters")
	}
	c.mu.Lock()
	for _, filter := range filters {
		c.subscriptions[filter] = struct{}{}
	}
	c.mu.Unlock()
	c.broker.logf("subscribe id=%s filters=%s", c.id, strings.Join(filters, ","))
	ack := []byte{byte(packetID >> 8), byte(packetID)}
	for range filters {
		ack = append(ack, 0) // granted QoS 0
	}
	return c.writePacket(mqttSubAck, 0, ack)
}

func (c *mqttBrokerClient) matches(topic string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for filter := range c.subscriptions {
		if TopicMatches(filter, topic) {
			return true
		}
	}
	return false
}

func (c *mqttBrokerClient) writePublish(topic string, payload []byte) error {
	body := make([]byte, 0, 2+len(topic)+len(payload))
	body = appendUTF8(body, topic)
	body = append(body, payload...)
	return c.writePacket(mqttPublish, 0, body)
}

func (c *mqttBrokerClient) writePacket(packetType byte, flags byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return writeMQTTPacket(c.rw, packetType, flags, payload)
}

func readMQTTPacket(rw *bufio.ReadWriter) (byte, byte, []byte, error) {
	header, err := rw.ReadByte()
	if err != nil {
		return 0, 0, nil, err
	}
	remaining, err := readRemainingLength(rw)
	if err != nil {
		return 0, 0, nil, err
	}
	payload := make([]byte, remaining)
	if _, err := io.ReadFull(rw, payload); err != nil {
		return 0, 0, nil, err
	}
	return header >> 4, header & 0x0f, payload, nil
}

func writeMQTTPacket(rw *bufio.ReadWriter, packetType byte, flags byte, payload []byte) error {
	fixed := []byte{packetType<<4 | flags}
	fixed = append(fixed, encodeRemainingLength(len(payload))...)
	if _, err := rw.Write(fixed); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := rw.Write(payload); err != nil {
			return err
		}
	}
	return rw.Flush()
}
