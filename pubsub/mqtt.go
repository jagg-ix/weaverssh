package pubsub

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type MQTTConfig struct {
	Broker          string
	ClientID        string
	Username        string
	Password        string
	KeepAlive       time.Duration
	ConnectTimeout  time.Duration
	InsecureTLS     bool
	DialContext     func(context.Context, string, string) (net.Conn, error)
	TLSClientConfig *tls.Config
}

type MQTTClient struct {
	cfg   MQTTConfig
	conn  net.Conn
	rw    *bufio.ReadWriter
	pktID atomic.Uint32
}

const (
	mqttConnect      byte = 1
	mqttConnAck      byte = 2
	mqttPublish      byte = 3
	mqttSubscribe    byte = 8
	mqttSubAck       byte = 9
	mqttPingReq      byte = 12
	mqttPingResp     byte = 13
	mqttDisconnect   byte = 14
	mqttProtocolName      = "MQTT"
)

func DialMQTT(ctx context.Context, cfg MQTTConfig) (*MQTTClient, error) {
	addr, network, useTLS, serverName, err := parseBroker(cfg.Broker)
	if err != nil {
		return nil, err
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "weaverssh-" + newID(time.Now().UTC().String())
	}
	if cfg.KeepAlive <= 0 {
		cfg.KeepAlive = 30 * time.Second
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 5 * time.Second
	}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > cfg.ConnectTimeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.ConnectTimeout)
		defer cancel()
	}

	var conn net.Conn
	if cfg.DialContext != nil {
		conn, err = cfg.DialContext(ctx, network, addr)
	} else if useTLS {
		tlsCfg := cfg.TLSClientConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, InsecureSkipVerify: cfg.InsecureTLS} //nolint:gosec // explicit CLI/debug option only
		} else {
			tlsCfg = tlsCfg.Clone()
			if tlsCfg.ServerName == "" {
				tlsCfg.ServerName = serverName
			}
		}
		dialer := tls.Dialer{Config: tlsCfg}
		conn, err = dialer.DialContext(ctx, network, addr)
	} else {
		var dialer net.Dialer
		conn, err = dialer.DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, err
	}
	client := &MQTTClient{cfg: cfg, conn: conn, rw: bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))}
	if err := client.connect(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return client, nil
}

func (c *MQTTClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	_ = c.writePacket(mqttDisconnect, 0, nil)
	return c.conn.Close()
}

func (c *MQTTClient) Publish(topic string, payload []byte) error {
	if err := ValidatePublishTopic(topic); err != nil {
		return err
	}
	body := make([]byte, 0, 2+len(topic)+len(payload))
	body = appendUTF8(body, topic)
	body = append(body, payload...)
	return c.writePacket(mqttPublish, 0, body)
}

func (c *MQTTClient) PublishEvent(prefix string, event Event) (string, error) {
	payload, err := event.JSON()
	if err != nil {
		return "", err
	}
	topic, err := EventTopic(prefix, event.Component, event.Type)
	if err != nil {
		return "", err
	}
	return topic, c.Publish(topic, payload)
}

func (c *MQTTClient) Subscribe(ctx context.Context, filter string, limit int) ([]Message, error) {
	if err := ValidateSubscribeTopic(filter); err != nil {
		return nil, err
	}
	id := uint16(c.pktID.Add(1))
	if id == 0 {
		id = 1
	}
	body := []byte{byte(id >> 8), byte(id)}
	body = appendUTF8(body, filter)
	body = append(body, 0) // QoS 0
	if err := c.writePacket(mqttSubscribe, 2, body); err != nil {
		return nil, err
	}
	packetType, flags, payload, err := c.readPacket(ctx)
	if err != nil {
		return nil, err
	}
	if packetType != mqttSubAck || len(payload) < 3 || binary.BigEndian.Uint16(payload[:2]) != id || payload[2] == 0x80 {
		return nil, fmt.Errorf("MQTT subscribe rejected for %q", filter)
	}
	if limit < 0 {
		limit = 0
	}
	var out []Message
	for limit == 0 || len(out) < limit {
		packetType, flags, payload, err = c.readPacket(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return out, nil
			}
			return out, err
		}
		switch packetType {
		case mqttPublish:
			msg, err := decodePublish(flags, payload)
			if err != nil {
				return out, err
			}
			out = append(out, msg)
		case mqttPingResp:
			continue
		default:
			continue
		}
	}
	return out, nil
}

func (c *MQTTClient) Ping(ctx context.Context) error {
	if err := c.writePacket(mqttPingReq, 0, nil); err != nil {
		return err
	}
	packetType, _, _, err := c.readPacket(ctx)
	if err != nil {
		return err
	}
	if packetType != mqttPingResp {
		return fmt.Errorf("MQTT expected PINGRESP, got packet type %d", packetType)
	}
	return nil
}

func (c *MQTTClient) connect(ctx context.Context) error {
	keepAlive := uint16(c.cfg.KeepAlive.Seconds())
	if keepAlive == 0 {
		keepAlive = 30
	}
	flags := byte(0x02) // clean session
	if c.cfg.Username != "" {
		flags |= 0x80
	}
	if c.cfg.Password != "" {
		flags |= 0x40
	}
	body := []byte{}
	body = appendUTF8(body, mqttProtocolName)
	body = append(body, 4, flags, byte(keepAlive>>8), byte(keepAlive))
	body = appendUTF8(body, c.cfg.ClientID)
	if c.cfg.Username != "" {
		body = appendUTF8(body, c.cfg.Username)
	}
	if c.cfg.Password != "" {
		body = appendUTF8(body, c.cfg.Password)
	}
	if err := c.writePacket(mqttConnect, 0, body); err != nil {
		return err
	}
	packetType, _, payload, err := c.readPacket(ctx)
	if err != nil {
		return err
	}
	if packetType != mqttConnAck || len(payload) < 2 {
		return fmt.Errorf("MQTT expected CONNACK")
	}
	if payload[1] != 0 {
		return fmt.Errorf("MQTT CONNACK rejected connection: code %d", payload[1])
	}
	return nil
}

func (c *MQTTClient) writePacket(packetType byte, flags byte, payload []byte) error {
	if c == nil || c.rw == nil {
		return fmt.Errorf("MQTT client is not connected")
	}
	fixed := []byte{packetType<<4 | flags}
	fixed = append(fixed, encodeRemainingLength(len(payload))...)
	if _, err := c.rw.Write(fixed); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := c.rw.Write(payload); err != nil {
			return err
		}
	}
	return c.rw.Flush()
}

func (c *MQTTClient) readPacket(ctx context.Context) (byte, byte, []byte, error) {
	for {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return 0, 0, nil, err
			}
		}
		if c.conn != nil {
			_ = c.conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		}
		header, err := c.rw.ReadByte()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return 0, 0, nil, err
		}
		remaining, err := readRemainingLength(c.rw)
		if err != nil {
			return 0, 0, nil, err
		}
		payload := make([]byte, remaining)
		if _, err := io.ReadFull(c.rw, payload); err != nil {
			return 0, 0, nil, err
		}
		return header >> 4, header & 0x0f, payload, nil
	}
}

func decodePublish(flags byte, payload []byte) (Message, error) {
	qos := (flags >> 1) & 0x03
	if qos != 0 {
		return Message{}, fmt.Errorf("MQTT QoS %d publish is not supported", qos)
	}
	topic, rest, err := readUTF8(payload)
	if err != nil {
		return Message{}, err
	}
	return Message{Topic: topic, Payload: append([]byte(nil), rest...)}, nil
}

func parseBroker(raw string) (addr, network string, useTLS bool, serverName string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "mqtt://127.0.0.1:1883"
	}
	if !strings.Contains(raw, "://") {
		raw = "mqtt://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", false, "", err
	}
	network = "tcp"
	switch u.Scheme {
	case "mqtt", "tcp":
		useTLS = false
	case "mqtts", "tls", "ssl":
		useTLS = true
	default:
		return "", "", false, "", fmt.Errorf("unsupported MQTT broker scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return "", "", false, "", fmt.Errorf("MQTT broker host is required")
	}
	port := u.Port()
	if port == "" {
		if useTLS {
			port = "8883"
		} else {
			port = "1883"
		}
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", "", false, "", fmt.Errorf("invalid MQTT broker port %q", port)
	}
	return net.JoinHostPort(host, port), network, useTLS, host, nil
}

func appendUTF8(dst []byte, value string) []byte {
	if len(value) > 65535 {
		value = value[:65535]
	}
	dst = append(dst, byte(len(value)>>8), byte(len(value)))
	return append(dst, []byte(value)...)
}

func readUTF8(buf []byte) (string, []byte, error) {
	if len(buf) < 2 {
		return "", nil, io.ErrUnexpectedEOF
	}
	n := int(binary.BigEndian.Uint16(buf[:2]))
	buf = buf[2:]
	if len(buf) < n {
		return "", nil, io.ErrUnexpectedEOF
	}
	return string(buf[:n]), buf[n:], nil
}

func encodeRemainingLength(n int) []byte {
	var out []byte
	for {
		digit := byte(n % 128)
		n /= 128
		if n > 0 {
			digit |= 0x80
		}
		out = append(out, digit)
		if n == 0 {
			break
		}
	}
	return out
}

func readRemainingLength(r io.ByteReader) (int, error) {
	multiplier := 1
	value := 0
	for i := 0; i < 4; i++ {
		digit, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		value += int(digit&127) * multiplier
		if digit&128 == 0 {
			return value, nil
		}
		multiplier *= 128
	}
	return 0, fmt.Errorf("malformed MQTT remaining length")
}
