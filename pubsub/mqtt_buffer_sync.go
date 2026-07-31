package pubsub

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"weaverssh/flowcontrol"
)

// MQTTBufferFactory creates MQTT clients with the coordinator's exact read and
// write sizes. A committed settings change closes clients from older
// generations so no live MQTT connection continues with stale buffering.
type MQTTBufferFactory struct {
	mu sync.Mutex
	snapshot flowcontrol.BufferSnapshot
	clients map[*SyncedMQTTClient]struct{}
	unregister func()
	closed bool
}

type SyncedMQTTClient struct {
	*MQTTClient
	factory *MQTTBufferFactory
	generation uint64
	closeOnce sync.Once
	closeErr error
}

func NewMQTTBufferFactory(coordinator *flowcontrol.BufferCoordinator) (*MQTTBufferFactory, error) {
	if coordinator == nil { return nil, errors.New("MQTT buffer coordinator is required") }
	factory := &MQTTBufferFactory{clients: map[*SyncedMQTTClient]struct{}{}}
	unregister, err := coordinator.Register(factory)
	if err != nil { return nil, err }
	factory.unregister = unregister
	return factory, nil
}

func (f *MQTTBufferFactory) ProtocolBufferName() string { return "mqtt" }
func (f *MQTTBufferFactory) PrepareProtocolBuffers(snapshot flowcontrol.BufferSnapshot) error {
	if err := snapshot.Validate(); err != nil { return err }
	return snapshot.Buffers.Validate()
}
func (f *MQTTBufferFactory) CommitProtocolBuffers(snapshot flowcontrol.BufferSnapshot) {
	f.mu.Lock()
	oldGeneration := f.snapshot.Generation
	f.snapshot = snapshot
	clients := make([]*SyncedMQTTClient, 0, len(f.clients))
	if oldGeneration != 0 && oldGeneration != snapshot.Generation {
		for client := range f.clients { clients = append(clients, client) }
	}
	f.mu.Unlock()
	for _, client := range clients { _ = client.Close() }
}

func (f *MQTTBufferFactory) Current() flowcontrol.BufferSnapshot {
	if f == nil { return flowcontrol.BufferSnapshot{} }
	f.mu.Lock(); defer f.mu.Unlock()
	return f.snapshot
}

func (f *MQTTBufferFactory) Dial(ctx context.Context, cfg MQTTConfig) (*SyncedMQTTClient, error) {
	if f == nil { return nil, errors.New("MQTT buffer factory is nil") }
	f.mu.Lock()
	if f.closed { f.mu.Unlock(); return nil, errors.New("MQTT buffer factory is closed") }
	snapshot := f.snapshot
	f.mu.Unlock()
	client, err := dialMQTTWithProtocolBuffers(ctx, cfg, snapshot.Buffers)
	if err != nil { return nil, err }
	synced := &SyncedMQTTClient{MQTTClient: client, factory: f, generation: snapshot.Generation}
	f.mu.Lock()
	if f.closed || f.snapshot.Generation != snapshot.Generation {
		f.mu.Unlock(); _ = client.Close(); return nil, flowcontrol.ErrStaleBufferUpdate
	}
	f.clients[synced] = struct{}{}
	f.mu.Unlock()
	return synced, nil
}

func (f *MQTTBufferFactory) Close() error {
	if f == nil { return nil }
	f.mu.Lock()
	if f.closed { f.mu.Unlock(); return nil }
	f.closed = true
	clients := make([]*SyncedMQTTClient, 0, len(f.clients))
	for client := range f.clients { clients = append(clients, client) }
	unregister := f.unregister
	f.unregister = nil
	f.mu.Unlock()
	if unregister != nil { unregister() }
	var errs []error
	for _, client := range clients { if err := client.Close(); err != nil { errs = append(errs, err) } }
	return errors.Join(errs...)
}

func (c *SyncedMQTTClient) BufferGeneration() uint64 { if c == nil { return 0 }; return c.generation }
func (c *SyncedMQTTClient) Close() error {
	if c == nil { return nil }
	c.closeOnce.Do(func() {
		if c.factory != nil { c.factory.mu.Lock(); delete(c.factory.clients, c); c.factory.mu.Unlock() }
		if c.MQTTClient != nil { c.closeErr = c.MQTTClient.Close() }
	})
	return c.closeErr
}

func dialMQTTWithProtocolBuffers(ctx context.Context, cfg MQTTConfig, buffers flowcontrol.ProtocolBuffers) (*MQTTClient, error) {
	buffers = buffers.Normalized()
	if err := buffers.Validate(); err != nil { return nil, err }
	addr, network, useTLS, serverName, err := parseBroker(cfg.Broker)
	if err != nil { return nil, err }
	if cfg.ClientID == "" { cfg.ClientID = "weaverssh-" + newID(time.Now().UTC().String()) }
	if cfg.KeepAlive <= 0 { cfg.KeepAlive = 30 * time.Second }
	if cfg.ConnectTimeout <= 0 { cfg.ConnectTimeout = 5 * time.Second }
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
			tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, InsecureSkipVerify: cfg.InsecureTLS} //nolint:gosec
		} else {
			tlsCfg = tlsCfg.Clone()
			if tlsCfg.ServerName == "" { tlsCfg.ServerName = serverName }
		}
		dialer := tls.Dialer{Config: tlsCfg}
		conn, err = dialer.DialContext(ctx, network, addr)
	} else {
		var dialer net.Dialer
		conn, err = dialer.DialContext(ctx, network, addr)
	}
	if err != nil { return nil, err }
	client := &MQTTClient{
		cfg: cfg,
		conn: conn,
		rw: bufio.NewReadWriter(
			bufio.NewReaderSize(conn, buffers.MQTTReadBufferBytes),
			bufio.NewWriterSize(conn, buffers.MQTTWriteBufferBytes),
		),
	}
	if err := client.connect(ctx); err != nil { _ = conn.Close(); return nil, err }
	return client, nil
}
