package socketengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gnet "github.com/panjf2000/gnet/v2"
	"github.com/panjf2000/gnet/v2/pkg/pool/byteslice"
)

const DependencyVersion = "v2.9.7"

// DialFunc opens the authenticated routed backend for one accepted local socket.
type DialFunc func(context.Context, Route) (net.Conn, error)

// ErrorFunc receives asynchronous bridge errors. It must return quickly.
type ErrorFunc func(route Route, remote string, err error)

// Engine manages multiple local listeners with gnet and bridges each accepted
// stream to an independently authenticated weaverssh backend connection.
type Engine struct {
	gnet.BuiltinEventEngine

	config normalizedConfig
	dial   DialFunc
	onErr  ErrorFunc

	routes map[string]*routeState
	states sync.Map

	ready    chan struct{}
	done     chan struct{}
	bootOnce sync.Once
	doneOnce sync.Once
	stopOnce sync.Once
	runOnce  atomic.Bool
	engine   gnet.Engine
	runCtx   context.Context

	bootErrMu sync.Mutex
	bootErr   error
	stopErrMu sync.Mutex
	stopErr   error

	active       atomic.Int64
	accepted     atomic.Uint64
	rejected     atomic.Uint64
	dialFailures atomic.Uint64
	queueDrops   atomic.Uint64
	bytesIn      atomic.Uint64
	bytesOut     atomic.Uint64
}

type routeState struct {
	*routeRuntime
	active       atomic.Int64
	accepted     atomic.Uint64
	rejected     atomic.Uint64
	dialFailures atomic.Uint64
	queueDrops   atomic.Uint64
	bytesIn      atomic.Uint64
	bytesOut     atomic.Uint64
}

type bridgeState struct {
	owner    *Engine
	route    *routeState
	client   gnet.Conn
	frontend net.Conn
	remote   string

	toBackend  chan []byte
	frontendEOF chan struct{}
	done        chan struct{}
	eofOnce     sync.Once
	closeOnce   sync.Once
	backendMu   sync.Mutex
	backend     net.Conn
	lastActive  atomic.Int64
}

// Stats is a point-in-time engine snapshot.
type Stats struct {
	Active       int64        `json:"active"`
	Accepted     uint64       `json:"accepted"`
	Rejected     uint64       `json:"rejected"`
	DialFailures uint64       `json:"dial_failures"`
	QueueDrops   uint64       `json:"queue_drops"`
	BytesIn      uint64       `json:"bytes_in"`
	BytesOut     uint64       `json:"bytes_out"`
	Routes       []RouteStats `json:"routes"`
}

// RouteStats is a point-in-time route snapshot.
type RouteStats struct {
	Name         string `json:"name"`
	Listen       string `json:"listen"`
	Node         string `json:"node"`
	Address      string `json:"address"`
	Active       int64  `json:"active"`
	Accepted     uint64 `json:"accepted"`
	Rejected     uint64 `json:"rejected"`
	DialFailures uint64 `json:"dial_failures"`
	QueueDrops   uint64 `json:"queue_drops"`
	BytesIn      uint64 `json:"bytes_in"`
	BytesOut     uint64 `json:"bytes_out"`
}

func New(config Config, dial DialFunc, onError ErrorFunc) (*Engine, error) {
	if dial == nil {
		return nil, errors.New("socketengine: dial function is required")
	}
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	engine := &Engine{
		config: normalized,
		dial:   dial,
		onErr:  onError,
		routes: make(map[string]*routeState, len(normalized.routes)),
		ready:  make(chan struct{}),
		done:   make(chan struct{}),
	}
	for _, route := range normalized.routes {
		engine.routes[route.key] = &routeState{routeRuntime: route}
	}
	return engine, nil
}

// Run starts every configured listener in one gnet engine and blocks until the
// engine stops or fails. Run may be called only once.
func (e *Engine) Run(ctx context.Context) error {
	if e == nil {
		return errors.New("socketengine: nil engine")
	}
	if !e.runOnce.CompareAndSwap(false, true) {
		return errors.New("socketengine: engine already started")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	e.runCtx = ctx
	if err := e.prepareUnixSockets(); err != nil {
		e.bootOnce.Do(func() { close(e.ready) })
		e.doneOnce.Do(func() { close(e.done) })
		return err
	}

	go func() {
		select {
		case <-ctx.Done():
			stopCtx, cancel := context.WithTimeout(context.Background(), e.config.shutdownTimeout)
			defer cancel()
			_ = e.Stop(stopCtx)
		case <-e.done:
		}
	}()

	options := []gnet.Option{
		gnet.WithLoadBalancing(e.loadBalancing()),
		gnet.WithReadBufferCap(e.config.ReadBufferBytes),
		gnet.WithReuseAddr(true),
		gnet.WithReusePort(e.config.ReusePort),
		gnet.WithTCPNoDelay(gnet.TCPNoDelay),
	}
	if e.config.EventLoops > 0 {
		options = append(options, gnet.WithNumEventLoop(e.config.EventLoops))
	} else {
		options = append(options, gnet.WithMulticore(true))
	}
	if e.config.tcpKeepAlive > 0 {
		options = append(options, gnet.WithTCPKeepAlive(e.config.tcpKeepAlive))
	}
	if e.config.idleTimeout > 0 {
		options = append(options, gnet.WithTicker(true))
	}

	err := gnet.Rotate(e, e.config.addresses, options...)
	e.bootOnce.Do(func() { close(e.ready) })
	e.doneOnce.Do(func() { close(e.done) })
	e.removeUnixSockets()
	if bootErr := e.getBootError(); bootErr != nil {
		return bootErr
	}
	if ctx.Err() != nil && (err == nil || errors.Is(err, context.Canceled)) {
		return nil
	}
	return err
}

// Stop closes active bridges and gracefully stops the gnet event loops.
func (e *Engine) Stop(ctx context.Context) error {
	if e == nil || !e.runOnce.Load() {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	e.stopOnce.Do(func() {
		e.closeAll()
		var err error
		select {
		case <-e.ready:
			select {
			case <-e.done:
			default:
				err = e.engine.Stop(ctx)
			}
		case <-e.done:
		case <-ctx.Done():
			err = ctx.Err()
		}
		e.stopErrMu.Lock()
		e.stopErr = err
		e.stopErrMu.Unlock()
	})
	e.stopErrMu.Lock()
	defer e.stopErrMu.Unlock()
	return e.stopErr
}

func (e *Engine) Ready() <-chan struct{} {
	if e == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return e.ready
}

func (e *Engine) Addresses() []string {
	if e == nil {
		return nil
	}
	return append([]string(nil), e.config.addresses...)
}

func (e *Engine) Snapshot() Stats {
	if e == nil {
		return Stats{}
	}
	stats := Stats{
		Active:       e.active.Load(),
		Accepted:     e.accepted.Load(),
		Rejected:     e.rejected.Load(),
		DialFailures: e.dialFailures.Load(),
		QueueDrops:   e.queueDrops.Load(),
		BytesIn:      e.bytesIn.Load(),
		BytesOut:     e.bytesOut.Load(),
	}
	for _, route := range e.routes {
		stats.Routes = append(stats.Routes, RouteStats{
			Name:         route.Name,
			Listen:       route.Listen,
			Node:         route.Node,
			Address:      route.Address,
			Active:       route.active.Load(),
			Accepted:     route.accepted.Load(),
			Rejected:     route.rejected.Load(),
			DialFailures: route.dialFailures.Load(),
			QueueDrops:   route.queueDrops.Load(),
			BytesIn:      route.bytesIn.Load(),
			BytesOut:     route.bytesOut.Load(),
		})
	}
	sort.Slice(stats.Routes, func(i, j int) bool { return stats.Routes[i].Name < stats.Routes[j].Name })
	return stats
}

func (e *Engine) OnBoot(engine gnet.Engine) gnet.Action {
	e.engine = engine
	for _, route := range e.routes {
		if route.unixPath == "" {
			continue
		}
		if err := os.Chmod(route.unixPath, e.config.unixMode); err != nil {
			e.setBootError(fmt.Errorf("socketengine: chmod Unix listener %s: %w", route.unixPath, err))
			e.bootOnce.Do(func() { close(e.ready) })
			return gnet.Shutdown
		}
	}
	e.bootOnce.Do(func() { close(e.ready) })
	return gnet.None
}

func (e *Engine) OnShutdown(gnet.Engine) {
	e.closeAll()
	e.doneOnce.Do(func() { close(e.done) })
}

func (e *Engine) OnOpen(client gnet.Conn) ([]byte, gnet.Action) {
	key := listenerKey(client.LocalAddr())
	route := e.routes[key]
	if route == nil || !tryAcquire(&e.active, int64(e.config.MaxConnections)) {
		e.reject(route)
		return nil, gnet.Close
	}
	if !tryAcquire(&route.active, int64(route.MaxConnections)) {
		e.active.Add(-1)
		e.reject(route)
		return nil, gnet.Close
	}

	remote := ""
	if address := client.RemoteAddr(); address != nil {
		remote = address.String()
	}
	frontend, err := duplicateFrontend(client, route.Name)
	if err != nil {
		e.active.Add(-1)
		route.active.Add(-1)
		e.reject(route)
		e.report(route.Route, remote, fmt.Errorf("socketengine: duplicate accepted socket: %w", err))
		return nil, gnet.Close
	}
	state := &bridgeState{
		owner:       e,
		route:       route,
		client:      client,
		frontend:    frontend,
		remote:      remote,
		toBackend:   make(chan []byte, e.config.QueueDepth),
		frontendEOF: make(chan struct{}),
		done:        make(chan struct{}),
	}
	state.touch()
	client.SetContext(state)
	e.states.Store(state, struct{}{})
	e.accepted.Add(1)
	route.accepted.Add(1)
	go state.bridge()
	return nil, gnet.None
}

func (e *Engine) OnTraffic(client gnet.Conn) gnet.Action {
	state, ok := client.Context().(*bridgeState)
	if !ok || state == nil {
		return gnet.Close
	}
	state.touch()
	remaining := client.InboundBuffered()
	for remaining > 0 {
		chunk := remaining
		if chunk > e.config.ReadBufferBytes {
			chunk = e.config.ReadBufferBytes
		}
		view, err := client.Next(chunk)
		if err != nil {
			state.report(err)
			return gnet.Close
		}
		payload := byteslice.Get(len(view))
		copy(payload, view)
		select {
		case state.toBackend <- payload:
			state.owner.bytesIn.Add(uint64(len(payload)))
			state.route.bytesIn.Add(uint64(len(payload)))
		case <-state.done:
			byteslice.Put(payload)
			return gnet.Close
		default:
			byteslice.Put(payload)
			state.owner.queueDrops.Add(1)
			state.route.queueDrops.Add(1)
			state.report(errors.New("socketengine: client-to-backend queue is full"))
			return gnet.Close
		}
		remaining -= chunk
	}
	return gnet.None
}

func (e *Engine) OnClose(client gnet.Conn, err error) gnet.Action {
	state, ok := client.Context().(*bridgeState)
	if !ok || state == nil {
		return gnet.None
	}
	if errors.Is(err, io.EOF) {
		state.signalFrontendEOF()
		return gnet.None
	}
	if err != nil && !normalSocketError(err) {
		state.report(err)
	}
	state.shutdown()
	return gnet.None
}

func (e *Engine) OnTick() (time.Duration, gnet.Action) {
	if e.config.idleTimeout <= 0 {
		return time.Hour, gnet.None
	}
	now := time.Now()
	e.states.Range(func(key, _ any) bool {
		state, ok := key.(*bridgeState)
		if ok && now.Sub(time.Unix(0, state.lastActive.Load())) >= e.config.idleTimeout {
			state.report(fmt.Errorf("socketengine: idle timeout after %s", e.config.idleTimeout))
			state.shutdown()
		}
		return true
	})
	delay := e.config.idleTimeout / 2
	if delay < 250*time.Millisecond {
		delay = 250 * time.Millisecond
	}
	if delay > time.Second {
		delay = time.Second
	}
	return delay, gnet.None
}

func (s *bridgeState) bridge() {
	ctx, cancel := context.WithTimeout(s.owner.runCtx, s.owner.config.dialTimeout)
	backend, err := s.owner.dial(ctx, s.route.Route)
	cancel()
	if err != nil {
		s.owner.dialFailures.Add(1)
		s.route.dialFailures.Add(1)
		s.report(fmt.Errorf("socketengine: dial routed backend: %w", err))
		s.shutdown()
		return
	}

	s.backendMu.Lock()
	select {
	case <-s.done:
		s.backendMu.Unlock()
		_ = backend.Close()
		return
	default:
		s.backend = backend
		s.backendMu.Unlock()
	}
	go s.copyBackendToFrontend(backend)

	for {
		select {
		case <-s.done:
			return
		default:
		}
		select {
		case payload := <-s.toBackend:
			if !s.writeBackend(backend, payload) {
				return
			}
		case <-s.frontendEOF:
			if !s.flushBackendQueue(backend) {
				return
			}
			if err := closeWrite(backend); err != nil {
				s.report(fmt.Errorf("socketengine: close routed backend write side: %w", err))
				s.shutdown()
			}
			return
		case <-s.done:
			return
		case <-s.owner.runCtx.Done():
			s.shutdown()
			return
		}
	}
}

func (s *bridgeState) writeBackend(backend net.Conn, payload []byte) bool {
	err := writeAll(backend, payload)
	byteslice.Put(payload)
	if err != nil {
		s.report(fmt.Errorf("socketengine: write routed backend: %w", err))
		s.shutdown()
		return false
	}
	s.touch()
	return true
}

func (s *bridgeState) flushBackendQueue(backend net.Conn) bool {
	for {
		select {
		case payload := <-s.toBackend:
			if !s.writeBackend(backend, payload) {
				return false
			}
		default:
			return true
		}
	}
}

func (s *bridgeState) copyBackendToFrontend(backend net.Conn) {
	buffer := byteslice.Get(s.owner.config.ReadBufferBytes)
	defer byteslice.Put(buffer)
	for {
		n, readErr := backend.Read(buffer)
		if n > 0 {
			if err := writeAll(s.frontend, buffer[:n]); err != nil {
				s.report(fmt.Errorf("socketengine: write frontend: %w", err))
				s.shutdown()
				return
			}
			s.touch()
			s.owner.bytesOut.Add(uint64(n))
			s.route.bytesOut.Add(uint64(n))
		}
		if readErr != nil {
			if !normalSocketError(readErr) {
				s.report(fmt.Errorf("socketengine: read routed backend: %w", readErr))
			}
			s.shutdown()
			return
		}
	}
}

func (s *bridgeState) signalFrontendEOF() {
	s.eofOnce.Do(func() {
		s.touch()
		close(s.frontendEOF)
	})
}

func (s *bridgeState) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

func (s *bridgeState) shutdown() {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.client.Close()
		_ = s.frontend.Close()
		s.backendMu.Lock()
		if s.backend != nil {
			_ = s.backend.Close()
		}
		s.backendMu.Unlock()
		s.drainBackendQueue()
		s.owner.states.Delete(s)
		s.owner.active.Add(-1)
		s.route.active.Add(-1)
	})
}

func (s *bridgeState) drainBackendQueue() {
	for {
		select {
		case payload := <-s.toBackend:
			byteslice.Put(payload)
		default:
			return
		}
	}
}

func (s *bridgeState) report(err error) {
	if err != nil {
		s.owner.report(s.route.Route, s.remote, err)
	}
}

func (e *Engine) reject(route *routeState) {
	e.rejected.Add(1)
	if route != nil {
		route.rejected.Add(1)
	}
}

func (e *Engine) report(route Route, remote string, err error) {
	if err == nil || e.onErr == nil {
		return
	}
	e.onErr(route, remote, err)
}

func (e *Engine) closeAll() {
	e.states.Range(func(key, _ any) bool {
		if state, ok := key.(*bridgeState); ok {
			state.shutdown()
		}
		return true
	})
}

func (e *Engine) prepareUnixSockets() error {
	for _, route := range e.routes {
		path := route.unixPath
		if path == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("socketengine: create Unix listener directory: %w", err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if !e.config.RemoveStaleUnix {
			return fmt.Errorf("socketengine: Unix listener already exists: %s", path)
		}
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("socketengine: refusing to remove non-socket path %s", path)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("socketengine: remove stale Unix socket %s: %w", path, err)
		}
	}
	return nil
}

func (e *Engine) removeUnixSockets() {
	for _, route := range e.routes {
		if route.unixPath != "" {
			_ = os.Remove(route.unixPath)
		}
	}
}

func (e *Engine) loadBalancing() gnet.LoadBalancing {
	switch e.config.LoadBalance {
	case "round-robin":
		return gnet.RoundRobin
	case "source-hash":
		return gnet.SourceAddrHash
	default:
		return gnet.LeastConnections
	}
}

func (e *Engine) setBootError(err error) {
	e.bootErrMu.Lock()
	e.bootErr = err
	e.bootErrMu.Unlock()
}

func (e *Engine) getBootError() error {
	e.bootErrMu.Lock()
	defer e.bootErrMu.Unlock()
	return e.bootErr
}

func duplicateFrontend(client gnet.Conn, routeName string) (net.Conn, error) {
	fd, err := client.Dup()
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "weaverssh-socket-engine-"+routeName)
	if file == nil {
		return nil, errors.New("os.NewFile returned nil")
	}
	connection, connErr := net.FileConn(file)
	closeErr := file.Close()
	if connErr != nil {
		return nil, connErr
	}
	if closeErr != nil {
		_ = connection.Close()
		return nil, closeErr
	}
	return connection, nil
}

func listenerKey(address net.Addr) string {
	if address == nil {
		return ""
	}
	network := strings.ToLower(address.Network())
	switch {
	case strings.HasPrefix(network, "tcp"):
		return "tcp://" + address.String()
	case strings.HasPrefix(network, "unix"):
		return "unix://" + address.String()
	default:
		return network + "://" + address.String()
	}
}

func tryAcquire(counter *atomic.Int64, maximum int64) bool {
	for {
		current := counter.Load()
		if maximum > 0 && current >= maximum {
			return false
		}
		if counter.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func closeWrite(connection net.Conn) error {
	if closer, ok := connection.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.New("routed backend does not support CloseWrite")
}

func normalSocketError(err error) bool {
	return err == nil ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled)
}
