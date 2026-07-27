// Package sessionbind implements SOCKS5 BIND over the existing ServiceTCP
// target. It uses typed metadata and two service-level responses before the
// stream becomes the accepted peer relay.
package sessionbind

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"weaverssh/sessionbroker"
	"weaverssh/sessionmux"
)

const (
	ProtocolVersion = "weaverssh.tcp-bind.v1"
	maxMessageBytes = 16 << 10
)

var messageMagic = [4]byte{'W', 'V', 'B', '1'}

type Request struct {
	Protocol     string `json:"protocol"`
	Network      string `json:"network"`
	ExpectedPeer string `json:"expected_peer"`
}

type Response struct {
	Protocol string `json:"protocol"`
	Phase    string `json:"phase"`
	Network  string `json:"network,omitempty"`
	Address  string `json:"address,omitempty"`
	Error    string `json:"error,omitempty"`
}

type AuthorizeFunc func(Request) error
type ListenFunc func(context.Context, string, string) (net.Listener, error)
type ResolvePeerFunc func(context.Context, string, string) ([]net.IP, error)

type Server struct {
	Authorize    AuthorizeFunc
	Listen       ListenFunc
	ResolvePeer  ResolvePeerFunc
	BindAddress  string
	BindTimeout  time.Duration
	AllowAnyPeer bool
}

func IsMetadata(payload []byte) bool {
	var header struct{ Protocol string `json:"protocol"` }
	return json.Unmarshal(payload, &header) == nil && header.Protocol == ProtocolVersion
}

func EncodeRequest(network, expectedPeer string) ([]byte, error) {
	req, err := NormalizeRequest(Request{Protocol: ProtocolVersion, Network: network, ExpectedPeer: expectedPeer})
	if err != nil {
		return nil, err
	}
	return json.Marshal(req)
}

func DecodeRequest(payload []byte) (Request, error) {
	if len(payload) == 0 || len(payload) > maxMessageBytes {
		return Request{}, errors.New("sessionbind: invalid metadata size")
	}
	var req Request
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return Request{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Request{}, errors.New("sessionbind: trailing metadata")
	}
	return NormalizeRequest(req)
}

func NormalizeRequest(req Request) (Request, error) {
	if strings.TrimSpace(req.Protocol) == "" {
		req.Protocol = ProtocolVersion
	}
	if req.Protocol != ProtocolVersion {
		return Request{}, fmt.Errorf("sessionbind: unsupported protocol %q", req.Protocol)
	}
	req.Network = strings.ToLower(strings.TrimSpace(req.Network))
	if req.Network == "" {
		req.Network = "tcp"
	}
	if req.Network != "tcp" && req.Network != "tcp4" && req.Network != "tcp6" {
		return Request{}, fmt.Errorf("sessionbind: unsupported network %q", req.Network)
	}
	host, portText, err := net.SplitHostPort(strings.TrimSpace(req.ExpectedPeer))
	if err != nil || strings.TrimSpace(host) == "" {
		return Request{}, errors.New("sessionbind: expected peer must be HOST:PORT")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return Request{}, errors.New("sessionbind: expected peer port must be 0..65535")
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if strings.IndexByte(host, 0) >= 0 {
		return Request{}, errors.New("sessionbind: expected peer contains NUL")
	}
	if port == 0 {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsUnspecified() {
			return Request{}, errors.New("sessionbind: zero port requires an unspecified peer address")
		}
	}
	req.ExpectedPeer = net.JoinHostPort(host, strconv.Itoa(port))
	return req, nil
}

func IsWildcardPeer(expected string) bool {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(expected))
	if err != nil || portText != "0" {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsUnspecified()
}

func (s *Server) Serve(ctx context.Context, stream io.ReadWriteCloser, metadata []byte) error {
	if stream == nil {
		return errors.New("sessionbind: nil stream")
	}
	defer stream.Close()
	req, err := DecodeRequest(metadata)
	if err != nil {
		_ = writeResponse(stream, Response{Protocol: ProtocolVersion, Phase: "bound", Error: err.Error()})
		return err
	}
	if s == nil {
		err = errors.New("sessionbind: nil server")
		_ = writeResponse(stream, Response{Protocol: ProtocolVersion, Phase: "bound", Error: err.Error()})
		return err
	}
	wildcard := IsWildcardPeer(req.ExpectedPeer)
	if wildcard {
		if !s.AllowAnyPeer {
			err = errors.New("sessionbind: wildcard peer requires explicit unrestricted allowlist")
			_ = writeResponse(stream, Response{Protocol: ProtocolVersion, Phase: "bound", Error: err.Error()})
			return err
		}
	} else {
		if s.Authorize == nil {
			err = errors.New("sessionbind: no authorization policy")
			_ = writeResponse(stream, Response{Protocol: ProtocolVersion, Phase: "bound", Error: err.Error()})
			return err
		}
		if err := s.Authorize(req); err != nil {
			wrapped := fmt.Errorf("sessionbind: peer denied: %w", err)
			_ = writeResponse(stream, Response{Protocol: ProtocolVersion, Phase: "bound", Error: wrapped.Error()})
			return wrapped
		}
	}

	bindAddress := strings.TrimSpace(s.BindAddress)
	if bindAddress == "" {
		if req.Network == "tcp6" {
			bindAddress = "[::1]:0"
		} else {
			bindAddress = "127.0.0.1:0"
		}
	}
	listen := s.Listen
	if listen == nil {
		var lc net.ListenConfig
		listen = lc.Listen
	}
	listenCtx := ctx
	var cancel context.CancelFunc
	if s.BindTimeout > 0 {
		listenCtx, cancel = context.WithTimeout(ctx, s.BindTimeout)
		defer cancel()
	}
	listener, err := listen(listenCtx, req.Network, bindAddress)
	if err != nil {
		_ = writeResponse(stream, Response{Protocol: ProtocolVersion, Phase: "bound", Error: err.Error()})
		return err
	}
	defer listener.Close()
	if err := writeResponse(stream, Response{Protocol: ProtocolVersion, Phase: "bound", Network: req.Network, Address: listener.Addr().String()}); err != nil {
		return err
	}

	peer, err := acceptExpectedPeer(listenCtx, listener, req.Network, req.ExpectedPeer, wildcard, s.ResolvePeer)
	if err != nil {
		_ = writeResponse(stream, Response{Protocol: ProtocolVersion, Phase: "accepted", Error: err.Error()})
		return err
	}
	defer peer.Close()
	if err := writeResponse(stream, Response{Protocol: ProtocolVersion, Phase: "accepted", Network: req.Network, Address: peer.RemoteAddr().String()}); err != nil {
		return err
	}
	return relay(listenCtx, stream, peer)
}

func acceptExpectedPeer(ctx context.Context, listener net.Listener, network, expected string, wildcard bool, resolve ResolvePeerFunc) (net.Conn, error) {
	var expectedIPs []net.IP
	var expectedPort string
	if !wildcard {
		host, port, err := net.SplitHostPort(expected)
		if err != nil {
			return nil, err
		}
		expectedPort = port
		if ip := net.ParseIP(host); ip != nil {
			expectedIPs = []net.IP{append(net.IP(nil), ip...)}
		} else {
			if resolve == nil {
				resolve = defaultResolvePeer
			}
			expectedIPs, err = resolve(ctx, network, host)
			if err != nil || len(expectedIPs) == 0 {
				if err == nil {
					err = errors.New("sessionbind: expected peer name resolved to no addresses")
				}
				return nil, err
			}
		}
	}
	for {
		type result struct {
			conn net.Conn
			err  error
		}
		accepted := make(chan result, 1)
		go func() {
			conn, err := listener.Accept()
			accepted <- result{conn: conn, err: err}
		}()
		select {
		case <-ctx.Done():
			_ = listener.Close()
			return nil, ctx.Err()
		case result := <-accepted:
			if result.err != nil {
				return nil, result.err
			}
			if wildcard || peerMatchesResolved(result.conn.RemoteAddr(), expectedPort, expectedIPs) {
				return result.conn, nil
			}
			_ = result.conn.Close()
		}
	}
}

func defaultResolvePeer(ctx context.Context, network, host string) ([]net.IP, error) {
	addresses, err := net.DefaultResolver.LookupIP(ctx, "ip", strings.TrimSuffix(strings.TrimSpace(host), "."))
	if err != nil {
		return nil, err
	}
	filtered := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		switch network {
		case "tcp4":
			if address.To4() == nil {
				continue
			}
		case "tcp6":
			if address.To16() == nil || address.To4() != nil {
				continue
			}
		}
		filtered = append(filtered, append(net.IP(nil), address...))
	}
	return filtered, nil
}

func peerMatchesResolved(address net.Addr, expectedPort string, expectedIPs []net.IP) bool {
	if address == nil {
		return false
	}
	actualHost, actualPort, err := net.SplitHostPort(address.String())
	if err != nil || actualPort != expectedPort {
		return false
	}
	actualIP := net.ParseIP(actualHost)
	if actualIP == nil {
		return false
	}
	for _, expectedIP := range expectedIPs {
		if actualIP.Equal(expectedIP) {
			return true
		}
	}
	return false
}

// Listener is a one-shot routed BIND result. Accept returns the same broker
// stream after the destination node has accepted the expected peer.
type Listener struct {
	conn       net.Conn
	bound      net.Addr
	acceptOnce sync.Once
	accepted   net.Conn
	acceptErr  error
}

func DialBroker(ctx context.Context, socketPath, node, network, expectedPeer string) (*Listener, error) {
	metadata, err := EncodeRequest(network, expectedPeer)
	if err != nil {
		return nil, err
	}
	conn, err := sessionbroker.Dial(ctx, "unix", socketPath, sessionbroker.OpenRequest{
		Node: strings.TrimSpace(node), Service: sessionmux.ServiceTCP, Data: metadata,
	})
	if err != nil {
		return nil, err
	}
	response, err := readResponse(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if response.Phase != "bound" || strings.TrimSpace(response.Error) != "" {
		_ = conn.Close()
		return nil, fmt.Errorf("sessionbind: bind failed: %s", response.Error)
	}
	bound, err := resolveAddr(response.Network, response.Address)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &Listener{conn: conn, bound: bound}, nil
}

func (l *Listener) Addr() net.Addr {
	if l == nil {
		return nil
	}
	return l.bound
}

func (l *Listener) Accept(ctx context.Context) (net.Conn, error) {
	if l == nil || l.conn == nil {
		return nil, net.ErrClosed
	}
	l.acceptOnce.Do(func() {
		if deadline, ok := ctx.Deadline(); ok {
			_ = l.conn.SetReadDeadline(deadline)
			defer l.conn.SetReadDeadline(time.Time{})
		}
		response, err := readResponse(l.conn)
		if err != nil {
			l.acceptErr = err
			return
		}
		if response.Phase != "accepted" || response.Error != "" {
			l.acceptErr = fmt.Errorf("sessionbind: accept failed: %s", response.Error)
			return
		}
		l.accepted = l.conn
	})
	return l.accepted, l.acceptErr
}

func (l *Listener) Close() error {
	if l == nil || l.conn == nil {
		return nil
	}
	return l.conn.Close()
}

func writeResponse(writer io.Writer, response Response) error {
	payload, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if len(payload) > maxMessageBytes {
		return errors.New("sessionbind: response too large")
	}
	header := make([]byte, 8)
	copy(header[:4], messageMagic[:])
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	if err := writeAll(writer, header); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func readResponse(reader io.Reader) (Response, error) {
	var response Response
	header := make([]byte, 8)
	if _, err := io.ReadFull(reader, header); err != nil {
		return response, err
	}
	if string(header[:4]) != string(messageMagic[:]) {
		return response, errors.New("sessionbind: invalid response magic")
	}
	length := int(binary.BigEndian.Uint32(header[4:]))
	if length <= 0 || length > maxMessageBytes {
		return response, errors.New("sessionbind: invalid response size")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return response, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return response, err
	}
	if response.Protocol != ProtocolVersion {
		return response, errors.New("sessionbind: invalid response protocol")
	}
	return response, nil
}

func resolveAddr(network, address string) (net.Addr, error) {
	switch network {
	case "tcp", "tcp4", "tcp6", "":
		return net.ResolveTCPAddr("tcp", address)
	default:
		return nil, fmt.Errorf("sessionbind: unsupported response network %q", network)
	}
}

func relay(ctx context.Context, left, right io.ReadWriteCloser) error {
	type result struct{ err error }
	results := make(chan result, 2)
	var once sync.Once
	closeBoth := func() {
		once.Do(func() { _ = left.Close(); _ = right.Close() })
	}
	pump := func(dst io.ReadWriteCloser, src io.ReadWriteCloser) {
		_, err := io.Copy(dst, src)
		if closer, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		results <- result{err: err}
	}
	go pump(right, left)
	go pump(left, right)
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			if result.err != nil && !errors.Is(result.err, io.EOF) && !errors.Is(result.err, net.ErrClosed) {
				closeBoth()
				return result.err
			}
		case <-ctx.Done():
			closeBoth()
			return ctx.Err()
		}
	}
	closeBoth()
	return nil
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
