// Package sessionudp carries RFC 1928 UDP datagrams over one logical
// dynamic-session association. The final owning node creates the real UDP socket.
package sessionudp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"weaverssh/sessionbroker"
	"weaverssh/sessionmux"
	"weaverssh/socksudp"
)

const (
	ProtocolVersion  = "weaverssh.udp.v1"
	maxMetadataBytes = 4 << 10
	maxErrorBytes    = 4 << 10
	maxFrameBytes    = socksudp.MaxDatagramBytes
)

var responseMagic = [4]byte{'W', 'V', 'U', '1'}

var (
	ErrDenied            = errors.New("sessionudp: destination denied")
	ErrAssociationFailed = errors.New("sessionudp: association failed")
)

// Request configures one routed UDP association.
type Request struct {
	Protocol string `json:"protocol"`
	Network  string `json:"network"`
}

// AuthorizeFunc checks one normalized RFC destination before a datagram is sent.
type AuthorizeFunc func(address string) error

// ListenPacketFunc creates the final-node UDP socket.
type ListenPacketFunc func(context.Context, string, string) (net.PacketConn, error)

// ResolveFunc resolves one RFC destination on the final node.
type ResolveFunc func(context.Context, string, string) (net.Addr, error)

// Server owns a final-node UDP socket for the lifetime of one logical stream.
type Server struct {
	Authorize       AuthorizeFunc
	ListenPacket    ListenPacketFunc
	Resolve         ResolveFunc
	ReadTimeout     time.Duration
	MaxDestinations int
}

func EncodeRequest(network string) ([]byte, error) {
	req, err := normalizeRequest(Request{Protocol: ProtocolVersion, Network: network})
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxMetadataBytes {
		return nil, errors.New("sessionudp: metadata too large")
	}
	return payload, nil
}

func DecodeRequest(payload []byte) (Request, error) {
	if len(payload) == 0 || len(payload) > maxMetadataBytes {
		return Request{}, errors.New("sessionudp: invalid metadata size")
	}
	var req Request
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return Request{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Request{}, errors.New("sessionudp: trailing metadata")
	}
	return normalizeRequest(req)
}

func IsMetadata(payload []byte) bool {
	var header struct {
		Protocol string `json:"protocol"`
	}
	return json.Unmarshal(payload, &header) == nil && header.Protocol == ProtocolVersion
}

func normalizeRequest(req Request) (Request, error) {
	if req.Protocol == "" {
		req.Protocol = ProtocolVersion
	}
	if req.Protocol != ProtocolVersion {
		return Request{}, fmt.Errorf("sessionudp: unsupported protocol %q", req.Protocol)
	}
	req.Network = strings.ToLower(strings.TrimSpace(req.Network))
	if req.Network == "" {
		req.Network = "udp"
	}
	if req.Network != "udp" && req.Network != "udp4" && req.Network != "udp6" {
		return Request{}, fmt.Errorf("sessionudp: unsupported network %q", req.Network)
	}
	return req, nil
}

// Serve relays framed RFC 1928 datagrams until the logical association closes.
func (s *Server) Serve(ctx context.Context, stream io.ReadWriteCloser, metadata []byte) error {
	if stream == nil {
		return errors.New("sessionudp: nil stream")
	}
	defer stream.Close()
	req, err := DecodeRequest(metadata)
	if err != nil {
		_ = writeResult(stream, err)
		return err
	}
	if s == nil || s.Authorize == nil {
		err := fmt.Errorf("%w: no UDP authorization policy configured", ErrDenied)
		_ = writeResult(stream, err)
		return err
	}

	listen := s.ListenPacket
	if listen == nil {
		var lc net.ListenConfig
		listen = lc.ListenPacket
	}
	packetConn, err := listen(ctx, req.Network, ":0")
	if err != nil {
		wrapped := fmt.Errorf("%w: %v", ErrAssociationFailed, err)
		_ = writeResult(stream, wrapped)
		return wrapped
	}
	defer packetConn.Close()
	if err := writeResult(stream, nil); err != nil {
		return err
	}

	maximum := s.MaxDestinations
	if maximum <= 0 {
		maximum = 256
	}
	destinations := newDestinationSet(maximum)
	assocCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	responses := make(chan error, 1)
	go func() {
		responses <- s.relayResponses(assocCtx, stream, packetConn, destinations)
	}()

	resolve := s.Resolve
	if resolve == nil {
		resolve = func(_ context.Context, network, address string) (net.Addr, error) {
			return net.ResolveUDPAddr(network, address)
		}
	}
	for {
		packet, readErr := ReadFrame(stream)
		if readErr != nil {
			cancel()
			if normalError(readErr) {
				return nil
			}
			return readErr
		}
		datagram, parseErr := socksudp.Parse(packet)
		if parseErr != nil {
			// RFC 1928 relay failures are silent. Invalid and fragmented packets are dropped.
			continue
		}
		if authErr := s.Authorize(datagram.Address); authErr != nil {
			continue
		}
		address, resolveErr := resolve(assocCtx, req.Network, datagram.Address)
		if resolveErr != nil || !destinations.Add(address.String()) {
			continue
		}
		if _, writeErr := packetConn.WriteTo(datagram.Data, address); writeErr != nil {
			cancel()
			return writeErr
		}
		select {
		case responseErr := <-responses:
			if normalError(responseErr) {
				return nil
			}
			return responseErr
		default:
		}
	}
}

func (s *Server) relayResponses(ctx context.Context, stream io.Writer, packetConn net.PacketConn, destinations *destinationSet) error {
	buffer := make([]byte, 65507)
	for {
		if s.ReadTimeout > 0 {
			_ = packetConn.SetReadDeadline(time.Now().Add(s.ReadTimeout))
		}
		n, source, err := packetConn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return err
		}
		if !destinations.Contains(source.String()) {
			continue
		}
		packet, err := socksudp.Marshal(source.String(), buffer[:n])
		if err != nil {
			continue
		}
		if err := WriteFrame(stream, packet); err != nil {
			return err
		}
	}
}

// Association is a client-side routed UDP association.
type Association struct {
	conn    net.Conn
	writeMu sync.Mutex
}

func DialBroker(ctx context.Context, socketPath, node, network string) (*Association, error) {
	metadata, err := EncodeRequest(network)
	if err != nil {
		return nil, err
	}
	conn, err := sessionbroker.Dial(ctx, "unix", socketPath, sessionbroker.OpenRequest{
		Node: strings.TrimSpace(node), Service: sessionmux.ServiceUDP, Data: metadata,
	})
	if err != nil {
		return nil, err
	}
	if err := readResult(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &Association{conn: conn}, nil
}

func (a *Association) Send(packet []byte) error {
	if a == nil || a.conn == nil {
		return errors.New("sessionudp: closed association")
	}
	if _, err := socksudp.Parse(packet); err != nil {
		return err
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	return WriteFrame(a.conn, packet)
}

func (a *Association) Receive() ([]byte, error) {
	if a == nil || a.conn == nil {
		return nil, errors.New("sessionudp: closed association")
	}
	return ReadFrame(a.conn)
}

func (a *Association) Close() error {
	if a == nil || a.conn == nil {
		return nil
	}
	return a.conn.Close()
}

func WriteFrame(writer io.Writer, packet []byte) error {
	if len(packet) == 0 || len(packet) > maxFrameBytes {
		return errors.New("sessionudp: invalid datagram frame size")
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(packet)))
	if err := writeAll(writer, header); err != nil {
		return err
	}
	return writeAll(writer, packet)
}

func ReadFrame(reader io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(header))
	if length < 1 || length > maxFrameBytes {
		return nil, errors.New("sessionudp: invalid datagram frame length")
	}
	packet := make([]byte, length)
	if _, err := io.ReadFull(reader, packet); err != nil {
		return nil, err
	}
	return packet, nil
}

func writeResult(writer io.Writer, resultErr error) error {
	status := byte(0)
	message := ""
	if resultErr != nil {
		status = 1
		message = resultErr.Error()
	}
	payload := []byte(message)
	if len(payload) > maxErrorBytes {
		payload = payload[:maxErrorBytes]
	}
	header := make([]byte, 9)
	copy(header[:4], responseMagic[:])
	header[4] = 1
	header[5] = status
	binary.BigEndian.PutUint16(header[7:9], uint16(len(payload)))
	if err := writeAll(writer, header); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func readResult(reader io.Reader) error {
	header := make([]byte, 9)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if string(header[:4]) != string(responseMagic[:]) || header[4] != 1 {
		return errors.New("sessionudp: invalid association result")
	}
	length := int(binary.BigEndian.Uint16(header[7:9]))
	if length > maxErrorBytes {
		return errors.New("sessionudp: oversized association error")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}
	if header[5] != 0 {
		return fmt.Errorf("%w: %s", ErrAssociationFailed, strings.TrimSpace(string(payload)))
	}
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

func normalError(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}

type destinationSet struct {
	mu      sync.RWMutex
	values  map[string]struct{}
	maximum int
}

func newDestinationSet(maximum int) *destinationSet {
	return &destinationSet{values: make(map[string]struct{}), maximum: maximum}
}

func (s *destinationSet) Add(address string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.values[address]; exists {
		return true
	}
	if len(s.values) >= s.maximum {
		return false
	}
	s.values[address] = struct{}{}
	return true
}

func (s *destinationSet) Contains(address string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.values[address]
	return exists
}
