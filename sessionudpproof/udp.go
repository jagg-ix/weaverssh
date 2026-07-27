// Package sessionudpproof carries proof-authenticated RFC 1928 UDP datagrams
// to the final owning node. The final node independently verifies the signed
// association bundle and each signed datagram before performing network I/O.
package sessionudpproof

import (
	"bytes"
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
	"weaverssh/sessionudp"
	"weaverssh/socksproof"
	"weaverssh/socksudp"
)

const (
	ProtocolVersion  = "weaverssh.udp-proof.v1"
	maxMetadataBytes = 64 << 10
	maxErrorBytes    = 4 << 10
	maxFrameBytes    = socksproof.MaxAuthenticatedDatagramBytes
)

var responseMagic = [4]byte{'W', 'V', 'Q', '1'}

var (
	ErrDenied            = errors.New("sessionudpproof: destination denied")
	ErrAssociationFailed = errors.New("sessionudpproof: association failed")
	ErrProofRequired     = errors.New("sessionudpproof: signed datagram required")
)

type Request struct {
	Protocol       string            `json:"protocol"`
	Network        string            `json:"network"`
	ClientEndpoint string            `json:"client_endpoint"`
	Proof          socksproof.Bundle `json:"proof"`
}

type Server struct {
	Verifier        *socksproof.Verifier
	ExpectedNode    string
	Authorize       sessionudp.AuthorizeFunc
	ListenPacket    sessionudp.ListenPacketFunc
	Resolve         sessionudp.ResolveFunc
	ReadTimeout     time.Duration
	MaxDestinations int
}

func EncodeRequest(network, clientEndpoint string, proof socksproof.Bundle) ([]byte, error) {
	network = strings.ToLower(strings.TrimSpace(network))
	if network == "" {
		network = "udp"
	}
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, fmt.Errorf("sessionudpproof: unsupported network %q", network)
	}
	clientEndpoint = strings.TrimSpace(clientEndpoint)
	if clientEndpoint == "" {
		return nil, errors.New("sessionudpproof: client endpoint is required")
	}
	request := Request{Protocol: ProtocolVersion, Network: network, ClientEndpoint: clientEndpoint, Proof: proof}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > maxMetadataBytes {
		return nil, errors.New("sessionudpproof: metadata too large")
	}
	return payload, nil
}

func DecodeRequest(payload []byte) (Request, error) {
	if len(payload) == 0 || len(payload) > maxMetadataBytes {
		return Request{}, errors.New("sessionudpproof: invalid metadata size")
	}
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return Request{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Request{}, errors.New("sessionudpproof: trailing metadata")
	}
	if request.Protocol != ProtocolVersion {
		return Request{}, fmt.Errorf("sessionudpproof: unsupported protocol %q", request.Protocol)
	}
	request.Network = strings.ToLower(strings.TrimSpace(request.Network))
	if request.Network == "" {
		request.Network = "udp"
	}
	if request.Network != "udp" && request.Network != "udp4" && request.Network != "udp6" {
		return Request{}, fmt.Errorf("sessionudpproof: unsupported network %q", request.Network)
	}
	if strings.TrimSpace(request.ClientEndpoint) == "" {
		return Request{}, errors.New("sessionudpproof: client endpoint is required")
	}
	return request, nil
}

func IsMetadata(payload []byte) bool {
	var header struct {
		Protocol string `json:"protocol"`
	}
	return json.Unmarshal(payload, &header) == nil && header.Protocol == ProtocolVersion
}

func (s *Server) Serve(ctx context.Context, stream io.ReadWriteCloser, metadata []byte) error {
	if stream == nil {
		return errors.New("sessionudpproof: nil stream")
	}
	defer stream.Close()
	request, err := DecodeRequest(metadata)
	if err != nil {
		_ = writeResult(stream, err)
		return err
	}
	if s == nil || s.Verifier == nil || s.Authorize == nil {
		err := fmt.Errorf("%w: proof verifier and UDP allowlist are required", ErrDenied)
		_ = writeResult(stream, err)
		return err
	}
	expectedNode := strings.TrimSpace(s.ExpectedNode)
	principal, err := s.Verifier.VerifyCommandBundle(
		request.Proof,
		socksproof.CommandUDPAssociate,
		"udp",
		request.ClientEndpoint,
		expectedNode,
		time.Now(),
	)
	if err != nil {
		_ = writeResult(stream, fmt.Errorf("%w: %v", ErrDenied, err))
		return err
	}
	if !containsCapability(principal.Capabilities, socksproof.CapabilityUDPAssociate) {
		err := fmt.Errorf("%w: principal lacks %s", ErrDenied, socksproof.CapabilityUDPAssociate)
		_ = writeResult(stream, err)
		return err
	}

	listen := s.ListenPacket
	if listen == nil {
		var lc net.ListenConfig
		listen = lc.ListenPacket
	}
	packetConn, err := listen(ctx, request.Network, ":0")
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
	var sequences socksproof.SequenceWindow
	for {
		envelope, readErr := readFrame(stream)
		if readErr != nil {
			cancel()
			if normalError(readErr) {
				return nil
			}
			return readErr
		}
		proof, packet, decodeErr := socksproof.DecodeDatagramEnvelope(envelope)
		if decodeErr != nil {
			continue
		}
		datagram, parseErr := socksudp.Parse(packet)
		if parseErr != nil {
			continue
		}
		_, verifyErr := s.Verifier.VerifyDatagram(
			socksproof.ServerSession{
				Challenge: request.Proof.Challenge,
				Identity:  request.Proof.Identity,
				Principal: principal,
			},
			proof,
			packet,
			"udp",
			datagram.Address,
			request.Proof.Challenge.SessionBinding,
			expectedNode,
			time.Now(),
		)
		if verifyErr != nil {
			continue
		}
		if !sequences.Accept(proof.Statement.Sequence) {
			continue
		}
		if authErr := s.Authorize(datagram.Address); authErr != nil {
			continue
		}
		address, resolveErr := resolve(assocCtx, request.Network, datagram.Address)
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
		if err := writeFrame(stream, packet); err != nil {
			return err
		}
	}
}

type Association struct {
	mu      sync.Mutex
	socket  string
	node    string
	network string
	conn    net.Conn
	writeMu sync.Mutex
}

func NewAssociation(socketPath, node, network string) *Association {
	return &Association{socket: strings.TrimSpace(socketPath), node: strings.TrimSpace(node), network: strings.TrimSpace(network)}
}

func (a *Association) ConfigureProof(ctx context.Context, clientEndpoint string, proof socksproof.Bundle) error {
	if a == nil {
		return net.ErrClosed
	}
	metadata, err := EncodeRequest(a.network, clientEndpoint, proof)
	if err != nil {
		return err
	}
	conn, err := sessionbroker.Dial(ctx, "unix", a.socket, sessionbroker.OpenRequest{
		Node: a.node, Service: sessionmux.ServiceUDP, Data: metadata,
	})
	if err != nil {
		return err
	}
	if err := readResult(conn); err != nil {
		_ = conn.Close()
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn != nil {
		_ = conn.Close()
		return errors.New("sessionudpproof: association already configured")
	}
	a.conn = conn
	return nil
}

func (a *Association) Send([]byte) error { return ErrProofRequired }

func (a *Association) SendProof(proof socksproof.SignedDatagram, packet []byte) error {
	if a == nil {
		return net.ErrClosed
	}
	a.mu.Lock()
	conn := a.conn
	a.mu.Unlock()
	if conn == nil {
		return ErrProofRequired
	}
	envelope, err := socksproof.EncodeDatagramEnvelope(proof, packet)
	if err != nil {
		return err
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	return writeFrame(conn, envelope)
}

func (a *Association) Receive() ([]byte, error) {
	if a == nil {
		return nil, net.ErrClosed
	}
	a.mu.Lock()
	conn := a.conn
	a.mu.Unlock()
	if conn == nil {
		return nil, ErrProofRequired
	}
	return readFrame(conn)
}

func (a *Association) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn == nil {
		return nil
	}
	err := a.conn.Close()
	a.conn = nil
	return err
}

func writeFrame(writer io.Writer, packet []byte) error {
	if len(packet) == 0 || len(packet) > maxFrameBytes {
		return errors.New("sessionudpproof: invalid datagram frame size")
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(packet)))
	if err := writeAll(writer, header); err != nil {
		return err
	}
	return writeAll(writer, packet)
}

func readFrame(reader io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(header))
	if length < 1 || length > maxFrameBytes {
		return nil, errors.New("sessionudpproof: invalid datagram frame length")
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
		return errors.New("sessionudpproof: invalid association result")
	}
	length := int(binary.BigEndian.Uint16(header[7:9]))
	if length > maxErrorBytes {
		return errors.New("sessionudpproof: oversized association error")
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

func containsCapability(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
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
