// Package sessiontcp carries authorized TCP connections over logical
// dynamic-session streams. Destination dialing occurs on the node that owns the
// accepted ServiceTCP target; callers never infer success from mux ACCEPT alone.
package sessiontcp

import (
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

	"weaverssh/sessionbind"
	"weaverssh/sessionbroker"
	"weaverssh/sessionmux"
)

const (
	ProtocolVersion  = "weaverssh.tcp.v1"
	maxMetadataBytes = 8 << 10
	maxErrorBytes    = 4 << 10
)

var (
	responseMagic = [4]byte{'W', 'V', 'T', '1'}
	ErrDenied     = errors.New("sessiontcp: destination denied")
	ErrDialFailed = errors.New("sessiontcp: destination dial failed")
)

type Request struct {
	Protocol string `json:"protocol"`
	Network  string `json:"network"`
	Address  string `json:"address"`
}

type DialContextFunc func(context.Context, string, string) (net.Conn, error)
type AuthorizeFunc func(Request) error

type Server struct {
	DialTimeout time.Duration
	DialContext DialContextFunc
	Authorize   AuthorizeFunc

	BindAddress      string
	BindTimeout      time.Duration
	BindListen       sessionbind.ListenFunc
	BindResolvePeer  sessionbind.ResolvePeerFunc
	BindAllowAnyPeer bool
}

func EncodeRequest(network, address string) ([]byte, error) {
	req, err := NormalizeRequest(Request{Protocol: ProtocolVersion, Network: network, Address: address})
	if err != nil { return nil, err }
	payload, err := json.Marshal(req)
	if err != nil { return nil, err }
	if len(payload) > maxMetadataBytes { return nil, errors.New("sessiontcp: metadata too large") }
	return payload, nil
}

func DecodeRequest(payload []byte) (Request, error) {
	if len(payload) == 0 || len(payload) > maxMetadataBytes { return Request{}, errors.New("sessiontcp: invalid metadata size") }
	var req Request
	if err := json.Unmarshal(payload, &req); err != nil { return Request{}, fmt.Errorf("sessiontcp: decode metadata: %w", err) }
	return NormalizeRequest(req)
}

func NormalizeRequest(req Request) (Request, error) {
	if req.Protocol == "" { req.Protocol = ProtocolVersion }
	if req.Protocol != ProtocolVersion { return Request{}, fmt.Errorf("sessiontcp: unsupported protocol %q", req.Protocol) }
	req.Network = strings.ToLower(strings.TrimSpace(req.Network))
	if req.Network == "" { req.Network = "tcp" }
	if req.Network != "tcp" && req.Network != "tcp4" && req.Network != "tcp6" { return Request{}, fmt.Errorf("sessiontcp: unsupported network %q", req.Network) }
	req.Address = strings.TrimSpace(req.Address)
	host, portText, err := net.SplitHostPort(req.Address)
	if err != nil || strings.TrimSpace(host) == "" { return Request{}, fmt.Errorf("sessiontcp: destination must be HOST:PORT: %q", req.Address) }
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 { return Request{}, fmt.Errorf("sessiontcp: invalid destination port %q", portText) }
	if strings.IndexByte(host, 0) >= 0 { return Request{}, errors.New("sessiontcp: destination contains NUL") }
	req.Address = net.JoinHostPort(host, strconv.Itoa(port))
	return req, nil
}

func (s *Server) Serve(ctx context.Context, stream io.ReadWriteCloser, metadata []byte) error {
	if stream == nil { return errors.New("sessiontcp: nil stream") }
	if sessionbind.IsMetadata(metadata) {
		bindServer := &sessionbind.Server{
			BindAddress: s.BindAddress,
			BindTimeout: s.BindTimeout,
			Listen: s.BindListen,
			ResolvePeer: s.BindResolvePeer,
			AllowAnyPeer: s.BindAllowAnyPeer,
			Authorize: func(bindRequest sessionbind.Request) error {
				if s == nil || s.Authorize == nil { return errors.New("sessiontcp: no destination authorization policy configured") }
				req, err := NormalizeRequest(Request{Protocol: ProtocolVersion, Network: bindRequest.Network, Address: bindRequest.ExpectedPeer})
				if err != nil { return err }
				return s.Authorize(req)
			},
		}
		return bindServer.Serve(ctx, stream, metadata)
	}
	defer stream.Close()
	req, err := DecodeRequest(metadata)
	if err != nil { _ = writeResult(stream, err); return err }
	if s == nil || s.Authorize == nil {
		err := fmt.Errorf("%w: no destination authorization policy configured", ErrDenied)
		_ = writeResult(stream, err)
		return err
	}
	if err := s.Authorize(req); err != nil { _ = writeResult(stream, fmt.Errorf("%w: %v", ErrDenied, err)); return err }
	dial := DialContextFunc((&net.Dialer{Timeout: 30 * time.Second}).DialContext)
	if s.DialContext != nil { dial = s.DialContext }
	timeout := 30 * time.Second
	if s.DialTimeout > 0 { timeout = s.DialTimeout }
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	target, err := dial(dialCtx, req.Network, req.Address)
	if err != nil { wrapped := fmt.Errorf("%w: %v", ErrDialFailed, err); _ = writeResult(stream, wrapped); return wrapped }
	defer target.Close()
	if err := writeResult(stream, nil); err != nil { return err }
	return relay(ctx, stream, target)
}

func DialBroker(ctx context.Context, socketPath, node, network, address string) (net.Conn, error) {
	metadata, err := EncodeRequest(network, address)
	if err != nil { return nil, err }
	conn, err := sessionbroker.Dial(ctx, "unix", socketPath, sessionbroker.OpenRequest{Node: strings.TrimSpace(node), Service: sessionmux.ServiceTCP, Data: metadata})
	if err != nil { return nil, err }
	if err := readResult(conn); err != nil { _ = conn.Close(); return nil, err }
	return conn, nil
}

func writeResult(w io.Writer, resultErr error) error {
	status := byte(0); message := ""
	if resultErr != nil { status = 1; message = resultErr.Error() }
	payload := []byte(message); if len(payload) > maxErrorBytes { payload = payload[:maxErrorBytes] }
	header := make([]byte, 9); copy(header[:4], responseMagic[:]); header[4] = 1; header[5] = status; binary.BigEndian.PutUint16(header[7:9], uint16(len(payload)))
	if err := writeAll(w, header); err != nil { return err }
	return writeAll(w, payload)
}

func readResult(r io.Reader) error {
	header := make([]byte, 9)
	if _, err := io.ReadFull(r, header); err != nil { return fmt.Errorf("sessiontcp: read dial result: %w", err) }
	if string(header[:4]) != string(responseMagic[:]) || header[4] != 1 { return errors.New("sessiontcp: invalid dial result") }
	length := int(binary.BigEndian.Uint16(header[7:9])); if length > maxErrorBytes { return errors.New("sessiontcp: oversized dial error") }
	payload := make([]byte, length); if _, err := io.ReadFull(r, payload); err != nil { return err }
	if header[5] != 0 { return fmt.Errorf("%w: %s", ErrDialFailed, strings.TrimSpace(string(payload))) }
	return nil
}

func relay(ctx context.Context, left, right io.ReadWriteCloser) error {
	type result struct{ err error }
	results := make(chan result, 2); var once sync.Once
	closeBoth := func(){ once.Do(func(){ _=left.Close(); _=right.Close() }) }
	pump := func(dst io.ReadWriteCloser, src io.ReadWriteCloser){ _,err:=io.Copy(dst,src); closeWrite(dst); results<-result{err:err} }
	go pump(right,left); go pump(left,right)
	var terminalErr error
	for i:=0;i<2;i++ { select { case result:=<-results: if !normalRelayError(result.err)&&terminalErr==nil {terminalErr=result.err;closeBoth()}; case <-ctx.Done(): closeBoth(); return ctx.Err() } }
	closeBoth(); return terminalErr
}

func closeWrite(endpoint io.ReadWriteCloser){ if closer,ok:=endpoint.(interface{CloseWrite()error});ok{_=closer.CloseWrite();return};_=endpoint.Close() }
func normalRelayError(err error)bool{return err==nil||errors.Is(err,io.EOF)||errors.Is(err,io.ErrClosedPipe)||errors.Is(err,net.ErrClosed)}
func writeAll(w io.Writer,payload []byte)error{for len(payload)>0{n,err:=w.Write(payload);if err!=nil{return err};if n==0{return io.ErrShortWrite};payload=payload[n:]};return nil}
