package sessiontcpproof

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

	"weaverssh/sessionbind"
	"weaverssh/sessionbroker"
	"weaverssh/sessionmux"
	"weaverssh/sessiontcp"
	"weaverssh/socksproof"
)

const (
	ProtocolVersion  = "weaverssh.tcp-proof.v1"
	maxMetadataBytes = 64 << 10
	maxErrorBytes    = 4 << 10
)

var responseMagic = [4]byte{'W', 'V', 'P', '1'}
var (
	ErrDenied     = errors.New("sessiontcpproof: destination denied")
	ErrDialFailed = errors.New("sessiontcpproof: destination dial failed")
)

type Request struct {
	Protocol string            `json:"protocol"`
	Command  byte              `json:"command,omitempty"`
	Network  string            `json:"network"`
	Address  string            `json:"address"`
	Proof    socksproof.Bundle `json:"proof"`
}

type Server struct {
	DialTimeout  time.Duration
	DialContext  sessiontcp.DialContextFunc
	Authorize    sessiontcp.AuthorizeFunc
	Verifier     *socksproof.Verifier
	ExpectedNode string

	BindAddress      string
	BindTimeout      time.Duration
	BindListen       sessionbind.ListenFunc
	BindResolvePeer  sessionbind.ResolvePeerFunc
	BindAllowAnyPeer bool
}

func EncodeRequest(network, address string, proof socksproof.Bundle) ([]byte, error) {
	return encodeCommandRequest(socksproof.CommandConnect, network, address, proof)
}

func EncodeBindRequest(network, address string, proof socksproof.Bundle) ([]byte, error) {
	return encodeCommandRequest(socksproof.CommandBind, network, address, proof)
}

func encodeCommandRequest(command byte, network, address string, proof socksproof.Bundle) ([]byte, error) {
	if command != socksproof.CommandConnect && command != socksproof.CommandBind {
		return nil, errors.New("sessiontcpproof: unsupported command")
	}
	network, address, err := normalizeCommandTarget(command, network, address)
	if err != nil { return nil, err }
	req := Request{Protocol: ProtocolVersion, Command: command, Network: network, Address: address, Proof: proof}
	payload, err := json.Marshal(req)
	if err != nil { return nil, err }
	if len(payload) == 0 || len(payload) > maxMetadataBytes { return nil, errors.New("sessiontcpproof: metadata too large") }
	return payload, nil
}

func DecodeRequest(payload []byte) (Request, error) {
	if len(payload) == 0 || len(payload) > maxMetadataBytes { return Request{}, errors.New("sessiontcpproof: invalid metadata size") }
	var req Request
	decoder := json.NewDecoder(bytes.NewReader(payload)); decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil { return Request{}, err }
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) { return Request{}, errors.New("sessiontcpproof: trailing JSON data") }
	if req.Protocol != ProtocolVersion { return Request{}, fmt.Errorf("sessiontcpproof: unsupported protocol %q", req.Protocol) }
	if req.Command == 0 { req.Command = socksproof.CommandConnect }
	if req.Command != socksproof.CommandConnect && req.Command != socksproof.CommandBind { return Request{}, fmt.Errorf("sessiontcpproof: unsupported command 0x%02x", req.Command) }
	network, address, err := normalizeCommandTarget(req.Command, req.Network, req.Address)
	if err != nil { return Request{}, err }
	req.Network, req.Address = network, address
	return req, nil
}

func normalizeCommandTarget(command byte, network, address string) (string, string, error) {
	if command == socksproof.CommandBind {
		req, err := sessionbind.NormalizeRequest(sessionbind.Request{Protocol: sessionbind.ProtocolVersion, Network: network, ExpectedPeer: address})
		if err != nil { return "", "", err }
		return req.Network, req.ExpectedPeer, nil
	}
	return socksproof.NormalizeAddress(network, address)
}

func IsMetadata(payload []byte) bool {
	if len(payload) == 0 || len(payload) > maxMetadataBytes { return false }
	var header struct{ Protocol string `json:"protocol"` }
	return json.Unmarshal(payload, &header) == nil && header.Protocol == ProtocolVersion
}

func (s *Server) Serve(ctx context.Context, stream io.ReadWriteCloser, metadata []byte) error {
	if stream == nil { return errors.New("sessiontcpproof: nil stream") }
	req, err := DecodeRequest(metadata)
	if err != nil { defer stream.Close(); _ = writeResult(stream, err); return err }
	if s == nil || s.Verifier == nil { defer stream.Close(); return deny(stream, errors.New("no cryptographic verifier configured")) }
	if s.Authorize == nil { defer stream.Close(); return deny(stream, errors.New("no destination allowlist configured")) }

	switch req.Command {
	case socksproof.CommandConnect:
		defer stream.Close()
		legacyReq := sessiontcp.Request{Protocol: sessiontcp.ProtocolVersion, Network: req.Network, Address: req.Address}
		if err := s.Authorize(legacyReq); err != nil { return deny(stream, err) }
		if _, err := s.Verifier.VerifyBundle(req.Proof, req.Network, req.Address, strings.TrimSpace(s.ExpectedNode), time.Now()); err != nil { return deny(stream, err) }
		return s.serveConnect(ctx, stream, req)
	case socksproof.CommandBind:
		if _, err := s.Verifier.VerifyCommandBundle(req.Proof, socksproof.CommandBind, req.Network, req.Address, strings.TrimSpace(s.ExpectedNode), time.Now()); err != nil {
			defer stream.Close(); return deny(stream, err)
		}
		bindMetadata, err := sessionbind.EncodeRequest(req.Network, req.Address)
		if err != nil { defer stream.Close(); return deny(stream, err) }
		bindServer := &sessionbind.Server{
			BindAddress: s.BindAddress,
			BindTimeout: s.BindTimeout,
			Listen: s.BindListen,
			ResolvePeer: s.BindResolvePeer,
			AllowAnyPeer: s.BindAllowAnyPeer,
			Authorize: func(bindRequest sessionbind.Request) error {
				legacy, err := sessiontcp.NormalizeRequest(sessiontcp.Request{Protocol: sessiontcp.ProtocolVersion, Network: bindRequest.Network, Address: bindRequest.ExpectedPeer})
				if err != nil { return err }
				return s.Authorize(legacy)
			},
		}
		return bindServer.Serve(ctx, stream, bindMetadata)
	default:
		defer stream.Close(); return deny(stream, errors.New("unsupported command"))
	}
}

func (s *Server) serveConnect(ctx context.Context, stream io.ReadWriteCloser, req Request) error {
	dial := sessiontcp.DialContextFunc((&net.Dialer{Timeout: 30 * time.Second}).DialContext)
	if s.DialContext != nil { dial = s.DialContext }
	timeout := 30 * time.Second
	if s.DialTimeout > 0 { timeout = s.DialTimeout }
	dialCtx, cancel := context.WithTimeout(ctx, timeout); defer cancel()
	target, err := dial(dialCtx, req.Network, req.Address)
	if err != nil { wrapped := fmt.Errorf("%w: %v", ErrDialFailed, err); _ = writeResult(stream, wrapped); return wrapped }
	defer target.Close()
	if err := writeResult(stream, nil); err != nil { return err }
	return relay(ctx, stream, target)
}

func deny(stream io.Writer, err error) error { wrapped:=fmt.Errorf("%w: %v",ErrDenied,err); _=writeResult(stream,wrapped); return wrapped }

func DialBroker(ctx context.Context, socketPath, node, network, address string, proof socksproof.Bundle) (net.Conn, error) {
	metadata, err := EncodeRequest(network, address, proof); if err != nil { return nil, err }
	conn, err := sessionbroker.Dial(ctx,"unix",socketPath,sessionbroker.OpenRequest{Node:strings.TrimSpace(node),Service:sessionmux.ServiceTCP,Data:metadata}); if err != nil { return nil, err }
	if err:=readResult(conn);err!=nil{_=conn.Close();return nil,err};return conn,nil
}

func DialBindBroker(ctx context.Context, socketPath, node, network, address string, proof socksproof.Bundle) (*sessionbind.Listener, error) {
	metadata, err := EncodeBindRequest(network,address,proof); if err != nil{return nil,err}
	conn,err:=sessionbroker.Dial(ctx,"unix",socketPath,sessionbroker.OpenRequest{Node:strings.TrimSpace(node),Service:sessionmux.ServiceTCP,Data:metadata});if err!=nil{return nil,err};return sessionbind.OpenClientStream(conn)
}

func writeResult(w io.Writer,resultErr error)error{status:=byte(0);message:="";if resultErr!=nil{status=1;message=resultErr.Error()};payload:=[]byte(message);if len(payload)>maxErrorBytes{payload=payload[:maxErrorBytes]};header:=make([]byte,9);copy(header[:4],responseMagic[:]);header[4]=1;header[5]=status;binary.BigEndian.PutUint16(header[7:9],uint16(len(payload)));if err:=writeAll(w,header);err!=nil{return err};return writeAll(w,payload)}
func readResult(r io.Reader)error{header:=make([]byte,9);if _,err:=io.ReadFull(r,header);err!=nil{return err};if string(header[:4])!=string(responseMagic[:])||header[4]!=1{return errors.New("sessiontcpproof: invalid dial result")};length:=int(binary.BigEndian.Uint16(header[7:9]));if length>maxErrorBytes{return errors.New("sessiontcpproof: oversized error")};payload:=make([]byte,length);if _,err:=io.ReadFull(r,payload);err!=nil{return err};if header[5]!=0{message:=strings.TrimSpace(string(payload));if strings.Contains(message,ErrDenied.Error()){return fmt.Errorf("%w: %s",ErrDenied,message)};return fmt.Errorf("%w: %s",ErrDialFailed,message)};return nil}
func relay(ctx context.Context,left,right io.ReadWriteCloser)error{type result struct{err error};results:=make(chan result,2);var once sync.Once;closeBoth:=func(){once.Do(func(){_=left.Close();_=right.Close()})};pump:=func(dst,src io.ReadWriteCloser){_,err:=io.Copy(dst,src);if closer,ok:=dst.(interface{CloseWrite()error});ok{_=closer.CloseWrite()}else{_=dst.Close()};results<-result{err:err}};go pump(right,left);go pump(left,right);var terminal error;for i:=0;i<2;i++{select{case result:=<-results:if result.err!=nil&&!errors.Is(result.err,io.EOF)&&!errors.Is(result.err,io.ErrClosedPipe)&&!errors.Is(result.err,net.ErrClosed)&&terminal==nil{terminal=result.err;closeBoth()};case<-ctx.Done():closeBoth();return ctx.Err()}};closeBoth();return terminal}
func writeAll(w io.Writer,payload []byte)error{for len(payload)>0{n,err:=w.Write(payload);if err!=nil{return err};if n==0{return io.ErrShortWrite};payload=payload[n:]};return nil}
