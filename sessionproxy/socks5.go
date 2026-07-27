// Package sessionproxy implements a SOCKS5 listener whose TCP and UDP
// destinations are supplied by the active dynamic-session broker.
package sessionproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"weaverssh/socksproof"
)

const (
	commandConnect      = byte(0x01)
	commandBind         = byte(0x02)
	commandUDPAssociate = byte(0x03)
)

type DialFunc func(context.Context, string, string) (net.Conn, error)
type DialProofFunc func(context.Context, string, string, socksproof.Bundle) (net.Conn, error)
type ProofConfigFunc func(context.Context) (*socksproof.ServerConfig, error)

// BindFunc starts one routed SOCKS5 BIND operation. The returned listener must
// provide its externally reachable address and one accepted peer connection.
type BindListener interface {
	Addr() net.Addr
	Accept(context.Context) (net.Conn, error)
	Close() error
}

type BindFunc func(context.Context, string, string) (BindListener, error)
type BindProofFunc func(context.Context, string, string, socksproof.Bundle) (BindListener, error)

type Server struct {
	Dial             DialFunc
	DialProof        DialProofFunc
	Bind             BindFunc
	BindProof        BindProofFunc
	AssociateUDP     UDPAssociateFunc
	Proof            *socksproof.ServerConfig
	ProofProvider    ProofConfigFunc
	AllowNoAuth      bool
	HandshakeTimeout time.Duration
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s == nil || (s.Dial == nil && s.DialProof == nil && s.Bind == nil && s.BindProof == nil && s.AssociateUDP == nil) {
		return errors.New("sessionproxy: missing routed service function")
	}
	if listener == nil {
		return errors.New("sessionproxy: nil listener")
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.handle(ctx, conn)
		}()
	}
}

func (s *Server) proofConfig(ctx context.Context) (*socksproof.ServerConfig, error) {
	if s.ProofProvider != nil {
		config, err := s.ProofProvider(ctx)
		if err != nil {
			return nil, fmt.Errorf("sessionproxy: refresh proof configuration: %w", err)
		}
		if config == nil {
			return nil, errors.New("sessionproxy: proof provider returned nil configuration")
		}
		return config, nil
	}
	return s.Proof, nil
}

func (s *Server) handle(ctx context.Context, client net.Conn) error {
	defer client.Close()
	timeout := s.HandshakeTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	_ = client.SetDeadline(time.Now().Add(timeout))
	proofConfig, err := s.proofConfig(ctx)
	if err != nil {
		return err
	}
	method, err := s.negotiate(client, proofConfig)
	if err != nil {
		return err
	}

	var proofSession socksproof.ServerSession
	if method == socksproof.MethodPrivate {
		if proofConfig == nil {
			return errors.New("sessionproxy: proof configuration missing")
		}
		proofSession, err = proofConfig.Begin(client, time.Now())
		if err != nil {
			return err
		}
	}

	command, network, address, err := readRequest(client)
	if err != nil {
		_ = sendReply(client, 0x07)
		return err
	}
	switch command {
	case commandUDPAssociate:
		if method == socksproof.MethodPrivate {
			return s.handleProofUDPAssociate(ctx, client, proofConfig, proofSession, network, address)
		}
		return s.handleUDPAssociate(ctx, client, address)
	case commandConnect:
		return s.handleConnect(ctx, client, proofConfig, method, proofSession, network, address)
	case commandBind:
		return s.handleBind(ctx, client, proofConfig, method, proofSession, network, address)
	default:
		_ = sendReply(client, 0x07)
		return errors.New("sessionproxy: unsupported SOCKS5 command")
	}
}

func (s *Server) handleConnect(ctx context.Context, client net.Conn, proofConfig *socksproof.ServerConfig, method byte, proofSession socksproof.ServerSession, network, address string) error {
	var target net.Conn
	var err error
	if method == socksproof.MethodPrivate {
		var proof socksproof.SignedConnect
		if err := socksproof.ReadFrame(client, &proof); err != nil {
			_ = sendReply(client, 0x01)
			return err
		}
		if err := proofConfig.VerifyConnect(proofSession, proof, network, address, time.Now()); err != nil {
			_ = sendReply(client, 0x02)
			return err
		}
		if s.DialProof == nil {
			_ = sendReply(client, 0x01)
			return errors.New("sessionproxy: proof dial unavailable")
		}
		bundle := socksproof.Bundle{Challenge: proofSession.Challenge, Identity: proofSession.Identity, Connect: proof}
		target, err = s.DialProof(ctx, network, address, bundle)
	} else {
		if s.Dial == nil {
			_ = sendReply(client, 0x01)
			return errors.New("sessionproxy: no-auth dial unavailable")
		}
		target, err = s.Dial(ctx, network, address)
	}
	if err != nil {
		_ = sendReply(client, 0x04)
		return err
	}
	defer target.Close()
	if err := sendReplyAddress(client, 0x00, target.LocalAddr()); err != nil {
		return err
	}
	_ = client.SetDeadline(time.Time{})
	return relay(ctx, client, target)
}

func (s *Server) handleBind(ctx context.Context, client net.Conn, proofConfig *socksproof.ServerConfig, method byte, proofSession socksproof.ServerSession, network, address string) error {
	var (
		listener BindListener
		err error
	)
	if method == socksproof.MethodPrivate {
		var proof socksproof.SignedConnect
		if err := socksproof.ReadFrame(client, &proof); err != nil {
			_ = sendReply(client, 0x01)
			return err
		}
		if err := proofConfig.VerifyCommand(proofSession, proof, commandBind, network, address, time.Now()); err != nil {
			_ = sendReply(client, 0x02)
			return err
		}
		if s.BindProof == nil {
			_ = sendReply(client, 0x07)
			return errors.New("sessionproxy: proof BIND unavailable")
		}
		bundle := socksproof.Bundle{Challenge: proofSession.Challenge, Identity: proofSession.Identity, Connect: proof}
		listener, err = s.BindProof(ctx, network, address, bundle)
	} else {
		if s.Bind == nil {
			_ = sendReply(client, 0x07)
			return errors.New("sessionproxy: BIND unavailable")
		}
		listener, err = s.Bind(ctx, network, address)
	}
	if err != nil {
		_ = sendReply(client, 0x04)
		return err
	}
	defer listener.Close()
	if err := sendReplyAddress(client, 0x00, listener.Addr()); err != nil {
		return err
	}
	peer, err := listener.Accept(ctx)
	if err != nil {
		_ = sendReply(client, 0x04)
		return err
	}
	defer peer.Close()
	if err := sendReplyAddress(client, 0x00, peer.RemoteAddr()); err != nil {
		return err
	}
	_ = client.SetDeadline(time.Time{})
	return relay(ctx, client, peer)
}

func (s *Server) negotiate(conn net.Conn, proofConfig *socksproof.ServerConfig) (byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, err
	}
	if header[0] != 5 || header[1] == 0 {
		return 0, errors.New("sessionproxy: invalid SOCKS5 greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, err
	}
	offered := func(want byte) bool {
		for _, method := range methods {
			if method == want {
				return true
			}
		}
		return false
	}
	if proofConfig != nil && offered(socksproof.MethodPrivate) {
		_, err := conn.Write([]byte{0x05, socksproof.MethodPrivate})
		return socksproof.MethodPrivate, err
	}
	if s.AllowNoAuth && offered(0x00) {
		_, err := conn.Write([]byte{0x05, 0x00})
		return 0x00, err
	}
	_, _ = conn.Write([]byte{0x05, 0xff})
	return 0, errors.New("sessionproxy: no acceptable SOCKS5 authentication method")
}

func readRequest(conn net.Conn) (command byte, network, address string, err error) {
	header := make([]byte, 4)
	if _, err = io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != 5 || header[2] != 0 {
		err = errors.New("sessionproxy: invalid SOCKS5 request")
		return
	}
	command = header[1]
	var host string
	switch header[3] {
	case 0x01:
		buffer := make([]byte, 4)
		if _, err = io.ReadFull(conn, buffer); err != nil {
			return
		}
		host = net.IP(buffer).String()
	case 0x03:
		length := []byte{0}
		if _, err = io.ReadFull(conn, length); err != nil {
			return
		}
		if length[0] == 0 {
			err = errors.New("sessionproxy: empty domain")
			return
		}
		buffer := make([]byte, int(length[0]))
		if _, err = io.ReadFull(conn, buffer); err != nil {
			return
		}
		host = string(buffer)
	case 0x04:
		buffer := make([]byte, 16)
		if _, err = io.ReadFull(conn, buffer); err != nil {
			return
		}
		host = net.IP(buffer).String()
	default:
		err = fmt.Errorf("sessionproxy: unsupported address type %d", header[3])
		return
	}
	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBytes); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBytes))
	if (command == commandConnect || command == commandBind) && port == 0 {
		err = errors.New("sessionproxy: zero destination port")
		return
	}
	if command == commandUDPAssociate {
		network = "udp"
	} else {
		network = "tcp"
	}
	address = net.JoinHostPort(host, strconv.Itoa(port))
	return
}

func sendReply(conn net.Conn, code byte) error { return sendReplyAddress(conn, code, nil) }

func sendReplyAddress(conn net.Conn, code byte, address net.Addr) error {
	host := net.IPv4zero
	port := 0
	if address != nil {
		switch value := address.(type) {
		case *net.TCPAddr:
			host, port = value.IP, value.Port
		case *net.UDPAddr:
			host, port = value.IP, value.Port
		}
	}
	reply := []byte{0x05, code, 0x00}
	if ipv4 := host.To4(); ipv4 != nil {
		reply = append(reply, 0x01)
		reply = append(reply, ipv4...)
	} else {
		reply = append(reply, 0x04)
		reply = append(reply, host.To16()...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	reply = append(reply, portBytes...)
	_, err := conn.Write(reply)
	return err
}

func relay(ctx context.Context, left, right net.Conn) error {
	type result struct{ err error }
	results := make(chan result, 2)
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = left.Close()
			_ = right.Close()
		})
	}
	pump := func(dst, src net.Conn) {
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
			if result.err != nil && !errors.Is(result.err, io.EOF) && !errors.Is(result.err, io.ErrClosedPipe) && !errors.Is(result.err, net.ErrClosed) {
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
