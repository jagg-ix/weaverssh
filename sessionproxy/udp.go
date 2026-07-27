package sessionproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"weaverssh/socksudp"
)

// UDPAssociation is the routed datagram interface required by SOCKS5 UDP ASSOCIATE.
type UDPAssociation interface {
	Send([]byte) error
	Receive() ([]byte, error)
	Close() error
}

// UDPAssociateFunc opens one routed final-node UDP association.
type UDPAssociateFunc func(context.Context, string) (UDPAssociation, error)

func (s *Server) handleUDPAssociate(ctx context.Context, control net.Conn, requested string) error {
	if s.AssociateUDP == nil {
		_ = sendReply(control, 0x07)
		return errors.New("sessionproxy: UDP association unavailable")
	}
	localTCP, _ := control.LocalAddr().(*net.TCPAddr)
	remoteTCP, _ := control.RemoteAddr().(*net.TCPAddr)
	if localTCP == nil || remoteTCP == nil || remoteTCP.IP == nil {
		_ = sendReply(control, 0x01)
		return errors.New("sessionproxy: UDP ASSOCIATE requires TCP endpoint addresses")
	}
	clientEndpoint, err := newUDPClientEndpoint(remoteTCP.IP, requested)
	if err != nil {
		_ = sendReply(control, 0x02)
		return err
	}
	association, err := s.AssociateUDP(ctx, "udp")
	if err != nil {
		_ = sendReply(control, 0x01)
		return err
	}
	defer association.Close()

	network := "udp4"
	bindIP := append(net.IP(nil), localTCP.IP...)
	if bindIP == nil || bindIP.IsUnspecified() {
		bindIP = net.IPv4zero
	}
	if bindIP.To4() == nil {
		network = "udp6"
	}
	udpConn, err := net.ListenUDP(network, &net.UDPAddr{IP: bindIP, Port: 0})
	if err != nil {
		_ = sendReply(control, 0x01)
		return err
	}
	defer udpConn.Close()
	if err := sendReplyAddress(control, 0x00, udpConn.LocalAddr()); err != nil {
		return err
	}
	_ = control.SetDeadline(time.Time{})

	assocCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	controlDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(io.Discard, control)
		controlDone <- copyErr
		cancel()
		_ = udpConn.Close()
		_ = association.Close()
	}()
	backendDone := make(chan error, 1)
	go func() {
		for {
			packet, receiveErr := association.Receive()
			if receiveErr != nil {
				backendDone <- receiveErr
				return
			}
			if _, parseErr := socksudp.Parse(packet); parseErr != nil {
				continue
			}
			destination := clientEndpoint.Address()
			if destination == nil {
				continue
			}
			if _, writeErr := udpConn.WriteToUDP(packet, destination); writeErr != nil {
				backendDone <- writeErr
				return
			}
		}
	}()

	buffer := make([]byte, socksudp.MaxDatagramBytes)
	for {
		_ = udpConn.SetReadDeadline(time.Now().Add(time.Second))
		n, source, readErr := udpConn.ReadFromUDP(buffer)
		if readErr != nil {
			if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
				select {
				case <-assocCtx.Done():
					return nil
				case err := <-backendDone:
					if normalProxyError(err) {
						return nil
					}
					return err
				default:
					continue
				}
			}
			if assocCtx.Err() != nil || errors.Is(readErr, net.ErrClosed) {
				return nil
			}
			return readErr
		}
		if !clientEndpoint.Accept(source) {
			continue
		}
		packet := append([]byte(nil), buffer[:n]...)
		if _, parseErr := socksudp.Parse(packet); parseErr != nil {
			continue
		}
		if sendErr := association.Send(packet); sendErr != nil {
			return sendErr
		}
		select {
		case <-assocCtx.Done():
			return nil
		case err := <-controlDone:
			if normalProxyError(err) {
				return nil
			}
			return err
		case err := <-backendDone:
			if normalProxyError(err) {
				return nil
			}
			return err
		default:
		}
	}
}

type udpClientEndpoint struct {
	mu   sync.RWMutex
	ip   net.IP
	port int
	zone string
}

func newUDPClientEndpoint(controlIP net.IP, requested string) (*udpClientEndpoint, error) {
	controlIP = append(net.IP(nil), controlIP...)
	if controlIP == nil {
		return nil, errors.New("sessionproxy: missing SOCKS client IP")
	}
	host, portText, err := net.SplitHostPort(requested)
	if err != nil {
		return nil, fmt.Errorf("sessionproxy: invalid UDP ASSOCIATE client endpoint: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, errors.New("sessionproxy: invalid UDP ASSOCIATE client port")
	}
	requestedIP := net.ParseIP(host)
	unspecified := requestedIP == nil || requestedIP.IsUnspecified()
	if port == 0 && !unspecified {
		return nil, errors.New("sessionproxy: UDP ASSOCIATE must use both address and port zero when endpoint is unknown")
	}
	if port != 0 && unspecified {
		return nil, errors.New("sessionproxy: UDP ASSOCIATE must provide a concrete address with a concrete port")
	}
	if requestedIP != nil && !requestedIP.IsUnspecified() && !requestedIP.Equal(controlIP) {
		return nil, errors.New("sessionproxy: requested UDP client IP does not match SOCKS control connection")
	}
	return &udpClientEndpoint{ip: controlIP, port: port}, nil
}

func (e *udpClientEndpoint) Accept(source *net.UDPAddr) bool {
	if e == nil || source == nil || !source.IP.Equal(e.ip) {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.port == 0 {
		e.port = source.Port
		e.zone = source.Zone
	}
	return e.port == source.Port && e.zone == source.Zone
}

func (e *udpClientEndpoint) Address() *net.UDPAddr {
	if e == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.port == 0 {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), e.ip...), Port: e.port, Zone: e.zone}
}

func normalProxyError(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}
