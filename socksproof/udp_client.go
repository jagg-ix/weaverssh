package socksproof

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"weaverssh/socksudp"
)

// UDPClient is one proof-authenticated SOCKS5 UDP association. The TCP control
// connection owns the association lifetime. Client-to-proxy datagrams carry
// Ed25519 proofs; proxy-to-client datagrams carry a per-association HMAC that was
// negotiated over the authenticated TCP control connection.
type UDPClient struct {
	control net.Conn
	udp     *net.UDPConn
	relay   *net.UDPAddr

	challenge Challenge
	identity  SignedIdentity
	signer    Signer
	proofTTL  time.Duration
	sequence  atomic.Uint64

	responseKey    []byte
	responseWindow SequenceWindow
}

func DialUDP(ctx context.Context, proxyAddress string, config ClientConfig) (*UDPClient, error) {
	if config.Signer == nil || strings.TrimSpace(config.Principal) == "" {
		return nil, ErrInvalidProof
	}
	dialer := net.Dialer{}
	control, err := dialer.DialContext(ctx, "tcp", strings.TrimSpace(proxyAddress))
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*UDPClient, error) {
		_ = control.Close()
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = control.SetDeadline(deadline)
	}
	if _, err := control.Write([]byte{0x05, 0x01, MethodPrivate}); err != nil {
		return fail(err)
	}
	selection := make([]byte, 2)
	if _, err := io.ReadFull(control, selection); err != nil {
		return fail(err)
	}
	if selection[0] != 0x05 || selection[1] != MethodPrivate {
		return fail(errors.New("socksproof: server did not select cryptographic method"))
	}
	var challenge Challenge
	if err := ReadFrame(control, &challenge); err != nil {
		return fail(err)
	}
	if err := validateChallenge(challenge, time.Now()); err != nil {
		return fail(err)
	}
	if expected := strings.TrimSpace(config.ExpectedServerID); expected != "" && challenge.ServerID != expected {
		return fail(fmt.Errorf("socksproof: server ID %q does not match expected %q", challenge.ServerID, expected))
	}
	if expected := strings.ToLower(strings.TrimSpace(config.ExpectedPolicySHA256)); expected != "" && challenge.PolicySHA256 != expected {
		return fail(fmt.Errorf("socksproof: policy digest %q does not match expected %q", challenge.PolicySHA256, expected))
	}
	if expected := strings.TrimSpace(config.ExpectedNode); expected != "" && challenge.SelectedNode != expected {
		return fail(fmt.Errorf("socksproof: selected node %q does not match expected %q", challenge.SelectedNode, expected))
	}
	capabilities := append([]string(nil), config.Capabilities...)
	capabilities = append(capabilities, CapabilityConnect, CapabilityUDPAssociate)
	identity, err := SignIdentity(challenge, config.Principal, capabilities, config.Signer, config.ProofTTL, time.Now())
	if err != nil {
		return fail(err)
	}
	if err := WriteFrame(control, identity); err != nil {
		return fail(err)
	}
	var result AuthResult
	if err := ReadFrame(control, &result); err != nil {
		return fail(err)
	}
	if !result.OK || result.Protocol != ProtocolVersion || result.Principal != identity.Statement.Principal {
		return fail(fmt.Errorf("socksproof: identity rejected: %s", result.Error))
	}

	requested := "0.0.0.0:0"
	if err := writeSocksCommand(control, CommandUDPAssociate, requested); err != nil {
		return fail(err)
	}
	var datagramSession DatagramSession
	if err := ReadFrame(control, &datagramSession); err != nil {
		return fail(err)
	}
	responseKey, err := datagramSession.ResponseKey(challenge, time.Now())
	if err != nil {
		return fail(err)
	}
	associationProof, err := SignUDPAssociate(challenge, identity, "udp", requested, config.Signer, config.ProofTTL, time.Now())
	if err != nil {
		return fail(err)
	}
	if err := WriteFrame(control, associationProof); err != nil {
		return fail(err)
	}
	relay, err := readSocksReplyAddress(control)
	if err != nil {
		return fail(err)
	}
	udpNetwork := "udp4"
	if relay.IP.To4() == nil {
		udpNetwork = "udp6"
	}
	udp, err := net.ListenUDP(udpNetwork, nil)
	if err != nil {
		return fail(err)
	}
	_ = control.SetDeadline(time.Time{})
	return &UDPClient{
		control:     control,
		udp:         udp,
		relay:       relay,
		challenge:   challenge,
		identity:    identity,
		signer:      config.Signer,
		proofTTL:    config.ProofTTL,
		responseKey: responseKey,
	}, nil
}

func (c *UDPClient) LocalAddr() net.Addr {
	if c == nil || c.udp == nil {
		return nil
	}
	return c.udp.LocalAddr()
}

func (c *UDPClient) RelayAddr() net.Addr {
	if c == nil {
		return nil
	}
	return c.relay
}

func (c *UDPClient) Send(address string, payload []byte) error {
	if c == nil || c.udp == nil || c.relay == nil {
		return net.ErrClosed
	}
	packet, err := socksudp.Marshal(address, payload)
	if err != nil {
		return err
	}
	sequence := c.sequence.Add(1)
	proof, err := SignDatagram(c.challenge, c.identity, sequence, "udp", address, packet, c.signer, c.proofTTL, time.Now())
	if err != nil {
		return err
	}
	envelope, err := EncodeDatagramEnvelope(proof, packet)
	if err != nil {
		return err
	}
	_, err = c.udp.WriteToUDP(envelope, c.relay)
	return err
}

func (c *UDPClient) Receive(ctx context.Context) (socksudp.Datagram, error) {
	if c == nil || c.udp == nil || len(c.responseKey) != 32 {
		return socksudp.Datagram{}, net.ErrClosed
	}
	buffer := make([]byte, MaxAuthenticatedDatagramBytes)
	for {
		deadline := time.Now().Add(time.Second)
		if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
			deadline = requested
		}
		_ = c.udp.SetReadDeadline(deadline)
		n, source, err := c.udp.ReadFromUDP(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				if ctx.Err() != nil {
					return socksudp.Datagram{}, ctx.Err()
				}
				continue
			}
			return socksudp.Datagram{}, err
		}
		if c.relay != nil && (!source.IP.Equal(c.relay.IP) || source.Port != c.relay.Port) {
			continue
		}
		response, packet, err := DecodeDatagramResponse(buffer[:n], c.responseKey, c.challenge, time.Now())
		if err != nil {
			continue
		}
		if !c.responseWindow.Accept(response.Statement.Sequence) {
			continue
		}
		return socksudp.Parse(packet)
	}
}

func (c *UDPClient) Close() error {
	if c == nil {
		return nil
	}
	var first error
	if c.udp != nil {
		first = c.udp.Close()
	}
	if c.control != nil {
		if err := c.control.Close(); first == nil {
			first = err
		}
	}
	return first
}

func writeSocksCommand(writer io.Writer, command byte, address string) error {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil || strings.TrimSpace(host) == "" {
		return ErrInvalidProof
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return ErrInvalidProof
	}
	request := []byte{0x05, command, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			request = append(request, 0x01)
			request = append(request, ipv4...)
		} else {
			request = append(request, 0x04)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return ErrInvalidProof
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	request = append(request, portBytes...)
	return writeAll(writer, request)
}

func readSocksReplyAddress(reader io.Reader) (*net.UDPAddr, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if header[0] != 0x05 || header[1] != 0x00 {
		return nil, fmt.Errorf("socksproof: SOCKS5 command failed with reply 0x%02x", header[1])
	}
	var host string
	switch header[3] {
	case 0x01:
		payload := make([]byte, 4)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, err
		}
		host = net.IP(payload).String()
	case 0x04:
		payload := make([]byte, 16)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, err
		}
		host = net.IP(payload).String()
	case 0x03:
		length := []byte{0}
		if _, err := io.ReadFull(reader, length); err != nil {
			return nil, err
		}
		payload := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, err
		}
		host = string(payload)
	default:
		return nil, errors.New("socksproof: invalid SOCKS5 reply address type")
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(portBytes))
	return net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
}
