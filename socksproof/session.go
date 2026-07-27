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
	"time"
)

type ServerSession struct {
	Challenge Challenge
	Identity  SignedIdentity
	Principal PrincipalPolicy
}

type ServerConfig struct {
	Verifier       *Verifier
	ServerID       string
	SessionBinding string
	SelectedNode   string
	ChallengeTTL   time.Duration
	MaxProofTTL    time.Duration
}

func (c ServerConfig) Begin(conn net.Conn, now time.Time) (ServerSession, error) {
	if c.Verifier == nil {
		return ServerSession{}, ErrUnauthorized
	}
	serverID := strings.TrimSpace(c.ServerID)
	if serverID == "" {
		serverID = c.Verifier.ServerID
	}
	challenge, err := NewChallenge(serverID, c.Verifier.PolicySHA256, c.SessionBinding, c.SelectedNode, c.ChallengeTTL, now)
	if err != nil {
		return ServerSession{}, err
	}
	if err := WriteFrame(conn, challenge); err != nil {
		return ServerSession{}, err
	}
	var identity SignedIdentity
	if err := ReadFrame(conn, &identity); err != nil {
		return ServerSession{}, err
	}
	principal, err := c.Verifier.VerifyIdentity(challenge, identity, now)
	if err != nil {
		_ = WriteFrame(conn, AuthResult{Protocol: ProtocolVersion, OK: false, Error: err.Error()})
		return ServerSession{}, err
	}
	if err := WriteFrame(conn, AuthResult{Protocol: ProtocolVersion, OK: true, Principal: principal.ID}); err != nil {
		return ServerSession{}, err
	}
	return ServerSession{Challenge: challenge, Identity: identity, Principal: principal}, nil
}

func (c ServerConfig) VerifyConnect(session ServerSession, proof SignedConnect, network, address string, now time.Time) error {
	if c.Verifier == nil {
		return ErrUnauthorized
	}
	_, err := c.Verifier.VerifyConnect(session.Challenge, session.Identity, proof, network, address, c.SessionBinding, c.SelectedNode, now)
	return err
}

type ClientConfig struct {
	Principal            string
	Capabilities         []string
	Signer               Signer
	ProofTTL             time.Duration
	ExpectedServerID     string
	ExpectedPolicySHA256 string
	ExpectedNode         string
}

// Dial establishes a proof-authenticated SOCKS5 CONNECT tunnel.
func Dial(ctx context.Context, proxyAddress, destination string, config ClientConfig) (net.Conn, SignedConnect, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", strings.TrimSpace(proxyAddress))
	if err != nil {
		return nil, SignedConnect{}, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	proof, err := HandshakeClient(conn, destination, config)
	if err != nil {
		_ = conn.Close()
		return nil, SignedConnect{}, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, proof, nil
}

func HandshakeClient(conn net.Conn, destination string, config ClientConfig) (SignedConnect, error) {
	if conn == nil || config.Signer == nil || strings.TrimSpace(config.Principal) == "" {
		return SignedConnect{}, ErrInvalidProof
	}
	if _, err := conn.Write([]byte{0x05, 0x01, MethodPrivate}); err != nil {
		return SignedConnect{}, err
	}
	selection := make([]byte, 2)
	if _, err := io.ReadFull(conn, selection); err != nil {
		return SignedConnect{}, err
	}
	if selection[0] != 0x05 || selection[1] != MethodPrivate {
		return SignedConnect{}, errors.New("socksproof: server did not select cryptographic method")
	}
	var challenge Challenge
	if err := ReadFrame(conn, &challenge); err != nil {
		return SignedConnect{}, err
	}
	if err := validateChallenge(challenge, time.Now()); err != nil {
		return SignedConnect{}, err
	}
	if expected := strings.TrimSpace(config.ExpectedServerID); expected != "" && challenge.ServerID != expected {
		return SignedConnect{}, fmt.Errorf("socksproof: server ID %q does not match expected %q", challenge.ServerID, expected)
	}
	if expected := strings.ToLower(strings.TrimSpace(config.ExpectedPolicySHA256)); expected != "" && challenge.PolicySHA256 != expected {
		return SignedConnect{}, fmt.Errorf("socksproof: policy digest %q does not match expected %q", challenge.PolicySHA256, expected)
	}
	if expected := strings.TrimSpace(config.ExpectedNode); expected != "" && challenge.SelectedNode != expected {
		return SignedConnect{}, fmt.Errorf("socksproof: selected node %q does not match expected %q", challenge.SelectedNode, expected)
	}
	identity, err := SignIdentity(challenge, config.Principal, append(config.Capabilities, CapabilityConnect), config.Signer, config.ProofTTL, time.Now())
	if err != nil {
		return SignedConnect{}, err
	}
	if err := WriteFrame(conn, identity); err != nil {
		return SignedConnect{}, err
	}
	var result AuthResult
	if err := ReadFrame(conn, &result); err != nil {
		return SignedConnect{}, err
	}
	if !result.OK || result.Protocol != ProtocolVersion || result.Principal != identity.Statement.Principal {
		return SignedConnect{}, fmt.Errorf("socksproof: identity rejected: %s", result.Error)
	}
	if err := writeConnectRequest(conn, destination); err != nil {
		return SignedConnect{}, err
	}
	connectProof, err := SignConnect(challenge, identity, "tcp", destination, config.Signer, config.ProofTTL, time.Now())
	if err != nil {
		return SignedConnect{}, err
	}
	if err := WriteFrame(conn, connectProof); err != nil {
		return SignedConnect{}, err
	}
	if err := readSocksReply(conn); err != nil {
		return SignedConnect{}, err
	}
	return connectProof, nil
}

func writeConnectRequest(writer io.Writer, address string) error {
	_, address, err := NormalizeAddress("tcp", address)
	if err != nil {
		return err
	}
	host, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portText)
	request := []byte{0x05, 0x01, 0x00}
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
			return errors.New("socksproof: invalid destination host")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, []byte(host)...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	request = append(request, portBytes...)
	return writeAll(writer, request)
}

func readSocksReply(reader io.Reader) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != 0x05 || header[1] != 0x00 {
		return fmt.Errorf("socksproof: SOCKS5 CONNECT failed with reply 0x%02x", header[1])
	}
	var length int
	switch header[3] {
	case 0x01:
		length = 4
	case 0x04:
		length = 16
	case 0x03:
		one := []byte{0}
		if _, err := io.ReadFull(reader, one); err != nil {
			return err
		}
		length = int(one[0])
	default:
		return errors.New("socksproof: invalid SOCKS5 reply address type")
	}
	payload := make([]byte, length+2)
	_, err := io.ReadFull(reader, payload)
	return err
}
