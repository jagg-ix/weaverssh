package socksproof

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// BindClient represents a proof-authenticated one-shot SOCKS5 BIND operation.
type BindClient struct {
	control    net.Conn
	bound      net.Addr
	acceptOnce sync.Once
	accepted   net.Conn
	peer       net.Addr
	acceptErr  error
}

func DialBind(ctx context.Context, proxyAddress, expectedPeer string, config ClientConfig) (*BindClient, error) {
	if config.Signer == nil || strings.TrimSpace(config.Principal) == "" {
		return nil, ErrInvalidProof
	}
	dialer := net.Dialer{}
	control, err := dialer.DialContext(ctx, "tcp", strings.TrimSpace(proxyAddress))
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*BindClient, error) {
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
	capabilities = append(capabilities, CapabilityConnect, CapabilityBind)
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
	if err := writeSocksCommand(control, CommandBind, expectedPeer); err != nil {
		return fail(err)
	}
	bindProof, err := SignBind(challenge, identity, "tcp", expectedPeer, config.Signer, config.ProofTTL, time.Now())
	if err != nil {
		return fail(err)
	}
	if err := WriteFrame(control, bindProof); err != nil {
		return fail(err)
	}
	boundUDP, err := readSocksReplyAddress(control)
	if err != nil {
		return fail(err)
	}
	bound := &net.TCPAddr{IP: append(net.IP(nil), boundUDP.IP...), Port: boundUDP.Port, Zone: boundUDP.Zone}
	_ = control.SetDeadline(time.Time{})
	return &BindClient{control: control, bound: bound}, nil
}

func (c *BindClient) Addr() net.Addr {
	if c == nil {
		return nil
	}
	return c.bound
}

func (c *BindClient) PeerAddr() net.Addr {
	if c == nil {
		return nil
	}
	return c.peer
}

func (c *BindClient) Accept(ctx context.Context) (net.Conn, error) {
	if c == nil || c.control == nil {
		return nil, net.ErrClosed
	}
	c.acceptOnce.Do(func() {
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.control.SetDeadline(deadline)
			defer c.control.SetDeadline(time.Time{})
		}
		peerUDP, err := readSocksReplyAddress(c.control)
		if err != nil {
			c.acceptErr = err
			return
		}
		c.peer = &net.TCPAddr{IP: append(net.IP(nil), peerUDP.IP...), Port: peerUDP.Port, Zone: peerUDP.Zone}
		c.accepted = c.control
	})
	return c.accepted, c.acceptErr
}

func (c *BindClient) Close() error {
	if c == nil || c.control == nil {
		return nil
	}
	return c.control.Close()
}
