package sessionproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"weaverssh/socksproof"
	"weaverssh/socksudp"
)

const maxProofUDPEnvelopeBytes = socksproof.MaxAuthenticatedDatagramBytes

type proofRoutedUDPAssociation interface {
	UDPAssociation
	ConfigureProof(context.Context, string, socksproof.Bundle) error
	SendProof(socksproof.SignedDatagram, []byte) error
}

func (s *Server) handleProofUDPAssociate(
	ctx context.Context,
	control net.Conn,
	proofConfig *socksproof.ServerConfig,
	proofSession socksproof.ServerSession,
	network,
	requested string,
) error {
	if proofConfig == nil || s.AssociateUDP == nil {
		_ = sendReply(control, 0x07)
		return errors.New("sessionproxy: proof UDP association unavailable")
	}

	datagramSession, responseKey, err := socksproof.NewDatagramSession(proofSession.Challenge, time.Now())
	if err != nil {
		_ = sendReply(control, 0x01)
		return err
	}
	if err := socksproof.WriteFrame(control, datagramSession); err != nil {
		return err
	}

	var associationProof socksproof.SignedConnect
	if err := socksproof.ReadFrame(control, &associationProof); err != nil {
		_ = sendReply(control, 0x01)
		return err
	}
	if err := proofConfig.VerifyCommand(
		proofSession,
		associationProof,
		socksproof.CommandUDPAssociate,
		network,
		requested,
		time.Now(),
	); err != nil {
		_ = sendReply(control, 0x02)
		return err
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
	proofAssociation, ok := association.(proofRoutedUDPAssociation)
	if !ok {
		_ = sendReply(control, 0x01)
		return errors.New("sessionproxy: proof UDP route does not support final-node verification")
	}
	bundle := socksproof.Bundle{
		Challenge: proofSession.Challenge,
		Identity:  proofSession.Identity,
		Connect:   associationProof,
	}
	if err := proofAssociation.ConfigureProof(ctx, requested, bundle); err != nil {
		_ = sendReply(control, 0x02)
		return err
	}

	udpNetwork := "udp4"
	bindIP := append(net.IP(nil), localTCP.IP...)
	if bindIP == nil || bindIP.IsUnspecified() {
		bindIP = net.IPv4zero
	}
	if bindIP.To4() == nil {
		udpNetwork = "udp6"
	}
	udpConn, err := net.ListenUDP(udpNetwork, &net.UDPAddr{IP: bindIP, Port: 0})
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
		var responseSequence uint64
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
			responseSequence++
			envelope, encodeErr := socksproof.EncodeDatagramResponse(
				responseKey,
				proofSession.Challenge,
				responseSequence,
				packet,
				time.Now(),
			)
			if encodeErr != nil {
				backendDone <- encodeErr
				return
			}
			if _, writeErr := udpConn.WriteToUDP(envelope, destination); writeErr != nil {
				backendDone <- writeErr
				return
			}
		}
	}()

	buffer := make([]byte, maxProofUDPEnvelopeBytes)
	var sequences sequenceWindow
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
		proof, packet, decodeErr := socksproof.DecodeDatagramEnvelope(buffer[:n])
		if decodeErr != nil {
			continue
		}
		datagram, parseErr := socksudp.Parse(packet)
		if parseErr != nil {
			continue
		}
		if verifyErr := proofConfig.VerifyDatagram(
			proofSession,
			proof,
			packet,
			"udp",
			datagram.Address,
			time.Now(),
		); verifyErr != nil {
			continue
		}
		if !sequences.Accept(proof.Statement.Sequence) {
			continue
		}
		if sendErr := proofAssociation.SendProof(proof, packet); sendErr != nil {
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
