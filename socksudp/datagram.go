// Package socksudp implements the SOCKS5 UDP request header from RFC 1928.
package socksudp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	ATYPIPv4   = byte(0x01)
	ATYPDomain = byte(0x03)
	ATYPIPv6   = byte(0x04)

	// MaxDatagramBytes bounds one complete RFC 1928 UDP request message.
	MaxDatagramBytes = 64 << 10
)

var (
	ErrInvalidDatagram     = errors.New("socksudp: invalid RFC 1928 datagram")
	ErrFragmentUnsupported = errors.New("socksudp: fragmented datagrams are unsupported")
)

// Datagram is one standalone RFC 1928 UDP request or response message.
type Datagram struct {
	Address string
	Data    []byte
}

// Parse validates and decodes one RFC 1928 UDP message. FRAG must be zero.
func Parse(packet []byte) (Datagram, error) {
	if len(packet) < 7 || len(packet) > MaxDatagramBytes {
		return Datagram{}, ErrInvalidDatagram
	}
	if packet[0] != 0 || packet[1] != 0 {
		return Datagram{}, ErrInvalidDatagram
	}
	if packet[2] != 0 {
		return Datagram{}, fmt.Errorf("%w: FRAG=%d", ErrFragmentUnsupported, packet[2])
	}
	index := 4
	var host string
	switch packet[3] {
	case ATYPIPv4:
		if len(packet) < index+4+2 {
			return Datagram{}, ErrInvalidDatagram
		}
		host = net.IP(packet[index : index+4]).String()
		index += 4
	case ATYPIPv6:
		if len(packet) < index+16+2 {
			return Datagram{}, ErrInvalidDatagram
		}
		host = net.IP(packet[index : index+16]).String()
		index += 16
	case ATYPDomain:
		if len(packet) < index+1 {
			return Datagram{}, ErrInvalidDatagram
		}
		length := int(packet[index])
		index++
		if length == 0 || len(packet) < index+length+2 {
			return Datagram{}, ErrInvalidDatagram
		}
		host = string(packet[index : index+length])
		if strings.IndexByte(host, 0) >= 0 {
			return Datagram{}, ErrInvalidDatagram
		}
		index += length
	default:
		return Datagram{}, fmt.Errorf("%w: ATYP=%d", ErrInvalidDatagram, packet[3])
	}
	port := int(binary.BigEndian.Uint16(packet[index : index+2]))
	if port < 1 {
		return Datagram{}, ErrInvalidDatagram
	}
	index += 2
	return Datagram{Address: net.JoinHostPort(host, strconv.Itoa(port)), Data: append([]byte(nil), packet[index:]...)}, nil
}

// Marshal encodes one standalone RFC 1928 UDP message with FRAG=0.
func Marshal(address string, data []byte) ([]byte, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil || strings.TrimSpace(host) == "" {
		return nil, fmt.Errorf("socksudp: destination must be HOST:PORT: %q", address)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("socksudp: invalid destination port %q", portText)
	}
	packet := []byte{0, 0, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			packet = append(packet, ATYPIPv4)
			packet = append(packet, ipv4...)
		} else {
			packet = append(packet, ATYPIPv6)
			packet = append(packet, ip.To16()...)
		}
	} else {
		host = strings.TrimSuffix(strings.TrimSpace(host), ".")
		if len(host) == 0 || len(host) > 255 || strings.IndexByte(host, 0) >= 0 {
			return nil, errors.New("socksudp: invalid destination domain")
		}
		packet = append(packet, ATYPDomain, byte(len(host)))
		packet = append(packet, host...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	packet = append(packet, portBytes...)
	packet = append(packet, data...)
	if len(packet) > MaxDatagramBytes {
		return nil, errors.New("socksudp: datagram too large")
	}
	return packet, nil
}
