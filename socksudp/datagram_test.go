package socksudp

import (
	"errors"
	"net"
	"testing"
)

func TestRoundTripRFC1928Addresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1:53", "[2001:db8::1]:5353", "dns.internal:53"} {
		packet, err := Marshal(address, []byte("query"))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Parse(packet)
		if err != nil {
			t.Fatal(err)
		}
		wantHost, wantPort, _ := net.SplitHostPort(address)
		gotHost, gotPort, _ := net.SplitHostPort(decoded.Address)
		if !equalHost(wantHost, gotHost) || wantPort != gotPort || string(decoded.Data) != "query" {
			t.Fatalf("decoded=%+v want=%s", decoded, address)
		}
	}
}

func TestRejectsReservedAndFragments(t *testing.T) {
	packet, _ := Marshal("127.0.0.1:53", nil)
	packet[0] = 1
	if _, err := Parse(packet); !errors.Is(err, ErrInvalidDatagram) {
		t.Fatalf("reserved error=%v", err)
	}
	packet, _ = Marshal("127.0.0.1:53", nil)
	packet[2] = 1
	if _, err := Parse(packet); !errors.Is(err, ErrFragmentUnsupported) {
		t.Fatalf("fragment error=%v", err)
	}
}

func equalHost(left, right string) bool {
	if leftIP, rightIP := net.ParseIP(left), net.ParseIP(right); leftIP != nil && rightIP != nil {
		return leftIP.Equal(rightIP)
	}
	return left == right
}
