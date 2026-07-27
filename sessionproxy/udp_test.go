package sessionproxy

import (
	"net"
	"strings"
	"testing"
)

func TestUDPClientEndpointLearnsOneSourcePort(t *testing.T) {
	endpoint, err := newUDPClientEndpoint(net.IPv4(127, 0, 0, 1), "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	first := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40123}
	if !endpoint.Accept(first) {
		t.Fatal("first UDP endpoint was rejected")
	}
	if !endpoint.Accept(first) {
		t.Fatal("learned UDP endpoint was not stable")
	}
	if endpoint.Accept(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40124}) {
		t.Fatal("second source port was accepted")
	}
	if endpoint.Accept(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 40123}) {
		t.Fatal("different source IP was accepted")
	}
	got := endpoint.Address()
	if got == nil || got.Port != 40123 || !got.IP.Equal(first.IP) {
		t.Fatalf("endpoint=%v", got)
	}
}

func TestUDPClientEndpointValidatesRequestedAddress(t *testing.T) {
	for _, test := range []struct {
		requested string
		wantError string
	}{
		{requested: "127.0.0.1:0", wantError: "both address and port zero"},
		{requested: "0.0.0.0:1234", wantError: "concrete address"},
		{requested: "127.0.0.2:1234", wantError: "does not match"},
	} {
		_, err := newUDPClientEndpoint(net.IPv4(127, 0, 0, 1), test.requested)
		if err == nil || !strings.Contains(err.Error(), test.wantError) {
			t.Fatalf("requested=%q error=%v", test.requested, err)
		}
	}
	endpoint, err := newUDPClientEndpoint(net.IPv4(127, 0, 0, 1), "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if !endpoint.Accept(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}) {
		t.Fatal("explicit client endpoint was rejected")
	}
}
