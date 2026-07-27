package app

import (
	"net"
	"testing"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"weaverssh/display"
)

func TestSOCKSHandlerValidatesX11RequestTargetAgainstDisplayEndpoint(t *testing.T) {
	endpoint, err := display.ResolveDisplayEndpoint("localhost:0.0")
	if err != nil {
		t.Fatalf("ResolveDisplayEndpoint: %v", err)
	}
	handler := &SOCKSHandler{hasX11Endpoint: true, x11Endpoint: endpoint}

	matchingReq := &socks5.Request{DestAddr: &statute.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 6000}}
	if err := handler.validateX11RequestTarget(matchingReq); err != nil {
		t.Fatalf("matching loopback target rejected: %v", err)
	}

	wrongPortReq := &socks5.Request{DestAddr: &statute.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 6001}}
	if err := handler.validateX11RequestTarget(wrongPortReq); err == nil {
		t.Fatalf("wrong display port should be rejected")
	}
}

func TestSOCKSHandlerRejectsTCPRequestForUnixDisplayEndpoint(t *testing.T) {
	endpoint, err := display.ResolveDisplayEndpoint("unix:0.0")
	if err != nil {
		t.Fatalf("ResolveDisplayEndpoint: %v", err)
	}
	handler := &SOCKSHandler{hasX11Endpoint: true, x11Endpoint: endpoint}

	req := &socks5.Request{DestAddr: &statute.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 6000}}
	if err := handler.validateX11RequestTarget(req); err == nil {
		t.Fatalf("TCP SOCKS request should not match Unix DISPLAY endpoint")
	}
}
