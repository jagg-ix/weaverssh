package display

import (
	"testing"

	"weaverssh/wverrors"
)

func TestResolveDisplayEndpointLocalhostTCP(t *testing.T) {
	ep, err := ResolveDisplayEndpoint("localhost:0.0")
	if err != nil {
		t.Fatalf("ResolveDisplayEndpoint: %v", err)
	}
	if ep.Kind != EndpointTCP || ep.Network != "tcp" || ep.Address != "localhost:6000" {
		t.Fatalf("endpoint = kind=%s network=%s address=%s", ep.Kind, ep.Network, ep.Address)
	}
	if ep.AuthorityKey != "localhost:0" || ep.ScreenName != "screen0" || !ep.IsScreen0() {
		t.Fatalf("authority/screen mismatch: %+v", ep)
	}
	if !ep.Matches("tcp", "127.0.0.1:6000") {
		t.Fatalf("localhost endpoint should match loopback TCP address")
	}
	if ep.Matches("tcp", "127.0.0.1:6001") {
		t.Fatalf("localhost endpoint matched wrong display port")
	}
	if ep.Matches("unix", "/tmp/.X11-unix/X0") {
		t.Fatalf("localhost endpoint matched Unix socket")
	}
}

func TestResolveDisplayEndpointUnixSocket(t *testing.T) {
	ep, err := ResolveDisplayEndpoint("unix:0.0")
	if err != nil {
		t.Fatalf("ResolveDisplayEndpoint: %v", err)
	}
	if ep.Kind != EndpointUnix || ep.Network != "unix" || ep.Address != "/tmp/.X11-unix/X0" {
		t.Fatalf("endpoint = kind=%s network=%s address=%s", ep.Kind, ep.Network, ep.Address)
	}
	if ep.AuthorityKey != "unix:0" || ep.ScreenName != "screen0" || !ep.IsScreen0() {
		t.Fatalf("authority/screen mismatch: %+v", ep)
	}
	if !ep.Matches("unix", "/tmp/.X11-unix/X0") {
		t.Fatalf("unix endpoint should match X0 Unix socket")
	}
	if ep.Matches("tcp", "localhost:6000") {
		t.Fatalf("unix endpoint matched TCP socket")
	}
}

func TestResolveDisplayEndpointRejectsUnsupportedScreen(t *testing.T) {
	if _, err := ResolveDisplayEndpoint("localhost:0.1"); err == nil {
		t.Fatalf("screen1 should fail closed because runtime only routes screen0")
	}
}

func TestValidateDialTargetForDisplayRejectsMismatchedSocket(t *testing.T) {
	if _, _, _, err := ValidateDialTargetForDisplay("localhost:0.0", "localhost:6000"); err != nil {
		t.Fatalf("matching TCP target rejected: %v", err)
	}
	if _, _, _, err := ValidateDialTargetForDisplay("localhost:0.0", "localhost:6001"); err == nil {
		t.Fatalf("wrong TCP port should be rejected")
	}
	if _, _, _, err := ValidateDialTargetForDisplay("unix:0.0", "unix:/tmp/.X11-unix/X0"); err != nil {
		t.Fatalf("matching Unix target rejected: %v", err)
	}
	if _, _, _, err := ValidateDialTargetForDisplay("unix:0.0", "localhost:6000"); err == nil {
		t.Fatalf("TCP target should not match Unix DISPLAY")
	}
}

func TestDisplayErrorsCarryStableCodes(t *testing.T) {
	if _, _, _, err := ParseDisplayString(""); !wverrors.IsCode(err, wverrors.CodeDisplayCouldNotBeResolved) {
		t.Fatalf("expected DISPLAY resolution code, got %v", err)
	}
	if _, err := ResolveDisplayEndpoint("localhost:0.1"); !wverrors.IsCode(err, wverrors.CodeX11SetupFailedClosed) {
		t.Fatalf("expected fail-closed X11 setup code, got %v", err)
	}
}
