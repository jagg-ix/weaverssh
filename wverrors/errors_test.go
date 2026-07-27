package wverrors

import (
	"errors"
	"strings"
	"testing"
)

func TestWrapPreservesCauseAndCode(t *testing.T) {
	cause := errors.New("ssh exited with status 255")
	err := Wrap(CodeSSHLoginFailed, "ssh", "connect", "remote login failed", cause).WithField("host", "203.0.113.10")

	if !errors.Is(err, cause) {
		t.Fatalf("expected wrapped cause to be discoverable")
	}
	if !IsCode(err, CodeSSHLoginFailed) {
		t.Fatalf("expected code %s", CodeSSHLoginFailed)
	}
	if got := err.Error(); !strings.Contains(got, "[WV-SSH-001] ssh.connect") {
		t.Fatalf("unexpected error string: %s", got)
	}
}

func TestEventIncludesRegistryMetadata(t *testing.T) {
	err := New(CodeXAuthorityCookieMismatch, "x11", "authorize", "cookie mismatch").WithField("display", "unix:0")
	event := Event(err)

	if event["code"] != string(CodeXAuthorityCookieMismatch) {
		t.Fatalf("unexpected event code: %#v", event["code"])
	}
	if event["subsystem"] != "x11" {
		t.Fatalf("expected x11 subsystem, got %#v", event["subsystem"])
	}
	if event["retryable"] != false {
		t.Fatalf("XAUTHORITY mismatch should not be retryable by default")
	}
	fields, ok := event["fields"].(map[string]string)
	if !ok || fields["display"] != "unix:0" {
		t.Fatalf("expected display field, got %#v", event["fields"])
	}
}

func TestRegistryContainsStableDebugKBCodes(t *testing.T) {
	expected := []Code{
		CodeAdapterDataPlaneOwner,
		CodeAuthproofMissingOrInvalid,
		CodeAuthorityRemoteRootDomain,
		CodeNoActiveConnectionProfile,
		CodeCapabilityVersionMismatch,
		CodeRequiredDependencyMissing,
		CodePackageManagerOperationDenied,
		CodeFuseUnavailable,
		CodeMCPListenerDown,
		CodeArtifactSignatureMismatch,
		CodeHomebrewFormulaInvalid,
		CodeSnapcraftUnavailable,
		CodeRelayPumpTerminatedEarly,
		CodeUnsafeNonLoopbackBindRejected,
		CodeSocketBridgeCommandRejected,
		CodeSSHLoginFailed,
		CodeAgentForwardingUnavailable,
		CodeValidationGateMissing,
		CodeVFSEndpointUnavailable,
		CodeWebSocketSecondPhaseRejected,
		CodeDisplayCouldNotBeResolved,
		CodeXAuthorityCookieMismatch,
		CodeX11SetupFailedClosed,
	}
	if len(Registry) != len(expected) {
		t.Fatalf("registry size mismatch: got %d want %d", len(Registry), len(expected))
	}
	for _, code := range expected {
		if !KnownCode(code) {
			t.Fatalf("missing code %s", code)
		}
	}
}
