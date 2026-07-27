package authproof

import (
	"errors"
	"strings"
	"testing"
)

func nativeForwardingTestProof(t *testing.T, mode string) RuntimeConfig {
	t.Helper()
	v := loadVector(t)
	caps := NativeForwardingRequiredCapabilities(mode)
	return RuntimeConfig{
		Mode:                 ProofModeRequired,
		SecurityLevel:        SecurityLevelAgentProof,
		SubjectPeerID:        "agent-linode-a",
		Audience:             AudienceAgent,
		PublicKey:            v.PublicKeyBase64URL,
		X11CookieSHA256:      HashX11Cookie("native-forward-cookie"),
		ChainSHA256:          ChainBindingSHA256("origin-alise", "jump-a", "agent-linode-a"),
		RequiredCapabilities: caps,
	}
}

func nativeForwardingTestPolicy(t *testing.T, mode string) NativeForwardingPolicy {
	t.Helper()
	p := NativeForwardingPolicy{
		Mode:                 mode,
		Role:                 NativeForwardingRoleForMode(mode),
		LocalBind:            "127.0.0.1",
		LocalPort:            19080,
		RemoteBind:           "127.0.0.1",
		RemotePort:           22022,
		TargetHost:           "127.0.0.1",
		TargetPort:           6017,
		ExitOnForwardFailure: true,
		ClearAllForwardings:  true,
		GatewayPortsDisabled: true,
		PermitLocalCommandNo: true,
		ForwardAgentDisabled: true,
		ForwardX11Disabled:   true,
		IdentitiesOnly:       true,
		StrictHostKey:        true,
		EndpointRestricted:   true,
		LifecycleAudited:     true,
		WeaversshEndpoint:    true,
		Proof:                nativeForwardingTestProof(t, mode),
	}
	if mode == NativeForwardSSHDynamic {
		p.TargetHost = ""
		p.TargetPort = 0
		p.Proof.Audience = AudienceSocks
	}
	return p
}

func TestValidateNativeForwardingPolicyAcceptsContractPreservingModes(t *testing.T) {
	for _, mode := range []string{NativeForwardSSHLocal, NativeForwardSSHRemote, NativeForwardSSHDynamic} {
		if err := ValidateNativeForwardingPolicy(nativeForwardingTestPolicy(t, mode)); err != nil {
			t.Fatalf("%s should validate: %v", mode, err)
		}
	}
}

func TestValidateNativeForwardingPolicyRejectsSSHOnlyAuthority(t *testing.T) {
	p := nativeForwardingTestPolicy(t, NativeForwardSSHRemote)
	p.Proof.Mode = ProofModeOff
	if err := ValidateNativeForwardingPolicy(p); !errors.Is(err, ErrNativeForwardingProofRequired) {
		t.Fatalf("expected proof-required failure, got %v", err)
	}

	p = nativeForwardingTestPolicy(t, NativeForwardSSHRemote)
	p.Proof.SecurityLevel = SecurityLevelX11Cookie
	if err := ValidateNativeForwardingPolicy(p); !errors.Is(err, ErrNativeForwardingProofRequired) {
		t.Fatalf("expected agent-proof minimum failure, got %v", err)
	}
}

func TestValidateNativeForwardingPolicyRejectsRemoteRootAuthorityMaterial(t *testing.T) {
	p := nativeForwardingTestPolicy(t, NativeForwardSSHRemote)
	p.AuthorityMaterialOnRemoteHost = true
	if err := ValidateNativeForwardingPolicy(p); !errors.Is(err, ErrUnsafeNativeForwardingPolicy) {
		t.Fatalf("expected remote authority material failure, got %v", err)
	}
}

func TestValidateNativeForwardingPolicyRejectsWildcardAndMissingGuardrails(t *testing.T) {
	p := nativeForwardingTestPolicy(t, NativeForwardSSHLocal)
	p.LocalBind = "0.0.0.0"
	if err := ValidateNativeForwardingPolicy(p); !errors.Is(err, ErrUnsafeNativeForwardingPolicy) {
		t.Fatalf("expected wildcard bind failure, got %v", err)
	}

	p = nativeForwardingTestPolicy(t, NativeForwardSSHLocal)
	p.EndpointRestricted = false
	if err := ValidateNativeForwardingPolicy(p); !errors.Is(err, ErrUnsafeNativeForwardingPolicy) {
		t.Fatalf("expected endpoint restriction failure, got %v", err)
	}
}

func TestValidateNativeForwardingPolicyRejectsDefaultChainAndMissingTrustedKey(t *testing.T) {
	p := nativeForwardingTestPolicy(t, NativeForwardSSHRemote)
	p.Proof.ChainSHA256 = DefaultChainSHA256()
	if err := ValidateNativeForwardingPolicy(p); !errors.Is(err, ErrNativeForwardingProofRequired) {
		t.Fatalf("expected explicit chain binding failure, got %v", err)
	}

	p = nativeForwardingTestPolicy(t, NativeForwardSSHRemote)
	p.Proof.PublicKey = ""
	if err := ValidateNativeForwardingPolicy(p); !errors.Is(err, ErrNativeForwardingProofRequired) {
		t.Fatalf("expected trusted public key failure, got %v", err)
	}
}

func TestBuildNativeForwardingOpenSSHArgsRendersOnlySafeOptions(t *testing.T) {
	args, err := BuildNativeForwardingOpenSSHArgs("root@203.0.113.20", nativeForwardingTestPolicy(t, NativeForwardSSHRemote))
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-N -T",
		"ExitOnForwardFailure=yes",
		"ClearAllForwardings=yes",
		"GatewayPorts=no",
		"ForwardAgent=no",
		"ForwardX11=no",
		"StrictHostKeyChecking=yes",
		"-R 127.0.0.1:22022:127.0.0.1:6017",
		"root@203.0.113.20",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("args missing %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, " -g ") || strings.Contains(joined, "ForwardAgent=yes") || strings.Contains(joined, "ForwardX11=yes") {
		t.Fatalf("unsafe option rendered: %s", joined)
	}
}

func TestNativeForwardingDynamicRequiresSocksCapability(t *testing.T) {
	p := nativeForwardingTestPolicy(t, NativeForwardSSHDynamic)
	p.Proof.RequiredCapabilities = []string{CapabilityWebSocketUpgrade}
	if err := ValidateNativeForwardingPolicy(p); !errors.Is(err, ErrNativeForwardingProofRequired) {
		t.Fatalf("expected socks capability failure, got %v", err)
	}
}
