package authproof

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	NativeForwardSSHLocal   = "sshL"
	NativeForwardSSHRemote  = "sshR"
	NativeForwardSSHDynamic = "sshD"

	NativeForwardRoleAuxiliaryLoopbackBridge = "auxiliaryLoopbackBridge"
	NativeForwardRoleManagedBackhaul         = "managedBackhaul"
	NativeForwardRoleBootstrapProbe          = "bootstrapProbe"
)

var (
	ErrInvalidNativeForwardingMode   = errors.New("invalid native ssh forwarding mode")
	ErrUnsafeNativeForwardingPolicy  = errors.New("unsafe native ssh forwarding policy")
	ErrNativeForwardingProofRequired = errors.New("native ssh forwarding requires trusted-peer authproof")
)

// NativeForwardingPolicy describes an SSH -L/-R/-D adapter plan after the
// weaverssh control plane has allocated ports. It is intentionally security
// policy, not an SSH implementation: callers must validate it before rendering
// SSH arguments or accepting traffic through the forwarded socket.
type NativeForwardingPolicy struct {
	Mode string
	Role string

	// Bind/target endpoints. Dynamic forwarding uses LocalBind and LocalPort.
	LocalBind  string
	LocalPort  int
	RemoteBind string
	RemotePort int
	TargetHost string
	TargetPort int

	ExitOnForwardFailure bool
	ClearAllForwardings  bool
	GatewayPortsDisabled bool
	PermitLocalCommandNo bool
	ForwardAgentDisabled bool
	ForwardX11Disabled   bool
	IdentitiesOnly       bool
	StrictHostKey        bool
	EndpointRestricted   bool
	LifecycleAudited     bool
	WeaversshEndpoint    bool

	// This must remain false for remote-root-resistant operation. If authority
	// material is present on a root-controlled remote host, SSH forwarding cannot
	// provide the contract's authority boundary.
	AuthorityMaterialOnRemoteHost bool

	Proof RuntimeConfig
}

func NativeForwardingRequiredCapabilities(mode string) []string {
	switch strings.TrimSpace(mode) {
	case NativeForwardSSHLocal, NativeForwardSSHRemote:
		return []string{CapabilityWebSocketUpgrade, CapabilityX11Relay}
	case NativeForwardSSHDynamic:
		return []string{CapabilitySocksProxy}
	default:
		return nil
	}
}

func NativeForwardingRoleForMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case NativeForwardSSHLocal:
		return NativeForwardRoleAuxiliaryLoopbackBridge
	case NativeForwardSSHRemote:
		return NativeForwardRoleManagedBackhaul
	case NativeForwardSSHDynamic:
		return NativeForwardRoleBootstrapProbe
	default:
		return ""
	}
}

func SecurityLevelRank(level string) int {
	switch NormalizeSecurityLevel(level) {
	case SecurityLevelCompat:
		return 0
	case SecurityLevelSameUID:
		return 1
	case SecurityLevelX11Cookie:
		return 2
	case SecurityLevelAgentProof:
		return 3
	case SecurityLevelStrict:
		return 4
	default:
		return -1
	}
}

func SecurityLevelAtLeast(level, minimum string) bool {
	return SecurityLevelRank(level) >= SecurityLevelRank(minimum) && SecurityLevelRank(minimum) >= 0
}

func ValidateNativeForwardingPolicy(p NativeForwardingPolicy) error {
	mode := strings.TrimSpace(p.Mode)
	if mode != NativeForwardSSHLocal && mode != NativeForwardSSHRemote && mode != NativeForwardSSHDynamic {
		return fmt.Errorf("%w: %q", ErrInvalidNativeForwardingMode, p.Mode)
	}
	if wantRole := NativeForwardingRoleForMode(mode); strings.TrimSpace(p.Role) != "" && strings.TrimSpace(p.Role) != wantRole {
		return fmt.Errorf("%w: mode %s cannot use role %s", ErrUnsafeNativeForwardingPolicy, mode, p.Role)
	}
	if err := validateNativeForwardingEndpoints(p); err != nil {
		return err
	}
	for name, ok := range map[string]bool{
		"ExitOnForwardFailure": p.ExitOnForwardFailure,
		"ClearAllForwardings":  p.ClearAllForwardings,
		"GatewayPortsDisabled": p.GatewayPortsDisabled,
		"PermitLocalCommandNo": p.PermitLocalCommandNo,
		"ForwardAgentDisabled": p.ForwardAgentDisabled,
		"ForwardX11Disabled":   p.ForwardX11Disabled,
		"IdentitiesOnly":       p.IdentitiesOnly,
		"StrictHostKey":        p.StrictHostKey,
		"EndpointRestricted":   p.EndpointRestricted,
		"LifecycleAudited":     p.LifecycleAudited,
		"WeaversshEndpoint":    p.WeaversshEndpoint,
	} {
		if !ok {
			return fmt.Errorf("%w: %s is required", ErrUnsafeNativeForwardingPolicy, name)
		}
	}
	if p.AuthorityMaterialOnRemoteHost {
		return fmt.Errorf("%w: authority material must stay outside remote-root authority domain", ErrUnsafeNativeForwardingPolicy)
	}
	return ValidateNativeForwardingProof(mode, p.Proof)
}

func ValidateNativeForwardingProof(mode string, cfg RuntimeConfig) error {
	proof := cfg.Normalized()
	proof.Mode = NormalizeProofMode(proof.Mode)
	if proof.Mode != ProofModeRequired {
		return fmt.Errorf("%w: proof mode must be required", ErrNativeForwardingProofRequired)
	}
	if !SecurityLevelAtLeast(proof.SecurityLevel, SecurityLevelAgentProof) {
		return fmt.Errorf("%w: security level must be agent_proof or strict", ErrNativeForwardingProofRequired)
	}
	if proof.SubjectPeerID == "" || proof.Audience == "" {
		return fmt.Errorf("%w: subject peer and audience binding required", ErrNativeForwardingProofRequired)
	}
	if proof.PublicKey == "" && proof.PublicKeyFile == "" {
		return fmt.Errorf("%w: trusted verifier public key required", ErrNativeForwardingProofRequired)
	}
	if _, err := proof.LoadPublicKey(); err != nil {
		return fmt.Errorf("%w: %v", ErrNativeForwardingProofRequired, err)
	}
	if proof.ChainSHA256 == "" || proof.ChainSHA256 == DefaultChainSHA256() {
		return fmt.Errorf("%w: explicit non-default chain binding required", ErrNativeForwardingProofRequired)
	}
	if proof.X11CookieSHA256 == "" && mode != NativeForwardSSHDynamic {
		return fmt.Errorf("%w: x11 cookie binding required", ErrNativeForwardingProofRequired)
	}
	for _, capability := range NativeForwardingRequiredCapabilities(mode) {
		if !hasCapability(proof.RequiredCapabilities, capability) {
			return fmt.Errorf("%w: missing capability %s", ErrNativeForwardingProofRequired, capability)
		}
	}
	return nil
}

func BuildNativeForwardingOpenSSHArgs(remote string, p NativeForwardingPolicy) ([]string, error) {
	if err := ValidateNativeForwardingPolicy(p); err != nil {
		return nil, err
	}
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return nil, fmt.Errorf("%w: remote ssh target required", ErrUnsafeNativeForwardingPolicy)
	}
	args := []string{
		"-N", "-T",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ClearAllForwardings=yes",
		"-o", "GatewayPorts=no",
		"-o", "PermitLocalCommand=no",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=yes",
	}
	switch p.Mode {
	case NativeForwardSSHLocal:
		args = append(args, "-L", net.JoinHostPort(p.LocalBind, strconv.Itoa(p.LocalPort))+":"+net.JoinHostPort(p.TargetHost, p.TargetPortString()))
	case NativeForwardSSHRemote:
		args = append(args, "-R", net.JoinHostPort(p.RemoteBind, strconv.Itoa(p.RemotePort))+":"+net.JoinHostPort(p.TargetHost, p.TargetPortString()))
	case NativeForwardSSHDynamic:
		args = append(args, "-D", net.JoinHostPort(p.LocalBind, strconv.Itoa(p.LocalPort)))
	}
	return append(args, remote), nil
}

func (p NativeForwardingPolicy) TargetPortString() string {
	return strconv.Itoa(p.TargetPort)
}

func validateNativeForwardingEndpoints(p NativeForwardingPolicy) error {
	switch p.Mode {
	case NativeForwardSSHLocal:
		if err := requireLoopbackEndpoint("local bind", p.LocalBind, p.LocalPort); err != nil {
			return err
		}
		if err := requireLoopbackEndpoint("target", p.TargetHost, p.TargetPort); err != nil {
			return err
		}
	case NativeForwardSSHRemote:
		if err := requireLoopbackEndpoint("remote bind", p.RemoteBind, p.RemotePort); err != nil {
			return err
		}
		if err := requireLoopbackEndpoint("target", p.TargetHost, p.TargetPort); err != nil {
			return err
		}
	case NativeForwardSSHDynamic:
		if err := requireLoopbackEndpoint("dynamic bind", p.LocalBind, p.LocalPort); err != nil {
			return err
		}
	}
	return nil
}

func requireLoopbackEndpoint(name, host string, port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("%w: %s port out of range", ErrUnsafeNativeForwardingPolicy, name)
	}
	if !isLoopbackHost(host) {
		return fmt.Errorf("%w: %s must bind/connect loopback", ErrUnsafeNativeForwardingPolicy, name)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
