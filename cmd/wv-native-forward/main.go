package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"weaverssh/authproof"
)

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value != "" {
		*s = append(*s, value)
	}
	return nil
}

type planOutput struct {
	OK                            bool              `json:"ok"`
	Mode                          string            `json:"mode"`
	Role                          string            `json:"role"`
	Remote                        string            `json:"remote"`
	SSHArgs                       []string          `json:"ssh_args"`
	SSHCommand                    string            `json:"ssh_command"`
	ProofRequired                 bool              `json:"proof_required"`
	SecurityLevel                 string            `json:"security_level"`
	RequiredCapabilities          []string          `json:"required_capabilities"`
	AuthorityMaterialOnRemoteHost bool              `json:"authority_material_on_remote_host"`
	Endpoints                     map[string]string `json:"endpoints"`
	Guardrails                    []string          `json:"guardrails"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		os.Exit(2)
	}
}

func run(args []string, stdout, stderr *os.File) error {
	fs := flag.NewFlagSet("wv-native-forward", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var capabilities stringList
	var chainParts stringList
	var (
		mode                          string
		role                          string
		remote                        string
		localBind                     string
		remoteBind                    string
		targetHost                    string
		localPort                     int
		remotePort                    int
		targetPort                    int
		proofMode                     string
		securityLevel                 string
		subjectPeer                   string
		audience                      string
		publicKey                     string
		publicKeyFile                 string
		chainSHA256                   string
		x11CookieSHA256               string
		x11Cookie                     string
		authorityMaterialOnRemoteHost bool
		format                        string
		jsonOutput                    bool
		shellOutput                   bool
	)

	fs.StringVar(&mode, "mode", "", "native SSH forwarding mode: sshL, sshR, or sshD")
	fs.StringVar(&role, "role", "", "optional role override; defaults from --mode")
	fs.StringVar(&remote, "remote", "", "remote SSH target, for example root@203.0.113.20")
	fs.StringVar(&localBind, "local-bind", "127.0.0.1", "local loopback bind address")
	fs.IntVar(&localPort, "local-port", 19080, "local bind port for sshL/sshD")
	fs.StringVar(&remoteBind, "remote-bind", "127.0.0.1", "remote loopback bind address for sshR")
	fs.IntVar(&remotePort, "remote-port", 22022, "remote bind port for sshR")
	fs.StringVar(&targetHost, "target-host", "127.0.0.1", "loopback target host behind the forward")
	fs.IntVar(&targetPort, "target-port", 6017, "loopback target port behind the forward")
	fs.StringVar(&proofMode, "proof-mode", authproof.ProofModeRequired, "authproof mode; must be required")
	fs.StringVar(&securityLevel, "proof-security-level", authproof.SecurityLevelAgentProof, "minimum security level; must be agent_proof or strict")
	fs.StringVar(&subjectPeer, "proof-subject-id", "", "subject peer bound to the proof")
	fs.StringVar(&audience, "proof-audience", "", "proof audience; defaults to wv-agent or wv-socks from --mode")
	fs.StringVar(&publicKey, "proof-public-key", "", "trusted verifier public key in base64url form")
	fs.StringVar(&publicKeyFile, "proof-public-key-file", "", "file containing trusted verifier public key")
	fs.StringVar(&chainSHA256, "proof-chain-sha256", "", "explicit non-default chain binding SHA-256")
	fs.Var(&chainParts, "chain-part", "chain element used to derive --proof-chain-sha256; repeat for each hop")
	fs.StringVar(&x11CookieSHA256, "proof-x11-cookie-sha256", "", "X11 cookie SHA-256 binding for sshL/sshR")
	fs.StringVar(&x11Cookie, "proof-x11-cookie", "", "raw X11 cookie value to hash for sshL/sshR binding")
	fs.Var(&capabilities, "capability", "required capability; repeat to override defaults")
	fs.BoolVar(&authorityMaterialOnRemoteHost, "authority-material-on-remote", false, "mark authority material as present on the remote host; validation should reject this")
	fs.StringVar(&format, "format", "text", "output format: text, json, or shell")
	fs.BoolVar(&jsonOutput, "json", false, "alias for --format json")
	fs.BoolVar(&shellOutput, "shell", false, "alias for --format shell")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: wv-native-forward --mode sshR --remote user@host [proof flags]\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if jsonOutput {
		format = "json"
	}
	if shellOutput {
		format = "shell"
	}

	plan, err := buildPlan(mode, role, remote, localBind, localPort, remoteBind, remotePort, targetHost, targetPort, proofMode, securityLevel, subjectPeer, audience, publicKey, publicKeyFile, chainSHA256, x11CookieSHA256, x11Cookie, capabilities, chainParts, authorityMaterialOnRemoteHost)
	if err != nil {
		writeRejected(stderr, format, err)
		return err
	}

	switch format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(plan)
	case "shell":
		_, err := fmt.Fprintln(stdout, plan.SSHCommand)
		return err
	case "text", "":
		_, err := fmt.Fprintf(stdout, "status=planned\nmode=%s\nrole=%s\nremote=%s\nssh_command=%s\n", plan.Mode, plan.Role, plan.Remote, plan.SSHCommand)
		return err
	default:
		err := fmt.Errorf("unsupported output format %q", format)
		writeRejected(stderr, "text", err)
		return err
	}
}

func buildPlan(mode, role, remote, localBind string, localPort int, remoteBind string, remotePort int, targetHost string, targetPort int, proofMode string, securityLevel string, subjectPeer string, audience string, publicKey string, publicKeyFile string, chainSHA256 string, x11CookieSHA256 string, x11Cookie string, capabilities []string, chainParts []string, authorityMaterialOnRemoteHost bool) (planOutput, error) {
	mode = strings.TrimSpace(mode)
	if role = strings.TrimSpace(role); role == "" {
		role = authproof.NativeForwardingRoleForMode(mode)
	}
	if audience = strings.TrimSpace(audience); audience == "" {
		audience = defaultAudience(mode)
	}
	if len(capabilities) == 0 {
		capabilities = authproof.NativeForwardingRequiredCapabilities(mode)
	}
	if strings.TrimSpace(chainSHA256) == "" && len(chainParts) > 0 {
		chainSHA256 = authproof.ChainBindingSHA256(chainParts...)
	}
	if strings.TrimSpace(x11CookieSHA256) == "" && strings.TrimSpace(x11Cookie) != "" {
		x11CookieSHA256 = authproof.HashX11Cookie(x11Cookie)
	}

	policy := authproof.NativeForwardingPolicy{
		Mode:                          mode,
		Role:                          role,
		LocalBind:                     localBind,
		LocalPort:                     localPort,
		RemoteBind:                    remoteBind,
		RemotePort:                    remotePort,
		TargetHost:                    targetHost,
		TargetPort:                    targetPort,
		ExitOnForwardFailure:          true,
		ClearAllForwardings:           true,
		GatewayPortsDisabled:          true,
		PermitLocalCommandNo:          true,
		ForwardAgentDisabled:          true,
		ForwardX11Disabled:            true,
		IdentitiesOnly:                true,
		StrictHostKey:                 true,
		EndpointRestricted:            true,
		LifecycleAudited:              true,
		WeaversshEndpoint:             true,
		AuthorityMaterialOnRemoteHost: authorityMaterialOnRemoteHost,
		Proof: authproof.RuntimeConfig{
			Mode:                 proofMode,
			SecurityLevel:        securityLevel,
			SubjectPeerID:        subjectPeer,
			Audience:             audience,
			PublicKey:            publicKey,
			PublicKeyFile:        publicKeyFile,
			X11CookieSHA256:      x11CookieSHA256,
			ChainSHA256:          chainSHA256,
			RequiredCapabilities: capabilities,
		},
	}

	sshArgs, err := authproof.BuildNativeForwardingOpenSSHArgs(remote, policy)
	if err != nil {
		return planOutput{}, err
	}

	return planOutput{
		OK:                            true,
		Mode:                          mode,
		Role:                          role,
		Remote:                        strings.TrimSpace(remote),
		SSHArgs:                       sshArgs,
		SSHCommand:                    renderCommand("ssh", sshArgs),
		ProofRequired:                 true,
		SecurityLevel:                 authproof.NormalizeSecurityLevel(securityLevel),
		RequiredCapabilities:          append([]string(nil), capabilities...),
		AuthorityMaterialOnRemoteHost: authorityMaterialOnRemoteHost,
		Endpoints:                     endpoints(mode, localBind, localPort, remoteBind, remotePort, targetHost, targetPort),
		Guardrails: []string{
			"ExitOnForwardFailure=yes",
			"ClearAllForwardings=yes",
			"GatewayPorts=no",
			"PermitLocalCommand=no",
			"ForwardAgent=no",
			"ForwardX11=no",
			"IdentitiesOnly=yes",
			"StrictHostKeyChecking=yes",
			"loopback-only",
			"trusted-peer-authproof-required",
			"authority-material-outside-remote-root",
			"explicit-chain-binding-required",
		},
	}, nil
}

func defaultAudience(mode string) string {
	if strings.TrimSpace(mode) == authproof.NativeForwardSSHDynamic {
		return authproof.AudienceSocks
	}
	return authproof.AudienceAgent
}

func endpoints(mode, localBind string, localPort int, remoteBind string, remotePort int, targetHost string, targetPort int) map[string]string {
	out := map[string]string{}
	switch mode {
	case authproof.NativeForwardSSHLocal:
		out["local_bind"] = net.JoinHostPort(localBind, strconv.Itoa(localPort))
		out["target"] = net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	case authproof.NativeForwardSSHRemote:
		out["remote_bind"] = net.JoinHostPort(remoteBind, strconv.Itoa(remotePort))
		out["target"] = net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	case authproof.NativeForwardSSHDynamic:
		out["dynamic_bind"] = net.JoinHostPort(localBind, strconv.Itoa(localPort))
	}
	return out
}

func renderCommand(binary string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, shellQuote(binary))
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' || r == '/' || r == ':' || r == '@' || r == '%' || r == '+' || r == '=' || r == ',' || r == '[' || r == ']' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z')
	}) == -1 {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func writeRejected(stderr *os.File, format string, err error) {
	if err == nil {
		err = errors.New("rejected")
	}
	if format == "json" {
		_ = json.NewEncoder(stderr).Encode(map[string]any{"ok": false, "status": "rejected", "error": err.Error()})
		return
	}
	fmt.Fprintf(stderr, "status=rejected\nerror=%s\n", err)
}
