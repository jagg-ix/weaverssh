package connectivity

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const ResultVersion = "weaverssh.connectivity.v1"

// Options describes a protocol-neutral reachability check. Underlay is an
// informational label and never participates in authorization.
type Options struct {
	Underlay       string
	SSHHost        string
	OverlayAddress string
	SSHBinary      string
	Timeout        time.Duration
}

// Check records one diagnostic without making it an authorization decision.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Result is stable JSON output for CLI and IDE consumers.
type Result struct {
	Version           string  `json:"version"`
	Underlay          string  `json:"underlay"`
	SSHHost           string  `json:"ssh_host"`
	ResolvedHost      string  `json:"resolved_host,omitempty"`
	ResolvedPort      int     `json:"resolved_port,omitempty"`
	ResolvedUser      string  `json:"resolved_user,omitempty"`
	OverlayAddress    string  `json:"overlay_address,omitempty"`
	SSHConfigResolved bool    `json:"ssh_config_resolved"`
	OverlayReachable  bool    `json:"overlay_reachable"`
	SSHReachable      bool    `json:"ssh_reachable"`
	WeaverSSHChecked  bool    `json:"weaverssh_checked"`
	WeaverSSHReady    bool    `json:"weaverssh_ready"`
	WeaverSSHDetail   string  `json:"weaverssh_detail,omitempty"`
	Checks            []Check `json:"checks"`
}

// Dependencies makes the checker deterministic in tests.
type Dependencies struct {
	CommandOutput func(context.Context, string, ...string) ([]byte, error)
	DialContext   func(context.Context, string, string) (net.Conn, error)
}

// DefaultDependencies returns process and network implementations.
func DefaultDependencies() Dependencies {
	return Dependencies{
		CommandOutput: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		},
		DialContext: (&net.Dialer{}).DialContext,
	}
}

// CheckConnectivity resolves an SSH profile and verifies that the target TCP
// path returns an SSH protocol banner. Underlay state is never consulted.
func CheckConnectivity(ctx context.Context, options Options) (Result, error) {
	return CheckWithDependencies(ctx, options, DefaultDependencies())
}

// CheckWithDependencies is the testable form of CheckConnectivity.
func CheckWithDependencies(ctx context.Context, options Options, deps Dependencies) (Result, error) {
	result := Result{Version: ResultVersion, Checks: []Check{}}
	underlay := strings.ToLower(strings.TrimSpace(options.Underlay))
	if underlay == "" {
		underlay = "ssh"
	}
	if len(underlay) > 64 || strings.ContainsAny(underlay, "\r\n\x00") {
		return result, errors.New("underlay label contains an unsafe value")
	}
	result.Underlay = underlay

	sshHost := strings.TrimSpace(options.SSHHost)
	if sshHost == "" {
		return result, errors.New("ssh host is required")
	}
	if strings.HasPrefix(sshHost, "-") || strings.ContainsAny(sshHost, "\r\n\x00") {
		return result, errors.New("ssh host contains an unsafe value")
	}
	result.SSHHost = sshHost

	if options.Timeout <= 0 {
		options.Timeout = 5 * time.Second
	}
	sshBinary := strings.TrimSpace(options.SSHBinary)
	if sshBinary == "" {
		sshBinary = "ssh"
	}

	if deps.CommandOutput == nil || deps.DialContext == nil {
		return result, errors.New("connectivity dependencies are incomplete")
	}

	resolveCtx, cancelResolve := context.WithTimeout(ctx, options.Timeout)
	output, err := deps.CommandOutput(resolveCtx, sshBinary, "-G", sshHost)
	cancelResolve()
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			detail = err.Error()
		}
		result.Checks = append(result.Checks, Check{Name: "ssh-config", OK: false, Detail: detail})
		return result, fmt.Errorf("resolve ssh config: %w", err)
	}

	resolved, err := ParseSSHConfig(output)
	if err != nil {
		result.Checks = append(result.Checks, Check{Name: "ssh-config", OK: false, Detail: err.Error()})
		return result, err
	}
	result.SSHConfigResolved = true
	result.ResolvedHost = resolved.Host
	result.ResolvedPort = resolved.Port
	result.ResolvedUser = resolved.User
	result.Checks = append(result.Checks, Check{
		Name: "ssh-config", OK: true,
		Detail: net.JoinHostPort(resolved.Host, strconv.Itoa(resolved.Port)),
	})

	overlay := strings.TrimSpace(options.OverlayAddress)
	if overlay == "" {
		overlay = resolved.Host
	}
	result.OverlayAddress = overlay
	if hostsConflict(options.OverlayAddress, resolved.Host) {
		detail := fmt.Sprintf("profile overlay address %q conflicts with ssh -G hostname %q", options.OverlayAddress, resolved.Host)
		result.Checks = append(result.Checks, Check{Name: "overlay-address", OK: false, Detail: detail})
		return result, errors.New(detail)
	}
	result.Checks = append(result.Checks, Check{Name: "overlay-address", OK: true, Detail: overlay})

	dialCtx, cancelDial := context.WithTimeout(ctx, options.Timeout)
	conn, err := deps.DialContext(dialCtx, "tcp", net.JoinHostPort(overlay, strconv.Itoa(resolved.Port)))
	cancelDial()
	if err != nil {
		result.Checks = append(result.Checks, Check{Name: "overlay-tcp", OK: false, Detail: err.Error()})
		return result, nil
	}
	defer conn.Close()
	result.OverlayReachable = true
	result.Checks = append(result.Checks, Check{Name: "overlay-tcp", OK: true, Detail: "TCP path established"})

	if deadlineConn, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = deadlineConn.SetReadDeadline(time.Now().Add(options.Timeout))
	}
	banner, bannerErr := readSSHBanner(conn)
	if bannerErr != nil {
		result.Checks = append(result.Checks, Check{Name: "ssh-banner", OK: false, Detail: bannerErr.Error()})
		return result, nil
	}
	result.SSHReachable = true
	result.Checks = append(result.Checks, Check{Name: "ssh-banner", OK: true, Detail: banner})
	return result, nil
}

// SSHResolvedConfig is the subset of ssh -G output used by the checker.
type SSHResolvedConfig struct {
	Host string
	Port int
	User string
}

// ParseSSHConfig parses OpenSSH's canonical `ssh -G` key/value output.
func ParseSSHConfig(output []byte) (SSHResolvedConfig, error) {
	resolved := SSHResolvedConfig{Port: 22}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "hostname":
			if resolved.Host == "" {
				resolved.Host = fields[1]
			}
		case "port":
			port, err := strconv.Atoi(fields[1])
			if err != nil || port < 1 || port > 65535 {
				return SSHResolvedConfig{}, fmt.Errorf("ssh config contains invalid port %q", fields[1])
			}
			resolved.Port = port
		case "user":
			if resolved.User == "" {
				resolved.User = fields[1]
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return SSHResolvedConfig{}, fmt.Errorf("scan ssh config: %w", err)
	}
	if resolved.Host == "" {
		return SSHResolvedConfig{}, errors.New("ssh config did not provide hostname")
	}
	return resolved, nil
}

func hostsConflict(left, right string) bool {
	left = strings.Trim(strings.TrimSpace(left), "[]")
	right = strings.Trim(strings.TrimSpace(right), "[]")
	if left == "" || right == "" {
		return false
	}
	leftIP, rightIP := net.ParseIP(left), net.ParseIP(right)
	if leftIP != nil && rightIP != nil {
		return !leftIP.Equal(rightIP)
	}
	return false
}

func readSSHBanner(conn net.Conn) (string, error) {
	reader := bufio.NewReaderSize(conn, 8192)
	for lineCount := 0; lineCount < 50; lineCount++ {
		line, err := reader.ReadString('\n')
		if len(line) > 1024 {
			return "", errors.New("ssh banner line exceeds 1024 bytes")
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "SSH-") {
			return trimmed, nil
		}
		if err != nil {
			return "", fmt.Errorf("read ssh banner: %w", err)
		}
	}
	return "", errors.New("ssh protocol banner not received")
}
