package app

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type AgentInterfaceMode string

const (
	AgentInterfaceTCP     AgentInterfaceMode = "tcp"
	AgentInterfaceUnix    AgentInterfaceMode = "unix"
	AgentInterfaceLibrary AgentInterfaceMode = "library"
)

func normalizeAgentInterfaceMode(input string) (AgentInterfaceMode, error) {
	switch strings.ToLower(strings.TrimSpace(strings.ReplaceAll(input, "-", "_"))) {
	case "", "auto", "tcp", "tcp_socket", "socket", "inet", "network":
		return AgentInterfaceTCP, nil
	case "unix", "unix_socket", "unix_domain", "uds", "local_socket", "local":
		return AgentInterfaceUnix, nil
	case "library", "library_only", "inprocess", "in_process", "embedded", "none", "no_listener", "nolisten":
		return AgentInterfaceLibrary, nil
	default:
		return "", fmt.Errorf("unsupported agent interface %q; use tcp, unix, or library", input)
	}
}

func parseAgentListenAddress(input string) (network, address string, port int, err error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", "", 0, fmt.Errorf("listen address is empty")
	}
	if mode, modeErr := normalizeAgentInterfaceMode(trimmed); modeErr == nil && mode == AgentInterfaceLibrary {
		return string(AgentInterfaceLibrary), "", 0, nil
	}
	if strings.HasPrefix(trimmed, "unix://") {
		path := strings.TrimSpace(strings.TrimPrefix(trimmed, "unix://"))
		if path == "" {
			return "", "", 0, fmt.Errorf("unix listener path is empty")
		}
		return "unix", path, 0, nil
	}
	if strings.HasPrefix(trimmed, "unix:") {
		path := strings.TrimSpace(strings.TrimPrefix(trimmed, "unix:"))
		if path == "" {
			return "", "", 0, fmt.Errorf("unix listener path is empty")
		}
		return "unix", path, 0, nil
	}
	trimmed = strings.TrimPrefix(trimmed, "tcp://")
	if isInteger(trimmed) {
		parsedPort, _ := strconv.Atoi(trimmed)
		return "tcp", fmt.Sprintf("localhost:%d", parsedPort), parsedPort, nil
	}

	host, portText, splitErr := net.SplitHostPort(trimmed)
	if splitErr != nil {
		return "", "", 0, fmt.Errorf("use localhost:<port>, tcp://host:port, unix:/path, or library: %w", splitErr)
	}
	if host == "" {
		host = "localhost"
	}
	parsedPort, convErr := strconv.Atoi(portText)
	if convErr != nil {
		return "", "", 0, fmt.Errorf("local port is not a number: %q", portText)
	}
	return "tcp", net.JoinHostPort(host, portText), parsedPort, nil
}

func defaultAgentUnixSocketPath() string {
	if runtimeDir := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); runtimeDir != "" {
		return filepath.Join(runtimeDir, "weaverssh", "agent.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("weaverssh-%d", os.Getuid()), "agent.sock")
}

func prepareUnixSocketPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("unix listener path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	_ = os.Remove(path)
	return nil
}

func listenAgent(config AgentConfig) (net.Listener, func(), error) {
	switch strings.ToLower(strings.TrimSpace(config.ListenNetwork)) {
	case "", "tcp", "tcp4", "tcp6":
		listener, err := net.Listen("tcp", config.ListenAddr)
		return listener, func() {}, err
	case "unix":
		if err := prepareUnixSocketPath(config.ListenAddr); err != nil {
			return nil, func() {}, err
		}
		listener, err := net.Listen("unix", config.ListenAddr)
		if err != nil {
			return nil, func() {}, err
		}
		cleanup := func() {
			_ = os.Remove(config.ListenAddr)
		}
		return listener, cleanup, nil
	case string(AgentInterfaceLibrary):
		return nil, func() {}, fmt.Errorf("library interface does not open a listener; use NewAgentRuntime and ServeConn")
	default:
		return nil, func() {}, fmt.Errorf("unsupported listen network %q", config.ListenNetwork)
	}
}
