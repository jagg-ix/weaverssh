package display

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"weaverssh/wverrors"
)

const X11PortBase = 6000

type EndpointKind string

const (
	EndpointTCP  EndpointKind = "tcpSocket"
	EndpointUnix EndpointKind = "unixSocket"
)

type Endpoint struct {
	RawDisplay    string
	Host          string
	AuthorityKey  string
	DisplayNumber int
	ScreenNumber  int
	ScreenName    string
	Kind          EndpointKind
	Network       string
	Address       string
}

// ParseDisplay parses the DISPLAY environment variable.
// Returns hostname, display number, screen number, and error.
func ParseDisplay() (string, int, int, error) {
	return ParseDisplayString(os.Getenv("DISPLAY"))
}

func ParseDisplayString(raw string) (string, int, int, error) {
	display := strings.TrimSpace(raw)
	if display == "" {
		return "", 0, 0, displayResolveError("parse", "DISPLAY environment variable not set", nil)
	}

	re := regexp.MustCompile(`^([^:]+)?:(\d+)(?:\.(\d+))?$`)
	matches := re.FindStringSubmatch(display)
	if len(matches) < 3 {
		return "", 0, 0, displayResolveError("parse", fmt.Sprintf("invalid DISPLAY format: %s", display), nil)
	}

	host := matches[1]
	if host == "" {
		host = "localhost"
	}

	displayNum, err := strconv.Atoi(matches[2])
	if err != nil {
		return "", 0, 0, displayResolveError("parse", "invalid display number", err)
	}

	screenNum := 0
	if len(matches) >= 4 && matches[3] != "" {
		screenNum, err = strconv.Atoi(matches[3])
		if err != nil {
			return "", 0, 0, displayResolveError("parse", "invalid screen number", err)
		}
	}

	return host, displayNum, screenNum, nil
}

func ResolveEnvEndpoint() (Endpoint, error) {
	return ResolveDisplayEndpoint(os.Getenv("DISPLAY"))
}

func ResolveDisplayEndpoint(raw string) (Endpoint, error) {
	display := strings.TrimSpace(raw)
	if display == "" {
		return Endpoint{}, displayResolveError("resolve", "DISPLAY environment variable not set", nil)
	}

	host, displayNum, screenNum, err := parseDisplayStringPreserveHost(display)
	if err != nil {
		return Endpoint{}, err
	}
	if screenNum != 0 {
		return Endpoint{}, displayFailClosedError("resolve", fmt.Sprintf("unsupported X11 screen %d for DISPLAY %s: only screen0 is routed", screenNum, display), nil)
	}

	endpoint := Endpoint{
		RawDisplay:    display,
		Host:          host,
		DisplayNumber: displayNum,
		ScreenNumber:  screenNum,
		ScreenName:    fmt.Sprintf("screen%d", screenNum),
	}

	if isUnixDisplayHost(host) {
		endpoint.Kind = EndpointUnix
		endpoint.Network = "unix"
		endpoint.Address = unixSocketPath(host, displayNum)
		endpoint.AuthorityKey = fmt.Sprintf("unix:%d", displayNum)
		return endpoint, nil
	}

	dialHost := host
	if dialHost == "" {
		dialHost = "localhost"
	}
	endpoint.Kind = EndpointTCP
	endpoint.Network = "tcp"
	endpoint.Address = net.JoinHostPort(dialHost, strconv.Itoa(X11PortBase+displayNum))
	endpoint.AuthorityKey = fmt.Sprintf("%s:%d", dialHost, displayNum)
	return endpoint, nil
}

func (e Endpoint) Port() int {
	return X11PortBase + e.DisplayNumber
}

func (e Endpoint) IsScreen0() bool {
	return e.ScreenNumber == 0 && e.ScreenName == "screen0"
}

func (e Endpoint) Matches(network, address string) bool {
	network = normalizeNetwork(network)
	address = strings.TrimSpace(address)
	if network == "" || address == "" || e.Network == "" || e.Address == "" {
		return false
	}
	if network != e.Network {
		return false
	}
	if e.Network == "unix" {
		return filepath.Clean(address) == filepath.Clean(e.Address)
	}
	return tcpAddressesEquivalent(e.Address, address)
}

func (e Endpoint) String() string {
	return fmt.Sprintf("display=%s authority=%s endpoint=%s:%s screen=%s", e.RawDisplay, e.AuthorityKey, e.Network, e.Address, e.ScreenName)
}

func ParseDialTarget(target string) (string, string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", "", displayResolveError("parse_target", "empty X11 target", nil)
	}
	if strings.HasPrefix(target, "unix://") {
		path := strings.TrimPrefix(target, "unix://")
		if path == "" {
			return "", "", displayResolveError("parse_target", "empty Unix socket target", nil)
		}
		return "unix", path, nil
	}
	if strings.HasPrefix(target, "unix:") {
		path := strings.TrimPrefix(target, "unix:")
		if strings.HasPrefix(path, "/") {
			return "unix", path, nil
		}
	}
	if strings.HasPrefix(target, "/") {
		return "unix", target, nil
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		return "", "", displayResolveError("parse_target", fmt.Sprintf("invalid TCP target %q", target), err)
	}
	return "tcp", target, nil
}

func ValidateDialTargetForDisplay(rawDisplay, target string) (Endpoint, string, string, error) {
	endpoint, err := ResolveDisplayEndpoint(rawDisplay)
	if err != nil {
		return Endpoint{}, "", "", err
	}
	network, address, err := ParseDialTarget(target)
	if err != nil {
		return Endpoint{}, "", "", err
	}
	if !endpoint.Matches(network, address) {
		return Endpoint{}, "", "", displayFailClosedError("validate_target", fmt.Sprintf("target %s:%s does not match DISPLAY endpoint %s:%s for %s", network, address, endpoint.Network, endpoint.Address, rawDisplay), nil)
	}
	if !endpoint.IsScreen0() {
		return Endpoint{}, "", "", displayFailClosedError("validate_target", fmt.Sprintf("target %s resolved to unsupported screen %s", rawDisplay, endpoint.ScreenName), nil)
	}
	return endpoint, network, address, nil
}

// GetX11Port returns the TCP port for the X11 display.
func GetX11Port() (int, error) {
	_, displayNum, _, err := ParseDisplay()
	if err != nil {
		return 0, err
	}

	return X11PortBase + displayNum, nil
}

func parseDisplayStringPreserveHost(display string) (string, int, int, error) {
	re := regexp.MustCompile(`^([^:]+)?:(\d+)(?:\.(\d+))?$`)
	matches := re.FindStringSubmatch(display)
	if len(matches) < 3 {
		return "", 0, 0, displayResolveError("parse", fmt.Sprintf("invalid DISPLAY format: %s", display), nil)
	}

	displayNum, err := strconv.Atoi(matches[2])
	if err != nil {
		return "", 0, 0, displayResolveError("parse", "invalid display number", err)
	}

	screenNum := 0
	if len(matches) >= 4 && matches[3] != "" {
		screenNum, err = strconv.Atoi(matches[3])
		if err != nil {
			return "", 0, 0, displayResolveError("parse", "invalid screen number", err)
		}
	}

	return matches[1], displayNum, screenNum, nil
}

func isUnixDisplayHost(host string) bool {
	host = strings.TrimSpace(host)
	return host == "" || host == "unix" || strings.HasPrefix(host, "/") || strings.Contains(host, "launchd")
}

func unixSocketPath(host string, displayNum int) string {
	if strings.HasPrefix(host, "/") {
		return host
	}
	return fmt.Sprintf("/tmp/.X11-unix/X%d", displayNum)
}

func normalizeNetwork(network string) string {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "tcp", "tcp4", "tcp6":
		return "tcp"
	case "unix", "unixpacket", "unixgram":
		return "unix"
	default:
		return strings.ToLower(strings.TrimSpace(network))
	}
}

func tcpAddressesEquivalent(expected, actual string) bool {
	expectedHost, expectedPort, err := net.SplitHostPort(expected)
	if err != nil {
		return false
	}
	actualHost, actualPort, err := net.SplitHostPort(actual)
	if err != nil {
		return false
	}
	if expectedPort != actualPort {
		return false
	}
	return hostsEquivalent(expectedHost, actualHost)
}

func hostsEquivalent(a, b string) bool {
	a = strings.Trim(strings.ToLower(strings.TrimSpace(a)), "[]")
	b = strings.Trim(strings.ToLower(strings.TrimSpace(b)), "[]")
	if a == b {
		return true
	}
	return isLoopbackName(a) && isLoopbackName(b)
}

func isLoopbackName(host string) bool {
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func displayResolveError(operation, message string, cause error) error {
	return wverrors.Wrap(wverrors.CodeDisplayCouldNotBeResolved, "display", operation, message, cause)
}

func displayFailClosedError(operation, message string, cause error) error {
	return wverrors.Wrap(wverrors.CodeX11SetupFailedClosed, "display", operation, message, cause).AsFault()
}
