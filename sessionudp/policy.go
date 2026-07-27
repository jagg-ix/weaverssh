package sessionudp

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Allowlist authorizes normalized UDP destinations. Syntax matches TCP policy:
// host:port, *.domain:port, *:port, host:*, or *:*.
type Allowlist struct { rules []allowRule }
type allowRule struct { host, port string }

func ParseAllowlist(raw string) (Allowlist, error) {
	var out Allowlist
	seen := map[string]bool{}
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" { continue }
		host, port, err := splitRule(field)
		if err != nil { return Allowlist{}, err }
		key := host + "\x00" + port
		if !seen[key] { seen[key] = true; out.rules = append(out.rules, allowRule{host, port}) }
	}
	return out, nil
}

func (a Allowlist) Empty() bool { return len(a.rules) == 0 }

func (a Allowlist) Authorize(address string) error {
	host, port, err := normalizeAddress(address)
	if err != nil { return err }
	for _, rule := range a.rules {
		hostMatch := rule.host == "*" || rule.host == host
		if strings.HasPrefix(rule.host, "*.") {
			suffix := strings.TrimPrefix(rule.host, "*")
			hostMatch = strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".")
		}
		if hostMatch && (rule.port == "*" || rule.port == port) { return nil }
	}
	return fmt.Errorf("%w: %s is not in the configured UDP allowlist", ErrDenied, address)
}

func splitRule(raw string) (string, string, error) {
	if raw == "*:*" { return "*", "*", nil }
	index := strings.LastIndexByte(raw, ':')
	if index <= 0 || index == len(raw)-1 { return "", "", fmt.Errorf("sessionudp: invalid allow rule %q", raw) }
	host, port := strings.TrimSpace(raw[:index]), strings.TrimSpace(raw[index+1:])
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") { host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]") }
	if host == "" || strings.ContainsAny(host, "\x00/\\") { return "", "", errors.New("sessionudp: invalid allow host") }
	if strings.Contains(host, "*") && host != "*" && !strings.HasPrefix(host, "*.") { return "", "", errors.New("sessionudp: invalid wildcard") }
	if port != "*" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 { return "", "", errors.New("sessionudp: invalid allow port") }
		port = strconv.Itoa(value)
	}
	if host != "*" { host = normalizeHost(host) }
	if host == "" || host == "*." { return "", "", errors.New("sessionudp: empty allow host") }
	return host, port, nil
}

func normalizeAddress(address string) (string, string, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil || strings.TrimSpace(host) == "" { return "", "", fmt.Errorf("sessionudp: destination must be HOST:PORT: %q", address) }
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 { return "", "", errors.New("sessionudp: invalid destination port") }
	return normalizeHost(host), strconv.Itoa(port), nil
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if strings.HasPrefix(host, "*.") { return "*." + strings.ToLower(strings.TrimPrefix(host, "*.")) }
	if ip := net.ParseIP(host); ip != nil { return ip.String() }
	return strings.ToLower(host)
}
