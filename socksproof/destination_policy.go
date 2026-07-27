package socksproof

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type destinationRule struct{ host, port string }
type destinationPolicy struct{ rules []destinationRule }

func newDestinationPolicy(values []string) (destinationPolicy, error) {
	var policy destinationPolicy
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		host, port, err := splitDestinationRule(value)
		if err != nil {
			return destinationPolicy{}, err
		}
		key := host + "\x00" + port
		if !seen[key] {
			seen[key] = true
			policy.rules = append(policy.rules, destinationRule{host: host, port: port})
		}
	}
	if len(policy.rules) == 0 {
		return destinationPolicy{}, fmt.Errorf("%w: empty destination policy", ErrUnauthorized)
	}
	return policy, nil
}

func (p destinationPolicy) Authorize(address string) error {
	_, address, err := NormalizeAddress("tcp", address)
	if err != nil {
		return err
	}
	host, port, _ := net.SplitHostPort(address)
	host = normalizeDestinationHost(host)
	for _, rule := range p.rules {
		hostMatch := rule.host == "*" || rule.host == host
		if strings.HasPrefix(rule.host, "*.") {
			suffix := strings.TrimPrefix(rule.host, "*")
			hostMatch = strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".")
		}
		portMatch := rule.port == "*" || rule.port == port
		if hostMatch && portMatch {
			return nil
		}
	}
	return fmt.Errorf("%w: destination %s denied by principal policy", ErrUnauthorized, address)
}

func (p destinationPolicy) AllowsAny() bool {
	for _, rule := range p.rules {
		if rule.host == "*" && rule.port == "*" {
			return true
		}
	}
	return false
}

func splitDestinationRule(raw string) (string, string, error) {
	if raw == "*:*" {
		return "*", "*", nil
	}
	index := strings.LastIndexByte(raw, ':')
	if index <= 0 || index == len(raw)-1 {
		return "", "", fmt.Errorf("invalid destination rule %q", raw)
	}
	host := strings.TrimSpace(raw[:index])
	port := strings.TrimSpace(raw[index+1:])
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	if host == "" || strings.ContainsAny(host, "\x00/\\") {
		return "", "", fmt.Errorf("invalid destination host %q", host)
	}
	if strings.Contains(host, "*") && host != "*" && !strings.HasPrefix(host, "*.") {
		return "", "", fmt.Errorf("invalid destination wildcard %q", host)
	}
	if port != "*" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return "", "", fmt.Errorf("invalid destination port %q", port)
		}
		port = strconv.Itoa(value)
	}
	if host != "*" {
		host = normalizeDestinationHost(host)
	}
	return host, port, nil
}

func normalizeDestinationHost(host string) string {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if strings.HasPrefix(host, "*.") {
		return "*." + strings.ToLower(strings.TrimPrefix(host, "*."))
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return strings.ToLower(host)
}
