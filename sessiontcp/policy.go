package sessiontcp

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Allowlist authorizes normalized TCP destinations. Rules are explicit:
//
//   host:port       exact destination
//   *.domain:port   subdomains of one DNS suffix
//   *:port          any host on one port
//   host:*          one host on any port
//   *:*             unrestricted TCP (must be chosen deliberately)
//
// Host matching is case-insensitive. IP literals are normalized by net.ParseIP.
type Allowlist struct {
	rules []allowRule
}

type allowRule struct {
	host string
	port string
}

func ParseAllowlist(raw string) (Allowlist, error) {
	var out Allowlist
	seen := map[string]bool{}
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		host, port, err := splitRule(field)
		if err != nil {
			return Allowlist{}, err
		}
		key := host + "\x00" + port
		if !seen[key] {
			seen[key] = true
			out.rules = append(out.rules, allowRule{host: host, port: port})
		}
	}
	return out, nil
}

func (a Allowlist) Empty() bool { return len(a.rules) == 0 }

// AllowsAny reports an explicit *:* rule. It is used for operations such as
// wildcard SOCKS5 BIND that cannot be authorized against one concrete peer in
// advance. No combination of narrower rules implies this permission.
func (a Allowlist) AllowsAny() bool {
	for _, rule := range a.rules {
		if rule.host == "*" && rule.port == "*" {
			return true
		}
	}
	return false
}

func (a Allowlist) Authorize(req Request) error {
	req, err := NormalizeRequest(req)
	if err != nil {
		return err
	}
	host, port, _ := net.SplitHostPort(req.Address)
	host = normalizeHost(host)
	for _, rule := range a.rules {
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
	return fmt.Errorf("%w: %s is not in the configured allowlist", ErrDenied, req.Address)
}

func splitRule(raw string) (string, string, error) {
	if raw == "*:*" {
		return "*", "*", nil
	}
	index := strings.LastIndexByte(raw, ':')
	if index <= 0 || index == len(raw)-1 {
		return "", "", fmt.Errorf("sessiontcp: invalid allow rule %q; expected HOST:PORT", raw)
	}
	host := strings.TrimSpace(raw[:index])
	port := strings.TrimSpace(raw[index+1:])
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	if host == "" || strings.ContainsAny(host, "\x00/\\") {
		return "", "", fmt.Errorf("sessiontcp: invalid allow host %q", host)
	}
	if strings.Contains(host, "*") && host != "*" && !strings.HasPrefix(host, "*.") {
		return "", "", fmt.Errorf("sessiontcp: wildcard must be '*' or begin '*.' in %q", host)
	}
	if port != "*" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return "", "", fmt.Errorf("sessiontcp: invalid allow port %q", port)
		}
		port = strconv.Itoa(value)
	}
	if host != "*" {
		host = normalizeHost(host)
	}
	if host == "" || host == "*." {
		return "", "", errors.New("sessiontcp: empty allow host")
	}
	return host, port, nil
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if strings.HasPrefix(host, "*.") {
		return "*." + strings.ToLower(strings.TrimPrefix(host, "*."))
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return strings.ToLower(host)
}
