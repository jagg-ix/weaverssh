package connectionscan

// known_hosts discovery: hosts you have connected to before are useful hints
// for connection profiles even when they are absent from ssh_config. Hashed
// entries (|1|...) cannot be reversed and are skipped, as are wildcards.

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type KnownHost struct {
	Index  int    `json:"index"`
	Host   string `json:"host"`
	Port   int    `json:"port,omitempty"`
	Source string `json:"source,omitempty"`
}

func DetectKnownHosts() []KnownHost {
	seen := map[string]bool{}
	out := []KnownHost{}
	for _, source := range knownHostsSources() {
		for _, host := range parseKnownHostsFile(source) {
			key := strings.ToLower(host.Host) + "\x00" + strconv.Itoa(host.Port)
			if host.Host == "" || seen[key] {
				continue
			}
			seen[key] = true
			host.Source = source
			out = append(out, host)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Host == out[j].Host {
			return out[i].Port < out[j].Port
		}
		return out[i].Host < out[j].Host
	})
	for i := range out {
		out[i].Index = i + 1
	}
	return out
}

func knownHostsSources() []string {
	paths := []string{}
	if override := firstEnv("WEAVERSSH_KNOWN_HOSTS"); override != "" {
		paths = append(paths, filepath.SplitList(override)...)
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		paths = append(paths,
			filepath.Join(home, ".ssh", "known_hosts"),
			filepath.Join(home, ".ssh", "known_hosts2"),
		)
	}
	if !envFlagEnabled("WEAVERSSH_DISABLE_SYSTEM_KNOWN_HOSTS") {
		paths = append(paths, "/etc/ssh/ssh_known_hosts")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, p := range paths {
		p = cleanPath(p)
		if p == "" || seen[p] || !pathExists(p) {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func parseKnownHostsFile(path string) []KnownHost {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := []KnownHost{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		hostField := fields[0]
		// @cert-authority / @revoked markers put the host pattern in field 2.
		if strings.HasPrefix(hostField, "@") {
			if len(fields) < 2 {
				continue
			}
			hostField = fields[1]
		}
		for _, token := range strings.Split(hostField, ",") {
			if h, ok := parseKnownHostToken(token); ok {
				out = append(out, h)
			}
		}
	}
	return out
}

func parseKnownHostToken(token string) (KnownHost, bool) {
	token = strings.TrimSpace(token)
	// Hashed (|1|salt|hash) entries and wildcard patterns are not usable hosts.
	if token == "" || strings.HasPrefix(token, "|") || strings.ContainsAny(token, "*?") {
		return KnownHost{}, false
	}
	port := 0
	if strings.HasPrefix(token, "[") {
		// [host]:port form used for non-default ports.
		end := strings.LastIndex(token, "]")
		if end < 0 {
			return KnownHost{}, false
		}
		host := token[1:end]
		rest := strings.TrimPrefix(token[end+1:], ":")
		if rest != "" {
			port = parsePositiveInt(rest)
		}
		token = host
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return KnownHost{}, false
	}
	return KnownHost{Host: token, Port: port}, true
}
