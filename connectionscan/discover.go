package connectionscan

// Discover is the single entry point wv uses: it runs the ssh_config, PuTTY, and
// known_hosts detectors and proposes de-duplicated connection profiles. It reads
// only local files/registry and never dials a host.

import "strings"

// DiscoveredProfile is a connection proposed from local configuration. It holds
// only transport-relevant fields; the caller maps it onto its own profile store.
type DiscoveredProfile struct {
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	Host         string   `json:"host"`
	User         string   `json:"user,omitempty"`
	Port         int      `json:"port,omitempty"`
	IdentityFile string   `json:"identity_file,omitempty"`
	Source       string   `json:"source"`          // ssh-config | putty | known-hosts
	Scope        string   `json:"scope,omitempty"` // originating source scope
	Tags         []string `json:"tags,omitempty"`
	Label        string   `json:"label,omitempty"`
}

// Result is the full local discovery: the raw detector output plus the merged
// list of proposed profiles.
type Result struct {
	SSHConfigSources []SSHConfigSource    `json:"ssh_config_sources"`
	SSHClientConfigs []SSHClientConfig    `json:"ssh_client_configs"`
	PuTTYSessions    []PuTTYSessionConfig `json:"putty_sessions"`
	KnownHosts       []KnownHost          `json:"known_hosts"`
	Profiles         []DiscoveredProfile  `json:"profiles"`
}

// Discover runs every detector and merges the results.
func Discover() Result {
	sources := DetectSSHConfigSources()
	res := Result{
		SSHConfigSources: sources,
		SSHClientConfigs: reindexSSHConfigs(ParseSSHClientConfigSources(sources)),
		PuTTYSessions:    DetectPuTTYSessionConfigs(),
		KnownHosts:       DetectKnownHosts(),
	}
	res.Profiles = mergeProfiles(res)
	return res
}

func reindexSSHConfigs(entries []SSHClientConfig) []SSHClientConfig {
	for i := range entries {
		entries[i].Index = i + 1
	}
	return entries
}

// mergeProfiles builds proposed profiles in priority order (ssh_config, then
// PuTTY, then known_hosts), keeping the first entry seen for a host/user/port.
func mergeProfiles(res Result) []DiscoveredProfile {
	seen := map[string]bool{}
	out := []DiscoveredProfile{}
	add := func(p DiscoveredProfile) {
		p.Host = strings.TrimSpace(p.Host)
		if p.Host == "" {
			return
		}
		key := strings.ToLower(p.Host + "\x00" + p.User + "\x00" + itoa(p.Port))
		if seen[key] {
			return
		}
		seen[key] = true
		if strings.TrimSpace(p.Name) == "" {
			p.Name = profileName(p.Host)
		}
		out = append(out, p)
	}

	for _, e := range res.SSHClientConfigs {
		host := strings.TrimSpace(e.HostName)
		alias := firstAlias(e.HostAliases)
		if host == "" {
			host = alias
		}
		name := alias
		if name == "" {
			name = host
		}
		add(DiscoveredProfile{
			Name:         profileName(name),
			Description:  descWithSource("SSH client config", e.SourcePath),
			Host:         host,
			User:         e.User,
			Port:         e.Port,
			IdentityFile: e.IdentityFile,
			Source:       "ssh-config",
			Scope:        e.SourceScope,
			Tags:         tags("ssh-config", e.SourceScope),
			Label:        SSHClientConfigLabel(e),
		})
	}
	for _, s := range res.PuTTYSessions {
		add(DiscoveredProfile{
			Name:         profileName(defaultString(s.Name, s.HostName)),
			Description:  descWithSource("PuTTY saved session", s.SourcePath),
			Host:         s.HostName,
			User:         s.User,
			Port:         s.Port,
			IdentityFile: s.IdentityFile,
			Source:       "putty",
			Scope:        s.SourceScope,
			Tags:         tags("putty", s.SourceScope),
			Label:        PuTTYSessionConfigLabel(s),
		})
	}
	for _, h := range res.KnownHosts {
		add(DiscoveredProfile{
			Name:        profileName(h.Host),
			Description: descWithSource("known_hosts entry", h.Source),
			Host:        h.Host,
			Port:        h.Port,
			Source:      "known-hosts",
			Scope:       "known-hosts",
			Tags:        []string{"known-hosts"},
		})
	}
	return out
}

func firstAlias(aliases []string) string {
	for _, a := range aliases {
		if a = strings.TrimSpace(a); a != "" {
			return a
		}
	}
	return ""
}

func descWithSource(kind, source string) string {
	d := "Discovered from " + kind + "."
	if strings.TrimSpace(source) != "" {
		d += " Source: " + source
	}
	return d
}

func tags(base, scope string) []string {
	out := []string{base}
	if scope = strings.TrimSpace(scope); scope != "" && scope != base {
		out = append(out, base+"-"+scope)
	}
	return out
}

// profileName lowercases and slugifies a host/alias into a store-safe name.
func profileName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		case r == '.' || r == '_' || r == '-' || r == '@' || r == ' ':
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func itoa(n int) string {
	if n == 0 {
		return ""
	}
	// small non-negative ints only (ports); avoid importing strconv here.
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}
