package connectionscan

// OpenSSH client-config discovery: finds ssh_config sources (with Include and
// config.d resolution) and parses Host blocks into SSHClientConfig entries.
// Ported from the weaverssh service-dock connection wizard; the dock-specific
// profile converters were dropped in favour of connectionscan's own mapping.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type SSHConfigSource struct {
	Index      int    `json:"index"`
	Path       string `json:"path"`
	Scope      string `json:"scope"`
	Reason     string `json:"reason,omitempty"`
	IncludedBy string `json:"included_by,omitempty"`
	Exists     bool   `json:"exists"`
}

type SSHClientConfig struct {
	Index        int               `json:"index"`
	SourcePath   string            `json:"source_path"`
	SourceScope  string            `json:"source_scope,omitempty"`
	SourceOrder  int               `json:"source_order,omitempty"`
	HostAliases  []string          `json:"host_aliases"`
	HostName     string            `json:"host_name,omitempty"`
	User         string            `json:"user,omitempty"`
	Port         int               `json:"port,omitempty"`
	IdentityFile string            `json:"identity_file,omitempty"`
	ProxyJump    string            `json:"proxy_jump,omitempty"`
	ProxyCommand string            `json:"proxy_command,omitempty"`
	ForwardAgent string            `json:"forward_agent,omitempty"`
	Options      map[string]string `json:"options,omitempty"`
}

func DetectSSHClientConfigs() []SSHClientConfig {
	entries := ParseSSHClientConfigSources(DetectSSHConfigSources())
	for i := range entries {
		entries[i].Index = i + 1
	}
	return entries
}

func DetectSSHConfigSources() []SSHConfigSource {
	sources := []SSHConfigSource{}
	seen := map[string]bool{}
	var addSource func(path string, scope string, reason string, includedBy string, includeRelated bool)
	addSource = func(path string, scope string, reason string, includedBy string, includeRelated bool) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		path = cleanPath(path)
		if seen[path] {
			return
		}
		seen[path] = true
		source := SSHConfigSource{
			Path:       path,
			Scope:      scope,
			Reason:     reason,
			IncludedBy: cleanPath(includedBy),
			Exists:     pathExists(path),
		}
		if strings.TrimSpace(includedBy) == "" {
			source.IncludedBy = ""
		}
		if source.Exists {
			sources = append(sources, source)
			for _, include := range detectSSHConfigIncludes(path) {
				addSource(include, scope+"-include", "Include directive", path, false)
			}
			if includeRelated {
				for _, related := range relatedSSHConfigFiles(path) {
					addSource(related, scope+"-related", "related config file", path, false)
				}
			}
		}
	}

	for _, path := range explicitSSHConfigPaths() {
		addSource(path, "override", "WEAVERSSH_SSH_CONFIG", "", true)
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		userConfig := filepath.Join(home, ".ssh", "config")
		addSource(userConfig, "user", "~/.ssh/config", "", true)
		for _, related := range sshConfigDirFiles(filepath.Join(home, ".ssh", "config.d")) {
			addSource(related, "user-related", "related config file", userConfig, false)
		}
	}
	if !envFlagEnabled("WEAVERSSH_DISABLE_SYSTEM_SSH_CONFIG") {
		systemConfig := systemSSHConfigPath()
		addSource(systemConfig, "system", "system-wide ssh_config", "", true)
		for _, related := range sshConfigDirFiles(filepath.Join(filepath.Dir(systemConfig), "ssh_config.d")) {
			addSource(related, "system-related", "related config file", systemConfig, false)
		}
	}
	for i := range sources {
		sources[i].Index = i + 1
	}
	return sources
}

func ParseSSHClientConfigSources(sources []SSHConfigSource) []SSHClientConfig {
	raw := []SSHClientConfig{}
	for _, source := range sources {
		raw = append(raw, parseSSHClientConfigBlocks(source)...)
	}
	return mergeAndFilterBlocks(raw)
}

// mergeAndFilterBlocks turns parsed Host blocks into concrete entries: a
// host-less block (bare "Host *" style defaults) is folded into every entry,
// and blocks with only wildcard/negated aliases are dropped.
func mergeAndFilterBlocks(rawBlocks []SSHClientConfig) []SSHClientConfig {
	defaults := SSHClientConfig{Options: map[string]string{}}
	blocks := []SSHClientConfig{}
	for _, block := range rawBlocks {
		if len(usableSSHHostAliases(block.HostAliases)) == 0 {
			defaults = mergeSSHConfigMissing(defaults, block)
			continue
		}
		blocks = append(blocks, block)
	}
	entries := []SSHClientConfig{}
	for _, block := range blocks {
		block.HostAliases = usableSSHHostAliases(block.HostAliases)
		if len(block.HostAliases) == 0 {
			continue
		}
		entry := mergeSSHConfigMissing(block, defaults)
		if len(entry.Options) == 0 {
			entry.Options = nil
		}
		entries = append(entries, entry)
	}
	return entries
}

func ParseSSHClientConfigFile(path string) []SSHClientConfig {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	return ParseSSHClientConfigSources([]SSHConfigSource{{Index: 1, Path: cleanPath(path), Scope: "file", Reason: "explicit file", Exists: pathExists(path)}})
}

func parseSSHClientConfigBlocks(source SSHConfigSource) []SSHClientConfig {
	path := cleanPath(strings.TrimSpace(source.Path))
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseSSHConfigData(data, path, source)
}

// parseSSHConfigData parses ssh_config content. path resolves relative
// IdentityFile values and labels the source; it need not exist, so content from
// a pipe, stdin, or a program (the config-source abstraction) parses the same.
func parseSSHConfigData(data []byte, path string, source SSHConfigSource) []SSHClientConfig {
	entries := []SSHClientConfig{}
	current := SSHClientConfig{SourcePath: path, SourceScope: source.Scope, SourceOrder: source.Index, Options: map[string]string{}}
	flush := func() {
		if len(current.HostAliases) == 0 {
			current = SSHClientConfig{SourcePath: path, SourceScope: source.Scope, SourceOrder: source.Index, Options: map[string]string{}}
			return
		}
		if len(current.Options) == 0 {
			current.Options = nil
		}
		entries = append(entries, current)
		current = SSHClientConfig{SourcePath: path, SourceScope: source.Scope, SourceOrder: source.Index, Options: map[string]string{}}
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		value := strings.TrimSpace(strings.Join(parts[1:], " "))
		switch key {
		case "host":
			flush()
			current.HostAliases = append([]string{}, parts[1:]...)
		case "include":
			continue
		case "hostname":
			current.HostName = value
		case "user":
			current.User = value
		case "port":
			current.Port = parsePositiveInt(value)
		case "identityfile":
			current.IdentityFile = cleanSSHConfigPath(value, filepath.Dir(path))
		case "proxyjump":
			current.ProxyJump = value
		case "proxycommand":
			current.ProxyCommand = value
		case "forwardagent":
			current.ForwardAgent = value
		default:
			if current.Options == nil {
				current.Options = map[string]string{}
			}
			current.Options[parts[0]] = value
		}
	}
	flush()
	return entries
}

func SSHClientConfigLabel(entry SSHClientConfig) string {
	alias := strings.Join(entry.HostAliases, ",")
	if alias == "" {
		alias = "<unnamed>"
	}
	target := strings.TrimSpace(entry.HostName)
	if target == "" {
		target = firstString(entry.HostAliases)
	}
	user := strings.TrimSpace(entry.User)
	if user != "" {
		target = user + "@" + target
	}
	if entry.Port > 0 && entry.Port != 22 {
		target += ":" + strconv.Itoa(entry.Port)
	}
	parts := []string{fmt.Sprintf("%d. %s -> %s", entry.Index, alias, target)}
	if entry.IdentityFile != "" {
		parts = append(parts, "identity="+entry.IdentityFile)
	}
	if entry.ProxyJump != "" {
		parts = append(parts, "proxy_jump="+entry.ProxyJump)
	}
	if entry.ProxyCommand != "" {
		parts = append(parts, "proxy_command="+entry.ProxyCommand)
	}
	if entry.SourceScope != "" {
		parts = append(parts, "scope="+entry.SourceScope)
	}
	parts = append(parts, "source="+entry.SourcePath)
	return strings.Join(parts, " ")
}

func explicitSSHConfigPaths() []string {
	raw := strings.TrimSpace(os.Getenv("WEAVERSSH_SSH_CONFIG"))
	if raw == "" {
		return nil
	}
	parts := filepath.SplitList(raw)
	if len(parts) <= 1 && strings.Contains(raw, ",") {
		parts = strings.Split(raw, ",")
	}
	out := []string{}
	for _, part := range parts {
		for _, path := range expandSSHConfigPattern(part, "") {
			out = append(out, path)
		}
	}
	return dedupeStrings(out)
}

func systemSSHConfigPath() string {
	if raw := strings.TrimSpace(os.Getenv("WEAVERSSH_SYSTEM_SSH_CONFIG")); raw != "" {
		return cleanPath(raw)
	}
	return "/etc/ssh/ssh_config"
}

func envFlagEnabled(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func detectSSHConfigIncludes(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	baseDir := filepath.Dir(path)
	out := []string{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 || !strings.EqualFold(parts[0], "include") {
			continue
		}
		for _, pattern := range parts[1:] {
			out = append(out, expandSSHConfigPattern(pattern, baseDir)...)
		}
	}
	return dedupeStrings(out)
}

func relatedSSHConfigFiles(path string) []string {
	base := filepath.Base(path)
	dir := filepath.Dir(path)
	out := []string{}
	if base == "config" {
		out = append(out, sshConfigDirFiles(filepath.Join(dir, "config.d"))...)
	}
	if base == "ssh_config" {
		out = append(out, sshConfigDirFiles(filepath.Join(dir, "ssh_config.d"))...)
	}
	return dedupeStrings(out)
}

func sshConfigDirFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if strings.HasSuffix(name, ".conf") || strings.HasSuffix(name, ".sshconfig") || !strings.Contains(name, ".") {
			out = append(out, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(out)
	return out
}

func expandSSHConfigPattern(pattern string, baseDir string) []string {
	pattern = strings.Trim(strings.TrimSpace(pattern), `"'`)
	if pattern == "" {
		return nil
	}
	if !filepath.IsAbs(pattern) && !strings.HasPrefix(pattern, "~/") {
		if strings.TrimSpace(baseDir) != "" {
			pattern = filepath.Join(baseDir, pattern)
		}
	}
	pattern = cleanPath(pattern)
	matches, err := filepath.Glob(pattern)
	if err == nil && len(matches) > 0 {
		sort.Strings(matches)
		return matches
	}
	if pathExists(pattern) {
		return []string{pattern}
	}
	return nil
}

func cleanSSHConfigPath(value string, baseDir string) string {
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	if value == "" || strings.Contains(value, "%") {
		return value
	}
	if filepath.IsAbs(value) || strings.HasPrefix(value, "~/") {
		return cleanPath(value)
	}
	if strings.TrimSpace(baseDir) != "" {
		return cleanPath(filepath.Join(baseDir, value))
	}
	return cleanPath(value)
}

func mergeSSHConfigMissing(primary SSHClientConfig, fallback SSHClientConfig) SSHClientConfig {
	if primary.HostName == "" {
		primary.HostName = fallback.HostName
	}
	if primary.User == "" {
		primary.User = fallback.User
	}
	if primary.Port == 0 {
		primary.Port = fallback.Port
	}
	if primary.IdentityFile == "" {
		primary.IdentityFile = fallback.IdentityFile
	}
	if primary.ProxyJump == "" {
		primary.ProxyJump = fallback.ProxyJump
	}
	if primary.ProxyCommand == "" {
		primary.ProxyCommand = fallback.ProxyCommand
	}
	if primary.ForwardAgent == "" {
		primary.ForwardAgent = fallback.ForwardAgent
	}
	if len(fallback.Options) > 0 {
		if primary.Options == nil {
			primary.Options = map[string]string{}
		}
		for key, value := range fallback.Options {
			if _, ok := primary.Options[key]; !ok {
				primary.Options[key] = value
			}
		}
	}
	return primary
}
