package connectionscan

// PuTTY saved-session discovery: reads sessions from the Windows registry
// (HKCU\Software\SimonTatham\PuTTY\Sessions, via an embedded PowerShell reader),
// from PSPuTTYCfg exports, or from JSON fixtures. Ported from the weaverssh
// service-dock; the dock-specific profile converters were dropped.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type PuTTYSessionConfig struct {
	Index           int    `json:"index"`
	Name            string `json:"name"`
	RawName         string `json:"raw_name,omitempty"`
	SourcePath      string `json:"source_path,omitempty"`
	SourceScope     string `json:"source_scope,omitempty"`
	HostName        string `json:"host_name,omitempty"`
	User            string `json:"user,omitempty"`
	Port            int    `json:"port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	IdentityFile    string `json:"identity_file,omitempty"`
	ProxyMethod     int    `json:"proxy_method,omitempty"`
	ProxyType       string `json:"proxy_type,omitempty"`
	ProxyHost       string `json:"proxy_host,omitempty"`
	ProxyPort       int    `json:"proxy_port,omitempty"`
	ProxyUser       string `json:"proxy_user,omitempty"`
	AgentForwarding *bool  `json:"agent_forwarding,omitempty"`
	X11Forwarding   *bool  `json:"x11_forwarding,omitempty"`
	Compression     *bool  `json:"compression,omitempty"`
	PortForwardings string `json:"port_forwardings,omitempty"`
}

type puttySessionsDocument struct {
	Schema       string               `json:"schema"`
	Source       string               `json:"source,omitempty"`
	RegistryRoot string               `json:"registry_root,omitempty"`
	GeneratedAt  string               `json:"generated_at,omitempty"`
	Sessions     []PuTTYSessionConfig `json:"sessions"`
	Errors       []string             `json:"errors,omitempty"`
}

func DetectPuTTYSessionConfigs() []PuTTYSessionConfig {
	var sessions []PuTTYSessionConfig
	explicitSource := false
	if path := strings.TrimSpace(os.Getenv("WEAVERSSH_PUTTY_SESSIONS_JSON")); path != "" {
		explicitSource = true
		sessions = append(sessions, readNormalizedPuTTYSessionConfigPath(path)...)
	}
	if path := firstEnv("WEAVERSSH_PSPUTTYCFG_JSON", "WEAVERSSH_PSPUTTYCFG_PATH"); path != "" {
		explicitSource = true
		sessions = append(sessions, readPSPuTTYCfgSessionConfigPath(path)...)
	}
	if explicitSource {
		return reindexPuTTYSessions(dedupePuTTYSessions(sessions))
	}
	if !puttyPowerShellScanEnabled() {
		return nil
	}

	// PSPuTTYCfg is the canonical PuTTY-session source when PowerShell is
	// available. It owns registry/file import semantics, analogous to OpenSSH
	// ssh_config discovery on Unix-like systems.
	if psPuTTYCfg := detectPSPuTTYCfgPowerShellSessions(); len(psPuTTYCfg) > 0 {
		return reindexPuTTYSessions(dedupePuTTYSessions(psPuTTYCfg))
	}
	if envFlagEnabled("WEAVERSSH_DISABLE_PUTTY_REGISTRY_FALLBACK") {
		return nil
	}
	return reindexPuTTYSessions(dedupePuTTYSessions(detectPuTTYRegistryPowerShellSessions()))
}

func puttyPowerShellScanEnabled() bool {
	return runtime.GOOS == "windows" || envFlagEnabled("WEAVERSSH_ENABLE_PUTTY_SCAN")
}

func readNormalizedPuTTYSessionConfigPath(path string) []PuTTYSessionConfig {
	path = cleanLocalConfigPath(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return ParsePuTTYSessionConfigsFromSource(data, path)
}

func readPSPuTTYCfgSessionConfigPath(path string) []PuTTYSessionConfig {
	path = cleanLocalConfigPath(path)
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if !info.IsDir() {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		return ParsePuTTYSessionConfigsFromSource(data, path)
	}
	var files []string
	_ = filepath.WalkDir(path, func(item string, entry os.DirEntry, err error) error {
		if err != nil || entry == nil || entry.IsDir() {
			return nil
		}
		lower := strings.ToLower(entry.Name())
		if strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".jsonc") {
			files = append(files, item)
		}
		return nil
	})
	sort.Strings(files)
	var sessions []PuTTYSessionConfig
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		sessions = append(sessions, ParsePuTTYSessionConfigsFromSource(data, file)...)
	}
	return sessions
}

func detectPuTTYRegistryPowerShellSessions() []PuTTYSessionConfig {
	script := puttySessionReaderScriptPath()
	if script == "" {
		return nil
	}
	powershell := powershellExecutable()
	if powershell == "" {
		return nil
	}
	cmd := exec.Command(powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script)
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return ParsePuTTYSessionConfigs(out)
}

func detectPSPuTTYCfgPowerShellSessions() []PuTTYSessionConfig {
	script := psPuTTYCfgSessionReaderScriptPath()
	if script == "" {
		return nil
	}
	powershell := powershellExecutable()
	if powershell == "" {
		return nil
	}
	args := []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script}
	if path := firstEnv("WEAVERSSH_PSPUTTYCFG_PATH", "WEAVERSSH_PSPUTTYCFG_JSON"); path != "" {
		args = append(args, "-Path", cleanLocalConfigPath(path))
	} else {
		args = append(args, "-Registry")
	}
	cmd := exec.Command(powershell, args...)
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return ParsePuTTYSessionConfigs(out)
}

func ParsePuTTYSessionConfigs(data []byte) []PuTTYSessionConfig {
	return ParsePuTTYSessionConfigsFromSource(data, "")
}

func ParsePuTTYSessionConfigsFromSource(data []byte, sourcePath string) []PuTTYSessionConfig {
	data = stripJSONComments(data)
	var doc puttySessionsDocument
	if err := json.Unmarshal(data, &doc); err == nil {
		if normalized := normalizePuTTYSessions(doc.Sessions); len(normalized) > 0 {
			return normalized
		}
	}
	var sessions []PuTTYSessionConfig
	if err := json.Unmarshal(data, &sessions); err == nil {
		if normalized := normalizePuTTYSessions(sessions); len(normalized) > 0 {
			return normalized
		}
	}
	return normalizePuTTYSessions(parsePSPuTTYCfgSessions(data, sourcePath))
}

func parsePSPuTTYCfgSessions(data []byte, sourcePath string) []PuTTYSessionConfig {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil
	}
	return parsePSPuTTYCfgValue(value, sourcePath)
}

func parsePSPuTTYCfgValue(value any, sourcePath string) []PuTTYSessionConfig {
	switch typed := value.(type) {
	case []any:
		var sessions []PuTTYSessionConfig
		for _, item := range typed {
			sessions = append(sessions, parsePSPuTTYCfgValue(item, sourcePath)...)
		}
		return sessions
	case map[string]any:
		if rawSessions, ok := fieldAny(typed, "sessions"); ok {
			return parsePSPuTTYCfgValue(rawSessions, sourcePath)
		}
		if session, ok := psPuTTYCfgSessionFromMap(typed, sourcePath); ok {
			return []PuTTYSessionConfig{session}
		}
	}
	return nil
}

func psPuTTYCfgSessionFromMap(item map[string]any, sourcePath string) (PuTTYSessionConfig, bool) {
	connection, ok := objectField(item, "connection")
	if !ok {
		return PuTTYSessionConfig{}, false
	}
	data, _ := objectField(connection, "data")
	proxy, _ := objectField(connection, "proxy")
	ssh, _ := objectField(connection, "ssh")
	auth, _ := objectField(ssh, "auth")
	x11, _ := objectField(ssh, "x11")
	tunnels, _ := objectField(ssh, "tunnels")

	host := stringField(connection, "host", "hostname", "HostName")
	if strings.TrimSpace(host) == "" {
		return PuTTYSessionConfig{}, false
	}
	name := firstNonEmptyText(
		stringField(item, "name", "session", "sessionName", "session_name"),
		sessionNameFromPath(sourcePath),
		host,
	)
	protocol := defaultString(stringField(connection, "protocol", "Protocol"), "ssh")
	forwardedPorts := stringSliceField(tunnels, "forwardedPorts", "forwarded_ports", "PortForwardings")
	scope := "psputtycfg-json"
	if sourcePath == "" {
		scope = "psputtycfg"
	}
	return PuTTYSessionConfig{
		Name:            name,
		SourcePath:      sourcePath,
		SourceScope:     scope,
		HostName:        host,
		User:            stringField(data, "username", "user", "UserName"),
		Port:            intField(connection, "port", "PortNumber"),
		Protocol:        protocol,
		IdentityFile:    stringField(auth, "authKeyFile", "auth_key_file", "PublicKeyFile"),
		ProxyType:       stringField(proxy, "type", "proxyType", "ProxyType"),
		ProxyHost:       stringField(proxy, "host", "hostname", "ProxyHost"),
		ProxyPort:       intField(proxy, "port", "ProxyPort"),
		ProxyUser:       stringField(proxy, "username", "user", "ProxyUsername"),
		AgentForwarding: boolPtrField(auth, "agentForwarding", "agent_forwarding", "AgentFwd"),
		X11Forwarding:   boolPtrField(x11, "x11Forwarding", "x11_forwarding", "X11Forward"),
		Compression:     boolPtrField(ssh, "compression", "Compression"),
		PortForwardings: strings.Join(forwardedPorts, ","),
	}, true
}

func normalizePuTTYSessions(sessions []PuTTYSessionConfig) []PuTTYSessionConfig {
	out := []PuTTYSessionConfig{}
	for _, session := range sessions {
		session.Name = strings.TrimSpace(session.Name)
		session.RawName = strings.TrimSpace(session.RawName)
		session.SourcePath = strings.TrimSpace(session.SourcePath)
		session.SourceScope = defaultString(session.SourceScope, "putty-registry")
		session.HostName = strings.TrimSpace(session.HostName)
		session.User = strings.TrimSpace(session.User)
		session.Protocol = strings.TrimSpace(session.Protocol)
		if session.Protocol == "" {
			session.Protocol = "ssh"
		}
		session.IdentityFile = cleanOptionalPath(session.IdentityFile)
		session.ProxyType = strings.TrimSpace(session.ProxyType)
		session.ProxyHost = strings.TrimSpace(session.ProxyHost)
		session.ProxyUser = strings.TrimSpace(session.ProxyUser)
		session.PortForwardings = strings.TrimSpace(session.PortForwardings)
		if session.Port <= 0 && strings.EqualFold(session.Protocol, "ssh") {
			session.Port = 22
		}
		if session.Name == "" {
			session.Name = firstNonEmptyText(session.RawName, sessionNameFromPath(session.SourcePath), session.HostName)
		}
		if session.HostName == "" {
			continue
		}
		out = append(out, session)
	}
	return reindexPuTTYSessions(out)
}

func reindexPuTTYSessions(sessions []PuTTYSessionConfig) []PuTTYSessionConfig {
	for i := range sessions {
		sessions[i].Index = i + 1
	}
	return sessions
}

func dedupePuTTYSessions(sessions []PuTTYSessionConfig) []PuTTYSessionConfig {
	seen := map[string]bool{}
	var out []PuTTYSessionConfig
	for _, session := range normalizePuTTYSessions(sessions) {
		key := strings.ToLower(strings.Join([]string{
			session.Name,
			session.User,
			session.HostName,
			strconv.Itoa(session.Port),
			session.IdentityFile,
		}, "\x00"))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, session)
	}
	return out
}

func PuTTYSessionConfigLabel(session PuTTYSessionConfig) string {
	name := defaultString(session.Name, session.RawName)
	if name == "" {
		name = "<unnamed>"
	}
	target := strings.TrimSpace(session.HostName)
	if session.User != "" {
		target = session.User + "@" + target
	}
	if session.Port > 0 && session.Port != 22 {
		target += ":" + strconv.Itoa(session.Port)
	}
	parts := []string{fmt.Sprintf("%d. %s -> %s", session.Index, name, target)}
	if session.SourceScope != "" {
		parts = append(parts, "scope="+session.SourceScope)
	}
	if session.IdentityFile != "" {
		parts = append(parts, "identity="+session.IdentityFile)
	}
	if session.Protocol != "" && !strings.EqualFold(session.Protocol, "ssh") {
		parts = append(parts, "protocol="+session.Protocol)
	}
	if session.ProxyType != "" {
		parts = append(parts, "proxy_type="+session.ProxyType)
	}
	if session.ProxyHost != "" {
		proxy := session.ProxyHost
		if session.ProxyPort > 0 {
			proxy += ":" + strconv.Itoa(session.ProxyPort)
		}
		parts = append(parts, "proxy="+proxy)
	}
	if session.SourcePath != "" {
		parts = append(parts, "source="+session.SourcePath)
	}
	return strings.Join(parts, " ")
}

func puttySessionReaderScriptPath() string {
	return powershellScriptPath("WEAVERSSH_PUTTY_SESSIONS_SCRIPT", "read_putty_sessions.ps1")
}

func psPuTTYCfgSessionReaderScriptPath() string {
	return powershellScriptPath("WEAVERSSH_PSPUTTYCFG_SCRIPT", "read_psputtycfg_sessions.ps1")
}

func powershellScriptPath(envName, scriptName string) string {
	if raw := strings.TrimSpace(os.Getenv(envName)); raw != "" {
		path := cleanPath(raw)
		if pathExists(path) {
			return path
		}
		return ""
	}
	return materializeEmbeddedScript(scriptName)
}

func powershellExecutable() string {
	if raw := strings.TrimSpace(os.Getenv("WEAVERSSH_POWERSHELL")); raw != "" {
		if sshClientOverrideLooksLikePath(raw) {
			path := cleanPath(raw)
			if pathExists(path) {
				return path
			}
			return ""
		}
		return firstCommandPath(raw)
	}
	return firstCommandPath("pwsh.exe", "pwsh", "powershell.exe", "powershell")
}

func cleanOptionalPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if windowsPathLike(path) {
		return path
	}
	if strings.Contains(path, "%") {
		path = os.ExpandEnv(path)
	}
	if strings.Contains(path, "~") || strings.Contains(path, "/") || filepath.IsAbs(path) {
		return cleanPath(path)
	}
	return path
}

func cleanLocalConfigPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || (runtime.GOOS != "windows" && windowsPathLike(path)) {
		return path
	}
	return cleanPath(path)
}

func windowsPathLike(path string) bool {
	path = strings.TrimSpace(path)
	if strings.HasPrefix(path, `\\`) {
		return true
	}
	return len(path) >= 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' && (path[2] == '\\' || path[2] == '/')
}

func sessionNameFromPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = strings.ReplaceAll(path, `\`, "/")
	name := filepath.Base(path)
	for _, suffix := range []string{".jsonc", ".json"} {
		if strings.HasSuffix(strings.ToLower(name), suffix) {
			name = name[:len(name)-len(suffix)]
			break
		}
	}
	return strings.TrimSpace(name)
}

func firstNonEmptyText(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func stripJSONComments(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false
	lineComment := false
	blockComment := false
	for i := 0; i < len(data); i++ {
		ch := data[i]
		if lineComment {
			if ch == '\n' || ch == '\r' {
				lineComment = false
				out = append(out, ch)
			}
			continue
		}
		if blockComment {
			if ch == '*' && i+1 < len(data) && data[i+1] == '/' {
				blockComment = false
				i++
			}
			continue
		}
		if inString {
			out = append(out, ch)
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inString = false
			}
			continue
		}
		if ch == '"' {
			inString = true
			out = append(out, ch)
			continue
		}
		if ch == '/' && i+1 < len(data) && data[i+1] == '/' {
			lineComment = true
			i++
			continue
		}
		if ch == '/' && i+1 < len(data) && data[i+1] == '*' {
			blockComment = true
			i++
			continue
		}
		out = append(out, ch)
	}
	return out
}

func objectField(m map[string]any, names ...string) (map[string]any, bool) {
	value, ok := fieldAny(m, names...)
	if !ok {
		return nil, false
	}
	obj, ok := value.(map[string]any)
	return obj, ok
}

func fieldAny(m map[string]any, names ...string) (any, bool) {
	if m == nil {
		return nil, false
	}
	for _, name := range names {
		if value, ok := m[name]; ok {
			return value, true
		}
	}
	for key, value := range m {
		for _, name := range names {
			if strings.EqualFold(key, name) {
				return value, true
			}
		}
	}
	return nil, false
}

func stringField(m map[string]any, names ...string) string {
	value, ok := fieldAny(m, names...)
	if !ok {
		return ""
	}
	return strings.TrimSpace(stringFromAny(value))
}

func intField(m map[string]any, names ...string) int {
	value, ok := fieldAny(m, names...)
	if !ok {
		return 0
	}
	return intFromAny(value)
}

func boolPtrField(m map[string]any, names ...string) *bool {
	value, ok := fieldAny(m, names...)
	if !ok {
		return nil
	}
	return boolPtrFromAny(value)
}

func stringSliceField(m map[string]any, names ...string) []string {
	value, ok := fieldAny(m, names...)
	if !ok {
		return nil
	}
	switch typed := value.(type) {
	case []any:
		var out []string
		for _, item := range typed {
			if text := strings.TrimSpace(stringFromAny(item)); text != "" {
				out = append(out, text)
			}
		}
		return out
	case []string:
		return typed
	default:
		if text := strings.TrimSpace(stringFromAny(value)); text != "" {
			return []string{text}
		}
	}
	return nil
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case float64:
		if typed == float64(int(typed)) {
			return strconv.Itoa(int(typed))
		}
		return fmt.Sprint(typed)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func intFromAny(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		if n, err := typed.Int64(); err == nil {
			return int(n)
		}
	case string:
		return parsePositiveInt(typed)
	}
	return 0
}

func boolPtrFromAny(value any) *bool {
	switch typed := value.(type) {
	case bool:
		return &typed
	case float64:
		b := typed != 0
		return &b
	case int:
		b := typed != 0
		return &b
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "1", "true", "yes", "on", "enabled":
			b := true
			return &b
		case "0", "false", "no", "off", "disabled":
			b := false
			return &b
		}
	}
	return nil
}
