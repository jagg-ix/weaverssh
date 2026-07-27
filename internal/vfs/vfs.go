// Package vfs resolves the weaverssh vfs:// namespace to a concrete 9P endpoint
// and connects to it. The vfs:// scheme refers to a directory published from a
// workstation by wv-9p (or `wtool setroot`); the convenience tools wls/wcp/
// wmkdir reach it through the weaverssh tunnel — directly via a forwarded port
// or through the SOCKS proxy — so data never lands on an intermediary hop.
package vfs

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	"weaverssh/internal/p9client"
)

// Scheme is the URL prefix that denotes the published 9P namespace.
const Scheme = "vfs://"

// NodeScheme denotes a node-qualified path within the published namespace.
//
//	vfs::origin:/logs/app.log
//	vfs::endpoint:/tmp/result.bin
//	vfs::self:/work/out.txt
//
// The node qualifier is resolved to a stable namespace subtree so the same
// command can be run from the origin workstation or a later hop in the chain.
const NodeScheme = "vfs::"

// DefaultNodeNamespace is reserved for node-qualified VFS paths.
const DefaultNodeNamespace = ".wv/nodes"

// DefaultEndpoint is the tunnel-local 9P address used when nothing overrides it.
const DefaultEndpoint = "127.0.0.1:5640"

// Environment overrides for endpoint resolution. The short WV_* aliases match
// the unified `wv` CLI; the long WEAVERSSH_VFS_* names take precedence when both
// are set.
const (
	EnvEndpoint      = "WEAVERSSH_VFS_ENDPOINT" // host:port of the 9P service (default 127.0.0.1:5640)
	EnvSocks         = "WEAVERSSH_VFS_SOCKS"    // optional SOCKS5 proxy host:port to reach the endpoint
	EnvEndpointShort = "WV_ENDPOINT"            // short alias for EnvEndpoint
	EnvSocksShort    = "WV_SOCKS"               // short alias for EnvSocks

	EnvCurrentNode       = "WEAVERSSH_NODE_ID"            // node name for the process executing wv
	EnvCurrentNodeShort  = "WV_NODE"                      // short alias for EnvCurrentNode
	EnvOriginNode        = "WEAVERSSH_ORIGIN_NODE"        // origin/workstation node in the active chain
	EnvOriginNodeShort   = "WV_ORIGIN_NODE"               // short alias for EnvOriginNode
	EnvEndpointNode      = "WEAVERSSH_ENDPOINT_NODE"      // final target node in the active chain
	EnvEndpointNodeShort = "WV_ENDPOINT_NODE"             // short alias for EnvEndpointNode
	EnvChainNodes        = "WEAVERSSH_CHAIN_NODES"        // comma-separated active chain nodes
	EnvNodeNamespace     = "WEAVERSSH_VFS_NODE_NAMESPACE" // optional namespace prefix for vfs::NODE paths
)

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// IsVFS reports whether ref is a VFS reference. Explicit vfs://PATH,
// vfs::NODE:/PATH, and SCP-style NODE:/PATH or USER@NODE:~/PATH forms are
// accepted. SCP-style paths are syntax sugar over node-qualified VFS paths so
// operators can use the same shape they already know from scp.
func IsVFS(ref string) bool {
	if strings.HasPrefix(ref, Scheme) || strings.HasPrefix(ref, NodeScheme) {
		return true
	}
	_, _, ok := splitSCPStyleNodeRef(ref)
	return ok
}

// NodePath is the parsed form of vfs::NODE:/PATH. NamespacePath is the concrete
// path used inside the published VFS tree.
type NodePath struct {
	Raw           string
	Node          string
	Path          string
	NamespacePath string
}

// ParsePath returns the namespace-relative path of a VFS reference.
// vfs:// and vfs:/// both resolve to the root (""). vfs::NODE:/PATH and
// SCP-style NODE:/PATH resolve to a reserved node subtree under
// DefaultNodeNamespace.
func ParsePath(ref string) (string, error) {
	switch {
	case strings.HasPrefix(ref, NodeScheme):
		np, err := ParseNodePath(ref)
		if err != nil {
			return "", err
		}
		return np.NamespacePath, nil
	case strings.HasPrefix(ref, Scheme):
		rest := strings.TrimPrefix(ref, Scheme)
		rest = strings.TrimPrefix(rest, "/") // tolerate vfs:///path
		return cleanNamespacePath(ref, rest)
	default:
		np, ok, err := ParseSCPStyleNodePath(ref)
		if err != nil {
			return "", err
		}
		if ok {
			return np.NamespacePath, nil
		}
		return "", fmt.Errorf("not a vfs://, vfs::, or SCP-style node reference: %q", ref)
	}
}

// ParseNodePath parses vfs::NODE:/PATH. NODE may be a concrete chain node or a
// relative alias: origin/workstation, self/local/here, or endpoint/target.
func ParseNodePath(ref string) (NodePath, error) {
	if !strings.HasPrefix(ref, NodeScheme) {
		return NodePath{}, fmt.Errorf("not a vfs:: reference: %q", ref)
	}
	rest := strings.TrimPrefix(ref, NodeScheme)
	nodeRef, pathPart, ok := splitNodeColonPath(rest)
	if !ok {
		return NodePath{}, fmt.Errorf("node-qualified VFS path must use vfs::NODE:/PATH: %q", ref)
	}
	return buildNodePath(ref, nodeRef, pathPart)
}

// ParseSCPStyleNodePath parses the scp-compatible NODE:/PATH,
// NODE:~/relative, and USER@NODE:/PATH forms. The boolean return is false when
// the input is not SCP-style, which lets local paths remain local.
func ParseSCPStyleNodePath(ref string) (NodePath, bool, error) {
	nodeRef, pathPart, ok := splitSCPStyleNodeRef(ref)
	if !ok {
		return NodePath{}, false, nil
	}
	np, err := buildNodePath(ref, nodeRef, pathPart)
	return np, true, err
}

func buildNodePath(raw, nodeRef, pathPart string) (NodePath, error) {
	node, err := ResolveNodeRef(nodeRef)
	if err != nil {
		return NodePath{}, err
	}
	rel, err := cleanNamespacePath(raw, pathPart)
	if err != nil {
		return NodePath{}, err
	}
	namespace, err := cleanNamespacePath(EnvNodeNamespace, firstEnv(EnvNodeNamespace))
	if err != nil || namespace == "" {
		namespace = DefaultNodeNamespace
	}
	return NodePath{
		Raw:           raw,
		Node:          node,
		Path:          rel,
		NamespacePath: joinNamespace(namespace, node, rel),
	}, nil
}

func splitSCPStyleNodeRef(ref string) (nodeRef, pathPart string, ok bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, Scheme) || strings.HasPrefix(ref, NodeScheme) {
		return "", "", false
	}
	if strings.Contains(ref, "://") {
		return "", "", false
	}
	if isWindowsLocalPath(ref) {
		return "", "", false
	}
	// A node may be an IP address. IPv4 (192.0.2.1) has no colon and splits
	// like any host; IPv6 literals carry colons, so they must be bracketed —
	// [2001:db8::1]:/path or user@[fe80::1]:~/path — per the scp/URL convention.
	if node, path, isBracket, okB := splitBracketedIPv6Ref(ref); isBracket {
		return node, path, okB
	}
	colon := strings.IndexByte(ref, ':')
	if colon <= 0 {
		return "", "", false
	}
	nodeRef = strings.TrimSpace(ref[:colon])
	pathPart = strings.TrimSpace(ref[colon+1:])
	if nodeRef == "" || strings.Contains(nodeRef, "://") {
		return "", "", false
	}
	// SCP's host:path form has no slash before the colon. This preserves local
	// paths such as ./build:artifact or /tmp/a:b.
	if strings.ContainsAny(nodeRef, `/\`) {
		return "", "", false
	}
	return nodeRef, pathPart, true
}

// splitBracketedIPv6Ref parses a bracketed IPv6 host reference of the form
// [ADDR]:PATH or USER@[ADDR]:PATH. isBracket reports that bracket syntax was
// used (so callers stop rather than fall through to the plain colon split); ok
// reports a well-formed split.
func splitBracketedIPv6Ref(ref string) (node, path string, isBracket, ok bool) {
	open := strings.IndexByte(ref, '[')
	if open < 0 {
		return "", "", false, false
	}
	prefix := ref[:open]
	if prefix != "" && !strings.HasSuffix(prefix, "@") {
		// '[' is not a leading host bracket (nor right after "user@").
		return "", "", false, false
	}
	closeIdx := strings.IndexByte(ref, ']')
	if closeIdx <= open+1 {
		return "", "", true, false // empty or malformed bracket
	}
	if closeIdx+1 >= len(ref) || ref[closeIdx+1] != ':' {
		return "", "", true, false // must be "]:" followed by a path
	}
	host := strings.TrimSpace(ref[open+1 : closeIdx])
	if host == "" {
		return "", "", true, false
	}
	node = strings.TrimSpace(prefix + host) // user@ + addr, brackets stripped
	path = strings.TrimSpace(ref[closeIdx+2:])
	return node, path, true, true
}

// splitNodeColonPath splits "NODE:PATH", accepting a bracketed IPv6 host for
// NODE ([2001:db8::1]) optionally prefixed by "user@".
func splitNodeColonPath(rest string) (node, path string, ok bool) {
	if n, p, isBracket, okB := splitBracketedIPv6Ref(rest); isBracket {
		return n, p, okB
	}
	return strings.Cut(rest, ":")
}

func isWindowsLocalPath(ref string) bool {
	if len(ref) < 2 || ref[1] != ':' {
		return false
	}
	if !unicode.IsLetter(rune(ref[0])) {
		return false
	}
	return len(ref) == 2 || ref[2] == '\\' || ref[2] == '/'
}

// ResolveNodeRef resolves a concrete node name or relative node alias into the
// stable name stored under the VFS node namespace.
func ResolveNodeRef(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", fmt.Errorf("node-qualified VFS path has an empty node")
	}
	lower := strings.ToLower(ref)
	switch lower {
	case "origin", "@origin", "workstation":
		if v := firstEnv(EnvOriginNode, EnvOriginNodeShort); v != "" {
			ref = v
		} else if first := firstChainNode(); first != "" {
			ref = first
		} else {
			ref = "origin"
		}
	case "local", "self", ".", "here", "this":
		if v := firstEnv(EnvCurrentNode, EnvCurrentNodeShort); v != "" {
			ref = v
		} else {
			ref = "local"
		}
	case "endpoint", "target", "remote", "last":
		if v := firstEnv(EnvEndpointNode, EnvEndpointNodeShort); v != "" {
			ref = v
		} else if last := lastChainNode(); last != "" {
			ref = last
		} else {
			ref = "endpoint"
		}
	}
	return cleanNodeName(ref)
}

func cleanNamespacePath(ref, rest string) (string, error) {
	rest = strings.TrimPrefix(rest, "/")
	rest = strings.Trim(rest, "/")
	if rest == "" || rest == "." {
		return "", nil
	}
	parts := strings.Split(rest, "/")
	out := make([]string, 0, len(parts))
	for _, seg := range parts {
		seg = strings.TrimSpace(seg)
		switch seg {
		case "", ".":
			continue
		case "..":
			return "", fmt.Errorf("path escapes namespace: %q", ref)
		default:
			out = append(out, seg)
		}
	}
	return strings.Join(out, "/"), nil
}

func cleanNodeName(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	lower := strings.ToLower(ref)
	for _, prefix := range []string{"node/", "nodes/", "profile/", "profiles/", "connection/", "connections/"} {
		if strings.HasPrefix(lower, prefix) {
			ref = strings.TrimSpace(ref[len(prefix):])
			lower = strings.ToLower(ref)
			break
		}
	}
	if ref == "" || ref == "." || ref == ".." {
		return "", fmt.Errorf("invalid VFS node name %q", ref)
	}
	// Accept IP-address nodes (IPv4, or bracket-stripped IPv6, optionally with a
	// user@ prefix). IPv6 literals contain colons, which the generic rule below
	// forbids, so validate them explicitly here.
	host := ref
	userPart := ""
	if at := strings.LastIndexByte(ref, '@'); at >= 0 {
		userPart, host = ref[:at], ref[at+1:]
	}
	if net.ParseIP(host) != nil {
		for _, r := range userPart {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.') {
				return "", fmt.Errorf("invalid VFS node name %q", ref)
			}
		}
		return ref, nil
	}
	for _, r := range ref {
		if r == '/' || r == '\\' || r == ':' || unicode.IsSpace(r) {
			return "", fmt.Errorf("invalid VFS node name %q", ref)
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		switch r {
		case '-', '_', '.', '@':
			continue
		default:
			return "", fmt.Errorf("invalid VFS node name %q", ref)
		}
	}
	return ref, nil
}

func firstChainNode() string {
	nodes := splitEnvNodeList(firstEnv(EnvChainNodes))
	if len(nodes) == 0 {
		return ""
	}
	return nodes[0]
}

func lastChainNode() string {
	nodes := splitEnvNodeList(firstEnv(EnvChainNodes))
	if len(nodes) == 0 {
		return ""
	}
	return nodes[len(nodes)-1]
}

func splitEnvNodeList(raw string) []string {
	repl := strings.NewReplacer("->", ",", "=>", ",", "→", ",")
	raw = repl.Replace(raw)
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '+' || unicode.IsSpace(r)
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		if node, err := cleanNodeName(field); err == nil {
			out = append(out, node)
		}
	}
	return out
}

func joinNamespace(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Trim(part, "/")
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, "/")
}

// Endpoint returns the configured 9P endpoint and optional SOCKS proxy. WSL
// host sentinels ("windows-host" / "wsl-host") in either address are resolved
// to the Windows host IP as seen from inside WSL.
func Endpoint() (endpoint, socks string) {
	endpoint, socks, err := EndpointChecked()
	if err != nil {
		return DefaultEndpoint, ""
	}
	return endpoint, socks
}

func EndpointChecked() (endpoint, socks string, err error) {
	endpoint = firstEnv(EnvEndpoint, EnvEndpointShort)
	socks = firstEnv(EnvSocks, EnvSocksShort)
	if endpoint == "" {
		var profile ProviderProfile
		var ok bool
		profile, ok, err = ResolveProviderConfig()
		if err != nil {
			return "", "", err
		}
		if ok {
			if providerEndpoint, providerSocks, direct := profile.EndpointPair(); direct {
				endpoint = providerEndpoint
				if socks == "" {
					socks = providerSocks
				}
			}
		}
	}
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	endpoint = resolveSentinel(endpoint)
	if socks != "" {
		socks = resolveSentinel(socks)
	}
	return endpoint, socks, nil
}

// Connect opens a 9P session to the resolved endpoint.
func Connect(timeout time.Duration) (*p9client.Client, error) {
	endpoint, socks, err := EndpointChecked()
	if err != nil {
		return nil, err
	}
	if socks != "" {
		return p9client.DialSOCKS(socks, endpoint, timeout)
	}
	return p9client.Dial(endpoint, timeout)
}

// --- publish-side config ---------------------------------------------------

// Config records what a workstation publishes, so `wtool setroot` and status
// reporting agree on the served root and listen address.
type Config struct {
	Root         string           `json:"root"`
	Listen       string           `json:"listen"`
	Endpoint     string           `json:"endpoint,omitempty"`
	Socks        string           `json:"socks,omitempty"`
	ProviderName string           `json:"provider_name,omitempty"`
	Provider     *ProviderProfile `json:"provider,omitempty"`
}

// ConfigPath returns the per-user config file location.
func ConfigPath() string {
	if p := strings.TrimSpace(os.Getenv("WEAVERSSH_VFS_CONFIG")); p != "" {
		return p
	}
	var base string
	switch runtime.GOOS {
	case "windows":
		base = os.Getenv("APPDATA")
		if base == "" {
			base, _ = os.UserConfigDir()
		}
	default:
		if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
			base = xdg
		} else if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, ".config")
		}
	}
	if base == "" {
		base = "."
	}
	return filepath.Join(base, "weaverssh", "vfs.json")
}

// SaveConfig writes cfg to ConfigPath, creating parent directories.
func SaveConfig(cfg Config) error {
	path := ConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// LoadConfig reads the saved publish config, if any.
func LoadConfig() (Config, error) {
	var cfg Config
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		return cfg, err
	}
	return cfg, json.Unmarshal(data, &cfg)
}
