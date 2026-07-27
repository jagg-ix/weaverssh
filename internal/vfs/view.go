package vfs

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"weaverssh/internal/p9client"
)

const (
	// ViewVersion identifies the JSON contract for VFS namespace projections.
	ViewVersion = "weaverssh.vfs.view.v1"

	// EnvViewConfig points at a JSON view config. EnvViewConfigShort is the
	// short alias used by the unified wv CLI.
	EnvViewConfig      = "WEAVERSSH_VFS_VIEW"
	EnvViewConfigShort = "WV_VIEW"

	ViewActionHide   = "hide"
	ViewActionRename = "rename"
)

// ViewRule describes one source-namespace projection rule. Rules operate on
// source-relative paths, not host filesystem paths.
type ViewRule struct {
	Action string `json:"action"`
	Match  string `json:"match"`
	To     string `json:"to,omitempty"`
}

// ViewConfig is a database-view-like projection over the published VFS tree.
// It never mutates the 9P server root; it only translates paths at the VFS API
// boundary before list/copy/read/write operations are issued.
type ViewConfig struct {
	Version string     `json:"version"`
	Rules   []ViewRule `json:"rules,omitempty"`
}

// ViewEntry preserves both the underlying source path and the projected entry
// name needed by recursive copy/list operations.
type ViewEntry struct {
	SourcePath string
	ViewPath   string
	Entry      p9client.DirEntry
}

// DefaultView returns an enabled-but-empty projection.
func DefaultView() ViewConfig {
	return ViewConfig{Version: ViewVersion}
}

// ViewPath returns the per-user view config file location.
func ViewPath() string {
	if p := firstEnv(EnvViewConfig, EnvViewConfigShort); p != "" {
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
	return filepath.Join(base, "weaverssh", "vfs-view.json")
}

// LoadView reads and validates the configured namespace projection.
func LoadView() (ViewConfig, error) {
	var cfg ViewConfig
	data, err := os.ReadFile(ViewPath())
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg.Normalize()
}

// SaveView validates and writes cfg to ViewPath, creating parent directories.
func SaveView(cfg ViewConfig) error {
	normalized, err := cfg.Normalize()
	if err != nil {
		return err
	}
	path := ViewPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Normalize canonicalizes and validates the projection rules.
func (cfg ViewConfig) Normalize() (ViewConfig, error) {
	if strings.TrimSpace(cfg.Version) == "" {
		cfg.Version = ViewVersion
	}
	if cfg.Version != ViewVersion {
		return cfg, fmt.Errorf("unsupported VFS view version %q", cfg.Version)
	}
	normalized := ViewConfig{Version: ViewVersion, Rules: make([]ViewRule, 0, len(cfg.Rules))}
	for i, r := range cfg.Rules {
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		match, err := cleanViewRel(r.Match)
		if err != nil {
			return cfg, fmt.Errorf("view rule %d match: %w", i, err)
		}
		if match == "" {
			return cfg, fmt.Errorf("view rule %d match must not be the namespace root", i)
		}
		r.Match = match
		switch r.Action {
		case ViewActionHide:
			r.To = ""
		case ViewActionRename:
			if containsGlob(r.Match) {
				return cfg, fmt.Errorf("view rule %d rename match must be a literal path", i)
			}
			to, err := cleanViewRel(r.To)
			if err != nil {
				return cfg, fmt.Errorf("view rule %d to: %w", i, err)
			}
			if to == "" {
				return cfg, fmt.Errorf("view rule %d rename target must not be the namespace root", i)
			}
			if containsGlob(to) {
				return cfg, fmt.Errorf("view rule %d rename target must be a literal path", i)
			}
			r.To = to
		default:
			return cfg, fmt.Errorf("view rule %d has unknown action %q", i, r.Action)
		}
		normalized.Rules = append(normalized.Rules, r)
	}
	return normalized, nil
}

// SourcePath maps a projected view path back to the underlying 9P source path.
// The hidden return value is true when the resolved source path is not allowed
// by this view and must fail closed.
func (cfg ViewConfig) SourcePath(viewPath string) (sourcePath string, hidden bool, err error) {
	cfg, err = cfg.Normalize()
	if err != nil {
		return "", false, err
	}
	sourcePath, err = cleanViewRel(viewPath)
	if err != nil {
		return "", false, err
	}
	// Reverse rename rules in reverse order to invert source->view projection.
	for i := len(cfg.Rules) - 1; i >= 0; i-- {
		r := cfg.Rules[i]
		if r.Action == ViewActionRename && pathWithin(sourcePath, r.To) {
			sourcePath = replacePrefix(sourcePath, r.To, r.Match)
		}
	}
	return sourcePath, cfg.IsHiddenSource(sourcePath), nil
}

// VisiblePath maps an underlying source path to its projected visible path.
func (cfg ViewConfig) VisiblePath(sourcePath string) (viewPath string, hidden bool, err error) {
	cfg, err = cfg.Normalize()
	if err != nil {
		return "", false, err
	}
	viewPath, err = cleanViewRel(sourcePath)
	if err != nil {
		return "", false, err
	}
	if cfg.IsHiddenSource(viewPath) {
		return "", true, nil
	}
	for _, r := range cfg.Rules {
		if r.Action == ViewActionRename && pathWithin(viewPath, r.Match) {
			viewPath = replacePrefix(viewPath, r.Match, r.To)
		}
	}
	return viewPath, false, nil
}

// IsHiddenSource reports whether sourcePath or one of its ancestors is hidden
// by a hide rule.
func (cfg ViewConfig) IsHiddenSource(sourcePath string) bool {
	sourcePath, err := cleanViewRel(sourcePath)
	if err != nil {
		return true
	}
	for _, r := range cfg.Rules {
		if r.Action == ViewActionHide && hideRuleMatches(r.Match, sourcePath) {
			return true
		}
	}
	return false
}

// ListEntries projects a 9P directory listing from sourceParent into viewParent.
// Entries hidden by the view are removed; renamed entries expose the view name.
func (cfg ViewConfig) ListEntries(sourceParent, viewParent string, entries []p9client.DirEntry) ([]ViewEntry, error) {
	cfg, err := cfg.Normalize()
	if err != nil {
		return nil, err
	}
	sourceParent, err = cleanViewRel(sourceParent)
	if err != nil {
		return nil, err
	}
	viewParent, err = cleanViewRel(viewParent)
	if err != nil {
		return nil, err
	}
	out := make([]ViewEntry, 0, len(entries))
	for _, e := range entries {
		sourceChild := joinViewRel(sourceParent, e.Name)
		viewChild, hidden, err := cfg.VisiblePath(sourceChild)
		if err != nil {
			return nil, err
		}
		if hidden {
			continue
		}
		parent, name := splitViewRel(viewChild)
		if parent != viewParent {
			continue
		}
		projected := e
		projected.Name = name
		out = append(out, ViewEntry{SourcePath: sourceChild, ViewPath: viewChild, Entry: projected})
	}
	return out, nil
}

// ApplyList projects entries when the caller does not need source-path metadata.
func (cfg ViewConfig) ApplyList(sourceParent, viewParent string, entries []p9client.DirEntry) ([]p9client.DirEntry, error) {
	mapped, err := cfg.ListEntries(sourceParent, viewParent, entries)
	if err != nil {
		return nil, err
	}
	out := make([]p9client.DirEntry, 0, len(mapped))
	for _, m := range mapped {
		out = append(out, m.Entry)
	}
	return out, nil
}

func cleanViewRel(p string) (string, error) {
	p = strings.TrimSpace(filepath.ToSlash(p))
	p = strings.Trim(p, "/")
	if p == "" || p == "." {
		return "", nil
	}
	if strings.ContainsRune(p, '\x00') {
		return "", fmt.Errorf("path contains NUL")
	}
	cleaned := path.Clean(p)
	if cleaned == "." {
		return "", nil
	}
	if path.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("path escapes namespace: %q", p)
	}
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == ".." {
			return "", fmt.Errorf("path escapes namespace: %q", p)
		}
	}
	return cleaned, nil
}

func joinViewRel(parent, name string) string {
	name = strings.Trim(name, "/")
	if parent == "" {
		return name
	}
	if name == "" {
		return parent
	}
	return parent + "/" + name
}

func splitViewRel(p string) (parent, name string) {
	p = strings.Trim(p, "/")
	if p == "" {
		return "", ""
	}
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return "", p
	}
	return p[:i], p[i+1:]
}

func pathWithin(p, root string) bool {
	if root == "" {
		return true
	}
	return p == root || strings.HasPrefix(p, root+"/")
}

func replacePrefix(p, from, to string) string {
	if p == from {
		return to
	}
	return joinViewRel(to, strings.TrimPrefix(p, from+"/"))
}

func containsGlob(p string) bool {
	return strings.ContainsAny(p, "*?[")
}

func hideRuleMatches(match, source string) bool {
	if match == "" {
		return false
	}
	if !containsGlob(match) {
		if strings.Contains(match, "/") {
			return pathWithin(source, match)
		}
		for _, seg := range strings.Split(source, "/") {
			if seg == match {
				return true
			}
		}
		return false
	}
	candidates := pathPrefixes(source)
	if !strings.Contains(match, "/") {
		for _, c := range candidates {
			for _, seg := range strings.Split(c, "/") {
				if ok, _ := path.Match(match, seg); ok {
					return true
				}
			}
		}
		return false
	}
	for _, c := range candidates {
		if ok, _ := path.Match(match, c); ok {
			return true
		}
	}
	return false
}

func pathPrefixes(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for i := range parts {
		out = append(out, strings.Join(parts[:i+1], "/"))
	}
	return out
}
