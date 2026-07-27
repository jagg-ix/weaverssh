package main

// Project-local configuration lives in a .wv directory, found by walking up from
// the working directory (like .git). It lets a project pin, next to its code:
//   - .wv/connections.json  the connection profiles and path sequences (chains)
//   - .wv/config.json       defaults, e.g. the ssh_config source and store path
// so `wv` run from a project origin uses that project's connection paths rather
// than the per-user store in ~/.config/weaverssh.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// wvConfig is the optional .wv/config.json.
type wvConfig struct {
	// SSHConfigSource is a config-source spec (see connectionscan: path, -,
	// fd:N, pipe:PATH, exec:CMD) used when no --ssh-config flag / env is set.
	SSHConfigSource string `json:"ssh_config_source,omitempty"`
	// ConnectionsFile overrides where the connection store is read/written.
	ConnectionsFile string `json:"connections_file,omitempty"`
}

// findWVDir returns the nearest .wv directory walking up from the working
// directory, or "" if none. WEAVERSSH_DIR overrides the search.
func findWVDir() string {
	if override := strings.TrimSpace(os.Getenv("WEAVERSSH_DIR")); override != "" {
		if fi, err := os.Stat(override); err == nil && fi.IsDir() {
			return override
		}
		return ""
	}
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		candidate := filepath.Join(dir, ".wv")
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// loadWVConfig reads .wv/config.json if present; a missing or invalid file
// yields the zero value (no error — the .wv dir is optional).
func loadWVConfig() wvConfig {
	dir := findWVDir()
	if dir == "" {
		return wvConfig{}
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return wvConfig{}
	}
	var cfg wvConfig
	_ = json.Unmarshal(data, &cfg)
	return cfg
}

// resolveSSHConfigSpec picks the ssh_config source: an explicit --ssh-config
// flag wins, then $WEAVERSSH_SSH_CONFIG_SOURCE, then the .wv config, else "".
func resolveSSHConfigSpec(flagValue string) string {
	if s := strings.TrimSpace(flagValue); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("WEAVERSSH_SSH_CONFIG_SOURCE")); s != "" {
		return s
	}
	if cfg := loadWVConfig(); strings.TrimSpace(cfg.SSHConfigSource) != "" {
		return cfg.SSHConfigSource
	}
	return ""
}
