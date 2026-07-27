package connectionscan

// The PuTTY registry/session readers are PowerShell scripts embedded in the wv
// binary. When a scan needs one (Windows, or WEAVERSSH_ENABLE_PUTTY_SCAN), it is
// written to a per-user temp file once and reused, so wv ships no loose assets.

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"os"
	"path/filepath"
)

//go:embed scripts/*.ps1
var embeddedScripts embed.FS

// materializeEmbeddedScript writes the named embedded script to a stable temp
// path and returns it, or "" if the script is unknown or cannot be written.
func materializeEmbeddedScript(name string) string {
	data, err := embeddedScripts.ReadFile("scripts/" + name)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	dir := filepath.Join(os.TempDir(), "weaverssh-connectionscan")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ""
	}
	// Content-addressed name so a stale copy is never reused after an upgrade.
	dst := filepath.Join(dir, hex.EncodeToString(sum[:6])+"-"+name)
	if pathExists(dst) {
		return dst
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return ""
	}
	return dst
}
