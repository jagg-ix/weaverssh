package app

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// sessionXAuthority is an isolated authority database used only by one
// session-host process and the SSH client it launches.
type sessionXAuthority struct {
	Path    string
	Display string
	Cookie  string
	xauth   string
}

func createSessionXAuthority(display string) (*sessionXAuthority, error) {
	xauth, err := findXAuthCommand()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "weaverssh-xauth-")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "Xauthority")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	cookie := hex.EncodeToString(raw)
	cmd := exec.Command(xauth, "-f", path, "add", display, "MIT-MAGIC-COOKIE-1", cookie)
	if output, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("session-host: xauth add: %w: %s", err, string(output))
	}
	return &sessionXAuthority{Path: path, Display: display, Cookie: cookie, xauth: xauth}, nil
}

func (a *sessionXAuthority) Close() error {
	if a == nil || a.Path == "" {
		return nil
	}
	return os.RemoveAll(filepath.Dir(a.Path))
}

func findXAuthCommand() (string, error) {
	candidates := []string{"xauth", "/opt/X11/bin/xauth", "/usr/bin/xauth", "/usr/X11R6/bin/xauth"}
	for _, candidate := range candidates {
		if filepath.IsAbs(candidate) {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
			continue
		}
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("session-host: xauth command not found")
}
