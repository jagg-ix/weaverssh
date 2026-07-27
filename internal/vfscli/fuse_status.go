package vfscli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"weaverssh/internal/vfs"
	"weaverssh/wverrors"
)

// FUSEStatus describes whether the current host can mount vfs:// as a real
// filesystem. Supported means the weaverssh build/OS has a mount implementation;
// enabled means the local runtime prerequisites are present.
type FUSEStatus struct {
	Supported  bool     `json:"supported"`
	Enabled    bool     `json:"enabled"`
	OS         string   `json:"os"`
	Provider   string   `json:"provider"`
	Device     string   `json:"device,omitempty"`
	Helpers    []string `json:"helpers,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	NextAction string   `json:"next_action,omitempty"`
}

type fuseProbeEnv struct {
	goos     string
	isWSL    bool
	stat     func(string) error
	lookPath func(string) (string, error)
}

func currentFUSEStatus() FUSEStatus {
	env := fuseProbeEnv{
		goos:  runtime.GOOS,
		isWSL: runtime.GOOS == "linux" && vfs.IsWSL(),
		stat: func(path string) error {
			_, err := os.Stat(path)
			return err
		},
		lookPath: exec.LookPath,
	}
	return probeFUSEStatus(env)
}

func probeFUSEStatus(env fuseProbeEnv) FUSEStatus {
	switch env.goos {
	case "linux":
		return probeLinuxFUSEStatus(env)
	case "darwin":
		return probeDarwinFUSEStatus(env)
	default:
		return FUSEStatus{
			Supported:  false,
			Enabled:    false,
			OS:         env.goos,
			Provider:   "unsupported",
			Reason:     "FUSE mounting is only implemented on Linux and macOS",
			NextAction: "Use vfs:// commands directly, sshfs where available, WSL2, or a Linux/macOS host for FUSE mounts.",
		}
	}
}

func probeLinuxFUSEStatus(env fuseProbeEnv) FUSEStatus {
	helpers := existingHelpers(env, "fusermount3", "fusermount")
	deviceOK := env.stat("/dev/fuse") == nil
	status := FUSEStatus{
		Supported: true,
		Enabled:   deviceOK && len(helpers) > 0,
		OS:        env.goos,
		Provider:  "libfuse/kernel-fuse",
		Device:    "/dev/fuse",
		Helpers:   helpers,
	}
	switch {
	case status.Enabled:
		status.Reason = "kernel FUSE device and unprivileged mount helper are available"
	case !deviceOK && env.isWSL:
		status.Reason = "/dev/fuse is missing under WSL"
		status.NextAction = "Use WSL2 with FUSE enabled; WSL1 cannot mount FUSE. vfs:// copy/list commands still work without a mount."
	case !deviceOK:
		status.Reason = "/dev/fuse is missing"
		status.NextAction = "Load the fuse kernel module or install/enable the distro FUSE package. vfs:// copy/list commands still work without a mount."
	default:
		status.Reason = "fusermount helper is missing"
		status.NextAction = "Install fuse3 or fuse so fusermount3/fusermount is on PATH. vfs:// copy/list commands still work without a mount."
	}
	return status
}

func probeDarwinFUSEStatus(env fuseProbeEnv) FUSEStatus {
	helpers := existingHelpers(env, "mount_macfuse", "mount_osxfuse", "mount_fusefs")
	candidates := []string{
		"/dev/macfuse0",
		"/dev/osxfuse0",
		"/Library/Filesystems/macfuse.fs",
		"/Library/Filesystems/osxfuse.fs",
	}
	device := ""
	for _, candidate := range candidates {
		if env.stat(candidate) == nil {
			device = candidate
			break
		}
	}
	enabled := device != "" || len(helpers) > 0
	status := FUSEStatus{
		Supported: true,
		Enabled:   enabled,
		OS:        env.goos,
		Provider:  "macFUSE",
		Device:    device,
		Helpers:   helpers,
	}
	if enabled {
		status.Reason = "macFUSE indicators are present; macOS may still require System Settings approval before the first mount"
		status.NextAction = "If mounting fails, approve macFUSE in System Settings and retry."
	} else {
		status.Reason = "macFUSE is not detected"
		status.NextAction = "Install macFUSE, approve it in System Settings if prompted, then retry the mount. vfs:// copy/list commands still work without a mount."
	}
	return status
}

func existingHelpers(env fuseProbeEnv, names ...string) []string {
	var found []string
	for _, name := range names {
		if path, err := env.lookPath(name); err == nil && strings.TrimSpace(path) != "" {
			found = append(found, path)
		}
	}
	return found
}

func (s FUSEStatus) Summary() string {
	return fmt.Sprintf("supported=%t enabled=%t provider=%s", s.Supported, s.Enabled, s.Provider)
}

func (s FUSEStatus) PreflightError() error {
	if s.Enabled {
		return nil
	}
	message := s.Reason
	if s.NextAction != "" {
		message = fmt.Sprintf("%s: %s", s.Reason, s.NextAction)
	}
	return wverrors.New(wverrors.CodeFuseUnavailable, "vfs", "fuse_preflight", message).
		WithField("os", s.OS).
		WithField("provider", s.Provider)
}

func (s FUSEStatus) JSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}
