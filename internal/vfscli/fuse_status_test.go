package vfscli

import (
	"os"
	"strings"
	"testing"

	"weaverssh/wverrors"
)

func fakeFuseEnv(goos string, paths []string, helpers map[string]string) fuseProbeEnv {
	existing := map[string]bool{}
	for _, p := range paths {
		existing[p] = true
	}
	return fuseProbeEnv{
		goos: goos,
		stat: func(path string) error {
			if existing[path] {
				return nil
			}
			return os.ErrNotExist
		},
		lookPath: func(name string) (string, error) {
			if p, ok := helpers[name]; ok {
				return p, nil
			}
			return "", os.ErrNotExist
		},
	}
}

func TestProbeLinuxFUSEEnabled(t *testing.T) {
	status := probeFUSEStatus(fakeFuseEnv("linux", []string{"/dev/fuse"}, map[string]string{
		"fusermount3": "/usr/bin/fusermount3",
	}))
	if !status.Supported || !status.Enabled {
		t.Fatalf("expected Linux FUSE enabled: %+v", status)
	}
	if status.Provider != "libfuse/kernel-fuse" || len(status.Helpers) != 1 {
		t.Fatalf("provider/helpers wrong: %+v", status)
	}
	if err := status.PreflightError(); err != nil {
		t.Fatalf("enabled status should pass preflight: %v", err)
	}
}

func TestProbeLinuxFUSEMissingDeviceUnderWSL(t *testing.T) {
	env := fakeFuseEnv("linux", nil, map[string]string{"fusermount3": "/usr/bin/fusermount3"})
	env.isWSL = true
	status := probeFUSEStatus(env)
	if !status.Supported || status.Enabled {
		t.Fatalf("expected supported but disabled under WSL: %+v", status)
	}
	if !strings.Contains(status.Reason, "WSL") || !strings.Contains(status.NextAction, "WSL2") {
		t.Fatalf("expected WSL-specific guidance: %+v", status)
	}
}

func TestProbeLinuxFUSEMissingHelper(t *testing.T) {
	status := probeFUSEStatus(fakeFuseEnv("linux", []string{"/dev/fuse"}, nil))
	if status.Enabled {
		t.Fatalf("expected disabled when fusermount helper is missing: %+v", status)
	}
	if !strings.Contains(status.Reason, "fusermount helper") {
		t.Fatalf("expected helper-specific reason: %+v", status)
	}
	if err := status.PreflightError(); err == nil || !strings.Contains(err.Error(), "Install fuse3") {
		t.Fatalf("expected actionable preflight error, got %v", err)
	}
}

func TestProbeDarwinFUSEEnabledFromMacFUSEPath(t *testing.T) {
	status := probeFUSEStatus(fakeFuseEnv("darwin", []string{"/Library/Filesystems/macfuse.fs"}, nil))
	if !status.Supported || !status.Enabled {
		t.Fatalf("expected macFUSE enabled from filesystem marker: %+v", status)
	}
	if status.Provider != "macFUSE" || status.Device == "" {
		t.Fatalf("macFUSE provider/device wrong: %+v", status)
	}
}

func TestProbeUnsupportedOS(t *testing.T) {
	status := probeFUSEStatus(fakeFuseEnv("windows", nil, nil))
	if status.Supported || status.Enabled {
		t.Fatalf("expected unsupported FUSE status: %+v", status)
	}
	if !strings.Contains(status.NextAction, "WSL2") {
		t.Fatalf("expected WSL2 guidance for unsupported OS: %+v", status)
	}
}

func TestFUSEPreflightErrorCarriesStableCode(t *testing.T) {
	status := probeFUSEStatus(fakeFuseEnv("linux", []string{"/dev/fuse"}, nil))
	err := status.PreflightError()
	if !wverrors.IsCode(err, wverrors.CodeFuseUnavailable) {
		t.Fatalf("expected FUSE unavailable code, got %v", err)
	}
}
