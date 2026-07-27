package contract

import (
	"errors"
	"strings"
)

func NormalizeRemotePlatform(value string) string {
	raw := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(strings.ToLower(value)), "_", "-"), " ", "-")
	switch raw {
	case "", "auto":
		return "auto"
	case "z/os", "z-os", "zos", "uss":
		return "zos"
	case "sunos", "solaris":
		return "solaris"
	case "aix":
		return "aix"
	case "linux", "linux-generic", "gnu/linux", "generic-linux":
		return "linux-generic"
	case "linux-headless", "headless-linux", "linux-without-gui", "linux-no-gui", "linux-iot", "iot", "embedded", "linux-embedded", "no-gui", "nogui":
		return "linux-headless"
	case "linux-gui", "linux-desktop", "desktop-linux", "gnome", "kde", "x11-linux", "wayland-linux":
		return "linux-gui"
	case "mac", "macos", "osx", "darwin":
		return "macos"
	case "freebsd", "freebsd-generic":
		return "freebsd-generic"
	case "freebsd-gui", "freebsd-desktop", "desktop-freebsd":
		return "freebsd-gui"
	case "openbsd":
		return "openbsd"
	case "generic", "posix", "unix":
		return "generic"
	default:
		return "auto"
	}
}

func ParseHostSpec(hostSpec string) (label string, host string, err error) {
	token := strings.TrimSpace(hostSpec)
	if token == "" {
		return "", "", errors.New("missing_host")
	}
	if strings.Contains(token, "=") {
		parts := strings.SplitN(token, "=", 2)
		label = strings.TrimSpace(parts[0])
		host = strings.TrimSpace(parts[1])
		if host == "" {
			return "", "", errors.New("missing_host")
		}
		if label == "" {
			label = host
		}
		return label, host, nil
	}
	return token, token, nil
}

func NormalizeUser(user string) string {
	token := strings.TrimSpace(user)
	if token == "" {
		return "root"
	}
	return token
}

func BuildTarget(user string, host string) (string, error) {
	u := NormalizeUser(user)
	h := strings.TrimSpace(host)
	if h == "" {
		return "", errors.New("missing_host")
	}
	return u + "@" + h, nil
}
