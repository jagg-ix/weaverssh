package vfs

import (
	"encoding/hex"
	"net"
	"os"
	"strings"
)

// WSL support: inside WSL2 the loopback address reaches the WSL distro, not the
// Windows host, so a 9P service published by a *Windows* weaverssh must be
// reached at the Windows host IP. The endpoint sentinels "windows-host" and
// "wsl-host" resolve to that address; IsWSL gates WSL-specific guidance.

// HostSentinels are endpoint hostnames that resolve to the Windows host when
// running inside WSL (e.g. WEAVERSSH_VFS_ENDPOINT=windows-host:5640).
var HostSentinels = []string{"windows-host", "wsl-host"}

// IsWSL reports whether the process is running inside WSL (1 or 2).
func IsWSL() bool {
	for _, p := range []string{"/proc/sys/kernel/osrelease", "/proc/version"} {
		if b, err := os.ReadFile(p); err == nil && detectWSL(string(b)) {
			return true
		}
	}
	return false
}

func detectWSL(osrelease string) bool {
	l := strings.ToLower(osrelease)
	return strings.Contains(l, "microsoft") || strings.Contains(l, "wsl")
}

// WindowsHostIP resolves the Windows host address as seen from inside WSL,
// trying the WSL-generated resolv.conf nameserver first, then the default
// gateway in /proc/net/route. Returns "" if it cannot be determined (e.g. WSL
// mirrored-networking mode, where 127.0.0.1 already reaches the host).
func WindowsHostIP() string {
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		if ip := parseResolvNameserver(string(b)); ip != "" {
			return ip
		}
	}
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		if ip := parseDefaultGatewayProcRoute(string(b)); ip != "" {
			return ip
		}
	}
	return ""
}

func parseResolvNameserver(content string) string {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ip := net.ParseIP(fields[1]); ip != nil && ip.To4() != nil {
				return fields[1]
			}
		}
	}
	return ""
}

// parseDefaultGatewayProcRoute reads the IPv4 default gateway from the kernel
// route table (/proc/net/route). The Gateway column is a little-endian hex IP
// on the row whose Destination is 00000000.
func parseDefaultGatewayProcRoute(content string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		// /proc/net/route stores the gateway little-endian, so the decoded
		// bytes are the reverse of the dotted-quad octets.
		ip := net.IPv4(raw[3], raw[2], raw[1], raw[0])
		if !ip.Equal(net.IPv4zero) {
			return ip.String()
		}
	}
	return ""
}

// resolveSentinel rewrites the host part of addr ("host:port") when it is a WSL
// host sentinel, leaving everything else untouched.
func resolveSentinel(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if !isSentinel(host) {
		return addr
	}
	if ip := WindowsHostIP(); ip != "" {
		return net.JoinHostPort(ip, port)
	}
	// Mirrored networking (or undeterminable): loopback reaches the host.
	return net.JoinHostPort("127.0.0.1", port)
}

func isSentinel(host string) bool {
	for _, s := range HostSentinels {
		if strings.EqualFold(host, s) {
			return true
		}
	}
	return false
}
