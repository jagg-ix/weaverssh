#!/usr/bin/env python3
from __future__ import annotations

"""Remote host compatibility helpers for non-Linux SSH targets."""

import re
import shlex


SUPPORTED_REMOTE_PLATFORMS: tuple[str, ...] = (
    "auto",
    "linux",  # legacy alias accepted by existing scripts
    "linux-generic",
    "linux-headless",
    "linux-gui",
    "macos",
    "freebsd",  # legacy alias for freebsd-generic
    "freebsd-generic",
    "freebsd-gui",
    "openbsd",
    "aix",
    "solaris",
    "zos",
    "generic",
)
LINUX_REMOTE_PROFILES = frozenset({"linux-generic", "linux-headless", "linux-gui"})
BSD_REMOTE_PROFILES = frozenset({"macos", "freebsd-generic", "freebsd-gui", "openbsd"})
PROBE_TOOLING_MISSING_MARKER = "__SSHX11_PROBE_TOOLING_MISSING__"
LOOPBACK_ASSIGN_UNSUPPORTED_MARKER = "__SSHX11_LOOPBACK_ASSIGN_UNSUPPORTED__"
LOOPBACK_VERIFY_UNSUPPORTED_MARKER = "__SSHX11_LOOPBACK_VERIFY_UNSUPPORTED__"
SHA256_TOOLING_MISSING_MARKER = "__SSHX11_SHA256_TOOLING_MISSING__"


def normalize_remote_platform(value: str | None) -> str:
    raw = str(value or "").strip().lower().replace("_", "-").replace(" ", "-")
    if raw in {"", "auto"}:
        return "auto"
    if raw in {"z/os", "z-os", "zos", "uss"}:
        return "zos"
    if raw in {"sunos", "solaris"}:
        return "solaris"
    if raw in {"aix"}:
        return "aix"
    if raw in {"linux", "linux-generic", "gnu/linux", "generic-linux"}:
        return "linux-generic"
    if raw in {"linux-headless", "headless-linux", "linux-without-gui", "linux-no-gui", "linux-iot", "iot", "embedded", "linux-embedded", "no-gui", "nogui"}:
        return "linux-headless"
    if raw in {"linux-gui", "linux-desktop", "desktop-linux", "gnome", "kde", "x11-linux", "wayland-linux"}:
        return "linux-gui"
    if raw in {"mac", "macos", "osx", "darwin"}:
        return "macos"
    if raw in {"freebsd", "freebsd-generic"}:
        return "freebsd-generic"
    if raw in {"freebsd-gui", "freebsd-desktop", "desktop-freebsd"}:
        return "freebsd-gui"
    if raw in {"openbsd"}:
        return "openbsd"
    if raw in {"generic", "posix", "unix"}:
        return "generic"
    return "auto"


def is_linux_profile(platform: str | None) -> bool:
    return normalize_remote_platform(platform) in LINUX_REMOTE_PROFILES


def is_bsd_profile(platform: str | None) -> bool:
    return normalize_remote_platform(platform) in BSD_REMOTE_PROFILES


def is_gui_profile(platform: str | None) -> bool:
    return normalize_remote_platform(platform) in {"linux-gui", "freebsd-gui", "macos"}


def python_candidates(platform: str, preferred_python: str = "") -> list[str]:
    out: list[str] = []
    pref = str(preferred_python or "").strip()
    if pref:
        out.append(pref)
    # Common bins first.
    out.extend(["python3", "python"])
    platform_norm = normalize_remote_platform(platform)
    if platform_norm == "aix":
        out.extend(
            [
                "/opt/freeware/bin/python3",
                "/usr/bin/python3",
                "/usr/local/bin/python3",
            ]
        )
    elif platform_norm == "macos":
        out.extend(
            [
                "/opt/homebrew/bin/python3",
                "/opt/local/bin/python3",
                "/usr/local/bin/python3",
                "/usr/bin/python3",
            ]
        )
    elif platform_norm in {"freebsd-generic", "freebsd-gui", "openbsd"}:
        out.extend(
            [
                "/usr/local/bin/python3",
                "/usr/bin/python3",
            ]
        )
    elif platform_norm == "solaris":
        out.extend(
            [
                "/usr/bin/python3",
                "/usr/local/bin/python3",
                "/opt/csw/bin/python3",
            ]
        )
    elif platform_norm == "zos":
        out.extend(
            [
                "/usr/lpp/cyp/v3r11/pyz/bin/python3",
                "/usr/lpp/cyp/v3r10/pyz/bin/python3",
                "/usr/lpp/IBM/cyp/v3r12/pyz/bin/python3",
                "/QOpenSys/pkgs/bin/python3",
            ]
        )
    else:
        out.extend(
            [
                "/usr/bin/python3",
                "/usr/local/bin/python3",
                "/QOpenSys/pkgs/bin/python3",
            ]
        )
    dedup: list[str] = []
    seen: set[str] = set()
    for item in out:
        key = str(item).strip()
        if not key or key in seen:
            continue
        seen.add(key)
        dedup.append(key)
    return dedup


def remote_shell_argv(shell_bin: str = "sh", login_shell: bool = True) -> list[str]:
    shell = str(shell_bin or "sh").strip() or "sh"
    return [shell, "-lc" if bool(login_shell) else "-c"]


def build_tcp_probe_command(
    *,
    host: str,
    port: int,
    timeout_s: float,
    platform: str = "auto",
    preferred_python: str = "",
) -> str:
    host_q = shlex.quote(str(host or "127.0.0.1"))
    port_i = int(port)
    timeout_f = max(0.2, float(timeout_s))
    timeout_s_fmt = f"{timeout_f:.2f}"
    py_expr = (
        "import os,socket;"
        "h=os.environ.get('SSHX11_PROBE_HOST','127.0.0.1');"
        "p=int(os.environ.get('SSHX11_PROBE_PORT','0'));"
        "t=max(0.2,float(os.environ.get('SSHX11_PROBE_TIMEOUT','1.0')));"
        "s=socket.socket();"
        "s.settimeout(t);"
        "s.connect((h,p));"
        "s.close()"
    )
    py_q = shlex.quote(py_expr)
    perl_expr = (
        "use strict; use warnings; use Socket;"
        "my $h=$ENV{'SSHX11_PROBE_HOST'}||'127.0.0.1';"
        "my $p=int($ENV{'SSHX11_PROBE_PORT'}||0);"
        "my $t=$ENV{'SSHX11_PROBE_TIMEOUT'}||'1.0';"
        "local $SIG{ALRM}=sub{exit 2};"
        "alarm(int($t>1?$t:1));"
        "socket(my $s, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or exit 1;"
        "my $iaddr = inet_aton($h) or exit 1;"
        "connect($s, sockaddr_in($p, $iaddr)) or exit 1;"
        "close($s);"
        "alarm(0);"
        "exit 0;"
    )
    perl_q = shlex.quote(perl_expr)
    candidates = python_candidates(platform, preferred_python)
    py_bins = " ".join(shlex.quote(x) for x in candidates)
    marker_q = shlex.quote(PROBE_TOOLING_MISSING_MARKER)
    parts = [
        f"SSHX11_PROBE_HOST={host_q}",
        f"SSHX11_PROBE_PORT={port_i}",
        f"SSHX11_PROBE_TIMEOUT={timeout_s_fmt}",
        (
            f"for py in {py_bins}; do "
            "if command -v \"$py\" >/dev/null 2>&1 || [ -x \"$py\" ]; then "
            "\"$py\" -c "
            f"{py_q} "
            ">/dev/null 2>&1 && exit 0; "
            "fi; "
            "done"
        ),
        (
            "if command -v perl >/dev/null 2>&1; then "
            "perl -e "
            f"{perl_q} "
            ">/dev/null 2>&1 && exit 0; "
            "fi"
        ),
        (
            "if command -v nc >/dev/null 2>&1; then "
            "nc -z \"$SSHX11_PROBE_HOST\" \"$SSHX11_PROBE_PORT\" >/dev/null 2>&1 && exit 0; "
            "nc -z -w 2 \"$SSHX11_PROBE_HOST\" \"$SSHX11_PROBE_PORT\" >/dev/null 2>&1 && exit 0; "
            "fi"
        ),
        (
            "if command -v netcat >/dev/null 2>&1; then "
            "netcat -z \"$SSHX11_PROBE_HOST\" \"$SSHX11_PROBE_PORT\" >/dev/null 2>&1 && exit 0; "
            "fi"
        ),
        (
            "if command -v ksh >/dev/null 2>&1; then "
            "ksh -c \"exec 3<>/dev/tcp/$SSHX11_PROBE_HOST/$SSHX11_PROBE_PORT\" >/dev/null 2>&1 && exit 0; "
            "fi"
        ),
        f"echo {marker_q}",
        "exit 127",
    ]
    return "; ".join(parts)


def probe_tooling_missing(stdout: str, stderr: str) -> bool:
    merged = f"{stdout or ''}\n{stderr or ''}".lower()
    if PROBE_TOOLING_MISSING_MARKER.lower() in merged:
        return True
    # Legacy fallback heuristic.
    return ("python3" in merged and "not found" in merged and "nc" in merged and "not found" in merged)


def has_marker(marker: str, stdout: str, stderr: str) -> bool:
    merged = f"{stdout or ''}\n{stderr or ''}"
    return str(marker or "").strip() in merged


def build_loopback_assign_command(ip_addr: str, platform: str = "auto") -> str:
    ip_q = shlex.quote(str(ip_addr))
    platform_norm = normalize_remote_platform(platform)
    marker_q = shlex.quote(LOOPBACK_ASSIGN_UNSUPPORTED_MARKER)
    parts = [f"SSHX11_LOOPBACK_IP={ip_q}"]
    if platform_norm in {"auto", "generic"} or platform_norm in LINUX_REMOTE_PROFILES:
        parts.append(
            "if command -v ip >/dev/null 2>&1; then "
            "ip -4 addr show dev lo | grep -Fq \"$SSHX11_LOOPBACK_IP/32\" "
            "|| ip -4 addr add \"$SSHX11_LOOPBACK_IP/32\" dev lo || true; "
            "ip -4 addr show dev lo | grep -Fq \"$SSHX11_LOOPBACK_IP/32\" && exit 0; "
            "fi"
        )
    if platform_norm in {"auto", "aix", "generic"} or platform_norm in BSD_REMOTE_PROFILES:
        parts.append(
            "if command -v ifconfig >/dev/null 2>&1; then "
            "ifconfig lo0 | grep -Fq \"$SSHX11_LOOPBACK_IP\" "
            "|| ifconfig lo0 alias \"$SSHX11_LOOPBACK_IP\" netmask 255.255.255.255 up || true; "
            "ifconfig lo0 | grep -Fq \"$SSHX11_LOOPBACK_IP\" && exit 0; "
            "fi"
        )
    if platform_norm in {"auto", "solaris", "generic"}:
        parts.append(
            "if command -v ipadm >/dev/null 2>&1; then "
            "ipadm show-addr -p -o ADDR 2>/dev/null | grep -Fq \"$SSHX11_LOOPBACK_IP/32\" "
            "|| ipadm create-addr -t -T static -a \"$SSHX11_LOOPBACK_IP/32\" lo0/sshx11backhaul >/dev/null 2>&1 "
            "|| ipadm up-addr lo0/sshx11backhaul >/dev/null 2>&1; "
            "ipadm show-addr -p -o ADDR 2>/dev/null | grep -Fq \"$SSHX11_LOOPBACK_IP/32\" && exit 0; "
            "fi; "
            "if command -v ifconfig >/dev/null 2>&1; then "
            "ifconfig lo0 | grep -Fq \"$SSHX11_LOOPBACK_IP\" "
            "|| ifconfig lo0 addif \"$SSHX11_LOOPBACK_IP/32\" up >/dev/null 2>&1 "
            "|| ifconfig lo0:1 plumb \"$SSHX11_LOOPBACK_IP\" netmask 255.255.255.255 up >/dev/null 2>&1; "
            "ifconfig lo0 | grep -Fq \"$SSHX11_LOOPBACK_IP\" && exit 0; "
            "fi"
        )
    if platform_norm in {"auto", "zos", "generic"}:
        parts.append(
            "if command -v ifconfig >/dev/null 2>&1; then "
            "ifconfig lo0 | grep -Fq \"$SSHX11_LOOPBACK_IP\" "
            "|| ifconfig lo0 alias \"$SSHX11_LOOPBACK_IP\" netmask 255.255.255.255 up >/dev/null 2>&1; "
            "ifconfig lo0 | grep -Fq \"$SSHX11_LOOPBACK_IP\" && exit 0; "
            "fi"
        )
    parts.append(f"echo {marker_q}")
    parts.append("exit 127")
    return "; ".join(parts)


def build_loopback_verify_command(ip_addr: str, platform: str = "auto") -> str:
    ip_q = shlex.quote(str(ip_addr))
    platform_norm = normalize_remote_platform(platform)
    marker_q = shlex.quote(LOOPBACK_VERIFY_UNSUPPORTED_MARKER)
    parts = [f"SSHX11_LOOPBACK_IP={ip_q}"]
    if platform_norm in {"auto", "generic"} or platform_norm in LINUX_REMOTE_PROFILES:
        parts.append(
            "if command -v ip >/dev/null 2>&1; then "
            "ip -4 addr show dev lo | grep -F \"$SSHX11_LOOPBACK_IP/32\" >/dev/null 2>&1 && exit 0; "
            "fi"
        )
    if platform_norm in {"auto", "aix", "solaris", "zos", "generic"} or platform_norm in BSD_REMOTE_PROFILES:
        parts.append(
            "if command -v ifconfig >/dev/null 2>&1; then "
            "ifconfig lo0 | grep -F \"$SSHX11_LOOPBACK_IP\" >/dev/null 2>&1 && exit 0; "
            "fi"
        )
    if platform_norm in {"auto", "solaris", "generic"}:
        parts.append(
            "if command -v ipadm >/dev/null 2>&1; then "
            "ipadm show-addr -p -o ADDR 2>/dev/null | grep -F \"$SSHX11_LOOPBACK_IP/32\" >/dev/null 2>&1 && exit 0; "
            "fi"
        )
    parts.append(f"echo {marker_q}")
    parts.append("exit 127")
    return "; ".join(parts)


def build_sha256_command(file_path: str, platform: str = "auto", preferred_python: str = "") -> str:
    file_q = shlex.quote(str(file_path))
    marker_q = shlex.quote(SHA256_TOOLING_MISSING_MARKER)
    py_expr = (
        "import hashlib,sys;"
        "p=sys.argv[1];"
        "h=hashlib.sha256();"
        "f=open(p,'rb');"
        "h.update(f.read());"
        "f.close();"
        "print(h.hexdigest())"
    )
    py_q = shlex.quote(py_expr)
    candidates = python_candidates(platform, preferred_python)
    py_bins = " ".join(shlex.quote(x) for x in candidates)
    parts = [
        f"SSHX11_SHA_FILE={file_q}",
        (
            f"for py in {py_bins}; do "
            "if command -v \"$py\" >/dev/null 2>&1 || [ -x \"$py\" ]; then "
            "\"$py\" -c "
            f"{py_q} "
            "\"$SSHX11_SHA_FILE\" && exit 0; "
            "fi; "
            "done"
        ),
        "if command -v sha256sum >/dev/null 2>&1; then sha256sum \"$SSHX11_SHA_FILE\" | awk '{print $1}'; exit 0; fi",
        "if command -v shasum >/dev/null 2>&1; then shasum -a 256 \"$SSHX11_SHA_FILE\" | awk '{print $1}'; exit 0; fi",
        "if command -v digest >/dev/null 2>&1; then digest -a sha256 \"$SSHX11_SHA_FILE\" | awk '{print $1}'; exit 0; fi",
        "if command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 \"$SSHX11_SHA_FILE\" | awk '{print $NF}'; exit 0; fi",
        f"echo {marker_q}",
        "exit 127",
    ]
    return "; ".join(parts)


def extract_sha256(text: str) -> str:
    m = re.search(r"\b([0-9a-fA-F]{64})\b", str(text or ""))
    if not m:
        return ""
    return str(m.group(1)).lower()
