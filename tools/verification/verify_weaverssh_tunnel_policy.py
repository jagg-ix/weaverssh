#!/usr/bin/env python3
"""Guard weaverssh's canonical tunnel mechanism.

The project data plane is implemented by the produced weaverssh binaries
(`wv`, `wv-server`, `wv-agent`, `wv-socks`). Plink/Pageant support is allowed as
an SSH authentication/session-launch adapter only. This verifier prevents future
changes from documenting or implementing Plink reverse forwarding as the primary
X11/WebSocket tunnel.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]

SKIP_DIRS = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "artifacts",
    "verification_results",
}

TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".go",
    ".json",
    ".md",
    ".mmd",
    ".py",
    ".sh",
    ".tla",
    ".toml",
    ".ts",
    ".txt",
    ".yaml",
    ".yml",
}

PLINK_REVERSE_RE = re.compile(r"\bplink(?:\.exe)?\b[^\n#]*\s-R(?:\s|=|$)", re.IGNORECASE)
RAW_REVERSE_RE = re.compile(r"\bssh\b[^\n#]*\s-R(?:\s|=|$)", re.IGNORECASE)
PRIMARY_TUNNEL_LANGUAGE_RE = re.compile(
    r"\b(primary|main|canonical|compatibility|recommended|default)\b.*\b(tunnel|data[- ]plane|x11|websocket|forwarding)\b"
    r"|\b(tunnel|data[- ]plane|x11|websocket|forwarding)\b.*\b(primary|main|canonical|compatibility|recommended|default)\b",
    re.IGNORECASE,
)
POLICY_SELF_REFERENCE_PATHS = {
    Path("docs/specs/tunnel_mechanism_policy.md"),
    Path("tools/verification/verify_weaverssh_tunnel_policy.py"),
    Path("tests/test_weaverssh_tunnel_policy.py"),
}

REQUIRED_POLICY_TERMS = (
    "Windows workstation",
    "Linux headless / IoT / embedded",
    "Linux generic",
    "Linux GUI: KDE, GNOME, and other desktops",
    "macOS workstation",
    "FreeBSD GUI",
    "FreeBSD generic",
    "OpenBSD",
    "Dropbear",
    "XQuartz",
    "KWallet",
    "GNOME Keyring",
    "They must not replace the weaverssh X11/WebSocket data plane.",
    "policy-gated native SSH forwarding adapter",
    "ssh -L",
    "ssh -R",
    "ssh -D",
    "sshOnly",
    "trusted-peer authproof",
    "explicit chain",
)

ALLOWED_RAW_REVERSE_CONTEXTS = (
    "reverse-socks",
    "reverse_socks",
    "backhaul",
    "internal-sftp -R",
    "repo-managed",
    "managed reverse",
    "policy-gated native ssh forwarding adapter",
    "auxiliary native forwarding adapter",
    "native ssh forwarding adapter",
)


@dataclass(frozen=True)
class Finding:
    path: Path
    line_no: int
    reason: str
    line: str

    def render(self, root: Path) -> str:
        rel = self.path.relative_to(root)
        return f"{rel}:{self.line_no}: {self.reason}: {self.line.strip()}"


def iter_repo_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.suffix not in TEXT_SUFFIXES:
            continue
        yield path


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")


def line_window(lines: list[str], idx: int, radius: int = 2) -> str:
    start = max(0, idx - radius)
    end = min(len(lines), idx + radius + 1)
    return "\n".join(lines[start:end])


def raw_reverse_is_allowed(context: str) -> bool:
    lowered = context.lower()
    return any(marker in lowered for marker in ALLOWED_RAW_REVERSE_CONTEXTS)


def scan_file(path: Path, root: Path) -> list[Finding]:
    text = read_text(path)
    lines = text.splitlines()
    findings: list[Finding] = []

    for idx, line in enumerate(lines):
        if PLINK_REVERSE_RE.search(line):
            findings.append(
                Finding(
                    path=path,
                    line_no=idx + 1,
                    reason="Plink reverse forwarding must not be the weaverssh tunnel mechanism",
                    line=line,
                )
            )
            continue

        if RAW_REVERSE_RE.search(line):
            context = line_window(lines, idx)
            if not raw_reverse_is_allowed(context):
                findings.append(
                    Finding(
                        path=path,
                        line_no=idx + 1,
                        reason="raw ssh reverse forwarding requires managed reverse-socks/backhaul context",
                        line=line,
                    )
                )
            elif PRIMARY_TUNNEL_LANGUAGE_RE.search(context):
                findings.append(
                    Finding(
                        path=path,
                        line_no=idx + 1,
                        reason="managed reverse forwarding must not be described as primary X11/WebSocket data plane",
                        line=line,
                    )
                )

    rel_path = path.relative_to(root)
    if rel_path not in POLICY_SELF_REFERENCE_PATHS:
        if PRIMARY_TUNNEL_LANGUAGE_RE.search(text) and "plink" in text.lower():
            for idx, line in enumerate(lines):
                if "plink" in line.lower() and PRIMARY_TUNNEL_LANGUAGE_RE.search(line_window(lines, idx)):
                    findings.append(
                        Finding(
                            path=path,
                            line_no=idx + 1,
                            reason="Plink/Pageant must be documented only as SSH launcher/auth compatibility",
                            line=line,
                        )
                    )

    return findings


def check_policy_doc(root: Path) -> list[str]:
    policy = root / "docs" / "specs" / "tunnel_mechanism_policy.md"
    if not policy.exists():
        return ["missing docs/specs/tunnel_mechanism_policy.md"]
    text = read_text(policy)
    errors: list[str] = []
    for required in ("wv", "wv-server", "wv-agent", "wv-socks", "Pageant", "Plink") + REQUIRED_POLICY_TERMS:
        if required not in text:
            errors.append(f"policy doc missing required term: {required}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args()

    root = args.repo_root.resolve()
    findings: list[Finding] = []
    for path in iter_repo_files(root):
        findings.extend(scan_file(path, root))

    policy_errors = check_policy_doc(root)

    if findings or policy_errors:
        for finding in findings:
            print(finding.render(root), file=sys.stderr)
        for error in policy_errors:
            print(f"policy: {error}", file=sys.stderr)
        print(
            "\nTunnel policy failed: use wv/wv-server/wv-agent/wv-socks for the "
            "weaverssh data plane; keep SSH clients, agents, keyrings, and service managers as launcher/auth adapters only.",
            file=sys.stderr,
        )
        return 1

    print("weaverssh tunnel policy verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
