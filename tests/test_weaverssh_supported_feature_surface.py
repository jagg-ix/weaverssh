from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SEARCH_ROOTS = [
    "docs",
    "extensions",
    "internal",
    "relay",
    "tests",
    "tools",
    "tunnel",
    "verification",
]
EXCLUDED_PARTS = {
    ".git",
    "node_modules",
    "verification_results",
}
EXCLUDED_FILES = {
    Path("tools/verification/zero_trust_proof_manifest.py"),
}
TEXT_SUFFIXES = {
    ".cfg",
    ".go",
    ".json",
    ".lean",
    ".md",
    ".mmd",
    ".py",
    ".sh",
    ".tla",
    ".ts",
    ".yaml",
    ".yml",
}

REMOVED_LAYER = "l" + "3"
REMOVED_NET = "v" + "pn"
REMOVED_NET_UPPER = REMOVED_NET.upper()
REMOVED_LAYER_UPPER = REMOVED_LAYER.upper()

def _rx(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


FORBIDDEN_PATTERNS = [
    _rx(rf"\bSSHX11{REMOVED_NET_UPPER}[A-Za-z0-9_]*\b"),
    _rx(rf"\b{REMOVED_NET_UPPER}SystemDecomposition\b"),
    _rx(rf"\b{REMOVED_NET_UPPER}BridgeSpec\b"),
    _rx(rf"\b{REMOVED_NET}_gateway\b"),
    _rx(rf"\b{REMOVED_NET}_file\b"),
    _rx(rf"\b{REMOVED_NET}_launcher\b"),
    _rx(rf"\bhop[0-9]+_{REMOVED_NET}_[A-Za-z0-9_]*\b"),
    _rx(rf"\b(assign|verify)_{REMOVED_NET}_[A-Za-z0-9_]*\b"),
    _rx(rf"\bset_{REMOVED_LAYER}_ready\b"),
    _rx(rf"\bstart{REMOVED_LAYER_UPPER}Negotiation\b"),
    _rx(rf"\b{REMOVED_LAYER}NegotiationSucceeded\b"),
    _rx(rf"\b{REMOVED_LAYER}Ready\b"),
    _rx(rf"\b{REMOVED_LAYER}Timeout\b"),
    _rx(rf"\b{REMOVED_LAYER_UPPER}\s*[-/]?\s*{REMOVED_NET_UPPER}\b", re.IGNORECASE),
]


def _candidate_files() -> list[Path]:
    files: list[Path] = []
    for root_name in SEARCH_ROOTS:
        root = REPO_ROOT / root_name
        if not root.exists():
            continue
        for path in root.rglob("*"):
            rel = path.relative_to(REPO_ROOT)
            if not path.is_file():
                continue
            if any(part in EXCLUDED_PARTS for part in rel.parts):
                continue
            if rel in EXCLUDED_FILES:
                continue
            if path.suffix not in TEXT_SUFFIXES:
                continue
            files.append(path)
    return sorted(files)


def test_supported_feature_surface_has_no_removed_transport_terms() -> None:
    matches: list[str] = []
    for path in _candidate_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(REPO_ROOT)
        for line_no, line in enumerate(text.splitlines(), start=1):
            for pattern in FORBIDDEN_PATTERNS:
                if pattern.search(line):
                    matches.append(f"{rel}:{line_no}: {line.strip()}")
                    break
    assert matches == []
