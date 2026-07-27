#!/usr/bin/env python3
from __future__ import annotations

"""Sync SSH agent public keys into Linode account sshkeys."""

import argparse
from pathlib import Path
import hashlib
import json
import subprocess
import sys
from typing import Any


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True)


def _normalize_pubkey(key: str) -> str:
    parts = key.strip().split()
    if len(parts) < 2:
        return ""
    return f"{parts[0]} {parts[1]}"


def _agent_keys() -> list[str]:
    proc = _run(["ssh-add", "-L"])
    if proc.returncode != 0:
        raise RuntimeError(f"ssh-add -L failed: {proc.stderr.strip() or proc.stdout.strip()}")
    out = proc.stdout.strip()
    if not out or "The agent has no identities." in out:
        return []
    keys = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        norm = _normalize_pubkey(line)
        if norm:
            keys.append(line)
    return keys


def _keys_from_pubfiles(paths: list[str]) -> list[str]:
    keys: list[str] = []
    for p in paths:
        path = Path(p).expanduser()
        if not path.exists() or not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            norm = _normalize_pubkey(line)
            if norm:
                keys.append(line)
    return keys


def _discover_default_pubkeys() -> list[str]:
    ssh_dir = Path("~/.ssh").expanduser()
    if not ssh_dir.exists():
        return []
    return [str(p) for p in sorted(ssh_dir.glob("*.pub")) if p.is_file()]


def _dedupe_by_norm(keys: list[str]) -> list[str]:
    seen = set()
    out: list[str] = []
    for key in keys:
        norm = _normalize_pubkey(key)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        out.append(key)
    return out


def _linode_sshkeys_list(linode_cli: str) -> list[dict[str, Any]]:
    proc = _run([linode_cli, "--suppress-warnings", "--json", "sshkeys", "list"])
    if proc.returncode != 0:
        msg = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(f"linode-cli sshkeys list failed: {msg}")
    payload = json.loads(proc.stdout or "[]")
    if isinstance(payload, dict) and isinstance(payload.get("data"), list):
        return payload["data"]
    if isinstance(payload, list):
        return payload
    return []


def _missing_agent_keys(
    agent_keys: list[str],
    linode_keys: list[dict[str, Any]],
    label_prefix: str,
) -> list[dict[str, str]]:
    existing_norm = set()
    for entry in linode_keys:
        ssh_key = str(entry.get("ssh_key", "")).strip()
        norm = _normalize_pubkey(ssh_key)
        if norm:
            existing_norm.add(norm)

    missing: list[dict[str, str]] = []
    for key in agent_keys:
        norm = _normalize_pubkey(key)
        if not norm or norm in existing_norm:
            continue
        digest = hashlib.sha256(norm.encode("utf-8")).hexdigest()[:12]
        label = f"{label_prefix}-{digest}"
        missing.append({"label": label, "ssh_key": key})
        existing_norm.add(norm)
    return missing


def _create_sshkey(linode_cli: str, label: str, ssh_key: str) -> dict[str, Any]:
    proc = _run(
        [
            linode_cli,
            "--suppress-warnings",
            "--json",
            "sshkeys",
            "create",
            "--label",
            label,
            "--ssh_key",
            ssh_key,
        ]
    )
    if proc.returncode != 0:
        msg = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(f"create failed for {label}: {msg}")
    payload = json.loads(proc.stdout or "[]")
    if isinstance(payload, list) and payload:
        return dict(payload[0])
    if isinstance(payload, dict):
        return payload
    return {"label": label}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--linode-cli", default="linode-cli")
    p.add_argument("--label-prefix", default="agent-key")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument(
        "--public-key-file",
        action="append",
        default=[],
        help="Read one or more public keys from file(s). Can be repeated.",
    )
    p.add_argument(
        "--public-key",
        action="append",
        default=[],
        help="Pass one or more public key strings directly. Can be repeated.",
    )
    p.add_argument(
        "--fallback-ssh-dir",
        action="store_true",
        help="Fallback to ~/.ssh/*.pub when ssh-add is unavailable.",
    )
    p.add_argument("--output-json", default="")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    result: dict[str, Any] = {
        "ok": False,
        "linode_cli": args.linode_cli,
        "label_prefix": args.label_prefix,
        "dry_run": bool(args.dry_run),
        "agent_key_count": 0,
        "linode_key_count": 0,
        "missing_count": 0,
        "created_count": 0,
        "missing": [],
        "created": [],
    }
    try:
        agent_keys: list[str] = []
        source = "ssh-agent"

        if args.public_key:
            agent_keys.extend([str(x).strip() for x in args.public_key if str(x).strip()])
            source = "arg-public-key"

        if args.public_key_file:
            agent_keys.extend(_keys_from_pubfiles([str(x) for x in args.public_key_file]))
            source = "arg-public-key-file"

        if not agent_keys:
            try:
                agent_keys = _agent_keys()
                source = "ssh-agent"
            except Exception:
                if args.fallback_ssh_dir:
                    agent_keys = _keys_from_pubfiles(_discover_default_pubkeys())
                    source = "fallback-ssh-dir"
                else:
                    raise

        agent_keys = _dedupe_by_norm(agent_keys)
        result["key_source"] = source
        result["agent_key_count"] = len(agent_keys)

        linode_keys = _linode_sshkeys_list(args.linode_cli)
        missing = _missing_agent_keys(agent_keys, linode_keys, args.label_prefix)

        result["linode_key_count"] = len(linode_keys)
        result["missing_count"] = len(missing)
        result["missing"] = missing

        if not args.dry_run:
            created = []
            for entry in missing:
                created.append(_create_sshkey(args.linode_cli, entry["label"], entry["ssh_key"]))
            result["created"] = created
            result["created_count"] = len(created)

        result["ok"] = True
    except Exception as exc:  # pragma: no cover - defensive path
        msg = str(exc)
        result["error"] = msg
        if "EOFError" in msg or "linode-cli configure" in msg:
            result["hint"] = "Run interactive Linode auth first: source ~/.zshrc && linode-cli configure"

    payload = json.dumps(result, indent=2) + "\n"
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            f.write(payload)
    print(payload, end="")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
