#!/usr/bin/env python3
from __future__ import annotations

"""Discover weaverssh feature plugins and service capabilities."""

import argparse
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "tools" / "verification" / "weaverssh_feature_plugins.json"
OPS_SCRIPT = REPO_ROOT / "tools" / "verification" / "sshx11_ops.sh"
CATALOG_VERSION = "weaverssh.feature_plugins.v1"


def _manifest_paths(values: list[str] | None = None) -> list[Path]:
    raw_values: list[str] = [str(DEFAULT_MANIFEST)]
    env_value = os.environ.get("WEAVERSSH_FEATURE_PLUGIN_MANIFEST", "")
    if env_value.strip():
        raw_values.extend([part for part in env_value.split(os.pathsep) if part.strip()])
    if values:
        raw_values.extend(values)
    out: list[Path] = []
    seen: set[str] = set()
    for raw in raw_values:
        p = Path(str(raw).strip()).expanduser()
        if not p.is_absolute():
            p = REPO_ROOT / p
        resolved = str(p.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        out.append(Path(resolved))
    return out


def _load_manifest(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if not path.exists():
        return [], [f"manifest_not_found:{path}"]
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [], [f"manifest_parse_failed:{path}:{exc}"]
    if not isinstance(raw, dict):
        return [], [f"manifest_invalid_type:{path}"]
    version = str(raw.get("version", "")).strip()
    warnings: list[str] = []
    if version != CATALOG_VERSION:
        warnings.append(f"manifest_version_mismatch:{path}:{version or 'missing'}")
    items = raw.get("plugins", [])
    if not isinstance(items, list):
        return [], warnings + [f"manifest_plugins_invalid:{path}"]
    plugins: list[dict[str, Any]] = []
    seen: set[str] = set()
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            warnings.append(f"plugin_invalid:{path}:{idx}")
            continue
        plugin_id = str(item.get("id", "")).strip()
        if not plugin_id:
            warnings.append(f"plugin_missing_id:{path}:{idx}")
            continue
        if plugin_id in seen:
            warnings.append(f"plugin_duplicate_in_manifest:{path}:{plugin_id}")
            continue
        seen.add(plugin_id)
        plugin = dict(item)
        plugin["_manifest_path"] = str(path)
        plugins.append(plugin)
    return plugins, warnings


def load_catalog(manifest_values: list[str] | None = None) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    warnings: list[str] = []
    manifest_paths = _manifest_paths(manifest_values)
    by_id: dict[str, dict[str, Any]] = {}
    for path in manifest_paths:
        plugins, ws = _load_manifest(path)
        warnings.extend(ws)
        for plugin in plugins:
            plugin_id = str(plugin.get("id", "")).strip()
            if plugin_id in by_id:
                warnings.append(f"plugin_overridden:{plugin_id}")
            by_id[plugin_id] = plugin
    return [by_id[k] for k in sorted(by_id.keys())], warnings, [str(p) for p in manifest_paths]


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if value is None:
        return []
    return [value]


def _string_list(value: Any) -> list[str]:
    return [str(item).strip() for item in _as_list(value) if str(item).strip()]


def _resolve_repo_path(raw: str) -> Path:
    p = Path(str(raw)).expanduser()
    if p.is_absolute():
        return p
    return (REPO_ROOT / p).resolve()


def _ops_subcommands() -> set[str]:
    if not OPS_SCRIPT.exists():
        return set()
    text = OPS_SCRIPT.read_text(encoding="utf-8", errors="replace")
    found = set(re.findall(r"^\s*([a-zA-Z0-9][a-zA-Z0-9_-]*)\)\s*$", text, flags=re.MULTILINE))
    return found


def _artifact_checks(plugin: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for rel in _string_list(plugin.get("required_artifacts", [])):
        path = _resolve_repo_path(rel)
        out.append({"path": rel, "exists": path.exists(), "is_file": path.is_file()})
    return out


def _command_checks(plugin: dict[str, Any]) -> list[dict[str, Any]]:
    known = _ops_subcommands()
    out: list[dict[str, Any]] = []
    for item in _as_list(plugin.get("commands", [])):
        if not isinstance(item, dict):
            continue
        cmd = dict(item)
        sub = str(cmd.get("ops_subcommand", "")).strip()
        cmd["available"] = bool(sub and sub in known)
        out.append(cmd)
    return out


def enrich_plugin(plugin: dict[str, Any], *, include_checks: bool = True) -> dict[str, Any]:
    commands = _command_checks(plugin) if include_checks else [dict(x) for x in _as_list(plugin.get("commands", [])) if isinstance(x, dict)]
    artifacts = _artifact_checks(plugin) if include_checks else []
    missing_artifacts = [item["path"] for item in artifacts if not item.get("exists")]
    missing_commands = [item.get("ops_subcommand") for item in commands if item.get("ops_subcommand") and not item.get("available", True)]
    enabled = bool(plugin.get("enabled_by_default", True))
    available = enabled and not missing_artifacts and not missing_commands
    out = {
        "id": str(plugin.get("id", "")).strip(),
        "name": str(plugin.get("name", "")).strip(),
        "kind": str(plugin.get("kind", "feature")).strip() or "feature",
        "enabled_by_default": enabled,
        "available": bool(available),
        "description": str(plugin.get("description", "")).strip(),
        "provides": _string_list(plugin.get("provides", [])),
        "services": [dict(x) for x in _as_list(plugin.get("services", [])) if isinstance(x, dict)],
        "commands": commands,
        "docs": _string_list(plugin.get("docs", [])),
        "tags": _string_list(plugin.get("tags", [])),
        "manifest_path": str(plugin.get("_manifest_path", "")),
    }
    if include_checks:
        out["artifact_checks"] = artifacts
        out["missing_artifacts"] = missing_artifacts
        out["missing_commands"] = missing_commands
    return out


def _matches(plugin: dict[str, Any], args: argparse.Namespace) -> bool:
    if getattr(args, "kind", ""):
        if str(plugin.get("kind", "")).strip() != str(args.kind).strip():
            return False
    feature = str(getattr(args, "feature", "") or "").strip()
    if feature and feature not in _string_list(plugin.get("provides", [])):
        return False
    tag = str(getattr(args, "tag", "") or "").strip()
    if tag and tag not in _string_list(plugin.get("tags", [])):
        return False
    if bool(getattr(args, "enabled_only", False)) and not bool(plugin.get("enabled_by_default", True)):
        return False
    return True


def build_catalog_payload(
    *,
    manifest_values: list[str] | None = None,
    include_checks: bool = True,
    kind: str = "",
    feature: str = "",
    tag: str = "",
    enabled_only: bool = False,
) -> dict[str, Any]:
    plugins, warnings, manifests = load_catalog(manifest_values)
    filters = argparse.Namespace(kind=kind, feature=feature, tag=tag, enabled_only=enabled_only)
    filtered = [plugin for plugin in plugins if _matches(plugin, filters)]
    enriched = [enrich_plugin(plugin, include_checks=include_checks) for plugin in filtered]
    return {
        "ok": True,
        "version": CATALOG_VERSION,
        "repo_root": str(REPO_ROOT),
        "manifest_paths": manifests,
        "count": len(enriched),
        "plugins": enriched,
        "warnings": warnings,
    }


def _catalog_payload(args: argparse.Namespace, *, include_checks: bool) -> dict[str, Any]:
    return build_catalog_payload(
        manifest_values=args.manifest,
        include_checks=include_checks,
        kind=str(getattr(args, "kind", "") or ""),
        feature=str(getattr(args, "feature", "") or ""),
        tag=str(getattr(args, "tag", "") or ""),
        enabled_only=bool(getattr(args, "enabled_only", False)),
    )


def _print(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def cmd_list(args: argparse.Namespace) -> int:
    payload = _catalog_payload(args, include_checks=False)
    _print(payload)
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    payload = _catalog_payload(args, include_checks=True)
    _print(payload)
    return 0 if payload.get("ok") else 1


def cmd_show(args: argparse.Namespace) -> int:
    plugins, warnings, manifests = load_catalog(args.manifest)
    target = str(args.plugin_id).strip()
    for plugin in plugins:
        if str(plugin.get("id", "")).strip() == target:
            payload = {
                "ok": True,
                "version": CATALOG_VERSION,
                "repo_root": str(REPO_ROOT),
                "manifest_paths": manifests,
                "plugin": enrich_plugin(plugin, include_checks=True),
                "warnings": warnings,
            }
            _print(payload)
            return 0
    _print(
        {
            "ok": False,
            "version": CATALOG_VERSION,
            "repo_root": str(REPO_ROOT),
            "manifest_paths": manifests,
            "reason": "plugin_not_found",
            "plugin_id": target,
            "warnings": warnings,
        }
    )
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", action="append", default=[], help="Additional feature plugin manifest path layered after the built-in catalog. Can be repeated.")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("list", "List declared feature plugins."),
        ("discover", "List plugins with artifact and ops-command availability checks."),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--kind", default="", help="Filter by plugin kind, for example service.")
        p.add_argument("--feature", default="", help="Filter by provided feature/capability id.")
        p.add_argument("--tag", default="", help="Filter by tag.")
        p.add_argument("--enabled-only", action="store_true", help="Only include plugins enabled by default.")
        p.set_defaults(func=cmd_list if name == "list" else cmd_discover)

    show = sub.add_parser("show", help="Show one feature plugin by id.")
    show.add_argument("plugin_id")
    show.set_defaults(func=cmd_show)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
