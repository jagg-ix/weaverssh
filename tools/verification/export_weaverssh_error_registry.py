#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = REPO_ROOT / "docs" / "debug" / "weaverssh_debug_kb.sqlite3"
DEFAULT_OUTPUT = REPO_ROOT / "docs" / "debug" / "weaverssh_error_registry.json"
DEFAULT_RESOURCE_OUTPUT = REPO_ROOT / "python" / "weaverssh_support" / "resources" / "weaverssh_error_registry.json"
NON_RETRYABLE_CODES = {
    "WV-ADP-001",
    "WV-AUT-001",
    "WV-AUT-002",
    "WV-PKG-001",
    "WV-PKG-002",
    "WV-RLY-002",
    "WV-SOC-001",
    "WV-VAL-001",
    "WV-WSS-001",
    "WV-X11-002",
    "WV-X11-003",
}


def _kind_for(severity: str) -> str:
    return "fault" if severity == "fatal" else "error"


def _retryable(code: str, severity: str) -> bool:
    if code in NON_RETRYABLE_CODES:
        return False
    return severity in {"warning", "error"}


def export_registry(db_path: Path) -> dict[str, Any]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    with conn:
        schema_version = conn.execute(
            "SELECT value FROM metadata WHERE key='schema_version'"
        ).fetchone()[0]
        rows = conn.execute(
            """
            SELECT e.code, e.subsystem, e.severity, e.title, e.description,
                   e.operator_action, e.developer_action, e.verification,
                   e.related_commands, e.source_refs, e.tags, e.status,
                   group_concat(k.slug, ',') AS kb_slugs,
                   group_concat(k.title, ' | ') AS kb_titles
            FROM error_codes e
            LEFT JOIN error_kb_links l ON l.code = e.code
            LEFT JOIN kb_articles k ON k.slug = l.article_slug
            GROUP BY e.code
            ORDER BY e.code
            """
        ).fetchall()

    codes: list[dict[str, Any]] = []
    components: dict[str, list[str]] = {}
    for row in rows:
        item = {key: row[key] for key in row.keys()}
        item["kind"] = _kind_for(str(item["severity"]))
        item["retryable"] = _retryable(str(item["code"]), str(item["severity"]))
        item["kb_slugs"] = [slug for slug in str(item.get("kb_slugs") or "").split(",") if slug]
        item["kb_titles"] = [title for title in str(item.get("kb_titles") or "").split(" | ") if title]
        codes.append(item)
        components.setdefault(str(item["subsystem"]), []).append(str(item["code"]))

    return {
        "version": "weaverssh.error_registry.v1",
        "source_schema_version": schema_version,
        "source": "docs/debug/weaverssh_debug_kb.sqlite3",
        "codes": codes,
        "components": {name: sorted(values) for name, values in sorted(components.items())},
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export the weaverssh SQLite debug KB as a runtime error registry JSON file.")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="SQLite debug KB path.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Registry JSON output path.")
    parser.add_argument(
        "--package-resource",
        default=str(DEFAULT_RESOURCE_OUTPUT),
        help="Optional package resource copy used by weaverssh_support.errors.",
    )
    parser.add_argument("--stdout", action="store_true", help="Print JSON to stdout instead of writing files.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    data = export_registry(Path(args.db))
    if args.stdout:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0
    write_json(Path(args.output), data)
    if args.package_resource:
        write_json(Path(args.package_resource), data)
    print(f"wrote {args.output}")
    if args.package_resource:
        print(f"wrote {args.package_resource}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
