#!/usr/bin/env python3
from __future__ import annotations

"""Materialize the SSHX11 VFS mesh namespace from the phase-1 registry.

This is the runtime bridge for the VFS mesh control-plane model:
- read the host registry produced by sshx11_vfs_agent.py
- build a deterministic /mesh/<host>/<export> metadata namespace
- build /views metadata indexes for WebDAV/SEARCH-facing workflows
- keep data-path mounting explicit; no symlinks are created unless requested
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTRY_FILE = REPO_ROOT / "verification_results" / "runtime" / "sshx11_vfs_registry.json"
DEFAULT_NAMESPACE_DIR = REPO_ROOT / "verification_results" / "runtime" / "sshx11_vfs_namespace"
SCHEMA_VERSION = "sshx11_vfs_mesh_namespace.v1"
MARKER_FILE = ".weaverssh-vfs-namespace"
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _now_unix() -> int:
    return int(time.time())


def _json_read(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _json_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _safe_name(value: Any, fallback: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raw = fallback
    name = SAFE_NAME_RE.sub("_", raw).strip("._-")
    if not name or name in {".", ".."}:
        name = fallback
    return name


def _host_items(registry: dict[str, Any], *, online_only: bool) -> list[tuple[str, dict[str, Any]]]:
    hosts = registry.get("hosts")
    if not isinstance(hosts, dict):
        return []
    out: list[tuple[str, dict[str, Any]]] = []
    for host_id, raw in sorted(hosts.items(), key=lambda item: str(item[0])):
        if not isinstance(raw, dict):
            continue
        status = str(raw.get("status", "")).strip().lower()
        if online_only and status != "online":
            continue
        out.append((str(host_id), raw))
    return out


def _exports_for(host: dict[str, Any]) -> list[dict[str, Any]]:
    exports = host.get("exports")
    if not isinstance(exports, list):
        return []
    return [item for item in exports if isinstance(item, dict)]


def _imports_for(host: dict[str, Any]) -> list[dict[str, Any]]:
    imports = host.get("imports")
    if not isinstance(imports, list):
        return []
    return [item for item in imports if isinstance(item, dict)]


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _maybe_link_local_export(export_dir: Path, export_path: str) -> dict[str, Any]:
    source = Path(str(export_path)).expanduser()
    result: dict[str, Any] = {
        "link_requested": True,
        "link_created": False,
        "source": str(source),
        "target": str(export_dir / "data"),
    }
    if not source.exists():
        result["reason"] = "source_missing"
        return result
    target = export_dir / "data"
    try:
        os.symlink(str(source.resolve()), str(target))
        result["link_created"] = True
    except Exception as exc:  # pragma: no cover - platform/permission dependent
        result["reason"] = str(exc)
    return result


def _build_namespace_payload(
    *,
    registry_file: Path,
    namespace_dir: Path,
    registry: dict[str, Any],
    online_only: bool,
    link_local_exports: bool,
) -> dict[str, Any]:
    hosts = _host_items(registry, online_only=online_only)
    export_rows: list[dict[str, Any]] = []
    import_rows: list[dict[str, Any]] = []
    mount_edges: list[dict[str, Any]] = []
    search_docs: list[dict[str, Any]] = []

    for host_id, host in hosts:
        host_safe = _safe_name(host_id, "host")
        host_dir = namespace_dir / "mesh" / host_safe
        host_dir.mkdir(parents=True, exist_ok=True)
        host_summary = {
            "host_id": host_id,
            "safe_host_id": host_safe,
            "node_endpoint": str(host.get("node_endpoint", "")),
            "namespace_prefix": str(host.get("namespace_prefix", f"/mesh/{host_safe}")),
            "status": str(host.get("status", "unknown")),
            "last_heartbeat_unix": int(host.get("last_heartbeat_unix", 0) or 0),
            "capability_token_sha256": str(host.get("capability_token_sha256", "")),
            "exports_count": len(_exports_for(host)),
            "imports_count": len(_imports_for(host)),
        }
        _json_write(host_dir / ".weaverssh-host.json", host_summary)

        for export in _exports_for(host):
            export_name = str(export.get("name", "export")).strip() or "export"
            export_safe = _safe_name(export_name, "export")
            export_path = str(export.get("path", ""))
            mode = str(export.get("mode", "ro")).strip().lower() or "ro"
            export_dir = host_dir / export_safe
            export_dir.mkdir(parents=True, exist_ok=True)
            row = {
                "host_id": host_id,
                "safe_host_id": host_safe,
                "export": export_name,
                "safe_export": export_safe,
                "source_path": export_path,
                "mode": mode,
                "mesh_path": f"/mesh/{host_safe}/{export_safe}",
                "node_endpoint": str(host.get("node_endpoint", "")),
                "host_status": str(host.get("status", "unknown")),
                "data_path_materialized": False,
                "data_path_kind": "metadata_stub",
            }
            if link_local_exports:
                link_result = _maybe_link_local_export(export_dir, export_path)
                row["link_result"] = link_result
                row["data_path_materialized"] = bool(link_result.get("link_created"))
                if row["data_path_materialized"]:
                    row["data_path_kind"] = "local_symlink"
            _json_write(export_dir / ".weaverssh-export.json", row)
            _write_text(
                export_dir / "README.weaverssh.txt",
                "weaverssh VFS export\n"
                f"host_id: {host_id}\n"
                f"export: {export_name}\n"
                f"mode: {mode}\n"
                f"source_path: {export_path}\n"
                f"data_path_kind: {row['data_path_kind']}\n"
                "\nThis directory is a VFS mesh metadata endpoint. Full remote data mounting requires the 9P-over-SOCKS data path.\n",
            )
            export_rows.append(row)
            search_docs.append({"kind": "export", **row})

        for imp in _imports_for(host):
            source_host = str(imp.get("source_host", "")).strip()
            source_export = str(imp.get("source_export", "")).strip()
            mount_path = str(imp.get("mount_path", "")).strip()
            mode = str(imp.get("mode", "ro")).strip().lower() or "ro"
            row = {
                "host_id": host_id,
                "safe_host_id": host_safe,
                "source_host": source_host,
                "source_export": source_export,
                "mount_path": mount_path,
                "mode": mode,
                "resolved_source_mesh_path": f"/mesh/{_safe_name(source_host, 'host')}/{_safe_name(source_export, 'export')}",
            }
            import_rows.append(row)
            mount_edges.append(
                {
                    "from": row["resolved_source_mesh_path"],
                    "to_host": host_id,
                    "to_mount_path": mount_path,
                    "mode": mode,
                }
            )
            search_docs.append({"kind": "import", **row})

    views = namespace_dir / "views"
    views.mkdir(parents=True, exist_ok=True)
    hosts_payload = [
        {
            "host_id": host_id,
            "safe_host_id": _safe_name(host_id, "host"),
            "status": str(host.get("status", "unknown")),
            "namespace_prefix": str(host.get("namespace_prefix", f"/mesh/{_safe_name(host_id, 'host')}")),
            "node_endpoint": str(host.get("node_endpoint", "")),
            "exports_count": len(_exports_for(host)),
            "imports_count": len(_imports_for(host)),
            "last_heartbeat_unix": int(host.get("last_heartbeat_unix", 0) or 0),
        }
        for host_id, host in hosts
    ]
    acl_payload = {
        "schema_version": "sshx11_vfs_acl_table.v1",
        "policy": "capability-token-hash-present",
        "capability": "vfs.mesh",
        "entries": [
            {
                "host_id": h[0],
                "capability_token_sha256": str(h[1].get("capability_token_sha256", "")),
                "allowed_when_hash_present": bool(str(h[1].get("capability_token_sha256", "")).strip()),
            }
            for h in hosts
        ],
    }
    lock_payload = {
        "schema_version": "sshx11_vfs_lock_table.v1",
        "locks": [],
        "note": "Phase-1.5 materializer exposes an empty lock table; write coordination is not active yet.",
    }
    mount_graph = {
        "schema_version": "sshx11_vfs_mount_graph.v1",
        "ready": bool(hosts and export_rows),
        "data_plane": "9P_OVER_SOCKS",
        "edges": mount_edges,
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "ok": True,
        "created_unix": _now_unix(),
        "registry_file": str(registry_file),
        "namespace_dir": str(namespace_dir),
        "online_only": bool(online_only),
        "link_local_exports": bool(link_local_exports),
        "host_count": len(hosts),
        "export_count": len(export_rows),
        "import_count": len(import_rows),
        "mount_graph_ready": bool(hosts and export_rows),
        "mesh_namespace_ready": bool(hosts and export_rows),
        "views_namespace_ready": True,
        "webdav_root": str(namespace_dir),
        "search_ready": True,
        "acl_ready": True,
        "lock_ready": True,
        "metadata_index_ready": True,
        "hosts": hosts_payload,
        "exports": export_rows,
        "imports": import_rows,
        "mount_graph": mount_graph,
    }

    _json_write(views / "hosts.json", hosts_payload)
    _json_write(views / "exports.json", export_rows)
    _json_write(views / "imports.json", import_rows)
    _json_write(views / "mount_graph.json", mount_graph)
    _json_write(views / "search_index.json", {"schema_version": "sshx11_vfs_search_index.v1", "documents": search_docs})
    _json_write(views / "acl.json", acl_payload)
    _json_write(views / "locks.json", lock_payload)
    _write_text(views / "webdav_root.txt", str(namespace_dir) + "\n")
    _json_write(namespace_dir / "weaverssh_vfs_manifest.json", manifest)
    _write_text(namespace_dir / MARKER_FILE, SCHEMA_VERSION + "\n")
    _write_text(
        namespace_dir / "README.weaverssh.txt",
        "weaverssh VFS mesh namespace\n\n"
        "Serve this directory with:\n"
        "  tools/verification/sshx11_ops.sh webdav-start --root verification_results/runtime/sshx11_vfs_namespace\n\n"
        "This tree materializes registry metadata and namespace intent. Full remote data access is provided by the 9P-over-SOCKS data path.\n",
    )
    return manifest


def _replace_namespace(tmp_dir: Path, namespace_dir: Path, *, force: bool) -> None:
    if namespace_dir.exists():
        marker = namespace_dir / MARKER_FILE
        if not marker.exists() and not force:
            raise RuntimeError(f"refusing to replace unmarked namespace directory: {namespace_dir}")
        shutil.rmtree(namespace_dir)
    namespace_dir.parent.mkdir(parents=True, exist_ok=True)
    tmp_dir.replace(namespace_dir)


def _cmd_build(args: argparse.Namespace) -> int:
    registry_file = Path(args.registry_file).expanduser().resolve()
    namespace_dir = Path(args.namespace_dir).expanduser().resolve()
    registry = _json_read(registry_file)
    if not registry:
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "failed",
                    "reason": "registry_missing_or_invalid",
                    "registry_file": str(registry_file),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    tmp_parent = namespace_dir.parent
    tmp_parent.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix=namespace_dir.name + ".tmp.", dir=str(tmp_parent)))
    try:
        manifest = _build_namespace_payload(
            registry_file=registry_file,
            namespace_dir=tmp_dir,
            registry=registry,
            online_only=bool(args.online_only),
            link_local_exports=bool(args.link_local_exports),
        )
        _replace_namespace(tmp_dir, namespace_dir, force=bool(args.force))
        manifest["namespace_dir"] = str(namespace_dir)
        manifest["webdav_root"] = str(namespace_dir)
        _json_write(namespace_dir / "weaverssh_vfs_manifest.json", manifest)
        _write_text(namespace_dir / "views" / "webdav_root.txt", str(namespace_dir) + "\n")
        print(json.dumps({"status": "built", **manifest}, indent=2, sort_keys=True))
        return 0
    except Exception:
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)
        raise


def _cmd_status(args: argparse.Namespace) -> int:
    namespace_dir = Path(args.namespace_dir).expanduser().resolve()
    manifest_file = namespace_dir / "weaverssh_vfs_manifest.json"
    manifest = _json_read(manifest_file)
    ok = bool(manifest.get("schema_version") == SCHEMA_VERSION and (namespace_dir / MARKER_FILE).exists())
    payload = {
        "ok": ok,
        "status": "ready" if ok else "missing",
        "namespace_dir": str(namespace_dir),
        "manifest_file": str(manifest_file),
        "manifest": manifest if manifest else {},
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if ok else 1


def _cmd_clean(args: argparse.Namespace) -> int:
    namespace_dir = Path(args.namespace_dir).expanduser().resolve()
    marker = namespace_dir / MARKER_FILE
    if not namespace_dir.exists():
        print(json.dumps({"ok": True, "status": "already_clean", "namespace_dir": str(namespace_dir)}, indent=2, sort_keys=True))
        return 0
    if not marker.exists() and not bool(args.force):
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "failed",
                    "reason": "refusing_to_remove_unmarked_directory",
                    "namespace_dir": str(namespace_dir),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    shutil.rmtree(namespace_dir)
    print(json.dumps({"ok": True, "status": "cleaned", "namespace_dir": str(namespace_dir)}, indent=2, sort_keys=True))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--registry-file", type=Path, default=DEFAULT_REGISTRY_FILE)
    p.add_argument("--namespace-dir", type=Path, default=DEFAULT_NAMESPACE_DIR)
    p.add_argument("--online-only", action="store_true", help="materialize only registry hosts with status=online")
    p.add_argument(
        "--link-local-exports",
        action="store_true",
        help="create data symlinks for exports whose source path exists locally; disabled by default for safety",
    )
    p.add_argument("--force", action="store_true", help="allow replacing/removing an unmarked namespace directory")
    p.add_argument("command", choices=["build", "status", "clean"])
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "build":
        return _cmd_build(args)
    if args.command == "status":
        return _cmd_status(args)
    return _cmd_clean(args)


if __name__ == "__main__":
    raise SystemExit(main())
