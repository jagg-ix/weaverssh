#!/usr/bin/env python3
from __future__ import annotations

"""Per-user SSHX11 local API daemon (extension-compatible contract)."""

import argparse
from collections import deque
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time
from typing import Any
from urllib import parse as urlparse
from urllib import request as urlrequest

try:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
except Exception as exc:  # pragma: no cover
    raise SystemExit("Python http.server support is required") from exc


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 19636
DEFAULT_EVENTS_MAX = 500
DEFAULT_TIMEOUT_S = 300.0


UI_ACTIONS: tuple[dict[str, str], ...] = (
    {
        "name": "configure",
        "commandId": "sshx11.configure",
        "title": "SSHX11: Configure",
        "category": "configuration",
        "kind": "configuration",
        "description": "Open the Configure popup and update SSHX11 extension settings.",
    },
    {
        "name": "startServices",
        "commandId": "sshx11.startServices",
        "title": "SSHX11: Start Services",
        "category": "lifecycle",
        "kind": "ops-command",
        "subcommand": "service-start",
        "description": "Start local SSHX11 control/data-plane services.",
    },
    {
        "name": "stopServices",
        "commandId": "sshx11.stopServices",
        "title": "SSHX11: Stop Services",
        "category": "lifecycle",
        "kind": "ops-command",
        "subcommand": "service-stop",
        "description": "Stop local SSHX11 control/data-plane services.",
    },
    {
        "name": "statusLocal",
        "commandId": "sshx11.statusLocal",
        "title": "SSHX11: Status (Local)",
        "category": "lifecycle",
        "kind": "ops-command",
        "subcommand": "status-local",
        "description": "Inspect local service, policy, and state health.",
    },
    {
        "name": "socksFallbackStart",
        "commandId": "sshx11.socksFallbackStart",
        "title": "SSHX11: Start SOCKS Fallback",
        "category": "workflow",
        "kind": "ops-command",
        "subcommand": "socks-fallback-start",
        "description": "Start the local SOCKS fallback path when direct routing is unavailable.",
    },
    {
        "name": "vscodeProfileGen",
        "commandId": "sshx11.vscodeProfileGen",
        "title": "SSHX11: Generate VS Code Profiles",
        "category": "workflow",
        "kind": "ops-command",
        "subcommand": "vscode-profile-gen",
        "description": "Generate local, remote, and reverse-SOCKS VS Code profile artifacts.",
    },
    {
        "name": "verifyExtensionHosts",
        "commandId": "sshx11.verifyExtensionHosts",
        "title": "SSHX11: Verify Extension Hosts",
        "category": "workflow",
        "kind": "ops-command",
        "subcommand": "verify-extension-hosts",
        "description": "Validate extension-host profile and SSH adapter compatibility settings.",
    },
    {
        "name": "reverseSocksSmoke",
        "commandId": "sshx11.reverseSocksSmoke",
        "title": "SSHX11: Reverse SOCKS Smoke",
        "category": "workflow",
        "kind": "prompted-ops-command",
        "subcommand": "reverse-socks-smoke",
        "description": "Run the prompted or programmatic reverse-SOCKS smoke workflow.",
    },
    {
        "name": "webdavStart",
        "commandId": "sshx11.webdavStart",
        "title": "SSHX11: Start WebDAV",
        "category": "workflow",
        "kind": "ops-command",
        "subcommand": "webdav-start",
        "description": "Start the local lightweight WebDAV endpoint.",
    },
    {
        "name": "ninepStart",
        "commandId": "sshx11.ninepStart",
        "title": "SSHX11: Start 9P Service",
        "category": "workflow",
        "kind": "ops-command",
        "subcommand": "9p-start",
        "description": "Start the repo-native read-only wv-9p service for VFS workflows.",
    },
    {
        "name": "ninepStatus",
        "commandId": "sshx11.ninepStatus",
        "title": "SSHX11: 9P Service Status",
        "category": "workflow",
        "kind": "ops-command",
        "subcommand": "9p-status",
        "description": "Inspect the repo-native wv-9p service status.",
    },
    {
        "name": "ninepStop",
        "commandId": "sshx11.ninepStop",
        "title": "SSHX11: Stop 9P Service",
        "category": "workflow",
        "kind": "ops-command",
        "subcommand": "9p-stop",
        "description": "Stop the repo-native wv-9p service.",
    },
    {
        "name": "ninepPlan",
        "commandId": "sshx11.ninepPlan",
        "title": "SSHX11: Plan 9P Service",
        "category": "workflow",
        "kind": "ops-command",
        "subcommand": "9p-plan",
        "description": "Show the wv-9p launch plan and prerequisites without starting it.",
    },
    {
        "name": "openWorkflowsDoc",
        "commandId": "sshx11.openWorkflowsDoc",
        "title": "SSHX11: Open Workflow Documentation",
        "category": "documentation",
        "kind": "document",
        "description": "Open the SSHX11 VS Code workflow documentation from the workspace.",
    },
)

NAMED_COMMANDS: tuple[str, ...] = tuple(action["name"] for action in UI_ACTIONS)


ALLOWED_OPS_SUBCOMMANDS: set[str] = {
    "service-start",
    "service-stop",
    "status-local",
    "socks-fallback-start",
    "vscode-profile-gen",
    "verify-extension-hosts",
    "reverse-socks-smoke",
    "webdav-start",
    "9p-start",
    "9p-status",
    "9p-stop",
    "9p-plan",
    "plugins-list",
    "plugins-show",
    "plugins-discover",
}


def _is_windows() -> bool:
    return os.name.lower() == "nt"


def _expand_home(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return str(Path(text).expanduser())


def _parse_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(default)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def _clamp_int(value: Any, lo: int, hi: int, default: int) -> int:
    try:
        n = int(str(value).strip())
    except Exception:
        n = int(default)
    return max(int(lo), min(int(hi), int(n)))


def _safe_relpath(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except Exception:
        return str(path)


_FEATURE_PLUGINS_MODULE: Any | None = None


def _load_feature_plugins_module() -> Any:
    global _FEATURE_PLUGINS_MODULE
    if _FEATURE_PLUGINS_MODULE is not None:
        return _FEATURE_PLUGINS_MODULE
    module_path = REPO_ROOT / "tools" / "verification" / "weaverssh_feature_plugins.py"
    spec = importlib.util.spec_from_file_location("weaverssh_feature_plugins_runtime", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"feature_plugin_module_unavailable:{module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _FEATURE_PLUGINS_MODULE = module
    return module


def build_feature_plugin_catalog(
    *,
    include_checks: bool,
    kind: str = "",
    feature: str = "",
    tag: str = "",
    enabled_only: bool = False,
) -> dict[str, Any]:
    try:
        module = _load_feature_plugins_module()
        payload = module.build_catalog_payload(
            include_checks=include_checks,
            kind=str(kind or ""),
            feature=str(feature or ""),
            tag=str(tag or ""),
            enabled_only=bool(enabled_only),
        )
        if isinstance(payload, dict):
            return payload
        return {"ok": False, "error": "feature_plugin_catalog_invalid_shape"}
    except Exception as exc:
        return {"ok": False, "error": "feature_plugin_catalog_failed", "detail": str(exc)}


def describe_feature_plugin(plugin_id: str) -> dict[str, Any]:
    target = str(plugin_id or "").strip()
    payload = build_feature_plugin_catalog(include_checks=True)
    if not bool(payload.get("ok")):
        return payload
    for plugin in list(payload.get("plugins", [])):
        if isinstance(plugin, dict) and str(plugin.get("id", "")).strip() == target:
            return {
                "ok": True,
                "version": payload.get("version"),
                "repo_root": payload.get("repo_root"),
                "manifest_paths": payload.get("manifest_paths", []),
                "plugin": plugin,
                "warnings": payload.get("warnings", []),
            }
    return {
        "ok": False,
        "error": "feature_plugin_not_found",
        "plugin_id": target,
        "warnings": payload.get("warnings", []),
    }


def default_state_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "sshx11d"
    if _is_windows():
        local = os.environ.get("LOCALAPPDATA", "")
        if local:
            return Path(local) / "sshx11d"
        return Path.home() / "AppData" / "Local" / "sshx11d"
    xdg = os.environ.get("XDG_STATE_HOME", "")
    if xdg:
        return Path(xdg) / "sshx11d"
    return Path.home() / ".local" / "state" / "sshx11d"


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if not _is_windows():
        try:
            os.chmod(path, 0o700)
        except Exception:
            pass


def _write_private_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if not _is_windows():
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass


def _resolve_path(raw: str | Path, *, base: Path) -> Path:
    p = Path(str(raw)).expanduser()
    if p.is_absolute():
        return p
    return (base / p).resolve()


def default_settings_snapshot() -> dict[str, Any]:
    return {
        "opsScriptPath": "tools/verification/sshx11_ops.sh",
        "showStatusBarConfigure": True,
        "widgetLocation": "auto",
        "resolvedWidgetLocation": "bottom",
        "verbose": False,
        "defaultRemoteHost": "",
        "defaultRemoteUser": "root",
        "defaultIdentityFile": "~/.ssh/id_ed25519",
        "defaultSshConfigPath": "",
        "defaultSshProxyJump": "",
        "defaultSshProxyCommand": "",
        "sshVerbosity": 0,
        "sshLogLevel": "",
        "sshLogFile": "",
        "agentMode": "auto",
        "forwardAgent": False,
        "identityAgent": "",
        "sshClientAdapter": "auto",
        "virtualizationLayer": "auto",
        "setupKind": "auto",
        "organizationProvider": "none",
        "chainConnector": "none",
        "organizationConfigPath": "",
        "remotePlatform": "auto",
        "remoteShellBin": "sh",
        "remoteShellLogin": True,
        "remotePythonBin": "",
        "insecureHostKey": False,
    }


def _resolved_widget_location(location: str) -> str:
    loc = str(location or "auto").strip().lower()
    if loc == "top":
        return "top"
    return "bottom"


def load_settings_snapshot(settings_file: Path | None = None) -> dict[str, Any]:
    snapshot = default_settings_snapshot()
    if settings_file and settings_file.exists():
        try:
            raw = json.loads(settings_file.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                snapshot.update(raw)
        except Exception:
            pass

    snapshot["showStatusBarConfigure"] = _parse_bool(snapshot.get("showStatusBarConfigure"), True)
    snapshot["verbose"] = _parse_bool(snapshot.get("verbose"), False)
    snapshot["forwardAgent"] = _parse_bool(snapshot.get("forwardAgent"), False)
    snapshot["remoteShellLogin"] = _parse_bool(snapshot.get("remoteShellLogin"), True)
    snapshot["insecureHostKey"] = _parse_bool(snapshot.get("insecureHostKey"), False)
    snapshot["sshVerbosity"] = _clamp_int(snapshot.get("sshVerbosity"), 0, 3, 0)

    agent_mode = str(snapshot.get("agentMode", "auto")).strip().lower()
    if agent_mode not in {"auto", "require", "disable"}:
        agent_mode = "auto"
    snapshot["agentMode"] = agent_mode

    location = str(snapshot.get("widgetLocation", "auto")).strip().lower()
    if location not in {"auto", "top", "bottom"}:
        location = "auto"
    snapshot["widgetLocation"] = location
    snapshot["resolvedWidgetLocation"] = _resolved_widget_location(location)

    return snapshot


def resolve_ops_script(snapshot: dict[str, Any], repo_root: Path) -> Path:
    configured = str(snapshot.get("opsScriptPath", "tools/verification/sshx11_ops.sh")).strip()
    if not configured:
        configured = "tools/verification/sshx11_ops.sh"
    return _resolve_path(configured, base=repo_root)


def build_proxy_args(snapshot: dict[str, Any]) -> list[str]:
    args: list[str] = []
    ssh_config = _expand_home(str(snapshot.get("defaultSshConfigPath", "")))
    proxy_jump = str(snapshot.get("defaultSshProxyJump", "")).strip()
    proxy_command = str(snapshot.get("defaultSshProxyCommand", "")).strip()

    if ssh_config:
        args.extend(["--ssh-config", ssh_config])
    if proxy_jump:
        args.extend(["--proxy-jump", proxy_jump])
    if proxy_command:
        args.extend(["--proxy-command", proxy_command])
    return args


def build_agent_args(snapshot: dict[str, Any]) -> list[str]:
    args: list[str] = []
    mode = str(snapshot.get("agentMode", "auto")).strip().lower()
    if mode not in {"auto", "require", "disable"}:
        mode = "auto"
    args.extend(["--agent-mode", mode])
    if _parse_bool(snapshot.get("forwardAgent"), False):
        args.append("--forward-agent")
    identity_agent = _expand_home(str(snapshot.get("identityAgent", "")))
    if identity_agent:
        args.extend(["--identity-agent", identity_agent])
    return args


def build_runtime_args(snapshot: dict[str, Any]) -> list[str]:
    args: list[str] = []
    platform = str(snapshot.get("remotePlatform", "auto")).strip().lower()
    shell_bin = str(snapshot.get("remoteShellBin", "sh")).strip() or "sh"
    shell_login = _parse_bool(snapshot.get("remoteShellLogin"), True)
    python_bin = str(snapshot.get("remotePythonBin", "")).strip()

    args.extend(["--remote-platform", platform])
    args.extend(["--remote-shell-bin", shell_bin])
    args.append("--remote-shell-login" if shell_login else "--no-remote-shell-login")
    if python_bin:
        args.extend(["--remote-python-bin", python_bin])
    return args


def build_ssh_logging_args(snapshot: dict[str, Any]) -> list[str]:
    args: list[str] = []
    verbosity = _clamp_int(snapshot.get("sshVerbosity"), 0, 3, 0)
    log_level = str(snapshot.get("sshLogLevel", "")).strip()
    log_file = _expand_home(str(snapshot.get("sshLogFile", "")).strip())
    if verbosity > 0:
        args.extend(["--ssh-verbosity", str(verbosity)])
    if log_level:
        args.extend(["--ssh-log-level", log_level])
    if log_file:
        args.extend(["--ssh-log-file", log_file])
    return args


def list_ui_actions() -> list[dict[str, str]]:
    return [dict(action) for action in UI_ACTIONS]


def describe_ui_action(name: str) -> dict[str, str] | None:
    n = str(name or "").strip()
    for action in UI_ACTIONS:
        if action.get("name") == n:
            return dict(action)
    return None


def resolve_ui_action_plan(
    name: str,
    snapshot: dict[str, Any],
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    n = str(name or "").strip()
    action = describe_ui_action(n)
    if not action:
        return {"ok": False, "error": f"unknown_ui_action:{n}", "name": n}

    if n == "configure":
        return {"ok": True, "name": n, "kind": "configuration", "action": "showConfigure"}
    if n == "openWorkflowsDoc":
        return {
            "ok": True,
            "name": n,
            "kind": "document",
            "relativePath": "docs/workstation/SSHX11_VSCODE_EXTENSION_NETWORK_WORKFLOWS.md",
        }

    resolved = resolve_named_command(name=n, snapshot=snapshot, request=request)
    if bool(resolved.get("ok")):
        return {
            "ok": True,
            "name": n,
            "kind": "ops-command",
            "subcommand": str(resolved.get("subcommand", "")),
            "args": [str(x) for x in list(resolved.get("args", []))],
        }

    if n == "reverseSocksSmoke" and str(resolved.get("error", "")) in {"missing_host", "missing_user"}:
        missing: list[str] = []
        payload = request or {}
        host = str(payload.get("host") or snapshot.get("defaultRemoteHost") or "").strip()
        user = str(payload.get("user") or snapshot.get("defaultRemoteUser") or "").strip()
        if not host:
            missing.append("host")
        if not user:
            missing.append("user")
        return {
            "ok": True,
            "name": n,
            "kind": "prompted-ops-command",
            "subcommand": "reverse-socks-smoke",
            "defaults": {
                "host": str(snapshot.get("defaultRemoteHost") or ""),
                "user": str(snapshot.get("defaultRemoteUser") or "root"),
                "identityFile": str(snapshot.get("defaultIdentityFile") or ""),
            },
            "missing": missing,
        }

    return {"ok": False, "name": n, **resolved}


def resolve_named_command(
    name: str,
    snapshot: dict[str, Any],
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    n = str(name or "").strip()
    payload = request or {}

    if n not in NAMED_COMMANDS:
        return {"ok": False, "error": f"unknown_named_command:{n}"}

    if n in {"configure", "openWorkflowsDoc"}:
        return {"ok": False, "status": "not_applicable", "name": n}

    if n == "startServices":
        return {"ok": True, "subcommand": "service-start", "args": []}
    if n == "stopServices":
        return {"ok": True, "subcommand": "service-stop", "args": []}
    if n == "statusLocal":
        return {"ok": True, "subcommand": "status-local", "args": []}
    if n == "socksFallbackStart":
        return {"ok": True, "subcommand": "socks-fallback-start", "args": []}
    if n == "vscodeProfileGen":
        return {
            "ok": True,
            "subcommand": "vscode-profile-gen",
            "args": ["--profile", "all", "--output-dir", ".vscode/sshx11"],
        }
    if n == "webdavStart":
        return {"ok": True, "subcommand": "webdav-start", "args": []}
    if n == "ninepStart":
        return {"ok": True, "subcommand": "9p-start", "args": []}
    if n == "ninepStatus":
        return {"ok": True, "subcommand": "9p-status", "args": []}
    if n == "ninepStop":
        return {"ok": True, "subcommand": "9p-stop", "args": []}
    if n == "ninepPlan":
        return {"ok": True, "subcommand": "9p-plan", "args": []}

    if n == "verifyExtensionHosts":
        args: list[str] = []
        args.extend(build_proxy_args(snapshot))
        args.extend(build_agent_args(snapshot))
        args.extend(build_runtime_args(snapshot))
        args.extend(build_ssh_logging_args(snapshot))
        if _parse_bool(snapshot.get("insecureHostKey"), False):
            args.append("--insecure-hostkey")
        return {"ok": True, "subcommand": "verify-extension-hosts", "args": args}

    if n == "reverseSocksSmoke":
        host = str(payload.get("host") or snapshot.get("defaultRemoteHost") or "").strip()
        user = str(payload.get("user") or snapshot.get("defaultRemoteUser") or "root").strip()
        identity_file = str(payload.get("identityFile") or snapshot.get("defaultIdentityFile") or "").strip()
        if not host:
            return {"ok": False, "error": "missing_host"}
        if not user:
            return {"ok": False, "error": "missing_user"}
        args = ["--host", host, "--user", user]
        if identity_file:
            args.extend(["--identity-file", _expand_home(identity_file)])
        args.extend(build_proxy_args(snapshot))
        args.extend(build_agent_args(snapshot))
        args.extend(build_runtime_args(snapshot))
        args.extend(build_ssh_logging_args(snapshot))
        if _parse_bool(snapshot.get("insecureHostKey"), False):
            args.append("--insecure-hostkey")
        return {"ok": True, "subcommand": "reverse-socks-smoke", "args": args}

    return {"ok": False, "error": f"unhandled_named_command:{n}"}


def _contract_named_commands(contract_file: Path) -> set[str]:
    if not contract_file.exists():
        return set()
    try:
        raw = json.loads(contract_file.read_text(encoding="utf-8"))
    except Exception:
        return set()
    cmds = raw.get("named_commands", [])
    if not isinstance(cmds, list):
        return set()
    out: set[str] = set()
    for item in cmds:
        text = str(item).strip()
        if text:
            out.add(text)
    return out


def contract_sync_report(contract_file: Path) -> dict[str, Any]:
    contract = _contract_named_commands(contract_file)
    local = set(NAMED_COMMANDS)
    if not contract:
        return {
            "ok": False,
            "status": "contract_missing_or_invalid",
            "contract_file": str(contract_file),
            "missing_from_daemon": [],
            "extra_in_daemon": sorted(local),
        }
    missing = sorted(contract - local)
    extra = sorted(local - contract)
    return {
        "ok": not missing and not extra,
        "status": "ok" if not missing and not extra else "mismatch",
        "contract_file": str(contract_file),
        "missing_from_daemon": missing,
        "extra_in_daemon": extra,
    }


class SSHX11Daemon:
    def __init__(
        self,
        *,
        repo_root: Path,
        host: str,
        port: int,
        state_dir: Path,
        token_file: Path,
        endpoint_file: Path,
        events_file: Path,
        settings_file: Path,
        contract_file: Path,
        allow_no_token: bool,
        allow_unsafe_subcommand: bool,
        timeout_s: float,
        events_max: int,
    ) -> None:
        self.repo_root = repo_root
        self.host = str(host)
        self.port = int(port)
        self.state_dir = state_dir
        self.token_file = token_file
        self.endpoint_file = endpoint_file
        self.events_file = events_file
        self.settings_file = settings_file
        self.contract_file = contract_file
        self.allow_no_token = bool(allow_no_token)
        self.allow_unsafe_subcommand = bool(allow_unsafe_subcommand)
        self.timeout_s = float(timeout_s)
        self.events_max = max(20, int(events_max))

        _ensure_private_dir(self.state_dir)
        self.token = self._load_or_create_token()
        self.settings_snapshot = load_settings_snapshot(self.settings_file)

        self._events: deque[dict[str, Any]] = deque(maxlen=self.events_max)
        self._events_lock = threading.Lock()
        self._next_event_id = 1

        self.sync = contract_sync_report(self.contract_file)
        self.write_endpoint_descriptor()
        self.emit_event("daemon_start", {"sync": self.sync})

    def _load_or_create_token(self) -> str:
        if self.token_file.exists():
            raw = self.token_file.read_text(encoding="utf-8", errors="replace").strip()
            if raw:
                return raw
        token = secrets.token_urlsafe(36)
        _write_private_file(self.token_file, token + "\n")
        return token

    def write_endpoint_descriptor(self) -> None:
        payload = {
            "service": "sshx11d",
            "api_version": "v1",
            "base_url": f"http://{self.host}:{self.port}",
            "state_dir": str(self.state_dir),
            "token_file": str(self.token_file),
            "events_file": str(self.events_file),
            "settings_file": str(self.settings_file),
            "contract_file": str(self.contract_file),
            "updated_at_unix": int(time.time()),
        }
        _write_private_file(self.endpoint_file, json.dumps(payload, indent=2, sort_keys=True) + "\n")

    def emit_event(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._events_lock:
            event = {
                "id": self._next_event_id,
                "type": str(event_type),
                "timestamp_unix": int(time.time()),
                "payload": payload,
            }
            self._next_event_id += 1
            self._events.append(event)

        line = json.dumps(event, sort_keys=True)
        self.events_file.parent.mkdir(parents=True, exist_ok=True)
        with self.events_file.open("a", encoding="utf-8") as h:
            h.write(line + "\n")
        return event

    def list_events(self, since: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        n = max(1, min(500, int(limit)))
        s = int(since)
        with self._events_lock:
            rows = [e for e in list(self._events) if int(e.get("id", 0)) > s]
        return rows[-n:]

    def verify_token(self, candidate: str) -> bool:
        if self.allow_no_token:
            return True
        if not candidate:
            return False
        try:
            return secrets.compare_digest(candidate, self.token)
        except Exception:
            return False

    def run_ops_command(self, subcommand: str, args: list[str] | None = None) -> dict[str, Any]:
        sc = str(subcommand or "").strip()
        argv_args = [str(x) for x in (args or [])]
        if not sc:
            return {"ok": False, "error": "missing_subcommand"}
        if not self.allow_unsafe_subcommand and sc not in ALLOWED_OPS_SUBCOMMANDS:
            return {
                "ok": False,
                "error": "subcommand_not_allowed",
                "subcommand": sc,
                "allowed": sorted(ALLOWED_OPS_SUBCOMMANDS),
            }

        ops_script = resolve_ops_script(self.settings_snapshot, self.repo_root)
        if not ops_script.exists():
            return {
                "ok": False,
                "error": "ops_script_missing",
                "path": str(ops_script),
            }

        cmd = [str(ops_script), sc, *argv_args]
        started = time.time()
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.repo_root),
                capture_output=True,
                text=True,
                check=False,
                timeout=max(2.0, self.timeout_s),
            )
            elapsed = round(time.time() - started, 3)
            result = {
                "ok": bool(proc.returncode == 0),
                "subcommand": sc,
                "args": argv_args,
                "exit_code": int(proc.returncode),
                "elapsed_s": elapsed,
                "stdout": str(proc.stdout or "")[-4000:],
                "stderr": str(proc.stderr or "")[-4000:],
                "argv": cmd,
            }
        except subprocess.TimeoutExpired:
            result = {
                "ok": False,
                "subcommand": sc,
                "args": argv_args,
                "error": "timeout",
                "timeout_s": max(2.0, self.timeout_s),
                "argv": cmd,
            }
        except Exception as exc:
            result = {
                "ok": False,
                "subcommand": sc,
                "args": argv_args,
                "error": str(exc),
                "argv": cmd,
            }

        self.emit_event("run_ops_command", {"result": result})
        return result

    def run_named_command(self, name: str, request: dict[str, Any] | None = None) -> dict[str, Any]:
        resolved = resolve_named_command(name=name, snapshot=self.settings_snapshot, request=request)
        if not bool(resolved.get("ok")):
            out = {
                "ok": bool(resolved.get("status") == "not_applicable"),
                "name": str(name),
                **resolved,
            }
            self.emit_event("run_named_command", {"result": out})
            return out

        result = self.run_ops_command(
            subcommand=str(resolved.get("subcommand")),
            args=[str(x) for x in list(resolved.get("args", []))],
        )
        out = {"ok": bool(result.get("ok")), "name": str(name), "resolved": resolved, "result": result}
        self.emit_event("run_named_command", {"result": out})
        return out

    def run_ui_action(self, name: str, request: dict[str, Any] | None = None) -> dict[str, Any]:
        plan = resolve_ui_action_plan(name=name, snapshot=self.settings_snapshot, request=request)
        if not bool(plan.get("ok")):
            out = {"ok": False, "name": str(name), "plan": plan, "error": plan.get("error", "ui_action_not_resolved")}
            self.emit_event("run_ui_action", {"result": out})
            return out

        kind = str(plan.get("kind", ""))
        if kind == "ops-command":
            result = self.run_ops_command(
                subcommand=str(plan.get("subcommand")),
                args=[str(x) for x in list(plan.get("args", []))],
            )
            out = {"ok": bool(result.get("ok")), "name": str(name), "plan": plan, "result": result}
            self.emit_event("run_ui_action", {"result": out})
            return out

        if kind == "prompted-ops-command":
            out = {
                "ok": False,
                "name": str(name),
                "error": "missing_prompt_input",
                "status": "requires_request_payload",
                "plan": plan,
            }
            self.emit_event("run_ui_action", {"result": out})
            return out

        out = {
            "ok": True,
            "name": str(name),
            "status": "not_applicable",
            "reason": f"{kind}_handled_by_interactive_ui",
            "plan": plan,
        }
        self.emit_event("run_ui_action", {"result": out})
        return out

    def run_reverse_socks_smoke(self, request: dict[str, Any] | None = None) -> dict[str, Any]:
        out = self.run_named_command("reverseSocksSmoke", request=request)
        self.emit_event("run_reverse_socks_smoke", {"result": out})
        return out


    def list_feature_plugins(
        self,
        *,
        include_checks: bool = False,
        kind: str = "",
        feature: str = "",
        tag: str = "",
        enabled_only: bool = False,
    ) -> dict[str, Any]:
        out = build_feature_plugin_catalog(
            include_checks=include_checks,
            kind=kind,
            feature=feature,
            tag=tag,
            enabled_only=enabled_only,
        )
        self.emit_event(
            "feature_plugins_discover" if include_checks else "feature_plugins_list",
            {
                "ok": bool(out.get("ok")),
                "count": int(out.get("count", 0) or 0),
                "include_checks": bool(include_checks),
                "kind": str(kind or ""),
                "feature": str(feature or ""),
                "tag": str(tag or ""),
            },
        )
        return out

    def describe_feature_plugin(self, plugin_id: str) -> dict[str, Any]:
        out = describe_feature_plugin(plugin_id)
        self.emit_event(
            "feature_plugin_describe",
            {
                "ok": bool(out.get("ok")),
                "plugin_id": str(plugin_id or ""),
            },
        )
        return out


def _extract_bearer_token(headers: dict[str, str]) -> str:
    auth = str(headers.get("Authorization") or headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return str(headers.get("X-SSHX11-Token") or headers.get("x-sshx11-token") or "").strip()


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    handler.send_response(int(status))
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except Exception:
        length = 0
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def _make_handler(daemon: SSHX11Daemon):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:  # pragma: no cover
            msg = fmt % args
            daemon.emit_event("http_log", {"message": msg, "path": self.path})

        def _auth_or_401(self) -> bool:
            token = _extract_bearer_token({k: v for k, v in self.headers.items()})
            if daemon.verify_token(token):
                return True
            _json_response(
                self,
                401,
                {
                    "ok": False,
                    "error": "unauthorized",
                    "hint": "pass Authorization: Bearer <token> or X-SSHX11-Token",
                },
            )
            return False

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse.urlparse(self.path)
            path = parsed.path
            params = urlparse.parse_qs(parsed.query)

            if path == "/v1/health":
                _json_response(
                    self,
                    200,
                    {
                        "ok": True,
                        "service": "sshx11d",
                        "api_version": "v1",
                        "contract_sync": daemon.sync,
                        "timestamp_unix": int(time.time()),
                    },
                )
                return

            if path == "/v1/settingsSnapshot":
                if not self._auth_or_401():
                    return
                _json_response(
                    self,
                    200,
                    {
                        "ok": True,
                        "settings": daemon.settings_snapshot,
                        "timestamp_unix": int(time.time()),
                    },
                )
                return

            if path == "/v1/uiActions":
                if not self._auth_or_401():
                    return
                _json_response(
                    self,
                    200,
                    {
                        "ok": True,
                        "actions": list_ui_actions(),
                        "timestamp_unix": int(time.time()),
                    },
                )
                return

            if path == "/v1/featurePlugins" or path == "/v1/featurePlugins/discover":
                if not self._auth_or_401():
                    return
                include_checks = path.endswith("/discover") or _parse_bool((params.get("checks") or ["0"])[0], False)
                out = daemon.list_feature_plugins(
                    include_checks=include_checks,
                    kind=str((params.get("kind") or [""])[0]),
                    feature=str((params.get("feature") or [""])[0]),
                    tag=str((params.get("tag") or [""])[0]),
                    enabled_only=_parse_bool((params.get("enabledOnly") or ["0"])[0], False),
                )
                out["timestamp_unix"] = int(time.time())
                _json_response(self, 200 if bool(out.get("ok")) else 500, out)
                return

            if path.startswith("/v1/featurePlugins/"):
                if not self._auth_or_401():
                    return
                raw_plugin_id = path.removeprefix("/v1/featurePlugins/")
                plugin_id = urlparse.unquote(raw_plugin_id)
                out = daemon.describe_feature_plugin(plugin_id)
                out["timestamp_unix"] = int(time.time())
                _json_response(self, 200 if bool(out.get("ok")) else 404, out)
                return

            if path.startswith("/v1/uiActions/"):
                if not self._auth_or_401():
                    return
                raw_name = path.removeprefix("/v1/uiActions/")
                name = urlparse.unquote(raw_name)
                action = describe_ui_action(name)
                if not action:
                    _json_response(self, 404, {"ok": False, "error": "unknown_ui_action", "name": name})
                    return
                _json_response(
                    self,
                    200,
                    {
                        "ok": True,
                        "action": action,
                        "timestamp_unix": int(time.time()),
                    },
                )
                return

            if path == "/v1/events":
                if not self._auth_or_401():
                    return
                since = 0
                limit = 100
                try:
                    since = int((params.get("since") or ["0"])[0])
                except Exception:
                    since = 0
                try:
                    limit = int((params.get("limit") or ["100"])[0])
                except Exception:
                    limit = 100
                _json_response(
                    self,
                    200,
                    {
                        "ok": True,
                        "events": daemon.list_events(since=since, limit=limit),
                        "timestamp_unix": int(time.time()),
                    },
                )
                return

            if path == "/v1/endpoint":
                if not self._auth_or_401():
                    return
                _json_response(
                    self,
                    200,
                    {
                        "ok": True,
                        "endpoint_file": str(daemon.endpoint_file),
                        "token_file": str(daemon.token_file),
                        "events_file": str(daemon.events_file),
                        "settings_file": str(daemon.settings_file),
                        "contract_file": str(daemon.contract_file),
                    },
                )
                return

            _json_response(self, 404, {"ok": False, "error": "not_found", "path": path})

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse.urlparse(self.path)
            path = parsed.path
            if not self._auth_or_401():
                return
            body = _read_json_body(self)

            if path == "/v1/runOpsCommand":
                subcommand = str(body.get("subcommand") or "").strip()
                args = body.get("args", [])
                out = daemon.run_ops_command(subcommand=subcommand, args=list(args) if isinstance(args, list) else [])
                _json_response(self, 200 if bool(out.get("ok")) else 400, out)
                return

            if path == "/v1/runNamedCommand":
                name = str(body.get("name") or "").strip()
                request_payload = body.get("request")
                if request_payload is not None and not isinstance(request_payload, dict):
                    request_payload = {}
                out = daemon.run_named_command(name=name, request=request_payload)
                _json_response(self, 200 if bool(out.get("ok")) else 400, out)
                return

            if path == "/v1/runUiAction":
                name = str(body.get("name") or "").strip()
                request_payload = body.get("request")
                if request_payload is not None and not isinstance(request_payload, dict):
                    request_payload = {}
                out = daemon.run_ui_action(name=name, request=request_payload)
                _json_response(self, 200 if bool(out.get("ok")) else 400, out)
                return

            if path == "/v1/runReverseSocksSmoke":
                out = daemon.run_reverse_socks_smoke(request=body)
                _json_response(self, 200 if bool(out.get("ok")) else 400, out)
                return

            if path == "/v1/showConfigure":
                out = {"ok": False, "status": "not_applicable", "reason": "extension_only"}
                daemon.emit_event("show_configure", {"result": out})
                _json_response(self, 200, out)
                return

            _json_response(self, 404, {"ok": False, "error": "not_found", "path": path})

    return Handler


def serve(daemon: SSHX11Daemon) -> int:
    handler = _make_handler(daemon)
    server = ThreadingHTTPServer((daemon.host, daemon.port), handler)
    daemon.emit_event(
        "http_serve",
        {
            "host": daemon.host,
            "port": daemon.port,
            "endpoint_file": str(daemon.endpoint_file),
        },
    )
    print(
        json.dumps(
            {
                "ok": True,
                "service": "sshx11d",
                "host": daemon.host,
                "port": daemon.port,
                "endpoint_file": str(daemon.endpoint_file),
                "contract_sync": daemon.sync,
            },
            indent=2,
            sort_keys=True,
        )
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        daemon.emit_event("daemon_stop", {"reason": "shutdown"})
    return 0


def _http_json(method: str, url: str, token: str, payload: dict[str, Any] | None = None, timeout_s: float = 2.0) -> dict[str, Any]:
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
    req = urlrequest.Request(url=url, method=method.upper(), data=body)
    req.add_header("Accept", "application/json")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urlrequest.urlopen(req, timeout=max(0.2, float(timeout_s))) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = {"ok": False, "error": "invalid_json", "raw": raw[-500:]}
    if not isinstance(parsed, dict):
        return {"ok": False, "error": "invalid_json_shape"}
    return parsed


def load_endpoint_descriptor(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"ok": False, "error": "endpoint_missing", "path": str(path)}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"ok": False, "error": str(exc), "path": str(path)}
    if not isinstance(raw, dict):
        return {"ok": False, "error": "endpoint_invalid_shape", "path": str(path)}
    return {"ok": True, "endpoint": raw}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=["serve", "status", "print-endpoint", "print-token"])
    p.add_argument("--host", default=os.environ.get("SSHX11D_HOST", DEFAULT_HOST))
    p.add_argument("--port", type=int, default=int(os.environ.get("SSHX11D_PORT", str(DEFAULT_PORT))))
    p.add_argument("--repo-root", default=str(REPO_ROOT))
    p.add_argument("--state-dir", default=os.environ.get("SSHX11D_STATE_DIR", str(default_state_dir())))
    p.add_argument("--token-file", default=os.environ.get("SSHX11D_TOKEN_FILE", ""))
    p.add_argument("--endpoint-file", default=os.environ.get("SSHX11D_ENDPOINT_FILE", ""))
    p.add_argument("--events-file", default=os.environ.get("SSHX11D_EVENTS_FILE", ""))
    p.add_argument("--settings-file", default=os.environ.get("SSHX11D_SETTINGS_FILE", ""))
    p.add_argument(
        "--contract-file",
        default=os.environ.get(
            "SSHX11D_CONTRACT_FILE",
            str(REPO_ROOT / "extensions" / "vscode-sshx11" / "data" / "api-contract.v1.json"),
        ),
    )
    p.add_argument("--allow-no-token", action="store_true", default=False)
    p.add_argument("--allow-unsafe-subcommand", action="store_true", default=False)
    p.add_argument("--timeout-s", type=float, default=float(os.environ.get("SSHX11D_TIMEOUT_S", str(DEFAULT_TIMEOUT_S))))
    p.add_argument("--events-max", type=int, default=int(os.environ.get("SSHX11D_EVENTS_MAX", str(DEFAULT_EVENTS_MAX))))
    p.add_argument("--show-token-value", action="store_true", default=False)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    repo_root = _resolve_path(args.repo_root, base=REPO_ROOT)
    state_dir = _resolve_path(args.state_dir, base=REPO_ROOT)
    _ensure_private_dir(state_dir)

    token_file = _resolve_path(args.token_file, base=state_dir) if str(args.token_file or "").strip() else (state_dir / "token")
    endpoint_file = _resolve_path(args.endpoint_file, base=state_dir) if str(args.endpoint_file or "").strip() else (state_dir / "endpoint.json")
    events_file = _resolve_path(args.events_file, base=state_dir) if str(args.events_file or "").strip() else (state_dir / "events.ndjson")
    settings_file = _resolve_path(args.settings_file, base=state_dir) if str(args.settings_file or "").strip() else (state_dir / "settings.json")
    contract_file = _resolve_path(args.contract_file, base=REPO_ROOT)

    daemon = SSHX11Daemon(
        repo_root=repo_root,
        host=str(args.host),
        port=int(args.port),
        state_dir=state_dir,
        token_file=token_file,
        endpoint_file=endpoint_file,
        events_file=events_file,
        settings_file=settings_file,
        contract_file=contract_file,
        allow_no_token=bool(args.allow_no_token),
        allow_unsafe_subcommand=bool(args.allow_unsafe_subcommand),
        timeout_s=float(args.timeout_s),
        events_max=int(args.events_max),
    )

    if args.command == "serve":
        return serve(daemon)

    if args.command == "print-token":
        payload = {
            "ok": True,
            "token_file": str(token_file),
            "token_length": len(daemon.token),
        }
        if bool(args.show_token_value):
            payload["token"] = daemon.token
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if args.command == "print-endpoint":
        payload = load_endpoint_descriptor(endpoint_file)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if bool(payload.get("ok")) else 1

    # status
    endpoint = load_endpoint_descriptor(endpoint_file)
    payload: dict[str, Any] = {
        "ok": False,
        "endpoint": endpoint,
        "contract_sync": daemon.sync,
        "state_dir": str(state_dir),
        "ops_script": _safe_relpath(resolve_ops_script(daemon.settings_snapshot, repo_root), repo_root),
    }
    if bool(endpoint.get("ok")):
        info = endpoint.get("endpoint", {})
        if isinstance(info, dict):
            base_url = str(info.get("base_url", "")).strip()
            try:
                health = _http_json("GET", base_url.rstrip("/") + "/v1/health", daemon.token, payload=None, timeout_s=1.5)
            except Exception as exc:
                health = {"ok": False, "error": str(exc)}
            payload["health"] = health
            payload["ok"] = bool(health.get("ok"))
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if bool(payload.get("ok")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
