from __future__ import annotations

import json
from pathlib import Path
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG = REPO_ROOT / "tools" / "verification" / "weaverssh_feature_plugins.json"
SCRIPT = REPO_ROOT / "tools" / "verification" / "weaverssh_feature_plugins.py"


def _run(*args: str) -> dict[str, object]:
    proc = subprocess.run(
        ["python3", str(SCRIPT), *args],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    return json.loads(proc.stdout)


def test_feature_plugin_manifest_declares_vfs_9p() -> None:
    raw = json.loads(CATALOG.read_text(encoding="utf-8"))
    assert raw["version"] == "weaverssh.feature_plugins.v1"
    plugins = {item["id"]: item for item in raw["plugins"]}

    plugin = plugins["vfs.9p"]
    assert plugin["kind"] == "service"
    assert "vfs.readonly.9p" in plugin["provides"]
    assert "containerized.service" in plugin["provides"]
    assert plugin["services"][0]["id"] == "wv-9p"
    assert plugin["services"][0]["read_only"] is True
    assert set(plugin["services"][0]["runtimes"]) >= {"host", "docker", "podman", "nerdctl"}
    assert {cmd["ops_subcommand"] for cmd in plugin["commands"]} >= {
        "9p-plan",
        "9p-start",
        "9p-status",
        "9p-logs",
        "9p-stop",
        "9p-image-build",
    }


def test_feature_plugin_discover_reports_9p_available() -> None:
    payload = _run("discover", "--feature", "vfs.readonly.9p")
    assert payload["ok"] is True
    assert payload["count"] == 1
    plugin = payload["plugins"][0]
    assert plugin["id"] == "vfs.9p"
    assert plugin["available"] is True
    assert plugin["missing_artifacts"] == []
    assert plugin["missing_commands"] == []
    assert all(item["exists"] for item in plugin["artifact_checks"])
    assert all(item["available"] for item in plugin["commands"])


def test_feature_plugin_show_returns_full_9p_service_metadata() -> None:
    payload = _run("show", "vfs.9p")
    plugin = payload["plugin"]
    assert plugin["id"] == "vfs.9p"
    assert plugin["kind"] == "service"
    assert plugin["services"][0]["binary"] == "build/bin/wv-9p"
    assert plugin["services"][0]["default_listen"] == "127.0.0.1:5640"
    assert "docs/workstation/SSHX11_9P_INTEROP_IMPLEMENTATIONS.md" in plugin["docs"]


def test_feature_plugin_filters_by_kind_and_tag() -> None:
    by_kind = _run("list", "--kind", "service")
    assert any(item["id"] == "vfs.9p" for item in by_kind["plugins"])

    by_tag = _run("discover", "--tag", "9p")
    assert [item["id"] for item in by_tag["plugins"]] == ["vfs.9p"]


def test_feature_plugin_extra_manifest_layers_after_default(tmp_path: Path) -> None:
    extra = tmp_path / "extra-plugins.json"
    extra.write_text(
        json.dumps(
            {
                "version": "weaverssh.feature_plugins.v1",
                "plugins": [
                    {
                        "id": "demo.extra",
                        "name": "Demo Extra Plugin",
                        "kind": "service",
                        "enabled_by_default": True,
                        "description": "Synthetic plugin used to prove manifest layering.",
                        "provides": ["demo.extra.feature"],
                        "commands": [],
                        "required_artifacts": [],
                        "docs": [],
                        "tags": ["demo"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["python3", str(SCRIPT), "--manifest", str(extra), "list"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = json.loads(proc.stdout)
    ids = {plugin["id"] for plugin in payload["plugins"]}
    assert "vfs.9p" in ids
    assert "demo.extra" in ids
