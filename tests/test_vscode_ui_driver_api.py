from __future__ import annotations

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
EXT_ROOT = REPO_ROOT / "extensions" / "vscode-sshx11"


def test_vscode_ui_driver_api_is_contract_backed() -> None:
    ui_api = (EXT_ROOT / "src" / "ui-api.ts").read_text(encoding="utf-8")
    extension = (EXT_ROOT / "src" / "extension.ts").read_text(encoding="utf-8")
    package_json = json.loads((EXT_ROOT / "package.json").read_text(encoding="utf-8"))
    contract = json.loads((EXT_ROOT / "data" / "api-contract.v1.json").read_text(encoding="utf-8"))
    command_map = json.loads((EXT_ROOT / "data" / "command-map.json").read_text(encoding="utf-8"))

    required_methods = {
        "listUiActions",
        "describeUiAction",
        "runUiAction",
        "listFeaturePlugins",
        "discoverFeaturePlugins",
        "describeFeaturePlugin",
    }
    required_command_ids = {
        "sshx11.api.listUiActions",
        "sshx11.api.describeUiAction",
        "sshx11.api.runUiAction",
        "sshx11.api.listFeaturePlugins",
        "sshx11.api.discoverFeaturePlugins",
        "sshx11.api.describeFeaturePlugin",
    }

    assert "export const SSHX11_UI_ACTIONS" in ui_api
    assert "resolveUiActionPlan" in ui_api
    assert 'from "./ui-api"' in extension
    assert "runUiAction(name, request)" in extension

    assert set(contract["ui_driver"]["action_names"]) == set(contract["named_commands"])
    assert required_methods <= set(contract["method_contract"])
    assert required_command_ids <= set(command["id"] for command in command_map["commands"])
    assert {f"onCommand:{command_id}" for command_id in required_command_ids} <= set(package_json["activationEvents"])

    for name in contract["named_commands"]:
        assert f'name: "{name}"' in ui_api

    assert "ninepStart" in contract["named_commands"]
    assert "sshx11.ninepStart" in {command["id"] for command in command_map["commands"]}
    assert "onCommand:sshx11.ninepStart" in package_json["activationEvents"]
    assert "9p-start" in ui_api

    feature_manifest = json.loads(
        (REPO_ROOT / "tools" / "verification" / "weaverssh_feature_plugins.json").read_text(encoding="utf-8")
    )
    vfs_9p = next(plugin for plugin in feature_manifest["plugins"] if plugin["id"] == "vfs.9p")
    assert 'id: "vfs.9p"' in ui_api
    assert 'name: "9P VFS Service"' in ui_api
    assert 'defaultListen: "127.0.0.1:5640"' in ui_api
    assert 'opsSubcommand: "9p-start"' in ui_api
    assert 'opsSubcommand: "9p-image-build"' in ui_api
    assert set(vfs_9p["provides"]) <= {"vfs.readonly.9p", "vfs.mesh.endpoint", "socks.data_path.validation", "containerized.service"}
    assert "SSHX11_FEATURE_PLUGINS" in ui_api
    assert "listFeaturePlugins(filter" in extension
    assert "discoverFeaturePlugins(filter" in extension
    assert "describeFeaturePlugin(id" in extension
