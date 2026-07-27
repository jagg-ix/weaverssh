#!/usr/bin/env python3
from __future__ import annotations

"""Smoke-check SSHX11 extension API contract."""

import json
from pathlib import Path
import re
import sys


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    package_json = json.loads((root / "package.json").read_text(encoding="utf-8"))
    src = (root / "src" / "extension.ts").read_text(encoding="utf-8")
    dist = (root / "dist" / "extension.js").read_text(encoding="utf-8")

    required_api_activation = {
        "onCommand:sshx11.api.getSettingsSnapshot",
        "onCommand:sshx11.api.runOpsCommand",
        "onCommand:sshx11.api.runNamedCommand",
        "onCommand:sshx11.api.showConfigure",
        "onCommand:sshx11.api.listUiActions",
        "onCommand:sshx11.api.describeUiAction",
        "onCommand:sshx11.api.runUiAction",
        "onCommand:sshx11.api.listFeaturePlugins",
        "onCommand:sshx11.api.discoverFeaturePlugins",
        "onCommand:sshx11.api.describeFeaturePlugin",
    }
    activation = set(str(x) for x in package_json.get("activationEvents", []))
    missing_activation = sorted(required_api_activation - activation)

    required_registered = {
        "sshx11.configure",
        "sshx11.startServices",
        "sshx11.stopServices",
        "sshx11.statusLocal",
        "sshx11.socksFallbackStart",
        "sshx11.vscodeProfileGen",
        "sshx11.verifyExtensionHosts",
        "sshx11.reverseSocksSmoke",
        "sshx11.webdavStart",
        "sshx11.ninepStart",
        "sshx11.ninepStatus",
        "sshx11.ninepStop",
        "sshx11.ninepPlan",
        "sshx11.openWorkflowsDoc",
        "sshx11.api.getSettingsSnapshot",
        "sshx11.api.runOpsCommand",
        "sshx11.api.runNamedCommand",
        "sshx11.api.showConfigure",
        "sshx11.api.listUiActions",
        "sshx11.api.describeUiAction",
        "sshx11.api.runUiAction",
        "sshx11.api.listFeaturePlugins",
        "sshx11.api.discoverFeaturePlugins",
        "sshx11.api.describeFeaturePlugin",
    }
    registered = set(re.findall(r'register(?:Command)?\(\s*"([^"]+)"', src))
    missing_registered = sorted(required_registered - registered)

    has_api_return_sig = "export function activate(context: vscode.ExtensionContext): SSHX11ExtensionApi" in src
    has_api_fields = all(
        token in src
        for token in (
            "onDidRunCommand: commandEventEmitter.event",
            "runOpsCommand: async (subcommand: string, args: string[] = [])",
            "runNamedCommand: async (name: SSHX11NamedCommand, request?: SSHX11ReverseSocksSmokeRequest)",
            "runReverseSocksSmoke: async (request?: SSHX11ReverseSocksSmokeRequest)",
            "getSettingsSnapshot: () => getSettingsSnapshot()",
            "listUiActions: () => listUiActions()",
            "describeUiAction: (name: SSHX11UiActionName)",
            "runUiAction: async (name: SSHX11UiActionName, request?: SSHX11UiActionRequest)",
            "listFeaturePlugins: (filter: SSHX11FeaturePluginFilter = {})",
            "discoverFeaturePlugins: (filter: SSHX11FeaturePluginFilter = {})",
            "describeFeaturePlugin: (id: string)",
        )
    )
    dist_has_api_commands = all(
        token in dist
        for token in (
            "sshx11.api.getSettingsSnapshot",
            "sshx11.api.runOpsCommand",
            "sshx11.api.runNamedCommand",
            "sshx11.api.showConfigure",
            "sshx11.api.listUiActions",
            "sshx11.api.describeUiAction",
            "sshx11.api.runUiAction",
            "sshx11.api.listFeaturePlugins",
            "sshx11.api.discoverFeaturePlugins",
            "sshx11.api.describeFeaturePlugin",
        )
    )

    has_ui_api_module = (root / "src" / "ui-api.ts").exists()
    extension_imports_ui_api = 'from "./ui-api"' in src
    ok = bool(
        not missing_activation
        and not missing_registered
        and has_api_return_sig
        and has_api_fields
        and dist_has_api_commands
        and has_ui_api_module
        and extension_imports_ui_api
    )

    payload = {
        "ok": ok,
        "missing_activation": missing_activation,
        "missing_registered": missing_registered,
        "has_api_return_signature": has_api_return_sig,
        "has_api_fields": has_api_fields,
        "dist_has_api_commands": dist_has_api_commands,
        "has_ui_api_module": has_ui_api_module,
        "extension_imports_ui_api": extension_imports_ui_api,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
