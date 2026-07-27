from __future__ import annotations

from pathlib import Path
import json
import sys
import threading


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification import sshx11d


CONTRACT_FILE = REPO_ROOT / "extensions" / "vscode-sshx11" / "data" / "api-contract.v1.json"


def test_named_commands_match_contract_file() -> None:
    report = sshx11d.contract_sync_report(CONTRACT_FILE)
    assert report["ok"] is True, report
    assert report["missing_from_daemon"] == []
    assert report["extra_in_daemon"] == []


def test_named_commands_resolve_to_supported_ops() -> None:
    snapshot = sshx11d.default_settings_snapshot()
    snapshot["defaultRemoteHost"] = "example.internal"
    snapshot["defaultRemoteUser"] = "root"
    snapshot["defaultIdentityFile"] = "~/.ssh/id_ed25519"

    for name in sshx11d.NAMED_COMMANDS:
        out = sshx11d.resolve_named_command(
            name=name,
            snapshot=snapshot,
            request={"host": "example.internal", "user": "root"},
        )
        if name in {"configure", "openWorkflowsDoc"}:
            assert out["ok"] is False
            assert out["status"] == "not_applicable"
            continue

        assert out["ok"] is True
        assert out["subcommand"] in sshx11d.ALLOWED_OPS_SUBCOMMANDS


def test_ui_actions_match_contract_file() -> None:
    contract = json.loads(CONTRACT_FILE.read_text(encoding="utf-8"))
    contract_actions = set(contract["ui_driver"]["action_names"])
    daemon_actions = {action["name"] for action in sshx11d.list_ui_actions()}

    assert daemon_actions == contract_actions
    assert tuple(action["name"] for action in sshx11d.list_ui_actions()) == sshx11d.NAMED_COMMANDS
    assert sshx11d.describe_ui_action("statusLocal") == {
        "name": "statusLocal",
        "commandId": "sshx11.statusLocal",
        "title": "SSHX11: Status (Local)",
        "category": "lifecycle",
        "kind": "ops-command",
        "subcommand": "status-local",
        "description": "Inspect local service, policy, and state health.",
    }
    assert sshx11d.describe_ui_action("ninepStatus") == {
        "name": "ninepStatus",
        "commandId": "sshx11.ninepStatus",
        "title": "SSHX11: 9P Service Status",
        "category": "workflow",
        "kind": "ops-command",
        "subcommand": "9p-status",
        "description": "Inspect the repo-native wv-9p service status.",
    }


def test_ui_action_plans_cover_ops_prompt_and_document() -> None:
    snapshot = sshx11d.default_settings_snapshot()

    status = sshx11d.resolve_ui_action_plan("statusLocal", snapshot)
    assert status == {
        "ok": True,
        "name": "statusLocal",
        "kind": "ops-command",
        "subcommand": "status-local",
        "args": [],
    }

    prompted = sshx11d.resolve_ui_action_plan("reverseSocksSmoke", snapshot)
    assert prompted["ok"] is True
    assert prompted["kind"] == "prompted-ops-command"
    assert prompted["missing"] == ["host"]

    reverse = sshx11d.resolve_ui_action_plan(
        "reverseSocksSmoke",
        snapshot,
        {"host": "example.internal", "user": "kb", "identityFile": "~/.ssh/id_ed25519"},
    )
    assert reverse["ok"] is True
    assert reverse["kind"] == "ops-command"
    assert reverse["subcommand"] == "reverse-socks-smoke"
    assert reverse["args"][:4] == ["--host", "example.internal", "--user", "kb"]

    ninep = sshx11d.resolve_ui_action_plan("ninepStatus", snapshot)
    assert ninep == {
        "ok": True,
        "name": "ninepStatus",
        "kind": "ops-command",
        "subcommand": "9p-status",
        "args": [],
    }

    document = sshx11d.resolve_ui_action_plan("openWorkflowsDoc", snapshot)
    assert document["ok"] is True
    assert document["kind"] == "document"
    assert document["relativePath"] == "docs/workstation/SSHX11_VSCODE_EXTENSION_NETWORK_WORKFLOWS.md"


def test_daemon_run_ui_action_executes_resolved_ops(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    ops_script = repo_root / "tools" / "verification" / "sshx11_ops.sh"
    ops_script.parent.mkdir(parents=True)
    ops_script.write_text('#!/bin/sh\nprintf "%s\\n" "$1"\n', encoding="utf-8")
    ops_script.chmod(0o755)

    state_dir = tmp_path / "state"
    daemon = sshx11d.SSHX11Daemon(
        repo_root=repo_root,
        host="127.0.0.1",
        port=0,
        state_dir=state_dir,
        token_file=state_dir / "token",
        endpoint_file=state_dir / "endpoint.json",
        events_file=state_dir / "events.ndjson",
        settings_file=state_dir / "settings.json",
        contract_file=CONTRACT_FILE,
        allow_no_token=True,
        allow_unsafe_subcommand=False,
        timeout_s=5.0,
        events_max=20,
    )

    out = daemon.run_ui_action("statusLocal")

    assert out["ok"] is True
    assert out["name"] == "statusLocal"
    assert out["plan"]["subcommand"] == "status-local"
    assert out["result"]["exit_code"] == 0
    assert out["result"]["stdout"] == "status-local\n"


def test_feature_plugin_catalog_exposes_9p_service() -> None:
    payload = sshx11d.build_feature_plugin_catalog(include_checks=True, feature="vfs.readonly.9p")
    assert payload["ok"] is True
    assert payload["count"] == 1
    plugin = payload["plugins"][0]
    assert plugin["id"] == "vfs.9p"
    assert plugin["available"] is True
    assert plugin["missing_artifacts"] == []
    assert plugin["missing_commands"] == []
    assert "9p-start" in {cmd["ops_subcommand"] for cmd in plugin["commands"]}

    described = sshx11d.describe_feature_plugin("vfs.9p")
    assert described["ok"] is True
    assert described["plugin"]["services"][0]["id"] == "wv-9p"
    assert {"plugins-list", "plugins-show", "plugins-discover"} <= sshx11d.ALLOWED_OPS_SUBCOMMANDS


def test_daemon_feature_plugin_methods_emit_discovery(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    daemon = sshx11d.SSHX11Daemon(
        repo_root=REPO_ROOT,
        host="127.0.0.1",
        port=0,
        state_dir=state_dir,
        token_file=state_dir / "token",
        endpoint_file=state_dir / "endpoint.json",
        events_file=state_dir / "events.ndjson",
        settings_file=state_dir / "settings.json",
        contract_file=CONTRACT_FILE,
        allow_no_token=True,
        allow_unsafe_subcommand=False,
        timeout_s=5.0,
        events_max=20,
    )

    discovered = daemon.list_feature_plugins(include_checks=True, feature="vfs.readonly.9p")
    assert discovered["ok"] is True
    assert discovered["plugins"][0]["id"] == "vfs.9p"

    described = daemon.describe_feature_plugin("vfs.9p")
    assert described["ok"] is True
    assert described["plugin"]["services"][0]["id"] == "wv-9p"

    event_types = {event["type"] for event in daemon.list_events(limit=20)}
    assert "feature_plugins_discover" in event_types
    assert "feature_plugin_describe" in event_types


def test_contract_declares_feature_plugin_http_methods() -> None:
    contract = json.loads(CONTRACT_FILE.read_text(encoding="utf-8"))
    methods = contract["method_contract"]
    assert methods["listFeaturePlugins"]["http"]["path"] == "/v1/featurePlugins"
    assert methods["discoverFeaturePlugins"]["http"]["path"] == "/v1/featurePlugins/discover"
    assert methods["describeFeaturePlugin"]["http"]["path"] == "/v1/featurePlugins/{id}"
    assert {"list-feature-plugins", "discover-feature-plugins", "describe-feature-plugin"} <= set(
        contract["ui_driver"]["capabilities"]
    )


def test_daemon_feature_plugin_http_routes(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    daemon = sshx11d.SSHX11Daemon(
        repo_root=REPO_ROOT,
        host="127.0.0.1",
        port=0,
        state_dir=state_dir,
        token_file=state_dir / "token",
        endpoint_file=state_dir / "endpoint.json",
        events_file=state_dir / "events.ndjson",
        settings_file=state_dir / "settings.json",
        contract_file=CONTRACT_FILE,
        allow_no_token=False,
        allow_unsafe_subcommand=False,
        timeout_s=5.0,
        events_max=20,
    )
    server = sshx11d.ThreadingHTTPServer(("127.0.0.1", 0), sshx11d._make_handler(daemon))
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        discovered = sshx11d._http_json(
            "GET",
            base + "/v1/featurePlugins/discover?feature=vfs.readonly.9p",
            daemon.token,
            timeout_s=2.0,
        )
        assert discovered["ok"] is True
        assert discovered["plugins"][0]["id"] == "vfs.9p"
        assert discovered["plugins"][0]["available"] is True

        described = sshx11d._http_json(
            "GET",
            base + "/v1/featurePlugins/vfs.9p",
            daemon.token,
            timeout_s=2.0,
        )
        assert described["ok"] is True
        assert described["plugin"]["services"][0]["id"] == "wv-9p"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
