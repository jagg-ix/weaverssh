#!/usr/bin/env python3
from __future__ import annotations

"""Registry-driven install/develop/test/verify/deploy workbench for weaverssh.

The workbench is intentionally declarative: every component and operator
workflow has a command plan for the same phases, and risky commands are marked
so scripts can plan them by default and require explicit opt-in to execute them.
"""

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import subprocess
import sys
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
PHASES = ("install", "develop", "test", "verify", "deploy")
RISK_SAFE = "safe"
RISK_DAEMON = "daemon"
RISK_PRIVILEGED = "privileged"
RISK_REMOTE = "remote"
RISK_EXTERNAL = "external"


@dataclass(frozen=True)
class CommandSpec:
    id: str
    description: str
    argv: tuple[str, ...]
    risk: str = RISK_SAFE


@dataclass(frozen=True)
class TargetSpec:
    id: str
    kind: str
    name: str
    description: str
    paths: tuple[str, ...]
    tags: tuple[str, ...]
    phases: dict[str, tuple[CommandSpec, ...]]


def cmd(id: str, description: str, *argv: str, risk: str = RISK_SAFE) -> CommandSpec:
    return CommandSpec(id=id, description=description, argv=tuple(argv), risk=risk)


def base_install_commands(target: str) -> tuple[CommandSpec, ...]:
    return (
        cmd(
            f"{target}.dependency-plan",
            "Print runtime/build dependency install commands for the current OS.",
            "python3",
            "tools/packaging/install_runtime_dependencies.py",
            "plan",
            "--include-build",
        ),
        cmd(f"{target}.dev-doctor", "Check Go, Python, pytest, and package surfaces.", "make", "dev-doctor"),
    )


def target(
    id: str,
    kind: str,
    name: str,
    description: str,
    paths: Iterable[str],
    tags: Iterable[str],
    *,
    develop: Iterable[CommandSpec],
    test: Iterable[CommandSpec],
    verify: Iterable[CommandSpec],
    deploy: Iterable[CommandSpec],
    install: Iterable[CommandSpec] | None = None,
) -> TargetSpec:
    phases = {
        "install": tuple(install if install is not None else base_install_commands(id)),
        "develop": tuple(develop),
        "test": tuple(test),
        "verify": tuple(verify),
        "deploy": tuple(deploy),
    }
    return TargetSpec(
        id=id,
        kind=kind,
        name=name,
        description=description,
        paths=tuple(paths),
        tags=tuple(tags),
        phases=phases,
    )


def registry() -> tuple[TargetSpec, ...]:
    """Return the canonical component/workflow registry."""
    return (
        target(
            "build-system",
            "component",
            "Build System and Developer Surface",
            "Makefile, packaging, dependency, and developer validation entrypoints.",
            ("Makefile", "tools/packaging", "tests/test_weaverssh_development_build.py"),
            ("build", "developer", "packaging"),
            develop=(cmd("build-system.dev-fast-dry-run", "Show the fast developer gate without running it.", "make", "-n", "dev-fast"),),
            test=(cmd("build-system.test-python-build", "Run build/development Python tests.", "make", "test-python-build"),),
            verify=(cmd("build-system.dev-fast", "Run the fast developer validation gate.", "make", "dev-fast"),),
            deploy=(cmd("build-system.native-binaries", "Build all native developer binaries.", "make", "build-all-native-binaries"),),
        ),
        target(
            "core-runtime",
            "component",
            "Core Runtime",
            "Integrated server/client commands, X11 protocol model, FSM, DISPLAY parsing, relay, tunnel, and padding libraries.",
            ("cmd/wv", "cmd/wv-server", "cmd/wv-client", "internal/app", "display", "relay", "tunnel", "padding"),
            ("go", "runtime", "x11", "websocket"),
            develop=(cmd("core-runtime.compile-surface", "Compile runtime libraries and command packages.", "make", "build-library-surface"), cmd("core-runtime.compile-commands", "Compile command packages into a temporary directory.", "make", "build-commands")),
            test=(cmd("core-runtime.go-tests", "Run core runtime Go tests.", "go", "test", "./internal/app", "./display", "./relay", "./tunnel", "./padding"),),
            verify=(cmd("core-runtime.vet", "Run go vet over the runtime surface.", "make", "vet"), cmd("core-runtime.tunnel-policy", "Verify tunnel mechanism policy drift.", "python3", "tools/verification/verify_weaverssh_tunnel_policy.py")),
            deploy=(cmd("core-runtime.build-native", "Build runtime binaries for the current platform.", "make", "build-main", "build-server", "build-client-native", "build-agent", "build-socks"),),
        ),
        target(
            "authproof-security",
            "component",
            "Cryptographic Authority and Native Forwarding Proofs",
            "Peer authority, authorization proof schema, and contract-checked native SSH forwarding plans.",
            ("authproof", "cmd/wv-native-forward", "docs/specs/native_ssh_forwarding_option.md"),
            ("security", "authproof", "native-forwarding"),
            develop=(cmd("authproof.compile", "Compile authproof package and native-forward command.", "go", "test", "-run", "^$", "./authproof"), cmd("authproof.build-native-forward", "Build native forwarding planner.", "make", "build-native-forward")),
            test=(cmd("authproof.go-tests", "Run authproof Go tests.", "go", "test", "./authproof"),),
            verify=(cmd("authproof.native-forward-plan", "Render a safe local native-forwarding plan.", "tools/verification/sshx11_ops.sh", "native-forward-plan", "--mode", "local", "--local-bind", "127.0.0.1:6010", "--target", "127.0.0.1:6000", "--principal", "developer", "--format", "json"),),
            deploy=(cmd("authproof.deploy-planner", "Build the native-forwarding planner artifact.", "make", "build-native-forward"),),
        ),
        target(
            "control-plane",
            "component",
            "Control Plane and Operator CLI",
            "Python/Bash service manager, control/data daemons, state model, and operator shell command surface.",
            ("tools/verification/sshx11_ops.sh", "tools/verification/sshx11_plane_service.py", "tools/verification/sshx11_control_plane_daemon.py", "tools/verification/sshx11_data_plane_daemon.py"),
            ("control-plane", "operator", "python"),
            develop=(cmd("control-plane.py-compile", "Compile Python control-plane modules.", "python3", "-m", "py_compile", "tools/verification/sshx11_plane_service.py", "tools/verification/sshx11_control_plane_daemon.py", "tools/verification/sshx11_data_plane_daemon.py", "tools/verification/sshx11_plane_model.py"),),
            test=(cmd("control-plane.pytest", "Run control-plane and ops unit tests.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11_plane_model.py", "tests/test_sshx11_plane_service.py", "tests/test_sshx11_ops_script.py"),),
            verify=(cmd("control-plane.status", "Read local control/data-plane status.", "tools/verification/sshx11_ops.sh", "status-local"),),
            deploy=(cmd("control-plane.service-start", "Start local control/data-plane daemons.", "tools/verification/sshx11_ops.sh", "service-start", risk=RISK_DAEMON), cmd("control-plane.service-status", "Check local daemon status after start.", "tools/verification/sshx11_ops.sh", "status-local", risk=RISK_DAEMON)),
        ),
        target(
            "dataplane-policy",
            "component",
            "Dataplane Firewall, OpenFlow, and Cilium Policy Planner",
            "Declarative dataflow policy renderer for iptables, OVS/OpenFlow, and CiliumNetworkPolicy plans.",
            ("tools/verification/sshx11_dataplane_iptables.py", "docs/specs/dataplane_firewall_policy.md", "tests/test_sshx11_dataplane_iptables.py"),
            ("dataplane", "firewall", "ovs", "cilium"),
            develop=(cmd("dataplane.py-compile", "Compile dataplane policy planner.", "python3", "-m", "py_compile", "tools/verification/sshx11_dataplane_iptables.py"),),
            test=(cmd("dataplane.pytest", "Run dataplane policy unit tests.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11_dataplane_iptables.py"),),
            verify=(cmd("dataplane.json-plan", "Render JSON dataplane policy plan.", "python3", "tools/verification/sshx11_dataplane_iptables.py", "plan", "--include-webdav", "--include-9p", "--format", "json"), cmd("dataplane.openflow-plan", "Render OVS/OpenFlow policy plan.", "python3", "tools/verification/sshx11_dataplane_iptables.py", "plan", "--backend", "ovs-openflow", "--format", "json")),
            deploy=(cmd("dataplane.restore-plan", "Render iptables-restore payload; apply manually after review.", "python3", "tools/verification/sshx11_dataplane_iptables.py", "plan", "--include-webdav", "--include-9p", "--format", "restore"),),
        ),
        target(
            "vfs-9p",
            "component",
            "9P VFS Service",
            "Read-only 9P service, container image, service manager, and 9P-over-SOCKS runner.",
            ("cmd/wv-9p", "internal/p9svc", "tools/verification/sshx11_9p_service.py", "tools/containers/wv-9p.Containerfile"),
            ("vfs", "9p", "container"),
            develop=(cmd("vfs-9p.build", "Build the 9P service binary.", "make", "build-9p"),),
            test=(cmd("vfs-9p.pytest", "Run 9P service and runner tests.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11_9p_service.py", "tests/test_sshx11_9p_over_socks_runner.py"), cmd("vfs-9p.go-tests", "Run internal 9P service Go tests.", "go", "test", "./internal/p9svc")),
            verify=(cmd("vfs-9p.plan", "Render 9P service launch plan.", "tools/verification/sshx11_ops.sh", "9p-plan"),),
            deploy=(cmd("vfs-9p.start", "Start the local 9P service.", "tools/verification/sshx11_ops.sh", "9p-start", risk=RISK_DAEMON), cmd("vfs-9p.status", "Check local 9P service status.", "tools/verification/sshx11_ops.sh", "9p-status", risk=RISK_DAEMON)),
        ),
        target(
            "vfs-mesh",
            "component",
            "Distributed VFS Mesh",
            "Per-host VFS registry, materialized mesh namespace, WebDAV/9P metadata view, and TLA/Lean bridge tests.",
            ("tools/verification/sshx11_vfs_agent.py", "tools/verification/sshx11_vfs_mesh.py", "tests/test_sshx11_vfs_agent.py"),
            ("vfs", "mesh", "webdav"),
            develop=(cmd("vfs-mesh.py-compile", "Compile VFS mesh modules.", "python3", "-m", "py_compile", "tools/verification/sshx11_vfs_agent.py", "tools/verification/sshx11_vfs_mesh.py"),),
            test=(cmd("vfs-mesh.pytest", "Run VFS mesh tests.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11_vfs_agent.py", "tests/test_sshx11_vfs_mesh_tla_contract.py"),),
            verify=(cmd("vfs-mesh.status", "Show materialized VFS mesh namespace status.", "tools/verification/sshx11_ops.sh", "vfs-mesh-status"),),
            deploy=(cmd("vfs-mesh.build", "Build materialized VFS mesh namespace.", "tools/verification/sshx11_ops.sh", "vfs-mesh-build", risk=RISK_DAEMON),),
        ),
        target(
            "transport-socks",
            "component",
            "SOCKS, Reverse SOCKS, Relay, and Profile Routing",
            "Local SOCKS proxy, reverse SOCKS manager, relay/pump behavior, and realtime/bulk route selection.",
            ("internal/app/socks.go", "relay", "tools/verification/sshx11_reverse_socks_service.py", "tools/verification/sshx11_socks_fallback_service.py"),
            ("socks", "relay", "transport"),
            develop=(cmd("transport.build", "Build agent and SOCKS binaries.", "make", "build-agent", "build-socks"),),
            test=(cmd("transport.pytest", "Run SOCKS/transport/profile tests.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11_socks5_udp_associate.py", "tests/test_sshx11_profile_routed_transfer_session_unit.py", "tests/test_sshx11_transport_profiles_benchmark.py"), cmd("transport.go-tests", "Run relay/tunnel Go tests.", "go", "test", "./relay", "./tunnel")),
            verify=(cmd("transport.socks-status", "Show SOCKS fallback service status.", "tools/verification/sshx11_ops.sh", "socks-fallback-status"),),
            deploy=(cmd("transport.socks-start", "Start SOCKS fallback service.", "tools/verification/sshx11_ops.sh", "socks-fallback-start", risk=RISK_DAEMON),),
        ),
        target(
            "backhaul-multihop",
            "component",
            "SCP/SFTP Backhaul and Multi-Hop Chains",
            "Backhaul planner and SSH multi-hop chain orchestration, including endpoint-to-origin file return.",
            ("tools/verification/sshx11_scp_sftp_backhaul.py", "tools/verification/sshx11_multihop_chain.py", "tests/test_sshx11_scp_sftp_backhaul_unit.py"),
            ("scp", "sftp", "multihop", "ssh"),
            develop=(cmd("backhaul.py-compile", "Compile backhaul and multihop modules.", "python3", "-m", "py_compile", "tools/verification/sshx11_scp_sftp_backhaul.py", "tools/verification/sshx11_multihop_chain.py"),),
            test=(cmd("backhaul.pytest", "Run backhaul and multihop unit tests.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11_scp_sftp_backhaul_unit.py", "tests/test_sshx11_multihop_chain_unit.py"),),
            verify=(cmd("backhaul.remote-plan", "Render remote execution verification plan.", "tools/verification/sshx11_ops.sh", "verify-remote", "plan"),),
            deploy=(cmd("backhaul.system-test", "Run remote multi-hop system tests when SSH hosts are configured.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11_multihop_chain_system.py", risk=RISK_REMOTE),),
        ),
        target(
            "extension-ui-api",
            "component",
            "VS Code Extension and UI API",
            "Extension command map, API contract, command catalog, and UI driver API surface.",
            ("extensions/vscode-sshx11", "tests/test_vscode_ui_driver_api.py", "tests/test_sshx11_extension_set_tla.py"),
            ("vscode", "ui", "api"),
            develop=(cmd("extension.smoke-contract", "Run extension API contract smoke script.", "python3", "extensions/vscode-sshx11/scripts/smoke_api_contract.py"),),
            test=(cmd("extension.pytest", "Run extension/API Python tests.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_vscode_ui_driver_api.py", "tests/test_sshx11_extension_set_tla.py"),),
            verify=(cmd("extension.verify-hosts", "Verify extension host profile paths.", "tools/verification/sshx11_ops.sh", "verify-extension-hosts", "--plan"),),
            deploy=(cmd("extension.profile-gen", "Generate VS Code profile/MCP wiring.", "tools/verification/sshx11_ops.sh", "vscode-profile-gen"),),
        ),
        target(
            "per-user-api",
            "component",
            "Per-User API Daemon and Local Service Installer",
            "sshx11d API daemon plus launchd/systemd/Task Scheduler user-service planning.",
            ("tools/verification/sshx11d.py", "tools/verification/sshx11_user_service_install.py", "extensions/vscode-sshx11/data/api-contract.v1.json"),
            ("api", "daemon", "service"),
            develop=(cmd("per-user-api.py-compile", "Compile per-user API and installer modules.", "python3", "-m", "py_compile", "tools/verification/sshx11d.py", "tools/verification/sshx11_user_service_install.py"),),
            test=(cmd("per-user-api.pytest", "Run API contract and user-service installer tests.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11d_contract_sync.py", "tests/test_sshx11_user_service_install.py"),),
            verify=(cmd("per-user-api.contract", "Verify sshx11d contract sync.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11d_contract_sync.py"),),
            deploy=(cmd("per-user-api.install-plan", "Render per-user service install plan.", "python3", "tools/verification/sshx11_user_service_install.py", "plan"),),
        ),
        target(
            "formal-contracts",
            "component",
            "Formal Models and Runtime Contract Drift Checks",
            "TLA+, Lean-adjacent checks, runtime trace/refinement, and generated diagram fidelity.",
            ("verification/tla", "tools/verification/verify_sshx11_tlc_trace_suite.py", "tools/verification/generate_tla_mermaid.py"),
            ("formal", "tla", "contracts"),
            develop=(cmd("formal.generate-diagrams-plan", "List generated TLA diagram artifacts.", "python3", "tools/verification/generate_tla_mermaid.py", "--help"),),
            test=(cmd("formal.pytest", "Run TLA trace and diagram tests.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11_tlc_trace_suite.py", "tests/test_tla_mermaid_diagrams.py", "tests/test_sshx11_contract_drift_report.py"),),
            verify=(cmd("formal.verify-tlc", "Run TLC trace suite verifier.", "tools/verification/sshx11_ops.sh", "verify-fsm"), cmd("formal.verify-crypto", "Run crypto cross-layer verifier.", "tools/verification/sshx11_ops.sh", "verify-crypto")),
            deploy=(cmd("formal.trace-local", "Emit local implementation probe trace.", "python3", "tools/verification/emit_sshx11_impl_probe_trace.py"),),
        ),
        target(
            "end-user-workflows",
            "workflow",
            "End-User No-Build Workflows",
            "UC01-UC13 documented user workflows covering local probes, extension profiles, multi-hop, and backhaul scenarios.",
            ("tools/verification/end_user_usecases", "docs/end_user_no_build_usecases_workbench.md"),
            ("end-user", "workflow", "no-build"),
            develop=(cmd("end-user.list", "List no-build use case runner options.", "python3", "tools/verification/end_user_usecases/run_end_user_usecases_suite.py", "--help"),),
            test=(cmd("end-user.pytest", "Run no-build workflow tests.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11_end_user_usecases_suite.py"),),
            verify=(cmd("end-user.system-suite", "Run end-user system suite; remote-only cases self-skip when unavailable.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11_end_user_usecases_system.py"),),
            deploy=(cmd("end-user.run-suite", "Run the no-build use-case suite.", "python3", "tools/verification/end_user_usecases/run_end_user_usecases_suite.py"),),
        ),
        target(
            "local-service-workflow",
            "workflow",
            "Local Service Lifecycle Workflow",
            "Start, stop, restart, status, and log tracing for control/data-plane processes.",
            ("tools/verification/sshx11_ops.sh", "tools/verification/sshx11_plane_service.py"),
            ("service", "workflow", "daemon"),
            develop=(cmd("local-service.status-plan", "Show local service status command wiring.", "tools/verification/sshx11_ops.sh", "status-local"),),
            test=(cmd("local-service.ops-tests", "Run operator script tests.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11_ops_script.py", "tests/test_sshx11_plane_service.py"),),
            verify=(cmd("local-service.status", "Check local service status.", "tools/verification/sshx11_ops.sh", "status-local"),),
            deploy=(cmd("local-service.start", "Start local services.", "tools/verification/sshx11_ops.sh", "service-start", risk=RISK_DAEMON), cmd("local-service.restart", "Restart local services.", "tools/verification/sshx11_ops.sh", "service-restart", risk=RISK_DAEMON)),
        ),
        target(
            "remote-linode-workflow",
            "workflow",
            "Remote Linode SSH Workflow",
            "Live SSH login matrix, remote compatibility, and remote e2e orchestration for configured hosts.",
            ("tools/verification/check_linode_ssh_login_matrix.py", "tests/test_sshx11_linode_ssh_login_matrix.py", "tools/verification/sshx11_remote_system_e2e.py"),
            ("remote", "linode", "ssh", "workflow"),
            develop=(cmd("remote.discovery-tests", "Run remote discovery unit tests.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11_linode_ssh_login_matrix.py", "-m", "unit"),),
            test=(cmd("remote.unit-tests", "Run remote orchestration unit tests.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11_remote_system_e2e_unit.py", "tests/test_sshx11_linode_ssh_login_matrix.py", "-m", "unit"),),
            verify=(cmd("remote.login-matrix", "Run live Linode login matrix if keys/hosts are configured.", "python3", "tools/verification/check_linode_ssh_login_matrix.py", risk=RISK_REMOTE),),
            deploy=(cmd("remote.system-e2e", "Run remote SSH/SCP e2e orchestrator.", "tools/verification/sshx11_ops.sh", "test-remote", risk=RISK_REMOTE),),
        ),
        target(
            "webdav-workflow",
            "workflow",
            "WebDAV File Endpoint Workflow",
            "Local WebDAV endpoint used by extension-host and VFS workflows.",
            ("tools/verification/sshx11_webdav_service.py", "tools/verification/sshx11_ops.sh"),
            ("webdav", "workflow", "files"),
            develop=(cmd("webdav.py-compile", "Compile WebDAV service module.", "python3", "-m", "py_compile", "tools/verification/sshx11_webdav_service.py"),),
            test=(cmd("webdav.ops-tests", "Run ops script tests that cover WebDAV command wiring.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11_ops_script.py"),),
            verify=(cmd("webdav.status", "Check WebDAV service status.", "tools/verification/sshx11_ops.sh", "webdav-status"),),
            deploy=(cmd("webdav.start", "Start WebDAV service.", "tools/verification/sshx11_ops.sh", "webdav-start", risk=RISK_DAEMON),),
        ),
        target(
            "collab-repl-workflow",
            "workflow",
            "Collaborative REPL and Terminal Workflow",
            "FIFO/tmux/screen collaborative terminal, recording, and publish probes.",
            ("tools/verification/sshx11_collab_terminal.py", "tools/verification/sshx11_vhs_record.py", "tests/test_sshx11_collab_terminal.py"),
            ("repl", "terminal", "workflow"),
            develop=(cmd("collab.py-compile", "Compile collaborative terminal modules.", "python3", "-m", "py_compile", "tools/verification/sshx11_collab_terminal.py", "tools/verification/sshx11_vhs_record.py"),),
            test=(cmd("collab.pytest", "Run collaborative terminal and VHS tests.", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_sshx11_collab_terminal.py", "tests/test_sshx11_vhs_record.py"),),
            verify=(cmd("collab.probe", "Probe collaborative terminal backend availability.", "tools/verification/sshx11_ops.sh", "repl-probe"),),
            deploy=(cmd("collab.start", "Start collaborative REPL session.", "tools/verification/sshx11_ops.sh", "repl-start", risk=RISK_DAEMON),),
        ),
    )


def target_map() -> dict[str, TargetSpec]:
    return {item.id: item for item in registry()}


def expand_targets(raw: str, *, kind: str | None = None) -> list[TargetSpec]:
    items = [item for item in registry() if kind in (None, item.kind)]
    if raw == "all":
        return items
    selected = target_map().get(raw)
    if selected is None:
        known = ", ".join(sorted(item.id for item in items))
        raise SystemExit(f"unknown target {raw!r}; known targets: {known}")
    if kind is not None and selected.kind != kind:
        raise SystemExit(f"target {raw!r} is kind {selected.kind!r}, not {kind!r}")
    return [selected]


def select_commands(targets: Iterable[TargetSpec], phase: str) -> list[tuple[TargetSpec, str, CommandSpec]]:
    phases = PHASES if phase == "all" else (phase,)
    selected: list[tuple[TargetSpec, str, CommandSpec]] = []
    for item in targets:
        for phase_name in phases:
            for spec in item.phases[phase_name]:
                selected.append((item, phase_name, spec))
    return selected


def command_to_dict(item: TargetSpec, phase: str, spec: CommandSpec) -> dict[str, object]:
    return {
        "target_id": item.id,
        "kind": item.kind,
        "phase": phase,
        "command_id": spec.id,
        "description": spec.description,
        "risk": spec.risk,
        "argv": list(spec.argv),
    }


def render_table(items: Iterable[TargetSpec]) -> str:
    rows = [(item.id, item.kind, ",".join(item.tags), item.name) for item in items]
    widths = [max(len(row[idx]) for row in rows + [("target", "kind", "tags", "name")]) for idx in range(4)]
    lines = [f"{'target'.ljust(widths[0])}  {'kind'.ljust(widths[1])}  {'tags'.ljust(widths[2])}  name"]
    for row in rows:
        lines.append(f"{row[0].ljust(widths[0])}  {row[1].ljust(widths[1])}  {row[2].ljust(widths[2])}  {row[3]}")
    return "\n".join(lines)


def render_plan(commands: Iterable[tuple[TargetSpec, str, CommandSpec]], fmt: str) -> str:
    entries = [command_to_dict(item, phase, spec) for item, phase, spec in commands]
    if fmt == "json":
        return json.dumps({"ok": True, "commands": entries}, indent=2, sort_keys=True)
    if fmt == "shell":
        lines: list[str] = []
        for entry in entries:
            quoted = " ".join(subprocess.list2cmdline([str(part)]) for part in entry["argv"])  # type: ignore[index]
            lines.append(f"# {entry['target_id']} {entry['phase']} {entry['command_id']} risk={entry['risk']}")
            lines.append(quoted)
        return "\n".join(lines)
    lines = []
    for entry in entries:
        argv = " ".join(str(part) for part in entry["argv"])
        lines.append(f"[{entry['kind']}/{entry['target_id']}] {entry['phase']} {entry['command_id']} risk={entry['risk']}\n  {argv}\n  {entry['description']}")
    return "\n".join(lines)


def validate_registry() -> list[str]:
    errors: list[str] = []
    ids: set[str] = set()
    command_ids: set[str] = set()
    for item in registry():
        if item.id in ids:
            errors.append(f"duplicate target id: {item.id}")
        ids.add(item.id)
        if item.kind not in {"component", "workflow"}:
            errors.append(f"{item.id}: invalid kind {item.kind}")
        for path in item.paths:
            if not (REPO_ROOT / path).exists():
                errors.append(f"{item.id}: missing path {path}")
        for phase in PHASES:
            commands = item.phases.get(phase, ())
            if not commands:
                errors.append(f"{item.id}: missing commands for phase {phase}")
            for spec in commands:
                if spec.id in command_ids:
                    errors.append(f"duplicate command id: {spec.id}")
                command_ids.add(spec.id)
                if not spec.argv:
                    errors.append(f"{item.id}/{phase}/{spec.id}: empty argv")
                if spec.risk not in {RISK_SAFE, RISK_DAEMON, RISK_PRIVILEGED, RISK_REMOTE, RISK_EXTERNAL}:
                    errors.append(f"{item.id}/{phase}/{spec.id}: invalid risk {spec.risk}")
    return errors


def run_commands(commands: Iterable[tuple[TargetSpec, str, CommandSpec]], *, include_risks: set[str], dry_run: bool) -> int:
    for item, phase, spec in commands:
        label = f"{item.id}:{phase}:{spec.id}"
        if spec.risk != RISK_SAFE and spec.risk not in include_risks:
            print(f"refusing {label}: risk={spec.risk}; pass --include-risk {spec.risk} to execute", file=sys.stderr)
            return 3
        print(f"==> {label}")
        print("    " + " ".join(spec.argv))
        if not dry_run:
            proc = subprocess.run(list(spec.argv), cwd=REPO_ROOT)
            if proc.returncode != 0:
                return proc.returncode
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("table", "text", "json", "shell"), default="text")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="List registered targets")
    p_list.add_argument("--kind", choices=("component", "workflow"))

    p_show = sub.add_parser("show", help="Show one target")
    p_show.add_argument("target")

    p_plan = sub.add_parser("plan", help="Render command plan")
    p_plan.add_argument("target", help="Target id or all")
    p_plan.add_argument("--kind", choices=("component", "workflow"))
    p_plan.add_argument("--phase", choices=(*PHASES, "all"), default="verify")

    p_run = sub.add_parser("run", help="Execute or dry-run command plan")
    p_run.add_argument("target", help="Target id or all")
    p_run.add_argument("--kind", choices=("component", "workflow"))
    p_run.add_argument("--phase", choices=(*PHASES, "all"), default="verify")
    p_run.add_argument("--execute", action="store_true", help="Execute commands. Default is dry-run.")
    p_run.add_argument("--include-risk", action="append", default=[], choices=(RISK_DAEMON, RISK_PRIVILEGED, RISK_REMOTE, RISK_EXTERNAL), help="Allow execution of risky commands; repeatable.")

    sub.add_parser("check", help="Validate registry integrity")

    args = parser.parse_args(argv)
    fmt = args.format

    if args.command == "list":
        items = [item for item in registry() if args.kind in (None, item.kind)]
        if fmt == "json":
            print(json.dumps({"ok": True, "targets": [asdict(item) for item in items]}, indent=2, sort_keys=True))
        else:
            print(render_table(items))
        return 0

    if args.command == "show":
        item = target_map().get(args.target)
        if item is None:
            raise SystemExit(f"unknown target {args.target!r}")
        if fmt == "json":
            print(json.dumps({"ok": True, "target": asdict(item)}, indent=2, sort_keys=True))
        else:
            print(render_table([item]))
            print()
            print(item.description)
        return 0

    if args.command == "plan":
        targets = expand_targets(args.target, kind=args.kind)
        plan_format = fmt if fmt in {"json", "shell"} else "text"
        print(render_plan(select_commands(targets, args.phase), plan_format))
        return 0

    if args.command == "run":
        targets = expand_targets(args.target, kind=args.kind)
        return run_commands(select_commands(targets, args.phase), include_risks=set(args.include_risk), dry_run=not args.execute)

    if args.command == "check":
        errors = validate_registry()
        if fmt == "json":
            print(json.dumps({"ok": not errors, "errors": errors, "target_count": len(registry())}, indent=2, sort_keys=True))
        elif errors:
            print("registry errors:", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
        else:
            print(f"registry ok: {len(registry())} targets")
        return 0 if not errors else 1

    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
