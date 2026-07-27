#!/usr/bin/env python3
"""Plan or run Jepsen fault-injection validation for weaverssh SUT nodes.

The default mode is safe: it writes a dry-run JSON plan and does not contact any
remote host. Real Jepsen execution requires both --execute and --allow-destructive.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
JEPSEN_ROOT = REPO_ROOT / "tools" / "jepsen" / "weaverssh"
DEFAULT_OUTPUT = REPO_ROOT / "artifacts" / "jepsen" / "weaverssh_jepsen_plan.json"
DEFAULT_NODES_FILE = REPO_ROOT / "artifacts" / "jepsen" / "nodes.txt"
SUPPORTED_WORKLOADS = {"x11-ws-handshake", "relay", "scp-backhaul", "vfs-9p", "ansible-install"}
SUPPORTED_NEMESES = {"none", "process-kill", "partition", "clock-skew"}


@dataclass(frozen=True)
class SSHOptions:
    username: str
    port: int
    identity_file: str | None


@dataclass(frozen=True)
class JepsenPlan:
    ok: bool
    status: str
    repo_root: str
    jepsen_root: str
    nodes: list[str]
    nodes_file: str
    ssh: SSHOptions
    remote_root: str
    workload: str
    nemesis: str
    time_limit: int
    concurrency: int
    store_dir: str
    command: list[str]
    destructive: bool
    ansible: dict[str, str]
    safety: dict[str, Any]


def parse_nodes(raw: str, nodes_file: Path | None) -> list[str]:
    nodes: list[str] = []
    if nodes_file is not None:
        if not nodes_file.exists():
            raise ValueError(f"nodes file does not exist: {nodes_file}")
        nodes.extend(line.strip() for line in nodes_file.read_text(encoding="utf-8").splitlines())
    if raw.strip():
        nodes.extend(part.strip() for part in raw.split(","))
    nodes = [node for node in nodes if node and not node.startswith("#")]
    deduped: list[str] = []
    seen: set[str] = set()
    for node in nodes:
        if node not in seen:
            seen.add(node)
            deduped.append(node)
    if not deduped:
        raise ValueError("provide at least one SUT node with --nodes or --nodes-file")
    return deduped


def write_nodes_file(nodes: list[str], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(nodes) + "\n", encoding="utf-8")
    return path


def build_command(args: argparse.Namespace, nodes_file: Path) -> list[str]:
    cmd = [
        args.clojure_bin,
        "-M:run",
        "test",
        "--nodes-file",
        str(nodes_file),
        "--username",
        args.username,
        "--ssh-port",
        str(args.ssh_port),
        "--remote-root",
        args.remote_root,
        "--workload",
        args.workload,
        "--nemesis",
        args.nemesis,
        "--time-limit",
        str(args.time_limit),
        "--concurrency",
        str(args.concurrency),
        "--ansible-playbook",
        args.ansible_playbook,
        "--ansible-archive",
        args.ansible_archive,
        "--ansible-checksum",
        args.ansible_checksum,
        "--ansible-version",
        args.ansible_version,
        "--ansible-release",
        args.ansible_release,
    ]
    if args.identity_file:
        cmd.extend(["--ssh-private-key", str(Path(args.identity_file).expanduser())])
    if args.dry_run:
        cmd.append("--dry-run")
    return cmd


def build_plan(args: argparse.Namespace) -> JepsenPlan:
    nodes = parse_nodes(args.nodes, args.nodes_file)
    if args.workload not in SUPPORTED_WORKLOADS:
        raise ValueError(f"unsupported workload {args.workload!r}; use one of {sorted(SUPPORTED_WORKLOADS)}")
    if args.nemesis not in SUPPORTED_NEMESES:
        raise ValueError(f"unsupported nemesis {args.nemesis!r}; use one of {sorted(SUPPORTED_NEMESES)}")
    if args.ssh_port <= 0:
        raise ValueError("--ssh-port must be positive")
    if args.time_limit <= 0:
        raise ValueError("--time-limit must be positive")
    if args.concurrency <= 0:
        raise ValueError("--concurrency must be positive")

    nodes_file = write_nodes_file(nodes, args.generated_nodes_file)
    command = build_command(args, nodes_file)
    destructive = bool(args.execute and args.allow_destructive)
    status = "ready_to_execute" if destructive else "dry_run"
    return JepsenPlan(
        ok=True,
        status=status,
        repo_root=str(REPO_ROOT),
        jepsen_root=str(JEPSEN_ROOT),
        nodes=nodes,
        nodes_file=str(nodes_file),
        ssh=SSHOptions(username=args.username, port=args.ssh_port, identity_file=args.identity_file),
        remote_root=args.remote_root,
        workload=args.workload,
        nemesis=args.nemesis,
        time_limit=args.time_limit,
        concurrency=args.concurrency,
        store_dir=str(JEPSEN_ROOT / "store"),
        command=command,
        destructive=destructive,
        ansible={
            "playbook": args.ansible_playbook,
            "archive": args.ansible_archive,
            "checksum": args.ansible_checksum,
            "version": args.ansible_version,
            "release": args.ansible_release,
            "install_strategy": "install ansible on each SUT, then run the weaverssh POSIX playbook locally",
        },
        safety={
            "default_is_non_mutating": True,
            "execute_requires_allow_destructive": True,
            "intended_for_disposable_sut_nodes": True,
            "normal_unit_tests_do_not_contact_remote_hosts": True,
            "ansible_install_workload_mutates_sut_home_and_packages": True,
        },
    )


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def execute_plan(plan: JepsenPlan) -> int:
    if not shutil.which(plan.command[0]):
        print(f"missing Clojure executable: {plan.command[0]}", file=sys.stderr)
        return 2
    env = os.environ.copy()
    proc = subprocess.run(plan.command, cwd=str(JEPSEN_ROOT), text=True, env=env, check=False)
    return proc.returncode


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--nodes", default=os.getenv("WEAVERSSH_JEPSEN_NODES", ""), help="comma-separated SUT nodes")
    p.add_argument("--nodes-file", type=Path, default=None, help="file with one SUT node per line")
    p.add_argument("--generated-nodes-file", type=Path, default=DEFAULT_NODES_FILE, help="nodes file generated for Clojure/Jepsen")
    p.add_argument("--username", default=os.getenv("WEAVERSSH_JEPSEN_USER", "root"), help="SSH username")
    p.add_argument("--ssh-port", type=int, default=int(os.getenv("WEAVERSSH_JEPSEN_SSH_PORT", "22")), help="SSH port")
    p.add_argument("--identity-file", default=os.getenv("WEAVERSSH_JEPSEN_IDENTITY_FILE", "") or None, help="SSH private key path")
    p.add_argument("--remote-root", default=os.getenv("WEAVERSSH_JEPSEN_REMOTE_ROOT", "~/weaverssh-sut/current"), help="remote SUT root already deployed by sut-update")
    p.add_argument("--workload", default=os.getenv("WEAVERSSH_JEPSEN_WORKLOAD", "x11-ws-handshake"), help="workload name")
    p.add_argument("--nemesis", default=os.getenv("WEAVERSSH_JEPSEN_NEMESIS", "process-kill"), help="nemesis name")
    p.add_argument("--time-limit", type=int, default=int(os.getenv("WEAVERSSH_JEPSEN_TIME_LIMIT", "30")), help="Jepsen time limit in seconds")
    p.add_argument("--concurrency", type=int, default=int(os.getenv("WEAVERSSH_JEPSEN_CONCURRENCY", "4")), help="logical client count")
    p.add_argument("--ansible-playbook", default=os.getenv("WEAVERSSH_JEPSEN_ANSIBLE_PLAYBOOK", "ansible/playbooks/install_wv.yml"), help="remote-root-relative or absolute Ansible playbook path for ansible-install workload")
    p.add_argument("--ansible-archive", default=os.getenv("WEAVERSSH_JEPSEN_ANSIBLE_ARCHIVE", ""), help="remote-root-relative or absolute weaverssh binary archive path passed to the playbook")
    p.add_argument("--ansible-checksum", default=os.getenv("WEAVERSSH_JEPSEN_ANSIBLE_CHECKSUM", ""), help="optional SHA-256 checksum passed to the playbook")
    p.add_argument("--ansible-version", default=os.getenv("WEAVERSSH_JEPSEN_ANSIBLE_VERSION", "0.1.0"), help="weaverssh version passed to the Ansible role")
    p.add_argument("--ansible-release", default=os.getenv("WEAVERSSH_JEPSEN_ANSIBLE_RELEASE", "1"), help="weaverssh release passed to the Ansible role")
    p.add_argument("--clojure-bin", default=os.getenv("CLOJURE", "clojure"), help="Clojure executable")
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="JSON plan/report path")
    p.add_argument("--dry-run", action="store_true", help="write plan only; default unless --execute is used")
    p.add_argument("--execute", action="store_true", help="run Clojure/Jepsen after writing the plan")
    p.add_argument("--allow-destructive", action="store_true", help="required with --execute; acknowledges SUT mutation/fault injection")
    return p


def main(argv: list[str] | None = None) -> int:
    p = parser()
    args = p.parse_args(argv)
    if not args.execute:
        args.dry_run = True
    if args.execute and not args.allow_destructive:
        p.error("--execute requires --allow-destructive")
    try:
        plan = build_plan(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    payload = asdict(plan)
    write_json(args.output, payload)
    print(f"weaverssh-jepsen: {plan.status}")
    print(f"plan: {args.output}")
    print("command: " + " ".join(plan.command))
    if not args.execute:
        return 0
    rc = execute_plan(plan)
    payload["execution_exit_code"] = rc
    payload["ok"] = rc == 0
    payload["status"] = "executed" if rc == 0 else "failed"
    write_json(args.output, payload)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
