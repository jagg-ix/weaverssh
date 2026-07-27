#!/usr/bin/env python3
"""Single trigger point for weaverssh repository workflows.

This dispatcher intentionally wraps existing Make targets and scripts instead of
reimplementing their behavior. The default `core` surface is product/operator
oriented. Validation harnesses such as Jepsen are exposed only through the
`validation` surface so they are not presented as weaverssh application
subcommands.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SURFACE = "core"


@dataclass(frozen=True)
class Workflow:
    name: str
    description: str
    command: tuple[str, ...]
    category: str
    surfaces: tuple[str, ...] = (DEFAULT_SURFACE,)
    destructive: bool = False
    notes: str = ""
    example: str = ""


@dataclass(frozen=True)
class Surface:
    name: str
    title: str
    script: str
    description: str


SURFACES: dict[str, Surface] = {
    "core": Surface(
        "core",
        "weaverssh workflow trigger",
        "./weaverssh",
        "Product, packaging, deployment, and local development workflows.",
    ),
    "validation": Surface(
        "validation",
        "weaverssh validation trigger",
        "./weaverssh-validate",
        "Validation harness workflows, including Jepsen and destructive SUT tests.",
    ),
}

WORKFLOWS: tuple[Workflow, ...] = (
    Workflow(
        "status",
        "Show concise repository status.",
        ("git", "status", "--short"),
        "inspect",
        example="./weaverssh run status",
    ),
    Workflow(
        "doctor",
        "Check local development prerequisites and package surfaces.",
        ("make", "dev-doctor"),
        "local",
        example="./weaverssh run doctor",
    ),
    Workflow(
        "dev-fast",
        "Run fast local developer validation without release binaries.",
        ("make", "dev-fast"),
        "local",
        example="./weaverssh run dev-fast",
    ),
    Workflow(
        "dev-check",
        "Run complete local development checks.",
        ("make", "dev-check"),
        "local",
        example="./weaverssh run dev-check",
    ),
    Workflow(
        "component-list",
        "List component/workflow registry targets.",
        ("make", "component-workflows-list"),
        "workbench",
        example="./weaverssh run component-list",
    ),
    Workflow(
        "component-check",
        "Validate component/workflow registry targets.",
        ("make", "component-workflows-check"),
        "workbench",
        example="./weaverssh run component-check",
    ),
    Workflow(
        "workflow-plan",
        "Print development install/deploy/verify plans for supported workflows.",
        ("sh", "-c", "make install-dev-plan && make deploy-local-plan && make verify-workflows-plan"),
        "workbench",
        example="./weaverssh run workflow-plan",
    ),
    Workflow(
        "binary-dist",
        "Build source-free binary distribution archive.",
        ("make", "binary-dist"),
        "package",
        notes="Pass BINARY_DIST_TARGET=linux/amd64 or another target as an extra argument when needed.",
        example="./weaverssh run binary-dist BINARY_DIST_TARGET=linux/amd64",
    ),
    Workflow(
        "homebrew-formula-plan",
        "Print Homebrew Formula generation plan from binary distribution archives.",
        ("make", "homebrew-formula-plan"),
        "package",
        notes="Set HOMEBREW_ARCHIVE or HOMEBREW_ARCHIVES. Set HOMEBREW_URL_BASE for release URLs instead of local file URLs.",
        example="./weaverssh run homebrew-formula-plan HOMEBREW_ARCHIVE=dist/binary/weaverssh-0.1.0-1-darwin-arm64.tar.gz",
    ),
    Workflow(
        "homebrew-formula",
        "Generate Homebrew Formula/weaverssh.rb from binary distribution archives.",
        ("make", "homebrew-formula"),
        "package",
        notes="Output defaults to dist/homebrew/Formula/weaverssh.rb.",
        example="./weaverssh run homebrew-formula HOMEBREW_ARCHIVE=dist/binary/weaverssh-0.1.0-1-darwin-arm64.tar.gz",
    ),
    Workflow(
        "snap-plan",
        "Print Snap package/project generation plan.",
        ("make", "package-snap-plan"),
        "package",
        notes="Set SNAP_BINARY to an existing Linux wv binary. The plan does not require snapcraft.",
        example="./weaverssh run snap-plan SNAP_BINARY=build/linux-x86_64/wv SNAP_ARCH=amd64",
    ),
    Workflow(
        "snap-project",
        "Generate dist/snap/weaverssh snapcraft project from a Linux wv binary.",
        ("make", "package-snap-project"),
        "package",
        notes="Requires SNAP_BINARY to exist. Does not run snapcraft.",
        example="./weaverssh run snap-project SNAP_BINARY=build/linux-x86_64/wv SNAP_ARCH=amd64",
    ),
    Workflow(
        "snap-package",
        "Build a .snap with snapcraft from a generated project.",
        ("make", "package-snap"),
        "package",
        notes="Requires snapcraft on Linux and an existing SNAP_BINARY.",
        example="./weaverssh run snap-package SNAP_BINARY=build/linux-x86_64/wv SNAP_ARCH=amd64",
    ),
    Workflow(
        "python-dist",
        "Build production Python support distribution archive.",
        ("make", "python-dist"),
        "package",
        example="./weaverssh run python-dist",
    ),
    Workflow(
        "ansible-syntax",
        "Run syntax checks for all weaverssh Ansible playbooks.",
        ("make", "ansible-syntax-check"),
        "ansible",
        example="./weaverssh run ansible-syntax",
    ),
    Workflow(
        "ansible-posix-plan",
        "Print POSIX SSH host Ansible install command.",
        ("make", "ansible-install-plan"),
        "ansible",
        example="./weaverssh run ansible-posix-plan ANSIBLE_INVENTORY=inventory.ini ANSIBLE_WV_ARCHIVE=dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz",
    ),
    Workflow(
        "ansible-posix-install",
        "Install wv onto POSIX SSH hosts with Ansible.",
        ("make", "ansible-install-wv"),
        "ansible",
        example="./weaverssh run ansible-posix-install ANSIBLE_INVENTORY=inventory.ini ANSIBLE_WV_ARCHIVE=dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz ANSIBLE_WV_CHECKSUM=<sha256>",
    ),
    Workflow(
        "ansible-docker-plan",
        "Print Docker/Podman runtime Ansible install command.",
        ("make", "ansible-install-docker-plan"),
        "ansible",
        example="./weaverssh run ansible-docker-plan ANSIBLE_DOCKER_CONTAINER=<container>",
    ),
    Workflow(
        "ansible-docker-install",
        "Install wv into a running Docker/Podman container.",
        ("make", "ansible-install-docker"),
        "ansible",
        example="./weaverssh run ansible-docker-install ANSIBLE_DOCKER_CONTAINER=<container> ANSIBLE_WV_ARCHIVE=dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz",
    ),
    Workflow(
        "ansible-k8s-plan",
        "Print Kubernetes pod Ansible install command.",
        ("make", "ansible-install-k8s-plan"),
        "ansible",
        example="./weaverssh run ansible-k8s-plan ANSIBLE_K8S_NAMESPACE=<namespace> ANSIBLE_K8S_POD=<pod>",
    ),
    Workflow(
        "ansible-k8s-install",
        "Install wv into a running Kubernetes pod.",
        ("make", "ansible-install-k8s"),
        "ansible",
        example="./weaverssh run ansible-k8s-install ANSIBLE_K8S_NAMESPACE=<namespace> ANSIBLE_K8S_POD=<pod> ANSIBLE_WV_ARCHIVE=dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz",
    ),
    Workflow(
        "bench-plan",
        "Generate a non-mutating validation workbench report with Jepsen planning evidence.",
        ("tools/verification/build_weaverssh_test_bench.sh", "--jepsen", "--no-tests"),
        "workbench",
        surfaces=("validation",),
        example="./weaverssh-validate run bench-plan",
    ),
    Workflow(
        "jepsen-unit",
        "Validate Jepsen infrastructure without contacting SUT hosts.",
        ("make", "jepsen-unit"),
        "jepsen",
        surfaces=("validation",),
        example="./weaverssh-validate run jepsen-unit",
    ),
    Workflow(
        "jepsen-plan",
        "Generate a non-mutating Jepsen validation plan.",
        ("make", "jepsen-plan"),
        "jepsen",
        surfaces=("validation",),
        example="./weaverssh-validate run jepsen-plan JEPSEN_NODES=203.0.113.10,203.0.113.20 JEPSEN_USER=kb",
    ),
    Workflow(
        "jepsen-system",
        "Run Jepsen against disposable SUT nodes.",
        ("make", "jepsen-system"),
        "jepsen",
        surfaces=("validation",),
        destructive=True,
        notes="Requires --allow-destructive or ALLOW_DESTRUCTIVE=1.",
        example="./weaverssh-validate run jepsen-system --allow-destructive JEPSEN_NODES=203.0.113.10,203.0.113.20 JEPSEN_USER=kb",
    ),
    Workflow(
        "jepsen-ansible-plan",
        "Plan Jepsen workload that installs Ansible and runs the weaverssh Ansible playbook.",
        ("make", "jepsen-ansible-install-plan"),
        "jepsen",
        surfaces=("validation",),
        example="./weaverssh-validate run jepsen-ansible-plan JEPSEN_NODES=203.0.113.10,203.0.113.20 JEPSEN_USER=kb JEPSEN_ANSIBLE_ARCHIVE=dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz",
    ),
    Workflow(
        "jepsen-ansible-system",
        "Execute Jepsen Ansible install workload on disposable SUT nodes.",
        ("make", "jepsen-ansible-install-system"),
        "jepsen",
        surfaces=("validation",),
        destructive=True,
        notes="Requires --allow-destructive or ALLOW_DESTRUCTIVE=1.",
        example="./weaverssh-validate run jepsen-ansible-system --allow-destructive JEPSEN_NODES=203.0.113.10,203.0.113.20 JEPSEN_USER=kb JEPSEN_ANSIBLE_ARCHIVE=dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz JEPSEN_ANSIBLE_CHECKSUM=<sha256>",
    ),
)


def workflows_for_surface(surface_name: str) -> tuple[Workflow, ...]:
    return tuple(workflow for workflow in WORKFLOWS if surface_name in workflow.surfaces)


def workflow_map_for_surface(surface_name: str) -> dict[str, Workflow]:
    return {workflow.name: workflow for workflow in workflows_for_surface(surface_name)}


WORKFLOW_BY_NAME = workflow_map_for_surface(DEFAULT_SURFACE)
ALL_WORKFLOW_BY_NAME = {workflow.name: workflow for workflow in WORKFLOWS}


def usage(surface: Surface) -> str:
    return f"""{surface.title}

{surface.description}

Usage:
  {surface.script} list
  {surface.script} plan <workflow> [VAR=value ... | extra args]
  {surface.script} run <workflow> [--allow-destructive] [VAR=value ... | extra args]
  {surface.script} help <workflow>

Use `plan` to print the exact command without executing it. Use `run` to execute.
Destructive workflows require --allow-destructive or ALLOW_DESTRUCTIVE=1.
"""


def list_workflows(surface: Surface) -> str:
    workflows = workflows_for_surface(surface.name)
    categories = sorted({workflow.category for workflow in workflows})
    lines = ["Available workflows:"]
    for category in categories:
        lines.append(f"\n[{category}]")
        for workflow in workflows:
            if workflow.category != category:
                continue
            marker = " destructive" if workflow.destructive else ""
            lines.append(f"  {workflow.name:<28} {workflow.description}{marker}")
    return "\n".join(lines)


def workflow_help(workflow: Workflow) -> str:
    lines = [workflow.name, "", workflow.description]
    lines.append("")
    lines.append("Command:")
    lines.append("  " + shlex.join(workflow.command))
    if workflow.destructive:
        lines.append("")
        lines.append("Destructive: yes. Requires --allow-destructive or ALLOW_DESTRUCTIVE=1.")
    if workflow.notes:
        lines.append("")
        lines.append("Notes:")
        lines.append("  " + workflow.notes)
    if workflow.example:
        lines.append("")
        lines.append("Example:")
        lines.append("  " + workflow.example)
    return "\n".join(lines)


def command_for(workflow: Workflow, extra: list[str]) -> list[str]:
    return [*workflow.command, *extra]


def print_plan(workflow: Workflow, extra: list[str]) -> None:
    cmd = command_for(workflow, extra)
    print(f"workflow: {workflow.name}")
    print(f"category: {workflow.category}")
    print(f"destructive: {'yes' if workflow.destructive else 'no'}")
    print(f"cwd: {REPO_ROOT}")
    print("command: " + shlex.join(cmd))
    if workflow.destructive:
        print("gate: pass --allow-destructive or set ALLOW_DESTRUCTIVE=1 before run")


def run_workflow(workflow: Workflow, extra: list[str]) -> int:
    env = os.environ.copy()
    allow = False
    filtered: list[str] = []
    for item in extra:
        if item == "--allow-destructive":
            allow = True
        else:
            filtered.append(item)
    if workflow.destructive:
        allow = allow or env.get("ALLOW_DESTRUCTIVE") == "1"
        if not allow:
            print(
                f"refusing to run destructive workflow {workflow.name!r}; pass --allow-destructive or set ALLOW_DESTRUCTIVE=1",
                file=sys.stderr,
            )
            return 2
        env["ALLOW_DESTRUCTIVE"] = "1"
    cmd = command_for(workflow, filtered)
    return subprocess.run(cmd, cwd=REPO_ROOT, env=env, check=False).returncode


def require_workflow(name: str, surface: Surface) -> Workflow:
    visible = workflow_map_for_surface(surface.name)
    try:
        return visible[name]
    except KeyError:
        if name in ALL_WORKFLOW_BY_NAME:
            print(
                f"workflow {name!r} is not available on {surface.script}; use the correct trigger surface",
                file=sys.stderr,
            )
        else:
            print(f"unknown workflow: {name}", file=sys.stderr)
        print("", file=sys.stderr)
        print(list_workflows(surface), file=sys.stderr)
        raise SystemExit(2)


def parse_surface(args: list[str]) -> tuple[Surface, list[str]]:
    surface_name = os.environ.get("WEAVERSSH_TRIGGER_SURFACE", DEFAULT_SURFACE)
    remaining: list[str] = []
    iterator = iter(args)
    for item in iterator:
        if item == "--surface":
            try:
                surface_name = next(iterator)
            except StopIteration:
                print("--surface requires a value", file=sys.stderr)
                raise SystemExit(2)
        elif item.startswith("--surface="):
            surface_name = item.split("=", 1)[1]
        else:
            remaining.append(item)
    try:
        return SURFACES[surface_name], remaining
    except KeyError:
        print(f"unknown trigger surface: {surface_name}", file=sys.stderr)
        print("available surfaces: " + ", ".join(sorted(SURFACES)), file=sys.stderr)
        raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    surface, args = parse_surface(raw_args)
    if not args or args[0] in {"-h", "--help"}:
        print(usage(surface))
        print(list_workflows(surface))
        return 0
    command = args.pop(0)
    if command == "list":
        print(list_workflows(surface))
        return 0
    if command in {"plan", "run", "help"}:
        if not args:
            print(f"{command} requires a workflow name", file=sys.stderr)
            return 2
        workflow = require_workflow(args.pop(0), surface)
        if command == "help":
            print(workflow_help(workflow))
            return 0
        if command == "plan":
            print_plan(workflow, args)
            return 0
        return run_workflow(workflow, args)
    print(f"unknown command: {command}", file=sys.stderr)
    print(usage(surface), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
