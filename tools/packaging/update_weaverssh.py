#!/usr/bin/env python3
from __future__ import annotations

"""Plan or execute a verified WeaverSSH package update with rollback journaling.

Execution is gated by ``--execute``. The updater verifies detached checksums and
archive safety using ``verify_release_artifact.py`` before invoking any native
installer. It snapshots the current wv executable and restores it if the health
check fails. Supplying ``--rollback-artifact`` enables package-manager rollback
instead of binary-only emergency restoration.
"""

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Sequence

SCHEMA = "weaverssh.update-transaction.v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = REPO_ROOT / "tools" / "packaging" / "verify_release_artifact.py"


@dataclass(frozen=True)
class UpdatePlan:
    schema: str
    artifact: str
    kind: str
    manager: str
    current_binary: str
    snapshot_dir: str
    snapshot_binary: str
    journal: str
    verify_command: list[str]
    install_commands: list[list[str]]
    health_command: list[str]
    rollback_artifact: str
    rollback_verify_command: list[str]
    rollback_install_commands: list[list[str]]
    emergency_restore_command: list[str]
    requires_privilege: bool
    notes: list[str]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_kind(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".pkg.tar.zst") or name.endswith(".pkg.tar.xz") or name.endswith(".pkg.tar.gz"):
        return "arch"
    if name.endswith(".deb"):
        return "deb"
    if name.endswith(".rpm"):
        return "rpm"
    if name.endswith(".pkg") and "freebsd" in name:
        return "freebsd-pkg"
    if name.endswith(".pkg"):
        return "macos-pkg"
    if name.endswith(".zip") and "windows" in name:
        return "windows-zip"
    raise ValueError(f"unsupported transactional update artifact: {path.name}")


def needs_privilege(kind: str) -> bool:
    return kind != "windows-zip"


def sudo_prefix(kind: str) -> list[str]:
    if not needs_privilege(kind):
        return []
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []
    return ["sudo"]


def normalize_manager(kind: str, manager: str) -> str:
    if manager != "auto":
        allowed = {
            "deb": {"apt", "dpkg"},
            "rpm": {"dnf", "yum", "zypper", "rpm"},
            "arch": {"pacman"},
            "freebsd-pkg": {"pkg"},
            "macos-pkg": {"installer"},
            "windows-zip": {"powershell"},
        }[kind]
        if manager not in allowed:
            raise ValueError(f"manager {manager!r} is not valid for {kind}")
        return manager
    return {
        "deb": "apt",
        "rpm": "dnf",
        "arch": "pacman",
        "freebsd-pkg": "pkg",
        "macos-pkg": "installer",
        "windows-zip": "powershell",
    }[kind]


def install_commands(kind: str, manager: str, artifact: Path, extract_dir: Path) -> list[list[str]]:
    prefix = sudo_prefix(kind)
    value = str(artifact.resolve())
    if kind == "deb":
        return [[*prefix, "apt-get", "install", "-y", value]] if manager == "apt" else [[*prefix, "dpkg", "-i", value]]
    if kind == "rpm":
        if manager == "dnf":
            return [[*prefix, "dnf", "install", "-y", value]]
        if manager == "yum":
            return [[*prefix, "yum", "localinstall", "-y", value]]
        if manager == "zypper":
            return [[*prefix, "zypper", "--non-interactive", "install", value]]
        return [[*prefix, "rpm", "-Uvh", value]]
    if kind == "arch":
        return [[*prefix, "pacman", "-U", "--noconfirm", value]]
    if kind == "freebsd-pkg":
        return [[*prefix, "pkg", "add", "-f", value]]
    if kind == "macos-pkg":
        return [[*prefix, "installer", "-pkg", value, "-target", "/"]]
    if kind == "windows-zip":
        install_script = extract_dir / "install.ps1"
        return [
            [sys.executable, "-m", "zipfile", "-e", value, str(extract_dir)],
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(install_script)],
        ]
    raise AssertionError(kind)


def verifier_command(artifact: Path, checksum: Path | None, rpm_family: str) -> list[str]:
    command = [sys.executable, str(VERIFIER), "verify", str(artifact.resolve()), "--rpm-family", rpm_family]
    if checksum is not None:
        command.extend(["--checksum", str(checksum.resolve())])
    return command


def find_current_binary(explicit: str) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    found = shutil.which("wv")
    return Path(found).resolve() if found else Path("wv").resolve()


def make_plan(
    artifact: Path,
    checksum: Path | None,
    manager: str,
    rpm_family: str,
    current_binary: str,
    snapshot_dir: Path,
    health_command: list[str],
    rollback_artifact: Path | None,
    rollback_checksum: Path | None,
) -> UpdatePlan:
    artifact = artifact.resolve()
    if not artifact.is_file():
        raise FileNotFoundError(artifact)
    kind = detect_kind(artifact)
    selected_manager = normalize_manager(kind, manager)
    current = find_current_binary(current_binary)
    snapshot_dir = snapshot_dir.expanduser().resolve()
    snapshot_binary = snapshot_dir / "wv.previous"
    if snapshot_binary == current:
        raise ValueError("snapshot binary must differ from the active wv binary")
    journal = snapshot_dir / "transaction.json"
    extract_dir = snapshot_dir / "windows-package"
    install = install_commands(kind, selected_manager, artifact, extract_dir)

    rollback_value = ""
    rollback_verify: list[str] = []
    rollback_install: list[list[str]] = []
    if rollback_artifact is not None:
        rollback_artifact = rollback_artifact.resolve()
        if not rollback_artifact.is_file():
            raise FileNotFoundError(rollback_artifact)
        if rollback_artifact == artifact:
            raise ValueError("rollback artifact must differ from the update artifact")
        rollback_kind = detect_kind(rollback_artifact)
        if rollback_kind != kind:
            raise ValueError("rollback artifact must use the same package kind")
        rollback_value = str(rollback_artifact)
        rollback_verify = verifier_command(rollback_artifact, rollback_checksum, rpm_family)
        rollback_install = install_commands(kind, selected_manager, rollback_artifact, snapshot_dir / "windows-rollback")

    health = health_command or [str(current), "version"]
    if os.name == "nt":
        restore = ["powershell", "-NoProfile", "-Command", f"Copy-Item -LiteralPath '{snapshot_binary}' -Destination '{current}' -Force"]
    else:
        restore = [*sudo_prefix(kind), "install", "-m", "0755", str(snapshot_binary), str(current)]
    notes = [
        "Artifact verification is mandatory and occurs before snapshot or installation.",
        "The transaction journal is rewritten atomically after each state transition.",
        "Without --rollback-artifact, rollback restores only the previous wv executable; package-manager metadata may still report the new version.",
        "No command runs unless --execute is supplied.",
    ]
    return UpdatePlan(
        schema=SCHEMA,
        artifact=str(artifact),
        kind=kind,
        manager=selected_manager,
        current_binary=str(current),
        snapshot_dir=str(snapshot_dir),
        snapshot_binary=str(snapshot_binary),
        journal=str(journal),
        verify_command=verifier_command(artifact, checksum, rpm_family),
        install_commands=install,
        health_command=health,
        rollback_artifact=rollback_value,
        rollback_verify_command=rollback_verify,
        rollback_install_commands=rollback_install,
        emergency_restore_command=restore,
        requires_privilege=needs_privilege(kind),
        notes=notes,
    )


def atomic_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    fd, name = tempfile.mkstemp(prefix=".transaction-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def run(command: Sequence[str]) -> None:
    subprocess.run(list(command), check=True)


def execute(plan: UpdatePlan, allow_no_current: bool, no_auto_rollback: bool) -> dict[str, object]:
    journal = Path(plan.journal)
    state: dict[str, object] = {"schema": SCHEMA, "state": "planned", "plan": asdict(plan)}
    atomic_json(journal, state)
    run(plan.verify_command)
    state["state"] = "verified"
    atomic_json(journal, state)

    current = Path(plan.current_binary)
    snapshot = Path(plan.snapshot_binary)
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    if current.is_file():
        shutil.copy2(current, snapshot)
        try:
            snapshot.chmod(0o700)
        except OSError:
            pass
        state["previous_sha256"] = sha256_file(snapshot)
        state["state"] = "snapshotted"
        atomic_json(journal, state)
    elif not allow_no_current:
        state["state"] = "failed"
        state["error"] = f"current wv binary not found: {current}"
        atomic_json(journal, state)
        raise FileNotFoundError(current)
    else:
        state["state"] = "snapshotted-none"
        atomic_json(journal, state)

    try:
        state["state"] = "installing"
        atomic_json(journal, state)
        if plan.kind == "windows-zip" and plan.install_commands:
            extract_dir = Path(plan.install_commands[0][-1])
            if extract_dir.exists():
                shutil.rmtree(extract_dir)
        for command in plan.install_commands:
            run(command)
        state["state"] = "health-check"
        atomic_json(journal, state)
        run(plan.health_command)
        state["state"] = "healthy"
        state["installed_sha256"] = sha256_file(current) if current.is_file() else ""
        atomic_json(journal, state)
        return {"ok": True, "state": "healthy", "journal": str(journal)}
    except Exception as exc:
        state["state"] = "install-failed"
        state["error"] = str(exc)
        atomic_json(journal, state)
        if no_auto_rollback:
            raise
        try:
            if plan.rollback_artifact:
                run(plan.rollback_verify_command)
                if plan.kind == "windows-zip" and plan.rollback_install_commands:
                    rollback_extract = Path(plan.rollback_install_commands[0][-1])
                    if rollback_extract.exists():
                        shutil.rmtree(rollback_extract)
                for command in plan.rollback_install_commands:
                    run(command)
                state["rollback"] = "package"
            elif snapshot.is_file():
                shutil.copy2(snapshot, current)
                try:
                    current.chmod(0o755)
                except OSError:
                    pass
                state["rollback"] = "binary-snapshot"
            else:
                state["rollback"] = "unavailable"
            state["state"] = "rolled-back"
            atomic_json(journal, state)
        except Exception as rollback_exc:
            state["state"] = "rollback-failed"
            state["rollback_error"] = str(rollback_exc)
            atomic_json(journal, state)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "update"), nargs="?", default="plan")
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--checksum", type=Path, default=None)
    parser.add_argument("--manager", choices=("auto", "apt", "dpkg", "dnf", "yum", "zypper", "rpm", "pacman", "pkg", "installer", "powershell"), default="auto")
    parser.add_argument("--rpm-family", choices=("redhat", "suse"), default="redhat")
    parser.add_argument("--current-binary", default="")
    parser.add_argument("--snapshot-dir", type=Path, default=Path.home() / ".weaverssh" / "update-snapshot")
    parser.add_argument("--health-command", action="append", default=[], help="One argv item; repeat to construct the health command")
    parser.add_argument("--rollback-artifact", type=Path, default=None)
    parser.add_argument("--rollback-checksum", type=Path, default=None)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--allow-no-current", action="store_true")
    parser.add_argument("--no-auto-rollback", action="store_true")
    args = parser.parse_args()
    plan = make_plan(
        args.artifact,
        args.checksum,
        args.manager,
        args.rpm_family,
        args.current_binary,
        args.snapshot_dir,
        args.health_command,
        args.rollback_artifact,
        args.rollback_checksum,
    )
    if args.command == "plan" or not args.execute:
        print(json.dumps(asdict(plan), indent=2, sort_keys=True))
        if args.command == "update" and not args.execute:
            print("update_weaverssh.py: update requires --execute", file=sys.stderr)
            return 2
        return 0
    print(json.dumps(execute(plan, args.allow_no_current, args.no_auto_rollback), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
