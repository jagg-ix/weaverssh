#!/usr/bin/env python3
from __future__ import annotations

"""Verify WeaverSSH release artifacts and print non-mutating install plans."""

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import zipfile

SCHEMA = "weaverssh.artifact-verification.v1"


@dataclass(frozen=True)
class ArtifactPlan:
    schema: str
    artifact: str
    kind: str
    checksum_file: str
    required_tools: list[str]
    install_command: list[str]
    notes: list[str]


def detect_kind(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".pkg.tar.zst"):
        return "arch"
    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        return "tar.gz"
    if name.endswith(".zip"):
        return "zip"
    if name.endswith(".deb"):
        return "deb"
    if name.endswith(".rpm"):
        return "rpm"
    if name.endswith(".pkg") and "freebsd" in name:
        return "freebsd-pkg"
    if name.endswith(".pkg"):
        return "macos-pkg"
    raise ValueError(f"unsupported artifact type: {path.name}")


def checksum_path(path: Path, explicit: Path | None) -> Path:
    return explicit if explicit is not None else path.with_name(path.name + ".sha256")


def install_plan(kind: str, path: Path, rpm_family: str) -> list[str]:
    quoted = str(path)
    if kind == "deb":
        return ["sudo", "dpkg", "-i", quoted]
    if kind == "rpm":
        return ["sudo", "zypper" if rpm_family == "suse" else "dnf", "install", quoted]
    if kind == "arch":
        return ["sudo", "pacman", "-U", quoted]
    if kind == "freebsd-pkg":
        return ["sudo", "pkg", "add", quoted]
    if kind == "macos-pkg":
        return ["sudo", "installer", "-pkg", quoted, "-target", "/"]
    if kind == "zip" and "windows" in path.name.lower():
        return ["powershell", "-NoProfile", "-Command", f"Expand-Archive -LiteralPath '{quoted}' -DestinationPath .\\weaverssh; .\\weaverssh\\install.ps1"]
    if kind == "zip":
        return ["unzip", quoted]
    return ["tar", "-xzf", quoted]


def make_plan(path: Path, explicit_checksum: Path | None = None, rpm_family: str = "redhat") -> ArtifactPlan:
    path = path.resolve()
    kind = detect_kind(path)
    required = {
        "deb": ["dpkg-deb"],
        "rpm": ["rpm"],
        "arch": ["tar", "zstd"],
        "freebsd-pkg": ["tar"],
        "macos-pkg": ["pkgutil"],
        "tar.gz": [],
        "zip": [],
    }[kind]
    notes = ["The install command is a plan only; this tool never installs the artifact."]
    if kind in {"deb", "rpm", "arch", "macos-pkg"}:
        notes.append("Native metadata verification is performed when the corresponding host tool is available.")
    return ArtifactPlan(
        schema=SCHEMA,
        artifact=str(path),
        kind=kind,
        checksum_file=str(checksum_path(path, explicit_checksum)),
        required_tools=required,
        install_command=install_plan(kind, path, rpm_family),
        notes=notes,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_checksum(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="strict").strip()
    match = re.search(r"\b([0-9a-fA-F]{64})\b", text)
    if not match:
        raise ValueError(f"no SHA-256 digest in {path}")
    return match.group(1).lower()


def safe_member(name: str) -> bool:
    normalized = name.replace("\\", "/")
    pure = PurePosixPath(normalized)
    return bool(normalized) and not pure.is_absolute() and ".." not in pure.parts and not re.match(r"^[A-Za-z]:", normalized)


def safe_link_target(member_name: str, target: str) -> bool:
    normalized = target.replace("\\", "/")
    if not normalized or PurePosixPath(normalized).is_absolute() or re.match(r"^[A-Za-z]:", normalized):
        return False
    parts: list[str] = []
    for part in (PurePosixPath(member_name).parent / PurePosixPath(normalized)).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return False
            parts.pop()
        else:
            parts.append(part)
    return bool(parts)


def parse_checksums(data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in data.decode("utf-8", errors="strict").splitlines():
        if not raw.strip():
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+\*?(.+)", raw.strip())
        if not match:
            raise ValueError(f"invalid checksum line: {raw!r}")
        name = match.group(2).strip()
        if not safe_member(name) or name in result:
            raise ValueError(f"unsafe or duplicate checksum path: {name}")
        result[name] = match.group(1).lower()
    return result


def verify_zip(path: Path) -> dict[str, object]:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        unsafe = [name for name in names if not safe_member(name)]
        if unsafe:
            raise ValueError(f"unsafe zip members: {unsafe}")
        for info in archive.infolist():
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                target = archive.read(info).decode("utf-8", errors="strict")
                if not safe_link_target(info.filename, target):
                    raise ValueError(f"unsafe zip symlink: {info.filename} -> {target}")
        checksum_names = [name for name in names if name.endswith("SHA256SUMS.txt")]
        verified = 0
        if checksum_names:
            checksum_name = sorted(checksum_names, key=len)[0]
            prefix = checksum_name[: -len("SHA256SUMS.txt")]
            checksums = parse_checksums(archive.read(checksum_name))
            for rel, expected in checksums.items():
                candidate = prefix + rel
                if candidate not in names:
                    raise ValueError(f"checksum references missing zip member: {candidate}")
                actual = hashlib.sha256(archive.read(candidate)).hexdigest()
                if actual != expected:
                    raise ValueError(f"checksum mismatch for zip member: {candidate}")
                verified += 1
        return {"members": len(names), "internal_checksums_verified": verified}


def verify_tar(path: Path) -> dict[str, object]:
    with tarfile.open(path, "r:*") as archive:
        members = archive.getmembers()
        unsafe = [member.name for member in members if not safe_member(member.name)]
        if unsafe:
            raise ValueError(f"unsafe tar members: {unsafe}")
        for member in members:
            if (member.issym() or member.islnk()) and not safe_link_target(member.name, member.linkname):
                raise ValueError(f"unsafe tar link: {member.name} -> {member.linkname}")
        checksum_members = [member for member in members if member.isfile() and member.name.endswith("SHA256SUMS.txt")]
        verified = 0
        if checksum_members:
            checksum_member = sorted(checksum_members, key=lambda item: len(item.name))[0]
            handle = archive.extractfile(checksum_member)
            if handle is None:
                raise ValueError("cannot read internal checksum file")
            prefix = checksum_member.name[: -len("SHA256SUMS.txt")]
            checksums = parse_checksums(handle.read())
            by_name = {member.name: member for member in members if member.isfile()}
            for rel, expected in checksums.items():
                candidate = prefix + rel
                member = by_name.get(candidate)
                if member is None:
                    raise ValueError(f"checksum references missing tar member: {candidate}")
                payload = archive.extractfile(member)
                if payload is None:
                    raise ValueError(f"cannot read tar member: {candidate}")
                actual = hashlib.sha256(payload.read()).hexdigest()
                if actual != expected:
                    raise ValueError(f"checksum mismatch for tar member: {candidate}")
                verified += 1
        roots = sorted({PurePosixPath(member.name).parts[0] for member in members if PurePosixPath(member.name).parts})
        return {"members": len(members), "roots": roots, "internal_checksums_verified": verified}


def native_verify(plan: ArtifactPlan) -> dict[str, object]:
    path = plan.artifact
    tool = plan.required_tools[0] if plan.required_tools else ""
    if not tool or shutil.which(tool) is None:
        return {"performed": False, "tool": tool, "reason": "tool unavailable" if tool else "not required"}
    command = {
        "deb": ["dpkg-deb", "--info", path],
        "rpm": ["rpm", "-qp", "--queryformat", "%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\\n", path],
        "macos-pkg": ["pkgutil", "--check-signature", path],
    }.get(plan.kind)
    if command is None:
        return {"performed": False, "tool": tool, "reason": "archive verification handled separately"}
    proc = subprocess.run(command, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise ValueError(f"native metadata verification failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return {"performed": True, "tool": tool, "output": proc.stdout.strip()}


def verify(plan: ArtifactPlan, require_checksum: bool = True) -> dict[str, object]:
    artifact = Path(plan.artifact)
    if not artifact.is_file():
        raise FileNotFoundError(artifact)
    checksum = Path(plan.checksum_file)
    checksum_result: dict[str, object]
    if checksum.is_file():
        expected = expected_checksum(checksum)
        actual = sha256(artifact)
        if expected != actual:
            raise ValueError(f"artifact checksum mismatch: expected {expected}, got {actual}")
        checksum_result = {"verified": True, "expected": expected, "actual": actual}
    elif require_checksum:
        raise FileNotFoundError(f"checksum sidecar not found: {checksum}")
    else:
        checksum_result = {"verified": False, "reason": "checksum sidecar unavailable"}

    archive_result: dict[str, object] = {}
    if plan.kind == "zip":
        archive_result = verify_zip(artifact)
    elif plan.kind in {"tar.gz", "freebsd-pkg"}:
        archive_result = verify_tar(artifact)
    native = native_verify(plan)
    return {
        "schema": SCHEMA,
        "ok": True,
        "artifact": plan.artifact,
        "kind": plan.kind,
        "checksum": checksum_result,
        "archive": archive_result,
        "native_metadata": native,
        "install_command": plan.install_command,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "verify"), nargs="?", default="plan")
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--checksum", type=Path, default=None)
    parser.add_argument("--rpm-family", choices=("redhat", "suse"), default="redhat")
    parser.add_argument("--no-require-checksum", action="store_true")
    args = parser.parse_args()
    plan = make_plan(args.artifact, args.checksum, args.rpm_family)
    payload = asdict(plan) if args.command == "plan" else verify(plan, not args.no_require_checksum)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
