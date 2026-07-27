#!/usr/bin/env python3
from __future__ import annotations

"""Assemble verified WeaverSSH artifacts into a deterministic release bundle."""

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import zipfile
from urllib.parse import urljoin

SCHEMA = "weaverssh.release-bundle.v1"


@dataclass(frozen=True)
class ReleaseArtifact:
    filename: str
    kind: str
    size: int
    sha256: str
    url: str
    checksum_sidecar: str


@dataclass(frozen=True)
class ReleaseBundlePlan:
    schema: str
    version: str
    release: str
    source_date_epoch: int
    output_dir: str
    url_base: str
    artifacts: list[ReleaseArtifact]
    tar_gz: str
    zip: str
    sign_method: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def clean_token(value: str, field: str) -> str:
    value = value.strip().lstrip("v") if field == "version" else value.strip()
    if not value or not re.fullmatch(r"[A-Za-z0-9._-]+", value):
        raise ValueError(f"invalid {field}: {value!r}")
    return value


def detect_kind(path: Path) -> str:
    name = path.name.lower()
    if name.endswith("-source.tar.gz"):
        return "source"
    if name.endswith(".pkg.tar.zst"):
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
    if name.endswith(".zip"):
        return "zip"
    if name.endswith(".tar.gz"):
        return "tar.gz"
    raise ValueError(f"unsupported release artifact: {path.name}")


def sidecar_for(path: Path) -> Path:
    return path.with_name(path.name + ".sha256")


def expected_sidecar_digest(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="strict")
    match = re.search(r"\b([0-9a-fA-F]{64})\b", text)
    if not match:
        raise ValueError(f"no SHA-256 digest in sidecar: {path}")
    return match.group(1).lower()


def read_epoch(value: str) -> int:
    raw = value or os.environ.get("SOURCE_DATE_EPOCH", "0") or "0"
    epoch = int(raw)
    if epoch < 315532800:
        epoch = 315532800
    return epoch


def make_plan(
    version: str,
    release: str,
    artifacts: list[Path],
    output_dir: Path,
    url_base: str,
    source_date_epoch: int,
    allow_missing_checksum: bool,
    sign_method: str,
) -> ReleaseBundlePlan:
    version = clean_token(version, "version")
    release = clean_token(release, "release")
    if not artifacts:
        raise ValueError("at least one --artifact is required")
    metadata: list[ReleaseArtifact] = []
    names: set[str] = set()
    for path in artifacts:
        path = path.resolve()
        if not path.is_file():
            raise FileNotFoundError(path)
        if path.name in names:
            raise ValueError(f"duplicate release artifact filename: {path.name}")
        names.add(path.name)
        digest = sha256_file(path)
        sidecar = sidecar_for(path)
        if sidecar.is_file():
            expected = expected_sidecar_digest(sidecar)
            if expected != digest:
                raise ValueError(f"checksum sidecar mismatch for {path.name}")
            sidecar_name = sidecar.name
        elif allow_missing_checksum:
            sidecar_name = ""
        else:
            raise FileNotFoundError(f"checksum sidecar not found: {sidecar}")
        metadata.append(
            ReleaseArtifact(
                filename=path.name,
                kind=detect_kind(path),
                size=path.stat().st_size,
                sha256=digest,
                url=urljoin(url_base.rstrip("/") + "/", path.name) if url_base else path.as_uri(),
                checksum_sidecar=sidecar_name,
            )
        )
    metadata.sort(key=lambda item: item.filename)
    stem = f"weaverssh-{version}-{release}-release"
    return ReleaseBundlePlan(
        schema=SCHEMA,
        version=version,
        release=release,
        source_date_epoch=source_date_epoch,
        output_dir=str(output_dir),
        url_base=url_base,
        artifacts=metadata,
        tar_gz=str(output_dir / f"{stem}.tar.gz"),
        zip=str(output_dir / f"{stem}.zip"),
        sign_method=sign_method,
    )


def canonical_zip_info(name: str, epoch: int, mode: int = 0o644) -> zipfile.ZipInfo:
    dt = datetime.fromtimestamp(epoch, timezone.utc)
    info = zipfile.ZipInfo(name, (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second))
    info.create_system = 3
    info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def tar_bytes(stage: Path, root_name: str, epoch: int) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for path in sorted(stage.rglob("*")):
            rel = path.relative_to(stage).as_posix()
            info = archive.gettarinfo(str(path), arcname=f"{root_name}/{rel}")
            info.mtime = epoch
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            if path.is_file():
                with path.open("rb") as handle:
                    archive.addfile(info, handle)
            else:
                archive.addfile(info)
    return buffer.getvalue()


def write_detached_checksum(path: Path) -> Path:
    sidecar = path.with_name(path.name + ".sha256")
    sidecar.write_text(f"{sha256_file(path)}  {path.name}\n", encoding="utf-8")
    return sidecar


def sign_checksums(checksums: Path, method: str, sign_key: str) -> Path | None:
    if method == "none":
        return None
    if method == "openssl":
        if not sign_key:
            raise ValueError("--sign-key is required for openssl signing")
        output = checksums.with_suffix(checksums.suffix + ".sig")
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", sign_key, "-out", str(output), str(checksums)], check=True)
        return output
    if method == "gpg":
        output = checksums.with_suffix(checksums.suffix + ".asc")
        command = ["gpg", "--batch", "--yes", "--armor", "--detach-sign", "--output", str(output)]
        if sign_key:
            command.extend(["--local-user", sign_key])
        command.append(str(checksums))
        subprocess.run(command, check=True)
        return output
    raise ValueError(f"unsupported sign method: {method}")


def build(plan: ReleaseBundlePlan, artifact_paths: list[Path], replace: bool, sign_key: str) -> dict[str, object]:
    output_dir = Path(plan.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    final_dir = output_dir / f"weaverssh-{plan.version}-{plan.release}"
    tar_path = Path(plan.tar_gz)
    zip_path = Path(plan.zip)
    preexisting = [
        path
        for path in (
            final_dir,
            tar_path,
            zip_path,
            tar_path.with_name(tar_path.name + ".sha256"),
            zip_path.with_name(zip_path.name + ".sha256"),
        )
        if path.exists()
    ]
    if preexisting and not replace:
        raise FileExistsError("release outputs already exist: " + ", ".join(str(path) for path in preexisting))
    if final_dir.exists():
        shutil.rmtree(final_dir)
    for path in preexisting:
        if path != final_dir and path.is_file():
            path.unlink()
    stage = output_dir / f".{final_dir.name}.stage"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    source_by_name = {path.name: path.resolve() for path in artifact_paths}
    for item in plan.artifacts:
        shutil.copy2(source_by_name[item.filename], stage / item.filename)
        sidecar = source_by_name[item.filename].with_name(source_by_name[item.filename].name + ".sha256")
        if sidecar.is_file():
            shutil.copy2(sidecar, stage / sidecar.name)

    index = stage / "release-index.json"
    index_payload = {
        "schema": plan.schema,
        "version": plan.version,
        "release": plan.release,
        "source_date_epoch": plan.source_date_epoch,
        "url_base": plan.url_base,
        "artifacts": [asdict(item) for item in plan.artifacts],
        "sign_method": plan.sign_method,
    }
    index.write_text(json.dumps(index_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    latest = stage / "LATEST.json"
    latest.write_text(
        json.dumps(
            {
                "schema": "weaverssh.latest-release.v1",
                "version": plan.version,
                "release": plan.release,
                "index": "release-index.json",
                "published_at": datetime.fromtimestamp(plan.source_date_epoch, timezone.utc).isoformat(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    checksums = stage / "SHA256SUMS.txt"
    files = sorted(path for path in stage.iterdir() if path.is_file() and path.name != checksums.name)
    checksums.write_text("".join(f"{sha256_file(path)}  {path.name}\n" for path in files), encoding="utf-8")
    signature = sign_checksums(checksums, plan.sign_method, sign_key)
    final_dir.parent.mkdir(parents=True, exist_ok=True)
    stage.rename(final_dir)

    root_name = final_dir.name
    tar_path.unlink(missing_ok=True)
    zip_path.unlink(missing_ok=True)
    raw_tar = tar_bytes(final_dir, root_name, plan.source_date_epoch)
    with tar_path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=plan.source_date_epoch) as gz:
            gz.write(raw_tar)
    with zipfile.ZipFile(zip_path, "w") as archive:
        for path in sorted(final_dir.iterdir()):
            if path.is_file():
                archive.writestr(canonical_zip_info(f"{root_name}/{path.name}", plan.source_date_epoch), path.read_bytes())
    sidecars = [write_detached_checksum(tar_path), write_detached_checksum(zip_path)]
    return {
        "ok": True,
        "release_dir": str(final_dir),
        "tar_gz": str(tar_path),
        "zip": str(zip_path),
        "sidecars": [str(path) for path in sidecars],
        "signature": str(final_dir / signature.name) if signature else "",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "build"), nargs="?", default="plan")
    parser.add_argument("--version", default=os.environ.get("WEAVERSSH_VERSION", "0.1.0"))
    parser.add_argument("--release", default=os.environ.get("WEAVERSSH_RELEASE", "1"))
    parser.add_argument("--artifact", type=Path, action="append", default=[])
    parser.add_argument("--output-dir", type=Path, default=Path("dist/release"))
    parser.add_argument("--url-base", default="")
    parser.add_argument("--source-date-epoch", default="")
    parser.add_argument("--allow-missing-checksum", action="store_true")
    parser.add_argument("--sign-method", choices=("none", "openssl", "gpg"), default="none")
    parser.add_argument("--sign-key", default="")
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    plan = make_plan(
        args.version,
        args.release,
        args.artifact,
        args.output_dir,
        args.url_base,
        read_epoch(args.source_date_epoch),
        args.allow_missing_checksum,
        args.sign_method,
    )
    payload = asdict(plan) if args.command == "plan" else build(plan, args.artifact, args.replace, args.sign_key)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
