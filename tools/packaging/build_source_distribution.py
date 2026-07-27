#!/usr/bin/env python3
from __future__ import annotations

"""Build reproducible WeaverSSH source archives with manifests and an SPDX SBOM."""

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "weaverssh.source-distribution.v1"
EXCLUDED_PARTS = {".git", "build", "dist", "artifacts", "verification_results", ".pytest_cache", "__pycache__"}


@dataclass(frozen=True)
class SourceDistributionPlan:
    schema: str
    version: str
    release: str
    source_root: str
    source_date_epoch: int
    vendor: bool
    archive_root: str
    tar_gz: str
    zip: str
    required_tools: list[str]


def clean_token(value: str, field: str) -> str:
    value = value.strip().lstrip("v") if field == "version" else value.strip()
    if not value or not re.fullmatch(r"[A-Za-z0-9._-]+", value):
        raise ValueError(f"invalid {field}: {value!r}")
    return value


def default_epoch(source_root: Path) -> int:
    try:
        output = subprocess.check_output(
            ["git", "-C", str(source_root), "show", "-s", "--format=%ct", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        return int(output)
    except (OSError, subprocess.CalledProcessError, ValueError):
        return int(os.environ.get("SOURCE_DATE_EPOCH", "0") or "0")


def make_plan(
    version: str,
    release: str,
    source_root: Path,
    dist_dir: Path,
    source_date_epoch: int | None,
    vendor: bool,
) -> SourceDistributionPlan:
    version = clean_token(version, "version")
    release = clean_token(release, "release")
    source_root = source_root.resolve()
    epoch = default_epoch(source_root) if source_date_epoch is None else int(source_date_epoch)
    if epoch < 0:
        raise ValueError("source date epoch must be non-negative")
    root = f"weaverssh-{version}"
    base = f"weaverssh-{version}-{release}-source"
    return SourceDistributionPlan(
        schema=SCHEMA,
        version=version,
        release=release,
        source_root=str(source_root),
        source_date_epoch=epoch,
        vendor=vendor,
        archive_root=root,
        tar_gz=str(dist_dir / f"{base}.tar.gz"),
        zip=str(dist_dir / f"{base}.zip"),
        required_tools=["git", "go"] if vendor else ["git"],
    )


def tracked_files(source_root: Path) -> list[Path]:
    try:
        raw = subprocess.check_output(
            ["git", "-C", str(source_root), "ls-files", "-z"],
            stderr=subprocess.DEVNULL,
        )
        files = [source_root / item.decode("utf-8") for item in raw.split(b"\0") if item]
        return sorted(path for path in files if path.is_file() or path.is_symlink())
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError):
        out: list[Path] = []
        for path in source_root.rglob("*"):
            rel = path.relative_to(source_root)
            if any(part in EXCLUDED_PARTS for part in rel.parts):
                continue
            if path.is_file() or path.is_symlink():
                out.append(path)
        return sorted(out)


def copy_sources(source_root: Path, stage: Path) -> None:
    for src in tracked_files(source_root):
        rel = src.relative_to(source_root)
        if any(part in EXCLUDED_PARTS for part in rel.parts):
            continue
        dst = stage / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_symlink():
            target = os.readlink(src)
            if Path(target).is_absolute() or ".." in PurePosixPath(target.replace("\\", "/")).parts:
                raise ValueError(f"unsafe source symlink: {rel} -> {target}")
            dst.symlink_to(target)
        else:
            shutil.copyfile(src, dst)
            dst.chmod(src.stat().st_mode & 0o777)


def parse_go_modules(go_mod: Path) -> list[dict[str, str]]:
    if not go_mod.exists():
        return []
    text = go_mod.read_text(encoding="utf-8", errors="strict")
    modules: list[dict[str, str]] = []
    in_require = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line == "require (":
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_require:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] != "(":
            modules.append({"name": parts[0], "version": parts[1]})
    return sorted(modules, key=lambda item: (item["name"], item["version"]))


def write_sbom(stage: Path, plan: SourceDistributionPlan) -> None:
    modules = parse_go_modules(stage / "go.mod")
    namespace_seed = hashlib.sha256(
        f"{plan.version}:{plan.release}:{plan.source_date_epoch}".encode("utf-8")
    ).hexdigest()
    packages = [
        {
            "SPDXID": "SPDXRef-Package-WeaverSSH",
            "name": "weaverssh",
            "versionInfo": plan.version,
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
        }
    ]
    relationships: list[dict[str, str]] = []
    for index, module in enumerate(modules, 1):
        spdx_id = f"SPDXRef-GoModule-{index}"
        packages.append(
            {
                "SPDXID": spdx_id,
                "name": module["name"],
                "versionInfo": module["version"],
                "downloadLocation": f"https://proxy.golang.org/{module['name']}/@v/{module['version']}.zip",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package-WeaverSSH",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": spdx_id,
            }
        )
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"weaverssh-{plan.version}-source",
        "documentNamespace": f"https://github.com/jagg-ix/weaverssh/source-sbom/{namespace_seed}",
        "creationInfo": {
            "created": datetime.fromtimestamp(plan.source_date_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: weaverssh-build_source_distribution.py"],
        },
        "packages": packages,
        "relationships": relationships,
    }
    (stage / "SBOM.spdx.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular_files(stage: Path) -> list[Path]:
    return sorted(path for path in stage.rglob("*") if path.is_file() and not path.is_symlink())


def write_build_guide(stage: Path, vendor: bool) -> None:
    mode = "-mod=vendor " if vendor else ""
    text = f"""# Build WeaverSSH from this source archive

Requirements: Go 1.24 or newer and GNU Make. Runtime SSH/X11 dependencies are
listed in `docs/packaging/cross-platform-source-builds.md`.

```sh
make source-build-plan
make build GOBUILD='go build {mode}-trimpath -buildvcs=false'
./build/bin/wv version
```

The archive {'contains a vendored Go dependency tree and can build without downloading modules.' if vendor else 'does not vendor Go modules; run `go mod download` before an offline build.'}
Verify `SHA256SUMS.txt` before building.
"""
    (stage / "BUILD-FROM-SOURCE.md").write_text(text, encoding="utf-8")


def write_manifest(stage: Path, plan: SourceDistributionPlan) -> None:
    entries = []
    for path in regular_files(stage):
        rel = path.relative_to(stage).as_posix()
        if rel in {"SOURCE-MANIFEST.json", "SHA256SUMS.txt"}:
            continue
        entries.append({"path": rel, "sha256": sha256(path), "size": path.stat().st_size})
    payload = {
        "schema": SCHEMA,
        "version": plan.version,
        "release": plan.release,
        "source_date_epoch": plan.source_date_epoch,
        "vendored": plan.vendor,
        "archive_root": plan.archive_root,
        "files": entries,
    }
    (stage / "SOURCE-MANIFEST.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksums = []
    for path in regular_files(stage):
        rel = path.relative_to(stage).as_posix()
        if rel == "SHA256SUMS.txt":
            continue
        checksums.append(f"{sha256(path)}  {rel}")
    (stage / "SHA256SUMS.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8")


def normalize_mode(path: Path) -> int:
    if path.is_symlink():
        return 0o777
    if path.is_dir():
        return 0o755
    return 0o755 if path.stat().st_mode & stat.S_IXUSR else 0o644


def build_tar(stage: Path, archive_root: str, output: Path, epoch: int) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tf:
                paths = [stage, *sorted(stage.rglob("*"))]
                for path in paths:
                    rel = Path(archive_root) if path == stage else Path(archive_root) / path.relative_to(stage)
                    info = tf.gettarinfo(str(path), arcname=rel.as_posix())
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    info.mtime = epoch
                    info.mode = normalize_mode(path)
                    if info.isfile():
                        with path.open("rb") as handle:
                            tf.addfile(info, handle)
                    else:
                        tf.addfile(info)


def zip_timestamp(epoch: int) -> tuple[int, int, int, int, int, int]:
    dt = datetime.fromtimestamp(max(epoch, 315532800), timezone.utc)
    return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second - dt.second % 2)


def build_zip(stage: Path, archive_root: str, output: Path, epoch: int) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    stamp = zip_timestamp(epoch)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(stage.rglob("*")):
            rel = (Path(archive_root) / path.relative_to(stage)).as_posix()
            if path.is_dir():
                rel += "/"
                data = b""
            elif path.is_symlink():
                data = os.readlink(path).encode("utf-8")
            else:
                data = path.read_bytes()
            info = zipfile.ZipInfo(rel, stamp)
            info.create_system = 3
            mode = normalize_mode(path)
            kind = stat.S_IFLNK if path.is_symlink() else stat.S_IFDIR if path.is_dir() else stat.S_IFREG
            info.external_attr = (kind | mode) << 16
            zf.writestr(info, data)


def write_sidecar(path: Path) -> None:
    path.with_name(path.name + ".sha256").write_text(f"{sha256(path)}  {path.name}\n", encoding="utf-8")


def build(plan: SourceDistributionPlan) -> list[Path]:
    source_root = Path(plan.source_root)
    with tempfile.TemporaryDirectory(prefix="weaverssh-source-") as temp:
        stage = Path(temp) / plan.archive_root
        stage.mkdir()
        copy_sources(source_root, stage)
        if plan.vendor:
            subprocess.run(["go", "mod", "vendor"], cwd=stage, check=True, env={**os.environ, "GOWORK": "off"})
        write_build_guide(stage, plan.vendor)
        write_sbom(stage, plan)
        write_manifest(stage, plan)
        tar_out = Path(plan.tar_gz)
        zip_out = Path(plan.zip)
        build_tar(stage, plan.archive_root, tar_out, plan.source_date_epoch)
        build_zip(stage, plan.archive_root, zip_out, plan.source_date_epoch)
    write_sidecar(tar_out)
    write_sidecar(zip_out)
    provenance = tar_out.parent / f"weaverssh-{plan.version}-{plan.release}-source.provenance.json"
    provenance.write_text(json.dumps(asdict(plan), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return [tar_out, zip_out, provenance]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "build"), nargs="?", default="plan")
    parser.add_argument("--version", default=os.environ.get("WEAVERSSH_VERSION", "0.1.0"))
    parser.add_argument("--release", default=os.environ.get("WEAVERSSH_RELEASE", "1"))
    parser.add_argument("--source-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--dist-dir", type=Path, default=REPO_ROOT / "dist" / "source")
    parser.add_argument("--source-date-epoch", type=int, default=None)
    parser.add_argument("--vendor", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()
    plan = make_plan(args.version, args.release, args.source_root, args.dist_dir, args.source_date_epoch, args.vendor)
    if args.command == "plan":
        print(json.dumps(asdict(plan), indent=2, sort_keys=True))
        return 0
    outputs = build(plan)
    print(json.dumps({"ok": True, "outputs": [str(path) for path in outputs]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
