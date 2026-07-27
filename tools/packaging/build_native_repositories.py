#!/usr/bin/env python3
from __future__ import annotations

"""Build static WeaverSSH package repositories from local release artifacts.

The builder is intentionally non-publishing: it creates repository trees under
an output directory. Native metadata tools are only invoked with
``--execute-native``. No package is installed and no remote upload occurs.
"""

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import urljoin

SCHEMA = "weaverssh.native-repositories.v1"
CHANNELS = ("apt", "rpm-redhat", "rpm-suse", "arch", "freebsd", "homebrew")


@dataclass(frozen=True)
class Artifact:
    path: str
    filename: str
    kind: str
    version: str
    release: str
    arch: str
    size: int
    sha256: str
    url: str


@dataclass(frozen=True)
class RepositoryPlan:
    schema: str
    output_dir: str
    suite: str
    component: str
    source_date_epoch: int
    channels: list[str]
    artifacts: list[Artifact]
    required_tools: dict[str, list[str]]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def clean_token(value: str, field: str) -> str:
    value = value.strip()
    if not value or not re.fullmatch(r"[A-Za-z0-9._-]+", value):
        raise ValueError(f"invalid {field}: {value!r}")
    return value


def detect_artifact(path: Path, url_base: str) -> Artifact:
    if not path.is_file():
        raise FileNotFoundError(path)
    name = path.name
    patterns = [
        ("deb", re.compile(r"^weaverssh_(?P<version>.+)-(?P<release>[^_]+)_(?P<arch>[^_]+)\.deb$")),
        ("rpm", re.compile(r"^weaverssh-(?P<version>.+)-(?P<release>[^.]+)\.(?P<arch>[^.]+)\.rpm$")),
        ("arch", re.compile(r"^weaverssh-(?P<version>.+)-(?P<release>[^-]+)-(?P<arch>[^-]+)\.pkg\.tar\.(?:zst|xz|gz)$")),
        ("freebsd", re.compile(r"^weaverssh-(?P<version>.+)-(?P<release>[^-]+)-freebsd-(?P<arch>[^.]+)\.pkg$")),
        ("source", re.compile(r"^weaverssh-(?P<version>.+)-(?P<release>[^-]+)-source\.tar\.gz$")),
    ]
    for kind, pattern in patterns:
        match = pattern.match(name)
        if match:
            version = clean_token(match.group("version"), "version")
            release = clean_token(match.group("release"), "release")
            arch = match.groupdict().get("arch") or "source"
            url = urljoin(url_base.rstrip("/") + "/", name) if url_base else path.resolve().as_uri()
            return Artifact(
                path=str(path.resolve()),
                filename=name,
                kind=kind,
                version=version,
                release=release,
                arch=arch,
                size=path.stat().st_size,
                sha256=sha256_file(path),
                url=url,
            )
    raise ValueError(f"unsupported artifact filename: {name}")


def read_epoch(value: str) -> int:
    raw = value or os.environ.get("SOURCE_DATE_EPOCH", "0") or "0"
    epoch = int(raw)
    if epoch < 0:
        raise ValueError("source date epoch must be non-negative")
    return epoch


def make_plan(
    artifacts: list[Path],
    output_dir: Path,
    channels: list[str],
    suite: str,
    component: str,
    url_base: str,
    source_date_epoch: int,
) -> RepositoryPlan:
    if not artifacts:
        raise ValueError("at least one --artifact is required")
    suite = clean_token(suite, "suite")
    component = clean_token(component, "component")
    metadata = [detect_artifact(path, url_base) for path in artifacts]
    if channels:
        selected = channels
    else:
        kinds = {item.kind for item in metadata}
        selected = []
        if "deb" in kinds:
            selected.append("apt")
        if "rpm" in kinds:
            selected.extend(["rpm-redhat", "rpm-suse"])
        if "arch" in kinds:
            selected.append("arch")
        if "freebsd" in kinds:
            selected.append("freebsd")
        if "source" in kinds:
            selected.append("homebrew")
    unknown = sorted(set(selected) - set(CHANNELS))
    if unknown:
        raise ValueError(f"unsupported channels: {', '.join(unknown)}")
    versions = {(item.version, item.release) for item in metadata}
    if len(versions) != 1:
        raise ValueError("all artifacts must share one version/release")
    required = {
        "apt": [],
        "rpm-redhat": ["createrepo_c"],
        "rpm-suse": ["createrepo_c"],
        "arch": ["repo-add"],
        "freebsd": ["pkg"],
        "homebrew": [],
    }
    for channel in selected:
        if channel == "apt" and not any(item.kind == "deb" for item in metadata):
            raise ValueError("apt channel requires at least one .deb artifact")
        if channel.startswith("rpm-") and not any(item.kind == "rpm" for item in metadata):
            raise ValueError(f"{channel} requires at least one .rpm artifact")
        if channel == "arch" and not any(item.kind == "arch" for item in metadata):
            raise ValueError("arch channel requires at least one Arch package")
        if channel == "freebsd" and not any(item.kind == "freebsd" for item in metadata):
            raise ValueError("freebsd channel requires at least one FreeBSD package")
        if channel == "homebrew" and not any(item.kind == "source" for item in metadata):
            raise ValueError("homebrew channel requires one source tar.gz artifact")
    return RepositoryPlan(
        schema=SCHEMA,
        output_dir=str(output_dir),
        suite=suite,
        component=component,
        source_date_epoch=source_date_epoch,
        channels=selected,
        artifacts=metadata,
        required_tools={name: required[name] for name in selected},
    )


def copy_artifact(item: Artifact, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / item.filename
    shutil.copy2(item.path, target)
    return target


def apt_arch(arch: str) -> str:
    return {
        "x86_64": "amd64",
        "aarch64": "arm64",
        "i386": "i386",
        "armv7": "armhf",
    }.get(arch, arch)


def build_apt(plan: RepositoryPlan, root: Path) -> list[Path]:
    apt_root = root / "apt"
    generated: list[Path] = []
    records: dict[str, list[str]] = {}
    for item in [artifact for artifact in plan.artifacts if artifact.kind == "deb"]:
        pool = apt_root / "pool" / plan.component / "w" / "weaverssh"
        target = copy_artifact(item, pool)
        arch = apt_arch(item.arch)
        rel = target.relative_to(apt_root).as_posix()
        record = "\n".join(
            [
                "Package: weaverssh",
                f"Version: {item.version}-{item.release}",
                f"Architecture: {arch}",
                "Section: net",
                "Priority: optional",
                "Maintainer: WeaverSSH maintainers <noreply@example.invalid>",
                f"Filename: {rel}",
                f"Size: {item.size}",
                f"SHA256: {item.sha256}",
                "Description: WeaverSSH user-space data bus over SSH",
                "",
            ]
        )
        records.setdefault(arch, []).append(record)
        generated.append(target)

    release_files: list[Path] = []
    for arch, chunks in records.items():
        directory = apt_root / "dists" / plan.suite / plan.component / f"binary-{arch}"
        directory.mkdir(parents=True, exist_ok=True)
        packages = directory / "Packages"
        packages.write_text("\n".join(chunks), encoding="utf-8")
        packages_gz = directory / "Packages.gz"
        with packages.open("rb") as source, packages_gz.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=plan.source_date_epoch) as output:
                shutil.copyfileobj(source, output)
        release_files.extend([packages, packages_gz])
        generated.extend([packages, packages_gz])

    suite_root = apt_root / "dists" / plan.suite
    checks: list[tuple[str, int, str, str]] = []
    for path in sorted(release_files):
        rel = path.relative_to(suite_root).as_posix()
        payload = path.read_bytes()
        checks.append((hashlib.md5(payload).hexdigest(), len(payload), hashlib.sha256(payload).hexdigest(), rel))
    date = datetime.fromtimestamp(plan.source_date_epoch, timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    release = suite_root / "Release"
    lines = [
        "Origin: WeaverSSH",
        "Label: WeaverSSH",
        f"Suite: {plan.suite}",
        f"Codename: {plan.suite}",
        f"Date: {date}",
        f"Architectures: {' '.join(sorted(records))}",
        f"Components: {plan.component}",
        "Description: WeaverSSH package repository",
        "MD5Sum:",
    ]
    lines.extend(f" {md5} {size:16d} {rel}" for md5, size, _sha, rel in checks)
    lines.append("SHA256:")
    lines.extend(f" {sha} {size:16d} {rel}" for _md5, size, sha, rel in checks)
    release.parent.mkdir(parents=True, exist_ok=True)
    release.write_text("\n".join(lines) + "\n", encoding="utf-8")
    generated.append(release)
    return generated


def build_native_channel(plan: RepositoryPlan, root: Path, channel: str, execute_native: bool) -> list[Path]:
    mapping = {
        "rpm-redhat": ("rpm", root / "rpm" / "redhat", "createrepo_c"),
        "rpm-suse": ("rpm", root / "rpm" / "suse", "createrepo_c"),
        "arch": ("arch", root / "arch", "repo-add"),
        "freebsd": ("freebsd", root / "freebsd", "pkg"),
    }
    kind, base, tool = mapping[channel]
    artifacts = [item for item in plan.artifacts if item.kind == kind]
    generated: list[Path] = []
    by_arch: dict[str, list[Path]] = {}
    for item in artifacts:
        target_dir = base / item.arch
        if channel == "freebsd":
            target_dir = target_dir / "All"
        target = copy_artifact(item, target_dir)
        by_arch.setdefault(item.arch, []).append(target)
        generated.append(target)

    for arch, files in by_arch.items():
        if channel.startswith("rpm-"):
            repo_dir = base / arch
            command = [tool, "--update", str(repo_dir)]
        elif channel == "arch":
            repo_dir = base / arch
            command = [tool, str(repo_dir / "weaverssh.db.tar.gz"), *map(str, files)]
        else:
            repo_dir = base / arch
            command = [tool, "repo", str(repo_dir)]
        command_file = repo_dir / "GENERATE-METADATA.json"
        command_file.parent.mkdir(parents=True, exist_ok=True)
        command_file.write_text(json.dumps({"tool": tool, "command": command}, indent=2) + "\n", encoding="utf-8")
        generated.append(command_file)
        if execute_native:
            if shutil.which(tool) is None:
                raise RuntimeError(f"required native repository tool unavailable: {tool}")
            subprocess.run(command, check=True)
    return generated


def build_homebrew(plan: RepositoryPlan, root: Path) -> list[Path]:
    source = next(item for item in plan.artifacts if item.kind == "source")
    formula = root / "homebrew" / "Formula" / "weaverssh.rb"
    formula.parent.mkdir(parents=True, exist_ok=True)
    formula.write_text(
        f'''class Weaverssh < Formula
  desc "User-space data bus over SSH"
  homepage "https://github.com/jagg-ix/weaverssh"
  url "{source.url}"
  sha256 "{source.sha256}"
  version "{source.version}"

  depends_on "go" => :build

  def install
    system "go", "build", "-mod=vendor", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", bin/"wv", "./cmd/wv"
  end

  test do
    assert_match "weaverssh", shell_output("#{{bin}}/wv version")
  end
end
''',
        encoding="utf-8",
    )
    return [formula]


def write_index(plan: RepositoryPlan, root: Path, generated: list[Path]) -> Path:
    index = root / "REPOSITORY.json"
    payload = {
        **asdict(plan),
        "generated_files": sorted(path.relative_to(root).as_posix() for path in generated if path.is_file()),
    }
    index.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksum = root / "SHA256SUMS.txt"
    files = sorted([*generated, index], key=lambda path: path.relative_to(root).as_posix())
    checksum.write_text(
        "".join(
            f"{sha256_file(path)}  {path.relative_to(root).as_posix()}\n"
            for path in files
            if path.is_file()
        ),
        encoding="utf-8",
    )
    return index


def build(plan: RepositoryPlan, execute_native: bool = False, replace: bool = False) -> dict[str, object]:
    root = Path(plan.output_dir)
    if root.exists():
        if not replace:
            raise FileExistsError(f"repository output already exists: {root}")
        shutil.rmtree(root)
    root.mkdir(parents=True)
    generated: list[Path] = []
    for channel in plan.channels:
        if channel == "apt":
            generated.extend(build_apt(plan, root))
        elif channel == "homebrew":
            generated.extend(build_homebrew(plan, root))
        else:
            generated.extend(build_native_channel(plan, root, channel, execute_native))
    index = write_index(plan, root, generated)
    return {"ok": True, "output_dir": str(root), "index": str(index), "files": len(generated) + 2}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "build"), nargs="?", default="plan")
    parser.add_argument("--artifact", type=Path, action="append", default=[])
    parser.add_argument("--output-dir", type=Path, default=Path("dist/native-repositories"))
    parser.add_argument("--channel", action="append", choices=CHANNELS, default=[])
    parser.add_argument("--suite", default="stable")
    parser.add_argument("--component", default="main")
    parser.add_argument("--url-base", default="")
    parser.add_argument("--source-date-epoch", default="")
    parser.add_argument("--execute-native", action="store_true")
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    plan = make_plan(
        args.artifact,
        args.output_dir,
        args.channel,
        args.suite,
        args.component,
        args.url_base,
        read_epoch(args.source_date_epoch),
    )
    payload = asdict(plan) if args.command == "plan" else build(plan, args.execute_native, args.replace)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
