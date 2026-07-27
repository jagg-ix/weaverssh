#!/usr/bin/env python3
from __future__ import annotations

"""Generate package-repository manifests for archive-based distribution channels.

Supported channels:
- nix: Nix derivation consuming a source-free weaverssh binary archive
- scoop: Windows Scoop app manifest consuming a wv.exe archive
- chocolatey: Chocolatey nuspec and install script consuming a wv.exe archive
"""

import argparse
import base64
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Iterable

DEFAULT_NAME = "weaverssh"
DEFAULT_OUTPUT_DIR = Path("dist/repository")
DEFAULT_HOMEPAGE = "https://weaverssh.com"
DEFAULT_DESCRIPTION = "weaverssh user-space data bus over SSH"
SUPPORTED_CHANNELS = ("nix", "scoop", "chocolatey")


@dataclass(frozen=True)
class ArchiveMetadata:
    archive: str
    target: str
    goos: str
    arch: str
    version: str
    release: str
    url: str
    sha256: str
    sha256_sri: str


@dataclass(frozen=True)
class RepositoryManifestPlan:
    name: str
    version: str
    channels: list[str]
    output_dir: str
    outputs: list[str]
    artifacts: list[ArchiveMetadata]


def sha256_file(path: Path) -> tuple[str, str]:
    digest = hashlib.sha256(path.read_bytes()).digest()
    return digest.hex(), "sha256-" + base64.b64encode(digest).decode("ascii")


def infer_archive_metadata(path: Path) -> tuple[str, str, str, str]:
    suffix = ".tar.gz"
    name = path.name
    if not name.startswith("weaverssh-") or not name.endswith(suffix):
        raise ValueError(f"archive name must look like weaverssh-VERSION-RELEASE-GOOS-ARCH.tar.gz: {name}")
    parts = name[: -len(suffix)].split("-")
    if len(parts) < 5:
        raise ValueError(f"archive name has too few components: {name}")
    arch = parts[-1]
    goos = parts[-2]
    release = parts[-3]
    version = "-".join(parts[1:-3])
    if not version or not release or not goos or not arch:
        raise ValueError(f"archive name has empty metadata fields: {name}")
    return version, release, goos, arch


def target_url(path: Path, *, target: str, url_base: str | None, url_overrides: dict[str, str]) -> str:
    if target in url_overrides:
        return url_overrides[target]
    if url_base:
        return url_base.rstrip("/") + "/" + path.name
    return path.resolve().as_uri()


def parse_key_value(items: Iterable[str] | None, *, field: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            raise ValueError(f"--{field} entries must use TARGET=value syntax: {item}")
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not value:
            raise ValueError(f"--{field} entries must use TARGET=value syntax: {item}")
        out[key] = value
    return out


def build_artifacts(archives: list[Path], *, url_base: str | None, url_overrides: dict[str, str]) -> list[ArchiveMetadata]:
    artifacts: list[ArchiveMetadata] = []
    for archive in archives:
        if not archive.exists():
            raise FileNotFoundError(f"archive not found: {archive}")
        version, release, goos, arch = infer_archive_metadata(archive)
        target = f"{goos}/{arch}"
        sha_hex, sha_sri = sha256_file(archive)
        artifacts.append(
            ArchiveMetadata(
                archive=str(archive),
                target=target,
                goos=goos,
                arch=arch,
                version=version,
                release=release,
                url=target_url(archive, target=target, url_base=url_base, url_overrides=url_overrides),
                sha256=sha_hex,
                sha256_sri=sha_sri,
            )
        )
    artifacts.sort(key=lambda item: (item.goos, item.arch))
    versions = {(item.version, item.release) for item in artifacts}
    if len(versions) > 1:
        raise ValueError("all archives in one manifest set must use the same version/release")
    return artifacts




def nix_system(artifact: ArchiveMetadata) -> str | None:
    mapping = {
        ("linux", "amd64"): "x86_64-linux",
        ("linux", "arm64"): "aarch64-linux",
        ("linux", "386"): "i686-linux",
        ("linux", "armv7"): "armv7l-linux",
        ("linux", "ppc64le"): "powerpc64le-linux",
        ("linux", "s390x"): "s390x-linux",
        ("linux", "riscv64"): "riscv64-linux",
        ("darwin", "amd64"): "x86_64-darwin",
        ("darwin", "arm64"): "aarch64-darwin",
    }
    return mapping.get((artifact.goos, artifact.arch))

def select_artifact(artifacts: list[ArchiveMetadata], *, goos: str | None = None, arch: str | None = None) -> ArchiveMetadata:
    for artifact in artifacts:
        if goos and artifact.goos != goos:
            continue
        if arch and artifact.arch != arch:
            continue
        return artifact
    wanted = "/".join(part for part in (goos, arch) if part)
    raise ValueError(f"no archive available for {wanted or 'requested target'}")


def render_nix(name: str, artifacts: list[ArchiveMetadata], *, homepage: str, description: str) -> str:
    nix_artifacts = [(nix_system(item), item) for item in artifacts]
    nix_artifacts = [(system, item) for system, item in nix_artifacts if system]
    if not nix_artifacts:
        raise ValueError("Nix derivation requires at least one linux or darwin archive")
    version = f"{nix_artifacts[0][1].version}-{nix_artifacts[0][1].release}"
    source_entries = "\n".join(
        f'    "{system}" = {{ url = "{item.url}"; hash = "{item.sha256_sri}"; }};'
        for system, item in nix_artifacts
    )
    platforms = " ".join(f'"{system}"' for system, _item in nix_artifacts)
    return f'''# Generated by tools/packaging/build_repository_manifests.py; do not edit by hand.
{{ lib, stdenvNoCC, fetchurl }}:

let
  sources = {{
{source_entries}
  }};
  source = sources.${{stdenvNoCC.hostPlatform.system}} or (throw "unsupported weaverssh binary platform: ${{stdenvNoCC.hostPlatform.system}}");
in
stdenvNoCC.mkDerivation rec {{
  pname = "{name}";
  version = "{version}";

  src = fetchurl source;

  sourceRoot = ".";

  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin $out/share/doc/{name}
    binary=$(find . -path '*/bin/wv' -type f | head -n 1)
    if [ -z "$binary" ]; then
      echo "wv binary not found in archive" >&2
      exit 1
    fi
    install -m 0755 "$binary" $out/bin/wv
    for doc in README.md MANIFEST.json SECURITY.json CHECKSUMS.txt; do
      found=$(find . -name "$doc" -type f | head -n 1 || true)
      [ -z "$found" ] || install -m 0644 "$found" $out/share/doc/{name}/"$doc"
    done
    runHook postInstall
  '';

  meta = with lib; {{
    description = "{description}";
    homepage = "{homepage}";
    platforms = [ {platforms} ];
    mainProgram = "wv";
  }};
}}
'''


def scoop_arch_key(arch: str) -> str:
    return {"amd64": "64bit", "arm64": "arm64", "386": "32bit"}.get(arch, arch)


def render_scoop(name: str, artifacts: list[ArchiveMetadata], *, homepage: str, description: str) -> str:
    windows = [item for item in artifacts if item.goos == "windows"]
    if not windows:
        raise ValueError("Scoop manifest requires at least one windows archive")
    version = f"{windows[0].version}-{windows[0].release}"
    arch_payload: dict[str, dict[str, str]] = {}
    for artifact in windows:
        arch_payload[scoop_arch_key(artifact.arch)] = {"url": artifact.url, "hash": artifact.sha256}
    payload = {
        "version": version,
        "description": description,
        "homepage": homepage,
        "license": "Apache-2.0",
        "architecture": arch_payload,
        "bin": [["bin\\wv.exe", "wv"]],
        "checkver": "github",
        "autoupdate": {"architecture": {key: {"url": value["url"]} for key, value in arch_payload.items()}},
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_chocolatey_nuspec(name: str, artifact: ArchiveMetadata, *, homepage: str, description: str) -> str:
    version = f"{artifact.version}.{artifact.release}"
    return f'''<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>{name}</id>
    <version>{version}</version>
    <title>weaverssh</title>
    <authors>weaverssh maintainers</authors>
    <owners>weaverssh maintainers</owners>
    <projectUrl>{homepage}</projectUrl>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <description>{description}</description>
    <summary>{description}</summary>
    <tags>ssh x11 websocket devops sre</tags>
  </metadata>
  <files>
    <file src="tools\\**" target="tools" />
  </files>
</package>
'''


def render_chocolatey_install(artifact: ArchiveMetadata, *, name: str) -> str:
    return f'''$ErrorActionPreference = 'Stop'
$packageName = '{name}'
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$url64 = '{artifact.url}'
$checksum64 = '{artifact.sha256}'
$installDir = Join-Path $env:ChocolateyInstall 'lib\\weaverssh\\bin'
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
$archive = Join-Path $toolsDir 'weaverssh.tar.gz'
Get-ChocolateyWebFile -PackageName $packageName -FileFullPath $archive -Url64bit $url64 -Checksum64 $checksum64 -ChecksumType64 'sha256'
tar -xzf $archive -C $toolsDir
$wv = Get-ChildItem -Path $toolsDir -Recurse -Filter 'wv.exe' | Select-Object -First 1
if (-not $wv) {{ throw 'wv.exe not found in archive' }}
Copy-Item $wv.FullName (Join-Path $installDir 'wv.exe') -Force
Install-ChocolateyPath $installDir 'Machine'
'''


def write_outputs(plan: RepositoryManifestPlan, artifacts: list[ArchiveMetadata], *, homepage: str, description: str) -> None:
    output_dir = Path(plan.output_dir)
    if "nix" in plan.channels:
        path = output_dir / "nix" / "weaverssh-bin.nix"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_nix(plan.name, artifacts, homepage=homepage, description=description), encoding="utf-8")
    if "scoop" in plan.channels:
        path = output_dir / "scoop" / "weaverssh.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_scoop(plan.name, artifacts, homepage=homepage, description=description), encoding="utf-8")
    if "chocolatey" in plan.channels:
        artifact = select_artifact(artifacts, goos="windows", arch="amd64")
        base = output_dir / "chocolatey" / "weaverssh"
        tools = base / "tools"
        tools.mkdir(parents=True, exist_ok=True)
        (base / "weaverssh.nuspec").write_text(render_chocolatey_nuspec(plan.name, artifact, homepage=homepage, description=description), encoding="utf-8")
        (tools / "chocolateyinstall.ps1").write_text(render_chocolatey_install(artifact, name=plan.name), encoding="utf-8")


def validate_channel_artifacts(channels: list[str], artifacts: list[ArchiveMetadata]) -> None:
    # Validate during --plan too, so CI catches impossible repository outputs early.
    if "nix" in channels and not any(nix_system(item) for item in artifacts):
        raise ValueError("Nix derivation requires at least one linux or darwin archive")
    if "scoop" in channels and not any(item.goos == "windows" for item in artifacts):
        raise ValueError("Scoop manifest requires at least one windows archive")
    if "chocolatey" in channels:
        select_artifact(artifacts, goos="windows", arch="amd64")


def build_plan(
    archives: list[Path],
    *,
    output_dir: Path,
    channels: list[str],
    name: str,
    url_base: str | None,
    url_overrides: dict[str, str],
) -> tuple[RepositoryManifestPlan, list[ArchiveMetadata]]:
    artifacts = build_artifacts(archives, url_base=url_base, url_overrides=url_overrides)
    validate_channel_artifacts(channels, artifacts)
    version = f"{artifacts[0].version}-{artifacts[0].release}"
    outputs: list[str] = []
    for channel in channels:
        if channel == "nix":
            outputs.append(str(output_dir / "nix" / "weaverssh-bin.nix"))
        elif channel == "scoop":
            outputs.append(str(output_dir / "scoop" / "weaverssh.json"))
        elif channel == "chocolatey":
            outputs.extend([
                str(output_dir / "chocolatey" / "weaverssh" / "weaverssh.nuspec"),
                str(output_dir / "chocolatey" / "weaverssh" / "tools" / "chocolateyinstall.ps1"),
            ])
        else:
            raise ValueError(f"unsupported channel: {channel}")
    return RepositoryManifestPlan(name=name, version=version, channels=channels, output_dir=str(output_dir), outputs=outputs, artifacts=artifacts), artifacts


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", action="append", default=[], help="Binary distribution archive; may be repeated")
    parser.add_argument("--channel", action="append", choices=SUPPORTED_CHANNELS, help="Channel to generate; defaults to all")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--name", default=DEFAULT_NAME)
    parser.add_argument("--url-base", help="Base download URL for archives; defaults to file:// URLs")
    parser.add_argument("--url", action="append", help="Per-target URL override: windows/amd64=https://...")
    parser.add_argument("--homepage", default=DEFAULT_HOMEPAGE)
    parser.add_argument("--description", default=DEFAULT_DESCRIPTION)
    parser.add_argument("--plan", action="store_true", help="Print JSON plan without writing files")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.archive:
        raise SystemExit("at least one --archive is required")
    channels = args.channel or list(SUPPORTED_CHANNELS)
    url_overrides = parse_key_value(args.url, field="url")
    plan, artifacts = build_plan([Path(item) for item in args.archive], output_dir=args.output_dir, channels=channels, name=args.name, url_base=args.url_base, url_overrides=url_overrides)
    if args.plan:
        print(json.dumps(asdict(plan), indent=2, sort_keys=True))
        return 0
    write_outputs(plan, artifacts, homepage=args.homepage, description=args.description)
    print(json.dumps(asdict(plan), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
