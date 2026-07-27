#!/usr/bin/env python3
from __future__ import annotations

"""Generate a Homebrew Formula from weaverssh binary distribution archives.

The formula is binary-archive based by design: Homebrew installs the released
`wv` binary from `dist/binary/weaverssh-<version>-<release>-<goos>-<arch>.tar.gz`
instead of rebuilding from source or depending on Python packaging helpers.
"""

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

DEFAULT_DESC = "weaverssh user-space data bus over SSH"
DEFAULT_HOMEPAGE = "https://weaverssh.com"
DEFAULT_LICENSE = ":cannot_represent"
DEFAULT_OUTPUT = "dist/homebrew/Formula/weaverssh.rb"
SUPPORTED_GOOS = {"darwin", "linux"}


@dataclass(frozen=True)
class HomebrewArtifact:
    archive: str
    target: str
    goos: str
    arch: str
    version: str
    release: str
    url: str
    sha256: str


@dataclass(frozen=True)
class HomebrewPlan:
    formula_name: str
    class_name: str
    version: str
    output: str
    artifacts: list[HomebrewArtifact]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ruby_string(value: str) -> str:
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def infer_archive_metadata(path: Path) -> tuple[str, str, str, str]:
    name = path.name
    suffix = ".tar.gz"
    if not name.startswith("weaverssh-") or not name.endswith(suffix):
        raise ValueError(f"archive name must look like weaverssh-VERSION-RELEASE-GOOS-ARCH.tar.gz: {name}")
    stem = name[: -len(suffix)]
    parts = stem.split("-")
    if len(parts) < 5:
        raise ValueError(f"archive name has too few components: {name}")
    arch = parts[-1]
    goos = parts[-2]
    release = parts[-3]
    version = "-".join(parts[1:-3])
    if not version or not release or not goos or not arch:
        raise ValueError(f"archive name has empty metadata fields: {name}")
    if goos not in SUPPORTED_GOOS:
        raise ValueError(f"Homebrew formula supports darwin/linux archives, got {goos!r} from {name}")
    return version, release, goos, arch


def parse_key_value(items: Iterable[str] | None, *, field: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            raise ValueError(f"--{field} entries must use TARGET=value syntax: {item}")
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not value:
            raise ValueError(f"--{field} entries must use TARGET=value syntax: {item}")
        result[key] = value
    return result


def artifact_url(path: Path, *, target: str, url_base: str | None, url_overrides: dict[str, str]) -> str:
    if target in url_overrides:
        return url_overrides[target]
    if url_base:
        return url_base.rstrip("/") + "/" + path.name
    return path.resolve().as_uri()


def build_plan(
    archives: list[Path],
    *,
    output: Path,
    formula_name: str,
    class_name: str,
    version_override: str | None = None,
    release_override: str | None = None,
    url_base: str | None = None,
    url_overrides: dict[str, str] | None = None,
    sha_overrides: dict[str, str] | None = None,
) -> HomebrewPlan:
    if not archives:
        raise ValueError("at least one --archive is required")
    url_overrides = url_overrides or {}
    sha_overrides = sha_overrides or {}

    artifacts: list[HomebrewArtifact] = []
    expected_version: str | None = None
    expected_release: str | None = None
    seen_targets: set[str] = set()
    for archive in archives:
        if not archive.exists():
            raise FileNotFoundError(f"archive not found: {archive}")
        parsed_version, parsed_release, goos, arch = infer_archive_metadata(archive)
        version = version_override or parsed_version
        release = release_override or parsed_release
        expected_version = expected_version or version
        expected_release = expected_release or release
        if version != expected_version or release != expected_release:
            raise ValueError(
                "all archives in one Formula must use the same version/release: "
                f"expected {expected_version}-{expected_release}, got {version}-{release} for {archive}"
            )
        target = f"{goos}/{arch}"
        if target in seen_targets:
            raise ValueError(f"duplicate Homebrew target: {target}")
        seen_targets.add(target)
        artifacts.append(
            HomebrewArtifact(
                archive=str(archive),
                target=target,
                goos=goos,
                arch=arch,
                version=version,
                release=release,
                url=artifact_url(archive, target=target, url_base=url_base, url_overrides=url_overrides),
                sha256=sha_overrides.get(target, sha256_file(archive)),
            )
        )

    artifacts.sort(key=lambda item: (item.goos, item.arch))
    assert expected_version is not None and expected_release is not None
    return HomebrewPlan(
        formula_name=formula_name,
        class_name=class_name,
        version=f"{expected_version}-{expected_release}",
        output=str(output),
        artifacts=artifacts,
    )


def cpu_predicate(goos: str, arch: str) -> str:
    if arch == "amd64":
        return "Hardware::CPU.intel? && Hardware::CPU.is_64_bit?" if goos == "linux" else "Hardware::CPU.intel?"
    if arch == "386":
        return "Hardware::CPU.intel? && !Hardware::CPU.is_64_bit?"
    if arch == "arm64":
        return "Hardware::CPU.arm? && Hardware::CPU.is_64_bit?" if goos == "linux" else "Hardware::CPU.arm?"
    if arch.startswith("armv") or arch == "arm":
        return "Hardware::CPU.arm? && !Hardware::CPU.is_64_bit?"
    return "true"


def render_url_sha(artifact: HomebrewArtifact, indent: str) -> list[str]:
    return [
        f"{indent}url {ruby_string(artifact.url)}",
        f"{indent}sha256 {ruby_string(artifact.sha256)}",
    ]


def render_platform_blocks(artifacts: list[HomebrewArtifact]) -> list[str]:
    if len(artifacts) == 1:
        return render_url_sha(artifacts[0], "  ")

    lines: list[str] = []
    for goos, block_name in (("darwin", "on_macos"), ("linux", "on_linux")):
        group = [artifact for artifact in artifacts if artifact.goos == goos]
        if not group:
            continue
        lines.append(f"  {block_name} do")
        for idx, artifact in enumerate(group):
            keyword = "if" if idx == 0 else "elsif"
            lines.append(f"    {keyword} {cpu_predicate(artifact.goos, artifact.arch)}")
            lines.extend(render_url_sha(artifact, "      "))
        lines.append("    end")
        lines.append("  end")
        lines.append("")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def render_formula(plan: HomebrewPlan, *, desc: str, homepage: str, license_value: str) -> str:
    license_line = f"  license {license_value}" if license_value.startswith(":") else f"  license {ruby_string(license_value)}"
    lines = [
        "# typed: false",
        "# Generated by tools/packaging/build_homebrew_formula.py; do not edit by hand.",
        f"class {plan.class_name} < Formula",
        f"  desc {ruby_string(desc)}",
        f"  homepage {ruby_string(homepage)}",
        license_line,
        f"  version {ruby_string(plan.version)}",
        "",
    ]
    lines.extend(render_platform_blocks(plan.artifacts))
    lines.extend(
        [
            "",
            "  def install",
            "    binary = Dir.glob([\"bin/wv\", \"*/bin/wv\"]).find { |candidate| File.file?(candidate) }",
            "    raise \"wv binary not found in archive\" unless binary",
            "",
            "    bin.install binary => \"wv\"",
            "",
            "    doc_candidates = Dir.glob([",
            "      \"README.md\", \"*/README.md\",",
            "      \"MANIFEST.json\", \"*/MANIFEST.json\",",
            "      \"SECURITY.json\", \"*/SECURITY.json\",",
            "      \"CHECKSUMS.txt\", \"*/CHECKSUMS.txt\",",
            "    ]).select { |candidate| File.file?(candidate) }",
            "    doc.install doc_candidates if doc_candidates.any?",
            "  end",
            "",
            "  def caveats",
            "    <<~EOS",
            "      Optional SSH/X11/FUSE helpers are managed by wv itself. Inspect them with:",
            "        wv deps status",
            "    EOS",
            "  end",
            "",
            "  test do",
            "    assert_match \"weaverssh\", shell_output(\"#{bin}/wv version\")",
            "    assert_match \"Usage:\", shell_output(\"#{bin}/wv help\")",
            "  end",
            "end",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a Homebrew Formula from weaverssh binary archives")
    parser.add_argument("--archive", action="append", default=[], help="Binary archive path; may be repeated")
    parser.add_argument("--url-base", help="Base URL used for archive downloads; defaults to file:// URLs")
    parser.add_argument("--url", action="append", help="Per-target URL override: darwin/arm64=https://...")
    parser.add_argument("--sha256", action="append", help="Per-target SHA-256 override: darwin/arm64=<hex>")
    parser.add_argument("--version", help="Override version inferred from archive names")
    parser.add_argument("--release", help="Override release inferred from archive names")
    parser.add_argument("--formula-name", default="weaverssh")
    parser.add_argument("--class-name", default="Weaverssh")
    parser.add_argument("--desc", default=DEFAULT_DESC)
    parser.add_argument("--homepage", default=DEFAULT_HOMEPAGE)
    parser.add_argument("--license", default=DEFAULT_LICENSE)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--plan", action="store_true", help="Print JSON plan without writing Formula")
    args = parser.parse_args(argv)

    try:
        plan = build_plan(
            [Path(item) for item in args.archive],
            output=Path(args.output),
            formula_name=args.formula_name,
            class_name=args.class_name,
            version_override=args.version,
            release_override=args.release,
            url_base=args.url_base,
            url_overrides=parse_key_value(args.url, field="url"),
            sha_overrides=parse_key_value(args.sha256, field="sha256"),
        )
    except Exception as exc:
        raise SystemExit(f"error: {exc}") from exc

    payload = asdict(plan)
    if args.plan:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    output = Path(plan.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_formula(plan, desc=args.desc, homepage=args.homepage, license_value=args.license), encoding="utf-8")
    print(json.dumps({**payload, "written": str(output)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
