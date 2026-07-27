#!/usr/bin/env python3
from __future__ import annotations

"""Build a Windows WeaverSSH zip package from a prebuilt wv.exe binary."""

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class WindowsPackagePlan:
    schema: str
    version: str
    release: str
    arch: str
    binary: str
    output: str
    contents: list[str]


def clean_token(value: str, name: str) -> str:
    value = value.strip().lstrip("v") if name == "version" else value.strip()
    if not value or any(ch.isspace() or ch in "/\\:+" for ch in value):
        raise ValueError(f"invalid {name}: {value!r}")
    return value


def make_plan(version: str, release: str, arch: str, binary_dir: Path, dist_dir: Path) -> WindowsPackagePlan:
    version = clean_token(version, "version")
    release = clean_token(release, "release")
    arch = arch.strip().lower()
    if arch not in {"amd64", "arm64", "386"}:
        raise ValueError("Windows package arch must be amd64, arm64, or 386")
    return WindowsPackagePlan(
        schema="weaverssh.windows-package-plan.v1",
        version=version,
        release=release,
        arch=arch,
        binary=str(binary_dir / "wv.exe"),
        output=str(dist_dir / f"weaverssh-{version}-{release}-windows-{arch}.zip"),
        contents=["wv.exe", "install.ps1", "uninstall.ps1", "README.md", "MANIFEST.json", "SHA256SUMS.txt"],
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_scripts(stage: Path) -> None:
    (stage / "install.ps1").write_text(r'''param(
  [string]$InstallDir = "$env:LOCALAPPDATA\WeaverSSH\bin",
  [switch]$System
)
$ErrorActionPreference = "Stop"
if ($System) { $InstallDir = "$env:ProgramFiles\WeaverSSH\bin" }
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force (Join-Path $PSScriptRoot "wv.exe") (Join-Path $InstallDir "wv.exe")
$scope = if ($System) { "Machine" } else { "User" }
$current = [Environment]::GetEnvironmentVariable("Path", $scope)
$parts = @($current -split ';' | Where-Object { $_ })
if ($parts -notcontains $InstallDir) {
  [Environment]::SetEnvironmentVariable("Path", (($parts + $InstallDir) -join ';'), $scope)
}
Write-Host "WeaverSSH installed to $InstallDir. Open a new terminal and run: wv --help"
''', encoding="utf-8")
    (stage / "uninstall.ps1").write_text(r'''param(
  [string]$InstallDir = "$env:LOCALAPPDATA\WeaverSSH\bin",
  [switch]$System
)
$ErrorActionPreference = "Stop"
if ($System) { $InstallDir = "$env:ProgramFiles\WeaverSSH\bin" }
$scope = if ($System) { "Machine" } else { "User" }
$current = [Environment]::GetEnvironmentVariable("Path", $scope)
$parts = @($current -split ';' | Where-Object { $_ -and $_ -ne $InstallDir })
[Environment]::SetEnvironmentVariable("Path", ($parts -join ';'), $scope)
Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
Write-Host "WeaverSSH removed from $InstallDir"
''', encoding="utf-8")


def build(plan: WindowsPackagePlan) -> Path:
    binary = Path(plan.binary)
    if not binary.is_file():
        raise FileNotFoundError(f"missing built Windows binary: {binary}")
    output = Path(plan.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="weaverssh-windows-") as raw:
        stage = Path(raw)
        shutil.copy2(binary, stage / "wv.exe")
        write_scripts(stage)
        readme = f"""# WeaverSSH for Windows

Version: {plan.version}-{plan.release}
Architecture: {plan.arch}

Install for the current user:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\\install.ps1
```

For a system installation, run an elevated PowerShell and use `.\\install.ps1 -System`.
WSL uses the Linux build and should be built inside the WSL distribution instead.
"""
        (stage / "README.md").write_text(readme, encoding="utf-8")
        manifest = {
            "schema": "weaverssh.windows-package.v1",
            "version": plan.version,
            "release": plan.release,
            "arch": plan.arch,
            "binary": "wv.exe",
            "sha256": sha256(stage / "wv.exe"),
        }
        (stage / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        checksums = []
        for path in sorted(stage.iterdir()):
            if path.is_file() and path.name != "SHA256SUMS.txt":
                checksums.append(f"{sha256(path)}  {path.name}")
        (stage / "SHA256SUMS.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8")
        if output.exists():
            output.unlink()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(stage.iterdir()):
                archive.write(path, arcname=path.name)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "build"), nargs="?", default="plan")
    parser.add_argument("--version", default="0.1.0")
    parser.add_argument("--release", default="1")
    parser.add_argument("--arch", default="amd64")
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--dist-dir", type=Path, default=REPO_ROOT / "dist" / "packages")
    args = parser.parse_args()
    plan = make_plan(args.version, args.release, args.arch, args.binary_dir, args.dist_dir)
    if args.command == "plan":
        print(json.dumps(asdict(plan), indent=2, sort_keys=True))
        return 0
    output = build(plan)
    print(json.dumps({"ok": True, "output": str(output)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
