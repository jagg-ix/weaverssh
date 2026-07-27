#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VERSION = os.environ.get("WEAVERSSH_VERSION", "0.1.0")
DEFAULT_RELEASE = os.environ.get("WEAVERSSH_RELEASE", "1")
MANIFEST_PATH = REPO_ROOT / "tools" / "packaging" / "python_distribution_manifest.json"


@dataclass(frozen=True)
class BuildResult:
    ok: bool
    archive: str
    checksum: str
    provenance: str
    package_root: str
    source_date_epoch: int
    default_profile: str
    tools: int


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_text(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def run(cmd: list[str], *, cwd: Path | None = None) -> str:
    return subprocess.check_output(cmd, cwd=str(cwd) if cwd else None, text=True).strip()


def git_commit() -> str:
    try:
        return run(["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO_ROOT)
    except Exception:
        return "unknown"


def git_dirty() -> bool:
    try:
        subprocess.run(["git", "diff", "--quiet", "--ignore-submodules", "--"], cwd=REPO_ROOT, check=True)
        subprocess.run(["git", "diff", "--cached", "--quiet", "--ignore-submodules", "--"], cwd=REPO_ROOT, check=True)
        return False
    except Exception:
        return True


def default_epoch(dirty: bool) -> int:
    env = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if env:
        return int(env)
    if not dirty:
        try:
            return int(run(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=REPO_ROOT))
        except Exception:
            pass
    return int(time.time())


def safe_part(value: str) -> str:
    cleaned = (value or "").strip() or "0"
    for ch in " /+":
        cleaned = cleaned.replace(ch, ".")
    return cleaned


def copy_file(src: Path, dst: Path, executable: bool = False) -> None:
    if not src.is_file():
        raise FileNotFoundError(f"missing required file: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    dst.chmod(0o755 if executable else 0o644)


ENTRYPOINT_LAUNCHER = '''#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "PYTHON_MANIFEST.json").read_text(encoding="utf-8"))
TOOLS = {tool["name"]: tool for tool in MANIFEST.get("tools", [])}


def print_list() -> None:
    print("weaverssh Python tools")
    for tool in sorted(TOOLS.values(), key=lambda item: item["name"]):
        print(f"  {tool['name']:<24} profile={tool['profile']:<8} {tool.get('description', '')}")


def print_profiles() -> None:
    print("weaverssh Python profiles")
    for name, profile in sorted(MANIFEST.get("profiles", {}).items()):
        print(f"  {name:<10} {profile.get('description', '')}")


def main(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help", "help"}:
        print("usage: weaverssh-py --list | --profiles | TOOL [args...]")
        print_list()
        return 0
    if argv[0] == "--list":
        print_list()
        return 0
    if argv[0] == "--profiles":
        print_profiles()
        return 0
    name, rest = argv[0], argv[1:]
    tool = TOOLS.get(name)
    if not tool:
        print(f"unknown Python tool: {name}", file=sys.stderr)
        print_list()
        return 2
    path = ROOT / tool["path"]
    if not path.is_file():
        print(f"tool file missing: {path}", file=sys.stderr)
        return 1
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(path.parent))
    sys.argv = [str(path), *rest]
    runpy.run_path(str(path), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
'''

BOOTSTRAP_SCRIPT = r'''#!/bin/sh
# Install a weaverssh Python production distribution into the current user's home.
set -eu
LC_ALL=C
LANG=C
export LC_ALL LANG

usage() {
  cat <<'USAGE'
usage: bootstrap-python.sh [options]

Options:
  --prefix DIR       Install prefix. Default: $HOME/.weaverssh/python
  --profile NAME     Dependency profile: core, mcp, webterm, tray, vision, all. Default: core.
  --python PYTHON    Python interpreter. Default: python3.
  --no-venv          Use the selected interpreter directly instead of creating a venv.
  --no-install-deps  Copy files but skip pip dependency installation.
  --log-file FILE    Log file. Default: <prefix>/logs/python-bootstrap.log
  -h, --help         Show help.
USAGE
}

prefix=${WEAVERSSH_PYTHON_PREFIX:-$HOME/.weaverssh/python}
profile=${WEAVERSSH_PYTHON_PROFILE:-core}
python_bin=${PYTHON:-python3}
use_venv=true
install_deps=true
log_file=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) prefix=${2:?missing --prefix value}; shift 2 ;;
    --profile) profile=${2:?missing --profile value}; shift 2 ;;
    --python) python_bin=${2:?missing --python value}; shift 2 ;;
    --no-venv) use_venv=false; shift ;;
    --no-install-deps) install_deps=false; shift ;;
    --log-file) log_file=${2:?missing --log-file value}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
case "$profile" in core|mcp|webterm|tray|vision|all) ;; *) echo "unsupported profile: $profile" >&2; exit 2 ;; esac
command -v "$python_bin" >/dev/null 2>&1 || { echo "python interpreter not found: $python_bin" >&2; exit 1; }
log_file=${log_file:-$prefix/logs/python-bootstrap.log}
mkdir -p "$prefix/current" "$(dirname "$log_file")"
{
  printf 'bootstrap started: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'source=%s\n' "$root"
  printf 'prefix=%s\n' "$prefix"
  printf 'profile=%s\n' "$profile"
  printf 'python=%s\n' "$python_bin"
} >> "$log_file"

# Copy the distribution into a stable user-home location. tar is used instead of
# rsync so the bootstrap works on minimal hosts.
( cd "$root" && tar -cf - . ) | ( cd "$prefix/current" && tar -xf - )

runtime_python="$python_bin"
if [ "$use_venv" = true ]; then
  "$python_bin" -m venv "$prefix/venv" >> "$log_file" 2>&1 || {
    echo "venv creation failed; retry with --no-venv or install python3-venv" >&2
    exit 1
  }
  runtime_python="$prefix/venv/bin/python"
fi

if [ "$install_deps" = true ]; then
  req="$prefix/current/requirements/python/$profile.txt"
  if [ "$profile" = all ]; then req="$prefix/current/requirements/python/production.txt"; fi
  [ -f "$req" ] || { echo "requirements file missing: $req" >&2; exit 1; }
  "$runtime_python" -m pip install --upgrade pip >> "$log_file" 2>&1 || true
  if [ -d "$prefix/current/wheelhouse" ]; then
    "$runtime_python" -m pip install --no-index --find-links "$prefix/current/wheelhouse" -r "$req" >> "$log_file" 2>&1
  else
    "$runtime_python" -m pip install -r "$req" >> "$log_file" 2>&1
  fi
fi

launcher="$prefix/bin/weaverssh-py"
mkdir -p "$prefix/bin"
cat > "$launcher" <<LAUNCHER
#!/bin/sh
exec "$runtime_python" "$prefix/current/bin/weaverssh-py" "\$@"
LAUNCHER
chmod 0755 "$launcher"
printf 'installed launcher: %s\n' "$launcher"
printf 'log file: %s\n' "$log_file"
printf 'list tools: %s --list\n' "$launcher"
'''

VERIFY_SHELL = '''#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
python_bin=${PYTHON:-python3}
exec "$python_bin" "$root/scripts/verify-python.py" "$@"
'''


def write_checksums(stage: Path) -> None:
    rows: list[str] = []
    for path in sorted(stage.rglob("*")):
        if path.is_file() and path.name != "CHECKSUMS.txt":
            rows.append(f"{sha256_file(path)}  {path.relative_to(stage).as_posix()}")
    write_text(stage / "CHECKSUMS.txt", "\n".join(rows) + "\n", 0o644)


def write_repro_tar(source: Path, root_name: str, archive: Path, epoch: int) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    members = sorted(source.rglob("*"), key=lambda p: p.relative_to(source).as_posix())
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=9) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tf:
                root_info = tarfile.TarInfo(root_name)
                root_info.type = tarfile.DIRTYPE
                root_info.mode = 0o755
                root_info.uid = root_info.gid = 0
                root_info.uname = root_info.gname = "root"
                root_info.mtime = epoch
                tf.addfile(root_info)
                for path in members:
                    rel = path.relative_to(source).as_posix()
                    info = path.lstat()
                    ti = tarfile.TarInfo(f"{root_name}/{rel}")
                    ti.uid = ti.gid = 0
                    ti.uname = ti.gname = "root"
                    ti.mtime = epoch
                    if path.is_dir():
                        ti.type = tarfile.DIRTYPE
                        ti.mode = 0o755
                        tf.addfile(ti)
                    elif path.is_symlink():
                        ti.type = tarfile.SYMTYPE
                        ti.linkname = os.readlink(path)
                        ti.mode = 0o777
                        tf.addfile(ti)
                    elif path.is_file():
                        ti.type = tarfile.REGTYPE
                        ti.mode = stat.S_IMODE(info.st_mode) or 0o644
                        ti.size = info.st_size
                        with path.open("rb") as f:
                            tf.addfile(ti, f)


def copy_distribution_files(stage: Path, manifest: dict[str, Any]) -> None:
    write_text(stage / "PYTHON_MANIFEST.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    requirements = set()
    for profile in manifest["profiles"].values():
        for rel in profile.get("requirements", []):
            requirements.add(rel)
    requirements.update(["requirements/python/production.txt", "requirements/python/core.txt"])
    for rel in sorted(requirements):
        copy_file(REPO_ROOT / rel, stage / rel)
    for tool in manifest["tools"]:
        copy_file(REPO_ROOT / tool["path"], stage / tool["path"], executable=True)
    local_helpers = [
        "tools/verification/sshx11_remote_compat.py",
        "tools/verification/zero_trust_proof_manifest.py",
    ]
    for rel in local_helpers:
        src = REPO_ROOT / rel
        if src.exists():
            copy_file(src, stage / rel, executable=bool(src.stat().st_mode & 0o111))
    write_text(stage / "bin" / "weaverssh-py", ENTRYPOINT_LAUNCHER, 0o755)
    write_text(stage / "scripts" / "bootstrap-python.sh", BOOTSTRAP_SCRIPT, 0o755)
    write_text(stage / "scripts" / "verify-python.sh", VERIFY_SHELL, 0o755)
    copy_file(REPO_ROOT / "tools" / "packaging" / "verify_python_distribution.py", stage / "scripts" / "verify-python.py", executable=True)


def maybe_download_wheels(stage: Path, profile: str, python_bin: str) -> None:
    req = stage / "requirements" / "python" / ("production.txt" if profile == "all" else f"{profile}.txt")
    wheelhouse = stage / "wheelhouse"
    wheelhouse.mkdir(parents=True, exist_ok=True)
    subprocess.run([python_bin, "-m", "pip", "download", "-r", str(req), "-d", str(wheelhouse)], check=True)


def sign_artifacts(archive: Path, sign: bool, sign_key: str, gpg_key: str) -> list[dict[str, str]]:
    signatures: list[dict[str, str]] = []
    if not sign:
        return signatures
    if sign_key:
        sig = Path(str(archive) + ".sig")
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", sign_key, "-out", str(sig), str(archive)], check=True)
        signatures.append({"type": "openssl-dgst-sha256", "path": sig.name, "sha256": sha256_file(sig)})
    else:
        sig = Path(str(archive) + ".asc")
        cmd = ["gpg", "--batch", "--yes", "--armor"]
        if gpg_key:
            cmd += ["--local-user", gpg_key]
        cmd += ["--detach-sign", "--output", str(sig), str(archive)]
        subprocess.run(cmd, check=True)
        signatures.append({"type": "gpg-detached-armored", "path": sig.name, "sha256": sha256_file(sig)})
    return signatures


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a production weaverssh Python distribution archive.")
    parser.add_argument("--version", default=DEFAULT_VERSION)
    parser.add_argument("--release", default=DEFAULT_RELEASE)
    parser.add_argument("--dist-dir", type=Path, default=REPO_ROOT / "dist" / "python")
    parser.add_argument("--build-dir", type=Path, default=REPO_ROOT / "build" / "python-dist")
    parser.add_argument("--source-date-epoch", type=int)
    parser.add_argument("--default-profile", default="core")
    parser.add_argument("--download-wheels", action="store_true", help="Vendor wheels into the archive using pip download.")
    parser.add_argument("--wheel-profile", default="all", help="Profile used with --download-wheels.")
    parser.add_argument("--python", default=sys.executable or "python3")
    parser.add_argument("--sign", action="store_true")
    parser.add_argument("--sign-key", default="")
    parser.add_argument("--gpg-key", default="")
    args = parser.parse_args()

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if args.default_profile not in manifest["profiles"]:
        raise SystemExit(f"unsupported default profile: {args.default_profile}")
    version = safe_part(args.version)
    release = safe_part(args.release)
    package_root = f"weaverssh-python-{version}-{release}"
    work = args.build_dir / f"{package_root}.work.{os.getpid()}"
    stage = work / package_root
    if work.exists():
        shutil.rmtree(work)
    stage.mkdir(parents=True)
    dirty = git_dirty()
    epoch = int(args.source_date_epoch if args.source_date_epoch is not None else default_epoch(dirty))
    built_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
    manifest["default_profile"] = args.default_profile
    copy_distribution_files(stage, manifest)
    if args.download_wheels:
        maybe_download_wheels(stage, args.wheel_profile, args.python)

    security = {
        "schema": "weaverssh.python.security.v1",
        "python_requires": manifest["python_requires"],
        "default_profile": args.default_profile,
        "dependency_model": "profile-requirements-plus-optional-wheelhouse",
        "wheelhouse_included": (stage / "wheelhouse").exists(),
        "checksum_algorithm": "sha256",
        "reproducible_archive": True,
        "source_date_epoch": epoch,
        "built_at": built_at,
        "normalized_uid_gid": True,
        "normalized_mtime": True,
        "deterministic_tar_gzip": True,
        "bootstrap": {
            "default_prefix": "$HOME/.weaverssh/python",
            "creates_venv_by_default": True,
            "supports_offline_wheelhouse": True,
            "log_file_default": "<prefix>/logs/python-bootstrap.log",
        },
        "profiles": manifest["profiles"],
    }
    write_text(stage / "PYTHON_SECURITY.json", json.dumps(security, indent=2, sort_keys=True) + "\n")
    write_checksums(stage)

    args.dist_dir.mkdir(parents=True, exist_ok=True)
    archive = args.dist_dir / f"{package_root}.tar.gz"
    write_repro_tar(stage, package_root, archive, epoch)
    archive_sha = sha256_file(archive)
    checksum = Path(str(archive) + ".sha256")
    write_text(checksum, f"{archive_sha}  {archive.name}\n")
    signatures = sign_artifacts(archive, args.sign or bool(args.sign_key or args.gpg_key), args.sign_key, args.gpg_key)
    provenance = {
        "schema": "weaverssh.python.provenance.v1",
        "name": "weaverssh-python",
        "version": version,
        "release": release,
        "archive": archive.name,
        "archive_sha256": archive_sha,
        "checksum_sidecar": checksum.name,
        "source_commit": git_commit(),
        "source_dirty": dirty,
        "source_date_epoch": epoch,
        "built_at": built_at,
        "default_profile": args.default_profile,
        "tools": len(manifest.get("tools", [])),
        "profiles": sorted(manifest.get("profiles", {}).keys()),
        "signatures": signatures,
        "verify": [
            f"python3 tools/packaging/verify_python_distribution.py --archive {archive.name} --checksum {checksum.name}",
            f"./{package_root}/scripts/verify-python.sh --archive ../{archive.name} --checksum ../{checksum.name}",
        ],
    }
    provenance_path = Path(str(archive) + ".provenance.json")
    write_text(provenance_path, json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    write_text(Path(str(provenance_path) + ".sha256"), f"{sha256_file(provenance_path)}  {provenance_path.name}\n")
    result = BuildResult(True, str(archive), str(checksum), str(provenance_path), package_root, epoch, args.default_profile, len(manifest.get("tools", [])))
    print(json.dumps(asdict(result), indent=2, sort_keys=True))
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
