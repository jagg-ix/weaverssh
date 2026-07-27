from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _fake_wv(path: Path) -> None:
    path.write_text(
        """#!/bin/sh
set -eu
cmd=${1:-help}
case "$cmd" in
  version)
    echo "weaverssh test"
    ;;
  help|--help|-h)
    echo "wv test help"
    ;;
  deps)
    log=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --log-file)
          log=${2:-}
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    if [ -n "$log" ]; then
      mkdir -p "$(dirname "$log")"
      printf '{"event":"deps status"}\n' > "$log"
    fi
    echo "deps ok"
    ;;
  *)
    echo "wv $*"
    ;;
esac
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def test_binary_distribution_is_source_free_and_smoke_testable(tmp_path: Path) -> None:
    fake = tmp_path / "wv"
    _fake_wv(fake)

    output = subprocess.check_output(
        [
            str(REPO_ROOT / "tools/packaging/build_binary_distribution.sh"),
            "--binary",
            str(fake),
            "--target",
            "linux/amd64",
            "--version",
            "1.2.3",
            "--release",
            "4",
            "--dist-dir",
            str(tmp_path / "dist"),
            "--build-dir",
            str(tmp_path / "build"),
        ],
        cwd=REPO_ROOT,
        text=True,
    )
    result = json.loads(output[output.index("{") :])
    archive = Path(result["archive"])
    checksum = Path(result["checksum"])
    assert archive.exists()
    assert checksum.exists()
    assert result["source_required_to_test"] is False
    checksum_text = checksum.read_text(encoding="utf-8").strip()
    assert len(checksum_text.split()[0]) == 64
    assert checksum_text.endswith(archive.name)

    with tarfile.open(archive, "r:gz") as tf:
        names = set(tf.getnames())
    root = "weaverssh-1.2.3-4-linux-amd64"
    assert f"{root}/bin/wv" in names
    assert f"{root}/scripts/install.sh" in names
    assert f"{root}/scripts/smoke-test.sh" in names
    assert f"{root}/scripts/verify.sh" in names
    assert f"{root}/MANIFEST.json" in names
    assert f"{root}/SECURITY.json" in names
    assert f"{root}/CHECKSUMS.txt" in names
    assert not any(name.endswith(".go") for name in names)
    assert not any(Path(name).name.startswith("._") for name in names)
    assert not any("/cmd/" in name or "/tools/packaging/" in name for name in names)

    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()
    with tarfile.open(archive, "r:gz") as tf:
        tf.extractall(extract_dir)
    extracted_root = extract_dir / root
    subprocess.run([str(extracted_root / "scripts" / "smoke-test.sh")], check=True)

    install_home = tmp_path / "install-home"
    env = os.environ.copy()
    env.update({"HOME": str(install_home), "LC_ALL": "C", "LANG": "C"})
    installed = subprocess.run(
        [str(extracted_root / "scripts" / "install.sh")],
        check=True,
        env=env,
        text=True,
        capture_output=True,
    )
    assert "Checksum verified: bin/wv" in installed.stdout
    assert (install_home / ".weaverssh" / "bin" / "wv").exists()
    assert (install_home / ".weaverssh" / "env.sh").exists()
    install_log = install_home / ".weaverssh" / "logs" / "install.jsonl"
    assert install_log.exists()
    assert "binary-distribution:weaverssh-1.2.3-4-linux-amd64" in install_log.read_text(encoding="utf-8")

    tampered_parent = tmp_path / "tampered"
    tampered_root = tampered_parent / root
    shutil.copytree(extracted_root, tampered_root)
    tampered_bin = tampered_root / "bin" / "wv"
    tampered_bin.write_text("#!/bin/sh\necho tampered\n", encoding="utf-8")
    tampered_bin.chmod(0o755)
    bad = subprocess.run(
        [str(tampered_root / "scripts" / "install.sh")],
        env={**env, "HOME": str(tmp_path / "bad-home")},
        text=True,
        capture_output=True,
    )
    assert bad.returncode != 0
    assert "checksum mismatch for bin/wv" in bad.stderr





def test_top_level_installer_declares_supported_posix_platform_matrix() -> None:
    script = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")

    assert "linux|darwin|freebsd|openbsd|netbsd|aix" in script
    assert "powerpc|PowerPC|ppc|ppc64|powerpc64" in script
    assert "ppc64le|s390x|riscv64" in script
    assert "BSD notes:" in script
    assert "AIX notes:" in script
    assert "Linux on IBM Z notes:" in script
    assert "gzip -dc" in script


def test_top_level_installer_installs_local_archive_source_free(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    bin_dir = pkg / "bin"
    bin_dir.mkdir(parents=True)
    _fake_wv(bin_dir / "wv")
    archive = tmp_path / "weaverssh-smoke.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(pkg, arcname=".")
    checksum = _sha256(archive)

    home = tmp_path / "home"
    env = os.environ.copy()
    env.update({
        "HOME": str(home),
        "WEAVERSSH_ARCHIVE": str(archive),
        "WEAVERSSH_CHECKSUM": checksum,
        "LC_ALL": "C",
        "LANG": "C",
    })
    result = subprocess.run(
        ["sh", str(REPO_ROOT / "install.sh")],
        check=True,
        env=env,
        text=True,
        capture_output=True,
    )
    assert "Checksum verified" in result.stdout
    assert (home / ".weaverssh" / "bin" / "wv").exists()
    assert (home / ".weaverssh" / "env.sh").exists()
    assert "archive:" in (home / ".weaverssh" / "logs" / "install.jsonl").read_text(encoding="utf-8")

    bad = subprocess.run(
        ["sh", str(REPO_ROOT / "install.sh")],
        env={**env, "HOME": str(tmp_path / "bad-home"), "WEAVERSSH_CHECKSUM": "0" * 64},
        text=True,
        capture_output=True,
    )
    assert bad.returncode != 0
    assert "checksum mismatch" in bad.stderr



def test_binary_distribution_injects_release_version_metadata(tmp_path: Path) -> None:
    if not shutil.which("go"):
        raise AssertionError("go is required to validate release metadata injection")

    goos = subprocess.check_output(["go", "env", "GOOS"], text=True).strip()
    goarch = subprocess.check_output(["go", "env", "GOARCH"], text=True).strip()
    target = f"{goos}/{goarch}"
    label = f"{goos}-{goarch}"
    bin_name = "wv.exe" if goos == "windows" else "wv"

    output = subprocess.check_output(
        [
            str(REPO_ROOT / "tools/packaging/build_binary_distribution.sh"),
            "--target",
            target,
            "--version",
            "9.8.7",
            "--release",
            "6",
            "--dist-dir",
            str(tmp_path / "dist"),
            "--build-dir",
            str(tmp_path / "build"),
        ],
        cwd=REPO_ROOT,
        text=True,
    )
    result = json.loads(output[output.index("{") :])
    archive = Path(result["archive"])
    root = f"weaverssh-9.8.7-6-{label}"
    extract_dir = tmp_path / "extract-real"
    extract_dir.mkdir()
    with tarfile.open(archive, "r:gz") as tf:
        tf.extractall(extract_dir)

    version = subprocess.check_output([str(extract_dir / root / "bin" / bin_name), "version"], text=True).strip()
    assert "weaverssh 9.8.7-6" in version
    assert f"target={target}" in version
    assert "commit=" in version
    assert "dirty=" in version
    assert "(dev)" not in version

    manifest = json.loads((extract_dir / root / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["version"] == "9.8.7"
    assert manifest["release"] == "6"
    assert manifest["target"] == target
    assert isinstance(manifest["source_dirty"], bool)



def _build_fake_distribution(tmp_path: Path, name: str, *, sign_key: Path | None = None) -> dict[str, str]:
    fake = tmp_path / f"{name}-wv"
    _fake_wv(fake)
    dist = tmp_path / f"{name}-dist"
    build = tmp_path / f"{name}-build"
    cmd = [
        str(REPO_ROOT / "tools/packaging/build_binary_distribution.sh"),
        "--binary",
        str(fake),
        "--target",
        "linux/amd64",
        "--version",
        "1.2.3",
        "--release",
        "4",
        "--source-date-epoch",
        "1700000000",
        "--dist-dir",
        str(dist),
        "--build-dir",
        str(build),
    ]
    if sign_key is not None:
        cmd.extend(["--sign-key", str(sign_key)])
    output = subprocess.check_output(cmd, cwd=REPO_ROOT, text=True)
    return json.loads(output[output.index("{") :])


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_binary_distribution_is_reproducible_and_verifiable(tmp_path: Path) -> None:
    first = _build_fake_distribution(tmp_path, "first")
    second = _build_fake_distribution(tmp_path, "second")
    first_archive = Path(first["archive"])
    second_archive = Path(second["archive"])
    assert _sha256(first_archive) == _sha256(second_archive)

    extract_dir = tmp_path / "extract-repro"
    extract_dir.mkdir()
    with tarfile.open(first_archive, "r:gz") as tf:
        tf.extractall(extract_dir)
    root = extract_dir / "weaverssh-1.2.3-4-linux-amd64"
    security = json.loads((root / "SECURITY.json").read_text(encoding="utf-8"))
    assert security["build"]["reproducible_archive"] is True
    assert security["build"]["source_date_epoch"] == 1700000000
    assert security["build"]["deterministic_tar_gzip"] is True
    assert security["build"]["normalized_uid_gid"] is True
    assert security["verification"]["verify_script"] == "scripts/verify.sh"

    subprocess.run(
        [
            str(REPO_ROOT / "tools/packaging/verify_binary_distribution.sh"),
            "--archive",
            str(first_archive),
            "--checksum",
            str(first_archive) + ".sha256",
            "--smoke",
        ],
        check=True,
    )


def test_binary_distribution_can_emit_and_verify_openssl_signature(tmp_path: Path) -> None:
    if not shutil.which("openssl"):
        pytest.skip("openssl not available")
    key = tmp_path / "release.key"
    pub = tmp_path / "release.pub"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["openssl", "rsa", "-in", str(key), "-pubout", "-out", str(pub)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    result = _build_fake_distribution(tmp_path, "signed", sign_key=key)
    archive = Path(result["archive"])
    signature = Path(str(archive) + ".sig")
    provenance = Path(result["provenance"])
    assert signature.exists()
    assert provenance.exists()
    provenance_data = json.loads(provenance.read_text(encoding="utf-8"))
    assert provenance_data["signatures"][0]["type"] == "openssl-dgst-sha256"

    subprocess.run(
        [
            str(REPO_ROOT / "tools/packaging/verify_binary_distribution.sh"),
            "--archive",
            str(archive),
            "--checksum",
            str(archive) + ".sha256",
            "--signature",
            str(signature),
            "--public-key",
            str(pub),
            "--smoke",
        ],
        check=True,
    )
