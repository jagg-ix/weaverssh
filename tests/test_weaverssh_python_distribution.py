from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_python_dist(tmp_path: Path, name: str, sign_key: Path | None = None) -> dict[str, str | int | bool]:
    cmd = [
        "python3",
        str(REPO_ROOT / "tools/packaging/build_python_distribution.py"),
        "--version",
        "1.2.3",
        "--release",
        "4",
        "--source-date-epoch",
        "1700000000",
        "--dist-dir",
        str(tmp_path / f"{name}-dist"),
        "--build-dir",
        str(tmp_path / f"{name}-build"),
    ]
    if sign_key is not None:
        cmd.extend(["--sign-key", str(sign_key)])
    output = subprocess.check_output(cmd, cwd=REPO_ROOT, text=True)
    return json.loads(output)


def test_python_distribution_contains_bootstrap_manifest_and_profiles(tmp_path: Path) -> None:
    result = build_python_dist(tmp_path, "first")
    archive = Path(result["archive"])
    assert archive.exists()
    assert Path(result["checksum"]).exists()
    assert Path(result["provenance"]).exists()
    assert result["default_profile"] == "core"
    assert result["tools"] >= 5

    with tarfile.open(archive, "r:gz") as tf:
        names = set(tf.getnames())
    root = "weaverssh-python-1.2.3-4"
    expected = {
        f"{root}/bin/weaverssh-py",
        f"{root}/scripts/bootstrap-python.sh",
        f"{root}/scripts/verify-python.py",
        f"{root}/PYTHON_MANIFEST.json",
        f"{root}/PYTHON_SECURITY.json",
        f"{root}/CHECKSUMS.txt",
        f"{root}/requirements/python/core.txt",
        f"{root}/requirements/python/mcp.txt",
        f"{root}/tools/packaging/install_runtime_dependencies.py",
    }
    assert expected.issubset(names)
    assert not any("/__pycache__/" in name or name.endswith(".pyc") for name in names)

    extract = tmp_path / "extract"
    extract.mkdir()
    with tarfile.open(archive, "r:gz") as tf:
        tf.extractall(extract)
    manifest = json.loads((extract / root / "PYTHON_MANIFEST.json").read_text(encoding="utf-8"))
    security = json.loads((extract / root / "PYTHON_SECURITY.json").read_text(encoding="utf-8"))
    assert "core" in manifest["profiles"]
    assert "mcp" in manifest["profiles"]
    assert security["bootstrap"]["creates_venv_by_default"] is True
    assert security["bootstrap"]["supports_offline_wheelhouse"] is True
    subprocess.run([str(extract / root / "bin" / "weaverssh-py"), "--list"], check=True)


def test_python_distribution_is_reproducible_and_verifiable(tmp_path: Path) -> None:
    first = build_python_dist(tmp_path, "first")
    second = build_python_dist(tmp_path, "second")
    assert sha256(Path(first["archive"])) == sha256(Path(second["archive"]))
    subprocess.run(
        [
            "python3",
            str(REPO_ROOT / "tools/packaging/verify_python_distribution.py"),
            "--archive",
            str(first["archive"]),
            "--checksum",
            str(first["checksum"]),
            "--smoke",
        ],
        cwd=REPO_ROOT,
        check=True,
    )


def test_python_distribution_can_emit_and_verify_openssl_signature(tmp_path: Path) -> None:
    if not shutil.which("openssl"):
        return
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
    result = build_python_dist(tmp_path, "signed", sign_key=key)
    archive = Path(result["archive"])
    signature = Path(str(archive) + ".sig")
    provenance = json.loads(Path(result["provenance"]).read_text(encoding="utf-8"))
    assert signature.exists()
    assert provenance["signatures"][0]["type"] == "openssl-dgst-sha256"
    subprocess.run(
        [
            "python3",
            str(REPO_ROOT / "tools/packaging/verify_python_distribution.py"),
            "--archive",
            str(archive),
            "--checksum",
            str(result["checksum"]),
            "--signature",
            str(signature),
            "--public-key",
            str(pub),
            "--smoke",
        ],
        cwd=REPO_ROOT,
        check=True,
    )
