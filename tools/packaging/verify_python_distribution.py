#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def first_field(path: Path) -> str:
    return path.read_text(encoding="utf-8").split()[0]


def verify_signature(archive: Path, signature: Path | None, public_key: Path | None, gpg_signature: Path | None) -> None:
    if signature:
        if not public_key:
            fail("--public-key is required with --signature")
        if not signature.is_file():
            fail(f"signature not found: {signature}")
        if not public_key.is_file():
            fail(f"public key not found: {public_key}")
        openssl = shutil.which("openssl")
        if not openssl:
            fail("openssl is required for --signature verification")
        subprocess.run(
            [openssl, "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature), str(archive)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        print("openssl signature: ok")
    elif gpg_signature:
        if not gpg_signature.is_file():
            fail(f"gpg signature not found: {gpg_signature}")
        gpg = shutil.which("gpg")
        if not gpg:
            fail("gpg is required for --gpg-signature verification")
        subprocess.run([gpg, "--verify", str(gpg_signature), str(archive)], check=True, stdout=subprocess.DEVNULL)
        print("gpg signature: ok")
    else:
        print("signature: skipped")


def verify_internal(root: Path) -> None:
    checksums = root / "CHECKSUMS.txt"
    if not checksums.is_file():
        fail("missing CHECKSUMS.txt")
    for raw in checksums.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            expected, rel = raw.split(None, 1)
        except ValueError:
            fail(f"invalid checksum line: {raw}")
        rel = rel.strip()
        target = root / rel
        if not target.is_file():
            fail(f"missing checksummed file: {rel}")
        actual = sha256_file(target)
        if actual != expected:
            fail(f"internal checksum mismatch for {rel}: expected {expected} got {actual}")
    print("internal checksums: ok")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a weaverssh Python production distribution archive.")
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--checksum", type=Path)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--gpg-signature", type=Path)
    parser.add_argument("--extract-dir", type=Path)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()

    archive = args.archive
    if not archive.is_file():
        fail(f"archive not found: {archive}")
    checksum = args.checksum or Path(str(archive) + ".sha256")
    if checksum.is_file():
        expected = first_field(checksum)
        actual = sha256_file(archive)
        if expected != actual:
            fail(f"archive checksum mismatch: expected {expected} got {actual}")
        print("archive checksum: ok")
    else:
        print("archive checksum: skipped")

    verify_signature(archive, args.signature, args.public_key, args.gpg_signature)

    cleanup = args.extract_dir is None
    extract_dir = args.extract_dir or Path(tempfile.mkdtemp(prefix="weaverssh-python-verify."))
    try:
        extract_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive, "r:gz") as tf:
            try:
                tf.extractall(extract_dir, filter="data")
            except TypeError:  # Python < 3.12
                tf.extractall(extract_dir)
        roots = sorted([p for p in extract_dir.iterdir() if p.is_dir()])
        if not roots:
            fail("archive did not contain a top-level directory")
        root = roots[0]
        for required in ("PYTHON_MANIFEST.json", "PYTHON_SECURITY.json", "CHECKSUMS.txt", "bin/weaverssh-py", "scripts/bootstrap-python.sh"):
            if not (root / required).exists():
                fail(f"missing {required}")
        verify_internal(root)
        manifest = json.loads((root / "PYTHON_MANIFEST.json").read_text(encoding="utf-8"))
        security = json.loads((root / "PYTHON_SECURITY.json").read_text(encoding="utf-8"))
        print(f"manifest: {root / 'PYTHON_MANIFEST.json'}")
        print(f"security: {root / 'PYTHON_SECURITY.json'}")
        print(f"tools: {len(manifest.get('tools', []))}")
        if not security.get("reproducible_archive"):
            fail("PYTHON_SECURITY.json does not declare reproducible_archive=true")
        if args.smoke:
            subprocess.run([str(root / "bin" / "weaverssh-py"), "--list"], check=True, stdout=subprocess.DEVNULL)
            print("smoke: ok")
    finally:
        if cleanup:
            shutil.rmtree(extract_dir, ignore_errors=True)
    print("verify: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
