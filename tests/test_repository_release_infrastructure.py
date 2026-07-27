from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "tools" / "packaging" / "build_native_repositories.py"
BUNDLE = ROOT / "tools" / "packaging" / "build_release_bundle.py"
UPDATER = ROOT / "tools" / "packaging" / "update_weaverssh.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def write_artifact(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    path.with_name(path.name + ".sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return path


def fixture_artifacts(tmp_path: Path) -> list[Path]:
    return [
        write_artifact(tmp_path / "weaverssh_1.2.3-4_amd64.deb", b"deb"),
        write_artifact(tmp_path / "weaverssh-1.2.3-4.x86_64.rpm", b"rpm"),
        write_artifact(tmp_path / "weaverssh-1.2.3-4-x86_64.pkg.tar.zst", b"arch"),
        write_artifact(tmp_path / "weaverssh-1.2.3-4-freebsd-amd64.pkg", b"freebsd"),
        write_artifact(tmp_path / "weaverssh-1.2.3-4-source.tar.gz", b"source"),
    ]


def test_native_repository_builder_generates_requested_layouts(tmp_path: Path) -> None:
    native = load(NATIVE, "native_repo_test")
    artifacts = fixture_artifacts(tmp_path / "artifacts")
    output = tmp_path / "repo"
    plan = native.make_plan(
        artifacts,
        output,
        ["apt", "rpm-redhat", "rpm-suse", "arch", "freebsd", "homebrew"],
        "stable",
        "main",
        "https://packages.example.invalid/weaverssh",
        1700000000,
    )
    result = native.build(plan)
    assert result["ok"] is True

    packages = output / "apt" / "dists" / "stable" / "main" / "binary-amd64" / "Packages"
    text = packages.read_text(encoding="utf-8")
    assert "Package: weaverssh" in text
    assert "Version: 1.2.3-4" in text
    assert "Filename: pool/main/w/weaverssh/weaverssh_1.2.3-4_amd64.deb" in text
    assert hashlib.sha256(b"deb").hexdigest() in text

    release = (output / "apt" / "dists" / "stable" / "Release").read_text(encoding="utf-8")
    assert "Suite: stable" in release
    assert "SHA256:" in release
    assert "main/binary-amd64/Packages.gz" in release

    assert (output / "rpm" / "redhat" / "x86_64" / "GENERATE-METADATA.json").is_file()
    assert (output / "rpm" / "suse" / "x86_64" / "GENERATE-METADATA.json").is_file()
    assert (output / "arch" / "x86_64" / "GENERATE-METADATA.json").is_file()
    assert (output / "freebsd" / "amd64" / "GENERATE-METADATA.json").is_file()

    formula = (output / "homebrew" / "Formula" / "weaverssh.rb").read_text(encoding="utf-8")
    assert "https://packages.example.invalid/weaverssh/weaverssh-1.2.3-4-source.tar.gz" in formula
    assert hashlib.sha256(b"source").hexdigest() in formula
    assert (output / "REPOSITORY.json").is_file()
    assert (output / "SHA256SUMS.txt").is_file()


def test_native_repository_channels_are_inferred_from_artifacts(tmp_path: Path) -> None:
    native = load(NATIVE, "native_repo_infer_test")
    deb = write_artifact(tmp_path / "weaverssh_1.2.3-4_amd64.deb", b"deb")
    source = write_artifact(tmp_path / "weaverssh-1.2.3-4-source.tar.gz", b"source")
    plan = native.make_plan([deb, source], tmp_path / "repo", [], "stable", "main", "", 0)
    assert plan.channels == ["apt", "homebrew"]


def test_native_repository_plan_rejects_mixed_versions(tmp_path: Path) -> None:
    native = load(NATIVE, "native_repo_mixed_test")
    first = write_artifact(tmp_path / "weaverssh_1.2.3-1_amd64.deb", b"a")
    second = write_artifact(tmp_path / "weaverssh_1.2.4-1_arm64.deb", b"b")
    try:
        native.make_plan([first, second], tmp_path / "out", ["apt"], "stable", "main", "", 0)
    except ValueError as exc:
        assert "one version/release" in str(exc)
    else:
        raise AssertionError("mixed repository versions were accepted")


def test_release_bundle_is_reproducible_and_self_describing(tmp_path: Path) -> None:
    bundle = load(BUNDLE, "release_bundle_test")
    artifacts = [
        write_artifact(tmp_path / "inputs" / "weaverssh_1.2.3-4_amd64.deb", b"deb"),
        write_artifact(tmp_path / "inputs" / "weaverssh-1.2.3-4-windows-amd64.zip", b"windows"),
    ]
    plan_a = bundle.make_plan(
        "1.2.3",
        "4",
        artifacts,
        tmp_path / "out-a",
        "https://releases.example.invalid/v1.2.3",
        1700000000,
        False,
        "none",
    )
    plan_b = bundle.make_plan(
        "1.2.3",
        "4",
        artifacts,
        tmp_path / "out-b",
        "https://releases.example.invalid/v1.2.3",
        1700000000,
        False,
        "none",
    )
    result_a = bundle.build(plan_a, artifacts, False, "")
    result_b = bundle.build(plan_b, artifacts, False, "")
    assert bundle.sha256_file(Path(result_a["tar_gz"])) == bundle.sha256_file(Path(result_b["tar_gz"]))
    assert bundle.sha256_file(Path(result_a["zip"])) == bundle.sha256_file(Path(result_b["zip"]))

    with tarfile.open(result_a["tar_gz"], "r:gz") as archive:
        names = set(archive.getnames())
        root_name = "weaverssh-1.2.3-4"
        assert f"{root_name}/release-index.json" in names
        assert f"{root_name}/LATEST.json" in names
        assert f"{root_name}/SHA256SUMS.txt" in names
        handle = archive.extractfile(f"{root_name}/release-index.json")
        assert handle is not None
        index = json.load(handle)
        assert index["schema"] == "weaverssh.release-bundle.v1"
        assert len(index["artifacts"]) == 2


def test_release_bundle_rejects_missing_or_wrong_sidecar(tmp_path: Path) -> None:
    bundle = load(BUNDLE, "release_bundle_sidecar_test")
    artifact = tmp_path / "weaverssh_1.2.3-4_amd64.deb"
    artifact.write_bytes(b"deb")
    try:
        bundle.make_plan("1.2.3", "4", [artifact], tmp_path / "out", "", 1700000000, False, "none")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("missing checksum sidecar was accepted")
    artifact.with_name(artifact.name + ".sha256").write_text("0" * 64 + "  " + artifact.name + "\n", encoding="utf-8")
    try:
        bundle.make_plan("1.2.3", "4", [artifact], tmp_path / "out", "", 1700000000, False, "none")
    except ValueError as exc:
        assert "mismatch" in str(exc)
    else:
        raise AssertionError("wrong checksum sidecar was accepted")


def test_update_plan_covers_verify_install_health_and_rollback(tmp_path: Path) -> None:
    updater = load(UPDATER, "updater_plan_test")
    artifact = write_artifact(tmp_path / "weaverssh-1.2.3-4.x86_64.rpm", b"rpm")
    rollback = write_artifact(tmp_path / "weaverssh-1.2.2-3.x86_64.rpm", b"old")
    current = tmp_path / "bin" / "wv"
    current.parent.mkdir()
    current.write_bytes(b"current")
    plan = updater.make_plan(
        artifact,
        None,
        "zypper",
        "suse",
        str(current),
        tmp_path / "snapshot",
        [str(current), "version"],
        rollback,
        None,
    )
    assert plan.schema == "weaverssh.update-transaction.v1"
    assert "verify_release_artifact.py" in plan.verify_command[1]
    assert "zypper" in plan.install_commands[0]
    assert plan.health_command == [str(current.resolve()), "version"]
    assert plan.rollback_artifact == str(rollback.resolve())
    assert "zypper" in plan.rollback_install_commands[0]
    assert plan.journal.endswith("transaction.json")


def test_update_plan_rejects_same_rollback_artifact(tmp_path: Path) -> None:
    updater = load(UPDATER, "updater_same_rollback_test")
    artifact = write_artifact(tmp_path / "weaverssh_1.2.3-4_amd64.deb", b"deb")
    current = tmp_path / "wv"
    current.write_bytes(b"current")
    try:
        updater.make_plan(
            artifact,
            None,
            "apt",
            "redhat",
            str(current),
            tmp_path / "snapshot",
            [],
            artifact,
            None,
        )
    except ValueError as exc:
        assert "must differ" in str(exc)
    else:
        raise AssertionError("same update and rollback artifact was accepted")


def test_update_execution_restores_snapshot_after_health_failure(tmp_path: Path) -> None:
    updater = load(UPDATER, "updater_execute_test")
    artifact = write_artifact(tmp_path / "weaverssh_1.2.3-4_amd64.deb", b"deb")
    current = tmp_path / "bin" / "wv"
    current.parent.mkdir()
    current.write_bytes(b"old-binary")
    plan = updater.make_plan(
        artifact,
        None,
        "apt",
        "redhat",
        str(current),
        tmp_path / "snapshot",
        [str(current), "version"],
        None,
        None,
    )

    calls: list[list[str]] = []

    def fake_run(command):
        command = list(command)
        calls.append(command)
        if command == plan.install_commands[0]:
            current.write_bytes(b"new-binary")
        if command == plan.health_command:
            raise RuntimeError("health failed")

    updater.run = fake_run
    try:
        updater.execute(plan, False, False)
    except RuntimeError as exc:
        assert "health failed" in str(exc)
    else:
        raise AssertionError("failed health check did not fail transaction")
    assert current.read_bytes() == b"old-binary"
    journal = json.loads(Path(plan.journal).read_text(encoding="utf-8"))
    assert journal["state"] == "rolled-back"
    assert journal["rollback"] == "binary-snapshot"
    assert calls[0] == plan.verify_command


def test_make_layer_exposes_repository_release_targets() -> None:
    layer = (ROOT / "mk" / "repository-release.mk").read_text(encoding="utf-8")
    top = (ROOT / "GNUmakefile").read_text(encoding="utf-8")
    assert "include mk/repository-release.mk" in top
    for target in (
        "native-repositories-plan",
        "native-repositories",
        "release-bundle-plan",
        "release-bundle",
        "update-plan",
        "update-apply",
        "test-repository-release",
    ):
        assert f"{target}:" in layer
