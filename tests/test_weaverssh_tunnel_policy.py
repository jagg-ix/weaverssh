from __future__ import annotations

from pathlib import Path
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "verification" / "verify_weaverssh_tunnel_policy.py"
POLICY = REPO_ROOT / "docs" / "specs" / "tunnel_mechanism_policy.md"


def test_tunnel_policy_guard_passes_repo() -> None:
    proc = subprocess.run(["python3", str(SCRIPT)], cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "weaverssh tunnel policy verified" in proc.stdout


def test_tunnel_policy_doc_keeps_ssh_clients_as_launchers_not_data_plane() -> None:
    text = POLICY.read_text(encoding="utf-8")
    assert "They must not replace the weaverssh X11/WebSocket data plane." in text
    assert "wv-server" in text
    assert "Pageant" in text
    assert "Plink" in text
    for platform_class in (
        "Windows workstation",
        "Linux headless / IoT / embedded",
        "Linux generic",
        "Linux GUI: KDE, GNOME, and other desktops",
        "macOS workstation",
        "FreeBSD GUI",
        "FreeBSD generic",
        "OpenBSD",
    ):
        assert platform_class in text
    for adapter_term in ("Dropbear", "XQuartz", "KWallet", "GNOME Keyring"):
        assert adapter_term in text
    assert "policy-gated native SSH forwarding adapter" in text
    assert "ssh -L" in text
    assert "ssh -R" in text
    assert "ssh -D" in text
    assert "native_ssh_forwarding_option.md" in text
    assert "sshOnly" in text
    assert "trusted-peer authproof" in text
    assert "explicit chain" in text


def test_native_forwarding_option_documents_root_resistant_methods() -> None:
    text = (REPO_ROOT / "docs" / "specs" / "native_ssh_forwarding_option.md").read_text(encoding="utf-8")
    for required in (
        "ValidateNativeForwardingPolicy",
        "ValidateNativeForwardingProof",
        "BuildNativeForwardingOpenSSHArgs",
        "sshOnly",
        "trusted-peer authproof",
        "remote-root authority domain",
        "authproof/native_forwarding.go",
    ):
        assert required in text


def _write_minimal_policy(root: Path) -> None:
    policy = root / "docs" / "specs" / "tunnel_mechanism_policy.md"
    policy.parent.mkdir(parents=True)
    policy.write_text(
        "wv wv-server wv-agent wv-socks Pageant Plink\n"
        "Windows workstation Linux headless / IoT / embedded Linux generic\n"
        "Linux GUI: KDE, GNOME, and other desktops macOS workstation\n"
        "FreeBSD GUI FreeBSD generic OpenBSD Dropbear XQuartz KWallet GNOME Keyring\n"
        "They must not replace the weaverssh X11/WebSocket data plane.\n"
        "policy-gated native SSH forwarding adapter ssh -L ssh -R ssh -D\n"
        "sshOnly trusted-peer authproof explicit chain\n",
        encoding="utf-8",
    )


def test_tunnel_policy_guard_rejects_plink_reverse_forwarding(tmp_path: Path) -> None:
    _write_minimal_policy(tmp_path)
    bad_doc = tmp_path / "docs" / "windows.md"
    bad_doc.write_text(
        "Use plink.exe "
        "-R 127.0.0.1:6000:127.0.0.1:6000 as the main tunnel.\n",
        encoding="utf-8",
    )

    proc = subprocess.run(
        ["python3", str(SCRIPT), "--repo-root", str(tmp_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert proc.returncode != 0
    assert "Plink reverse forwarding must not be the weaverssh tunnel mechanism" in proc.stderr


def test_tunnel_policy_guard_rejects_unmanaged_raw_reverse_forwarding(tmp_path: Path) -> None:
    _write_minimal_policy(tmp_path)
    bad_doc = tmp_path / "docs" / "x11.md"
    bad_doc.write_text(
        "Start the X11/WebSocket path with ssh "
        "-R 6000:127.0.0.1:6000.\n",
        encoding="utf-8",
    )

    proc = subprocess.run(
        ["python3", str(SCRIPT), "--repo-root", str(tmp_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert proc.returncode != 0
    assert "raw ssh reverse forwarding requires managed reverse-socks/backhaul context" in proc.stderr


def test_tunnel_policy_guard_allows_auxiliary_native_reverse_forwarding(tmp_path: Path) -> None:
    _write_minimal_policy(tmp_path)
    good_doc = tmp_path / "docs" / "native.md"
    good_doc.write_text(
        "This is a policy-gated native SSH forwarding adapter.\n"
        "Use ssh "
        "-R 127.0.0.1:22022:127.0.0.1:6017 only as an auxiliary native forwarding adapter for managed backhaul.\n",
        encoding="utf-8",
    )

    proc = subprocess.run(
        ["python3", str(SCRIPT), "--repo-root", str(tmp_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0, proc.stderr


def test_tunnel_policy_guard_rejects_native_forwarding_as_primary_path(tmp_path: Path) -> None:
    _write_minimal_policy(tmp_path)
    bad_doc = tmp_path / "docs" / "native-primary.md"
    bad_doc.write_text(
        "This is a policy-gated native SSH forwarding adapter.\n"
        "Use ssh "
        "-R 127.0.0.1:22022:127.0.0.1:6017 as the primary X11/WebSocket tunnel.\n",
        encoding="utf-8",
    )

    proc = subprocess.run(
        ["python3", str(SCRIPT), "--repo-root", str(tmp_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert proc.returncode != 0
    assert "managed reverse forwarding must not be described as primary X11/WebSocket data plane" in proc.stderr
