from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOC_ROOT = REPO_ROOT / "docs" / "installation"

GUIDES = {
    "linux.md": ["# Linux Installation", "Default User-Home Install", "Dependency Planning", "Verification"],
    "windows-wsl.md": ["# Windows and WSL Installation", "Native Windows PowerShell", "WSL", "Verification"],
    "macos.md": ["# macOS Installation", "Homebrew Route", "Dependency Planning", "Verification"],
    "freebsd.md": ["# FreeBSD and BSD-Family Installation", "Dependency Planning", "pkg_add", "Verification"],
    "aix.md": ["# AIX Installation", "installp", "Local Archive With Checksum", "Verification"],
    "zos.md": ["# z/OS and IBM Z Installation", "linux/s390x", "Dependency Planning", "Verification"],
}


def test_installation_readme_index_links_all_os_guides() -> None:
    index = (DOC_ROOT / "README.md").read_text(encoding="utf-8")
    for guide in GUIDES:
        assert f"[{guide}]({guide})" in index


def test_each_major_os_installation_readme_has_required_sections() -> None:
    for guide, required in GUIDES.items():
        text = (DOC_ROOT / guide).read_text(encoding="utf-8")
        for marker in required:
            assert marker in text, f"{guide} missing {marker!r}"
        assert "wv version" in text
        assert "wv help" in text


def test_main_readme_links_installation_guides() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    for guide in GUIDES:
        assert f"docs/installation/{guide}" in readme
