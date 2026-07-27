from __future__ import annotations

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification import sshx11_plane_service as svc


def test_tail_log_missing_file_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "missing.log"
    assert svc._tail_log(p) == ""


def test_tail_log_returns_last_n_lines(tmp_path: Path) -> None:
    p = tmp_path / "service.log"
    p.write_text("a\nb\nc\nd\n", encoding="utf-8")
    assert svc._tail_log(p, n_lines=2) == "c\nd"


def test_session_spawn_kwargs_posix() -> None:
    out = svc._session_spawn_kwargs("posix")
    assert out.get("start_new_session") is True


def test_session_spawn_kwargs_freebsd() -> None:
    out = svc._session_spawn_kwargs("freebsd")
    assert out.get("start_new_session") is True


def test_session_spawn_kwargs_windows() -> None:
    out = svc._session_spawn_kwargs("nt")
    assert "start_new_session" not in out
    if hasattr(svc.subprocess, "CREATE_NEW_PROCESS_GROUP"):
        assert "creationflags" in out


def test_is_windows_detection() -> None:
    assert svc._is_windows("nt") is True
    assert svc._is_windows("posix") is False
    assert svc._is_windows("freebsd") is False
