from __future__ import annotations

import pytest

from tools.verification import sshwb_contract_eval as eval_py


@pytest.mark.sshx11
@pytest.mark.unit
def test_normalize_remote_platform_variants() -> None:
    assert eval_py.normalize_remote_platform("linux") == "linux-generic"
    assert eval_py.normalize_remote_platform("linux without gui") == "linux-headless"
    assert eval_py.normalize_remote_platform("linux-headless") == "linux-headless"
    assert eval_py.normalize_remote_platform("kde") == "linux-gui"
    assert eval_py.normalize_remote_platform("darwin") == "macos"
    assert eval_py.normalize_remote_platform("freebsd") == "freebsd-generic"
    assert eval_py.normalize_remote_platform("freebsd-gui") == "freebsd-gui"
    assert eval_py.normalize_remote_platform("openbsd") == "openbsd"
    assert eval_py.normalize_remote_platform("z/os") == "zos"
    assert eval_py.normalize_remote_platform("sunos") == "solaris"
    assert eval_py.normalize_remote_platform("posix") == "generic"
    assert eval_py.normalize_remote_platform("unknown") == "auto"


@pytest.mark.sshx11
@pytest.mark.unit
def test_parse_host_spec_and_errors() -> None:
    label, host = eval_py.parse_host_spec("linode-a=203.0.113.10")
    assert label == "linode-a"
    assert host == "203.0.113.10"
    label, host = eval_py.parse_host_spec("203.0.113.20")
    assert label == "203.0.113.20"
    assert host == "203.0.113.20"
    with pytest.raises(ValueError, match="missing_host"):
        eval_py.parse_host_spec("broken=")


@pytest.mark.sshx11
@pytest.mark.unit
def test_evaluate_case_validation_failure() -> None:
    out = eval_py.evaluate_case(
        {
            "id": "bad",
            "platform": "linux",
            "host_spec": "broken=",
            "user": "root",
        }
    )
    assert out["ok"] is False
    assert out["error"] == "missing_host"

