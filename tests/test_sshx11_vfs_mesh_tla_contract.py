from __future__ import annotations

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.verification import verify_sshx11_extension_set_tla as verifier


def test_vfs_mesh_tla_contract_schema_is_present() -> None:
    path = REPO_ROOT / "verification" / "tla" / "SSHX11VFSMeshNamespaceContract.tla"
    text = verifier._read_tla(path)
    required = [
        "DataPlaneBindings",
        "ControlPlaneComponents",
        "NamespaceLayouts",
        "NorthboundAPIs",
        "ExecutionNodes",
        "MandatoryExecutionSequence",
        "CrossLayerObligations",
        "SafetyInvariant",
        "CanonicalHappyPathTrace",
    ]
    for name in required:
        assert verifier._get_tla_def(text, name) is not None, name


def test_vfs_mesh_tla_happy_path_has_expected_endpoints() -> None:
    path = REPO_ROOT / "verification" / "tla" / "SSHX11VFSMeshNamespaceContract.tla"
    text = verifier._read_tla(path)
    trace = verifier._parse_string_seq(verifier._must_def(text, "CanonicalHappyPathTrace"))
    assert trace[0] == "set_data_plane_ready"
    assert trace[-2] == "expose_webdav"
    assert trace[-1] == "expose_search"


def test_vfs_mesh_tla_cfg_exists() -> None:
    cfg = REPO_ROOT / "verification" / "tla" / "SSHX11VFSMeshNamespaceContract.cfg"
    assert cfg.exists()
    text = cfg.read_text(encoding="utf-8")
    assert "SPECIFICATION Spec" in text
    assert "INVARIANTS" in text
    assert "SafetyInvariant" in text
