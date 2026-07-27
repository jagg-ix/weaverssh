from __future__ import annotations

from pathlib import Path
import subprocess

REPO_ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = REPO_ROOT / "Makefile"


def run_make(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["make", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def assert_success(proc: subprocess.CompletedProcess[str]) -> None:
    assert proc.returncode == 0, proc.stderr + proc.stdout


def test_makefile_declares_development_build_targets() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    for target in [
        "build-all-native-binaries:",
        "list-libraries:",
        "list-commands:",
        "build-libraries:",
        "build-internal-libraries:",
        "build-library-surface:",
        "build-commands:",
        "dev-doctor:",
        "dev-setup:",
        "dev-fast:",
        "dev-check:",
        "fmt-check:",
        "vet:",
        "pytest-collect:",
        "test-go:",
        "test-go-race:",
        "test-python-build:",
    ]:
        assert target in text
    assert "LIBRARY_PACKAGES?=./authproof ./display ./padding ./relay ./tunnel" in text
    assert "INTERNAL_LIBRARY_PACKAGES?=./internal/app ./internal/p9svc" in text
    assert "COMMAND_PACKAGES=$(MAIN_PKG)" in text
    assert "PYTEST?=$(PYTHON_BIN) -m pytest" in text


def test_makefile_list_libraries_reports_public_and_internal_packages() -> None:
    proc = run_make("list-libraries")
    assert_success(proc)
    assert "Public library packages:" in proc.stdout
    assert "./authproof" in proc.stdout
    assert "./relay" in proc.stdout
    assert "Internal library packages:" in proc.stdout
    assert "./internal/app" in proc.stdout
    assert "./internal/p9svc" in proc.stdout


def test_makefile_dev_fast_is_no_release_binary_gate() -> None:
    proc = run_make("-n", "dev-fast")
    assert_success(proc)
    for expected in [
        "go mod verify",
        "Checking Go formatting",
        "Running go vet",
        "Compiling public Go library packages",
        "Compiling internal Go library packages",
        "Compiling Go command packages",
        "Collecting Python tests",
        "verify_weaverssh_tunnel_policy.py",
    ]:
        assert expected in proc.stdout
    assert "Building integrated server" not in proc.stdout
    assert "build/bin" not in proc.stdout


def test_makefile_dev_check_extends_fast_gate_with_native_binaries_and_go_tests() -> None:
    proc = run_make("-n", "dev-check")
    assert_success(proc)
    assert "Fast development checks passed" in proc.stdout
    assert "Building X11 test client for native platform" in proc.stdout
    assert "Building native SSH forwarding planner" in proc.stdout
    assert "Running Go tests" in proc.stdout
    assert "GOOS=linux GOARCH=amd64" not in proc.stdout


def test_makefile_dev_doctor_reports_prerequisites_and_surfaces() -> None:
    proc = run_make("dev-doctor")
    assert_success(proc)
    assert "Checking development prerequisites" in proc.stdout
    assert "Go:" in proc.stdout
    assert "Python:" in proc.stdout
    assert "Pytest:" in proc.stdout
    assert "Public library packages:" in proc.stdout
    assert "Command packages:" in proc.stdout


def test_makefile_native_binary_target_uses_native_client_not_linux_client() -> None:
    proc = run_make("-n", "build-all-native-binaries")
    assert_success(proc)
    assert "Building X11 test client for native platform" in proc.stdout
    assert "Building native SSH forwarding planner" in proc.stdout
    assert "GOOS=linux GOARCH=amd64" not in proc.stdout


def test_makefile_build_libraries_compiles_public_packages() -> None:
    proc = run_make("build-libraries")
    assert_success(proc)
    assert "weaverssh/authproof" in proc.stdout
    assert "weaverssh/tunnel" in proc.stdout


def test_makefile_build_internal_libraries_compiles_internal_packages() -> None:
    proc = run_make("build-internal-libraries")
    assert_success(proc)
    assert "weaverssh/internal/app" in proc.stdout
    assert "weaverssh/internal/p9svc" in proc.stdout
