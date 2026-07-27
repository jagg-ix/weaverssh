from __future__ import annotations

from pathlib import Path
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
FLAG_SCRIPT = REPO_ROOT / "tools" / "verification" / "test_authproof_agent_flags.sh"
INTEGRATION_SCRIPT = REPO_ROOT / "tools" / "verification" / "test_authproof_agent_integration.sh"

SOCKS_FLAGS = {
    "-proof-mode",
    "-proof-security-level",
    "-proof-issuer-id",
    "-proof-subject-id",
    "-proof-private-key",
    "-proof-private-key-file",
    "-proof-signer-provider",
    "-proof-signer",
    "-proof-identity",
    "-proof-identity-file",
    "-proof-agent-socket",
    "-proof-chain-sha256",
    "-proof-session-id",
    "-proof-ttl",
}

AGENT_FLAGS = {
    "-proof-mode",
    "-proof-security-level",
    "-proof-peer-id",
    "-proof-public-key",
    "-proof-public-key-file",
    "-proof-chain-sha256",
    "-proof-ttl",
}


def test_authproof_agent_scripts_exist_are_executable_and_parse() -> None:
    for script in (FLAG_SCRIPT, INTEGRATION_SCRIPT):
        assert script.exists(), script
        assert script.stat().st_mode & 0o111, script
        proc = subprocess.run(["bash", "-n", str(script)], cwd=REPO_ROOT, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr


def test_authproof_agent_flag_script_tracks_every_signer_and_verifier_flag() -> None:
    text = FLAG_SCRIPT.read_text(encoding="utf-8")
    for flag in SOCKS_FLAGS | AGENT_FLAGS:
        assert flag in text
    assert "run ./cmd/wv-socks" in text
    assert "run ./cmd/wv proxy" in text
    assert "run ./cmd/wv-agent" in text
    assert "run ./cmd/wv agent" in text
    agent_tests = (REPO_ROOT / "authproof" / "ssh_agent_test.go").read_text(encoding="utf-8")
    assert "TestRuntimeConfigSignsWithSSHAgentProvider" in agent_tests
    assert "TestRuntimeConfigSignsWithGPGAgentSSHSocketProvider" in agent_tests


def test_authproof_agent_integration_script_builds_commands_and_runs_fresh_agent_tests() -> None:
    text = INTEGRATION_SCRIPT.read_text(encoding="utf-8")
    assert "build -o" in text
    assert "./cmd/wv" in text
    assert "./cmd/wv-agent" in text
    assert "./cmd/wv-socks" in text
    assert "-count=1 ./authproof" in text
    assert "RuntimeConfigSignsWithSSHAgentProvider" in text
    assert "RuntimeConfigSignsWithGPGAgentSSHSocketProvider" in text
    assert "SOCKSHandlerSendsAuthproofAsFirstWebSocketFrame" in text
    assert "VerifyWebSocketProofAcceptsFirstControlFrame" in text


def test_makefile_exposes_authproof_agent_script_targets() -> None:
    text = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "test-authproof-agent-flags:" in text
    assert "tools/verification/test_authproof_agent_flags.sh" in text
    assert "test-authproof-agent-integration:" in text
    assert "tools/verification/test_authproof_agent_integration.sh" in text
