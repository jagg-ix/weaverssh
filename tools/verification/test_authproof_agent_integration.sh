#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GO_BIN="${GO_BIN:-go}"
PYTEST_BIN="${PYTEST_BIN:-python3 -m pytest}"
TMP_BASE="${TMPDIR:-/tmp}"
AUTHPROOF_AGENT_TMP_DIR=""

SOCKS_FLAGS=(
  -proof-mode
  -proof-security-level
  -proof-issuer-id
  -proof-subject-id
  -proof-private-key
  -proof-private-key-file
  -proof-signer-provider
  -proof-signer
  -proof-identity
  -proof-identity-file
  -proof-agent-socket
  -proof-chain-sha256
  -proof-session-id
  -proof-ttl
)

AGENT_FLAGS=(
  -proof-mode
  -proof-security-level
  -proof-peer-id
  -proof-public-key
  -proof-public-key-file
  -proof-chain-sha256
  -proof-ttl
)

usage() {
  cat <<'USAGE'
Build the real weaverssh command binaries and run local authproof integration tests.

Usage:
  tools/verification/test_authproof_agent_integration.sh

This is intentionally local-only. It does not contact Linodes or external SSH
hosts. The integration path uses temporary binaries plus fake ssh-agent sockets
from the Go tests to validate ssh-agent and gpg-agent signing behavior.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

run() {
  echo "+ $*"
  "$@"
}

capture_help() {
  local output status
  set +e
  output="$($@ -h 2>&1)"
  status=$?
  set -e
  if [[ "$status" -ne 0 ]]; then
    printf '%s\n' "$output" >&2
    echo "error: help command failed: $* -h" >&2
    exit "$status"
  fi
  printf '%s\n' "$output"
}

assert_flags() {
  local label="$1"
  local output="$2"
  shift 2
  local missing=()
  for flag in "$@"; do
    if ! grep -Fq -- "$flag" <<<"$output"; then
      missing+=("$flag")
    fi
  done
  if (( ${#missing[@]} > 0 )); then
    echo "error: $label missing expected flags: ${missing[*]}" >&2
    exit 1
  fi
  echo "ok: $label exposes required authproof flags"
}

main() {
  cd "$REPO_ROOT"
  AUTHPROOF_AGENT_TMP_DIR="$(mktemp -d "$TMP_BASE/weaverssh-authproof-agent-it.XXXXXX")"
  trap 'rm -rf "$AUTHPROOF_AGENT_TMP_DIR"' EXIT
  local tmp_dir="$AUTHPROOF_AGENT_TMP_DIR"

  echo "==> Building temporary command binaries"
  run "$GO_BIN" build -o "$tmp_dir/wv" ./cmd/wv
  run "$GO_BIN" build -o "$tmp_dir/wv-agent" ./cmd/wv-agent
  run "$GO_BIN" build -o "$tmp_dir/wv-socks" ./cmd/wv-socks

  echo "==> Checking built binary flag surfaces"
  assert_flags "built wv-socks" "$(capture_help "$tmp_dir/wv-socks")" "${SOCKS_FLAGS[@]}"
  assert_flags "built wv proxy" "$(capture_help "$tmp_dir/wv" proxy)" "${SOCKS_FLAGS[@]}"
  assert_flags "built wv-agent" "$(capture_help "$tmp_dir/wv-agent")" "${AGENT_FLAGS[@]}"
  assert_flags "built wv agent" "$(capture_help "$tmp_dir/wv" agent)" "${AGENT_FLAGS[@]}"

  echo "==> Running fresh authproof agent integration tests"
  run "$GO_BIN" test -count=1 ./authproof -run 'Test(DecodePublicKeyAcceptsOpenSSHEd25519PublicKey|RuntimeConfigSignsWithSSHAgentProvider|RuntimeConfigSignsWithGPGAgentSSHSocketProvider|SSHAgentProviderRequiresIdentityWhenMultipleKeys)$'
  run "$GO_BIN" test -count=1 ./internal/app -run 'Test(SOCKSHandlerSendsAuthproofAsFirstWebSocketFrame|VerifyWebSocketProofAcceptsFirstControlFrame|VerifyWebSocketProofRejectsNonProofFirstFrame|AuthorizeWebSocketSessionAppliesSecurityLevels|VerifyWebSocketProofBindsSecurityLevelForAgentProof|ConfigRequiredProofAcceptsExplicitChainBinding)$'

  echo "==> Running setup/discovery integration checks"
  # shellcheck disable=SC2086
  run $PYTEST_BIN -q \
    tests/test_sshx11_adapter_discovery.py::test_detects_gpg_agent_credential_provider_on_unix_platforms \
    tests/test_weaverssh_linux_setup.py::test_platform_setup_prefers_explicit_gpg_agent_socket

  echo "ok: authproof agent integration test workbench passed"
}

main "$@"
