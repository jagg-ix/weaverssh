#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GO_BIN="${GO_BIN:-go}"
PYTEST_BIN="${PYTEST_BIN:-python3 -m pytest}"

SOCKS_FLAGS=(
  -port
  -agent
  -X
  -loglevel
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
  -port
  -listen
  -interface
  -agent-interface
  -listen-unix
  -timeout
  -trusted
  -security
  -loglevel
  -proof-mode
  -proof-security-level
  -proof-peer-id
  -proof-public-key
  -proof-public-key-file
  -proof-chain-sha256
  -proof-ttl
  -nolisten_tcp
  -listen_tcp
  -allow-mismatch
)

usage() {
  cat <<'USAGE'
Run local unit coverage for weaverssh authproof ssh-agent/gpg-agent flags.

Usage:
  tools/verification/test_authproof_agent_flags.sh

Checks:
  - wv-socks exposes every signer/authproof flag
  - wv proxy exposes the same signer/authproof flags through the unified binary
  - wv-agent exposes every verifier/authproof flag
  - wv agent exposes the same verifier/authproof flags through the unified binary
  - Go unit tests cover authproof and internal app proof handling
  - Python unit tests cover adapter/setup discovery for gpg-agent
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
  echo "ok: $label exposes ${#missing[@]} missing / $# expected flags"
}

main() {
  cd "$REPO_ROOT"

  echo "==> Checking authproof signer/verifier flag surfaces"
  local socks_help proxy_help agent_help unified_agent_help
  socks_help="$(capture_help "$GO_BIN" run ./cmd/wv-socks)"
  proxy_help="$(capture_help "$GO_BIN" run ./cmd/wv proxy)"
  agent_help="$(capture_help "$GO_BIN" run ./cmd/wv-agent)"
  unified_agent_help="$(capture_help "$GO_BIN" run ./cmd/wv agent)"

  assert_flags "wv-socks" "$socks_help" "${SOCKS_FLAGS[@]}"
  assert_flags "wv proxy" "$proxy_help" "${SOCKS_FLAGS[@]}"
  assert_flags "wv-agent" "$agent_help" "${AGENT_FLAGS[@]}"
  assert_flags "wv agent" "$unified_agent_help" "${AGENT_FLAGS[@]}"

  echo "==> Running authproof Go unit tests"
  run "$GO_BIN" test ./authproof ./internal/app

  echo "==> Running Python setup/discovery unit tests"
  # shellcheck disable=SC2086
  run $PYTEST_BIN -q \
    tests/test_sshx11_adapter_discovery.py::test_detects_gpg_agent_credential_provider_on_unix_platforms \
    tests/test_weaverssh_linux_setup.py::test_platform_setup_prefers_explicit_gpg_agent_socket

  echo "ok: authproof agent flag/unit test workbench passed"
}

main "$@"
