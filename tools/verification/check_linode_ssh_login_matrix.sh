#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HOSTS="${WEAVERSSH_LINODE_HOSTS:-203.0.113.10,203.0.113.20}"
USERS="${WEAVERSSH_LINODE_USERS:-root,kb}"
PORT="${WEAVERSSH_LINODE_SSH_PORT:-22}"
TIMEOUT_S="${WEAVERSSH_LINODE_SSH_TIMEOUT:-8}"
STRICT_HOSTKEY="${WEAVERSSH_LINODE_STRICT_HOSTKEY:-accept-new}"
IDENTITY_FILE="${WEAVERSSH_LINODE_IDENTITY_FILE:-}"
INCLUDE_PLAIN=1
PLAIN_EXPECTED_SUCCESS=0

usage() {
  cat <<'EOF'
check_linode_ssh_login_matrix.sh

Live SSH login matrix for the two Linode hosts used by weaverssh tests.

Default expected behavior:
- root@203.0.113.10 and root@203.0.113.20 must succeed.
- kb@203.0.113.10 and kb@203.0.113.20 must succeed.
- plain ssh 203.0.113.10 and ssh 203.0.113.20 should fail because
  OpenSSH uses the local account name unless a Host config overrides User.

Usage:
  tools/verification/check_linode_ssh_login_matrix.sh
  tools/verification/check_linode_ssh_login_matrix.sh --no-plain
  tools/verification/check_linode_ssh_login_matrix.sh --identity-file ~/.ssh/id_ed25519

Options:
  --hosts csv                  Default: 203.0.113.10,203.0.113.20
  --users csv                  Default: root,kb
  --port n                     Default: 22
  --timeout-s n                Default: 8
  --identity-file path         Optional explicit key file. Default uses SSH agent/defaults.
  --strict-hostkey value       Default: accept-new
  --include-plain              Include plain ssh <ip> checks. Default.
  --no-plain                   Only test explicit users.
  --plain-expected-success     Treat plain ssh <ip> as expected success.
  -h, --help                   Show this help.
EOF
}

while (($#)); do
  case "$1" in
    --hosts)
      HOSTS="$2"
      shift 2
      ;;
    --users)
      USERS="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
      shift 2
      ;;
    --timeout-s)
      TIMEOUT_S="$2"
      shift 2
      ;;
    --identity-file)
      IDENTITY_FILE="$2"
      shift 2
      ;;
    --strict-hostkey)
      STRICT_HOSTKEY="$2"
      shift 2
      ;;
    --include-plain)
      INCLUDE_PLAIN=1
      shift
      ;;
    --no-plain)
      INCLUDE_PLAIN=0
      shift
      ;;
    --plain-expected-success)
      PLAIN_EXPECTED_SUCCESS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

ARGS=(
  --hosts "$HOSTS"
  --users "$USERS"
  --port "$PORT"
  --timeout-s "$TIMEOUT_S"
  --strict-hostkey "$STRICT_HOSTKEY"
)

if [[ -n "$IDENTITY_FILE" ]]; then
  ARGS+=(--identity-file "$IDENTITY_FILE")
fi
if [[ "$INCLUDE_PLAIN" -eq 0 ]]; then
  ARGS+=(--no-plain)
fi
if [[ "$PLAIN_EXPECTED_SUCCESS" -eq 1 ]]; then
  ARGS+=(--plain-expected-success)
fi

python3 "$SCRIPT_DIR/check_linode_ssh_login_matrix.py" "${ARGS[@]}"
