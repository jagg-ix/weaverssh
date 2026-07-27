#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd "$SCRIPT_DIR/../.." && pwd)
PYTHON_BIN=${PYTHON_BIN:-python3}
WORKBENCH="$REPO_ROOT/tools/verification/weaverssh_component_workbench.py"
TARGET=all
PHASE=verify
MODE=plan
ALLOW_DAEMONS=0
ALLOW_REMOTE=0

usage() {
  cat <<'EOF'
verify_weaverssh_workflows.sh - plan or run component/workflow verification commands

Usage:
  tools/verification/verify_weaverssh_workflows.sh [target] [--phase develop|test|verify|all] [--plan|--execute] [--allow-daemons] [--allow-remote]

Examples:
  tools/verification/verify_weaverssh_workflows.sh --phase verify --plan
  tools/verification/verify_weaverssh_workflows.sh dataplane-policy --phase test --execute
  tools/verification/verify_weaverssh_workflows.sh all --phase develop --execute
  tools/verification/verify_weaverssh_workflows.sh remote-linode-workflow --phase verify --execute --allow-remote
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --phase) PHASE=${2:?missing phase}; shift ;;
    --plan) MODE=plan ;;
    --execute) MODE=execute ;;
    --allow-daemons) ALLOW_DAEMONS=1 ;;
    --allow-remote) ALLOW_REMOTE=1 ;;
    -h|--help) usage; exit 0 ;;
    --*) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    *) TARGET=$1 ;;
  esac
  shift
done

cd "$REPO_ROOT"
if [ "$MODE" = plan ]; then
  "$PYTHON_BIN" "$WORKBENCH" --format shell plan "$TARGET" --phase "$PHASE"
else
  set -- "$WORKBENCH" run "$TARGET" --phase "$PHASE" --execute
  if [ "$ALLOW_DAEMONS" = 1 ]; then set -- "$@" --include-risk daemon; fi
  if [ "$ALLOW_REMOTE" = 1 ]; then set -- "$@" --include-risk remote; fi
  "$PYTHON_BIN" "$@"
fi
