#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd "$SCRIPT_DIR/../.." && pwd)
PYTHON_BIN=${PYTHON_BIN:-python3}
WORKBENCH="$REPO_ROOT/tools/verification/weaverssh_component_workbench.py"
TARGET=all
MODE=plan
ALLOW_DAEMONS=0
ALLOW_REMOTE=0

usage() {
  cat <<'EOF'
deploy_weaverssh_local.sh - plan or run local weaverssh deployment workflows

Usage:
  tools/verification/deploy_weaverssh_local.sh [target] [--plan|--execute] [--allow-daemons] [--allow-remote]

Examples:
  tools/verification/deploy_weaverssh_local.sh --plan
  tools/verification/deploy_weaverssh_local.sh core-runtime --execute
  tools/verification/deploy_weaverssh_local.sh control-plane --execute --allow-daemons

Safety:
  Plans are printed by default. Commands that start daemons or touch remote hosts
  require --execute plus --allow-daemons or --allow-remote.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
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
  "$PYTHON_BIN" "$WORKBENCH" --format shell plan "$TARGET" --phase deploy
else
  set -- "$WORKBENCH" run "$TARGET" --phase deploy --execute
  if [ "$ALLOW_DAEMONS" = 1 ]; then set -- "$@" --include-risk daemon; fi
  if [ "$ALLOW_REMOTE" = 1 ]; then set -- "$@" --include-risk remote; fi
  "$PYTHON_BIN" "$@"
fi
