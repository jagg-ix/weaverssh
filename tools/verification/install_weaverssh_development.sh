#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd "$SCRIPT_DIR/../.." && pwd)
PYTHON_BIN=${PYTHON_BIN:-python3}
WORKBENCH="$REPO_ROOT/tools/verification/weaverssh_component_workbench.py"
MODE=plan

usage() {
  cat <<'EOF'
install_weaverssh_development.sh - plan or run weaverssh development installation checks

Usage:
  tools/verification/install_weaverssh_development.sh [--plan|--execute|--system-install]

Modes:
  --plan            Print install commands for every component/workflow (default)
  --execute         Run safe install-phase checks only: dependency plan + dev doctor
  --system-install  Run OS package-manager install first, then safe install checks

Notes:
  --system-install may use sudo or platform package managers. Review --plan first.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan) MODE=plan ;;
    --execute) MODE=execute ;;
    --system-install) MODE=system-install ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

cd "$REPO_ROOT"
case "$MODE" in
  plan)
    "$PYTHON_BIN" "$WORKBENCH" --format shell plan all --phase install
    ;;
  execute)
    "$PYTHON_BIN" "$WORKBENCH" run all --phase install --execute
    ;;
  system-install)
    "$PYTHON_BIN" tools/packaging/install_runtime_dependencies.py install --include-build --yes
    "$PYTHON_BIN" "$WORKBENCH" run all --phase install --execute
    ;;
esac
