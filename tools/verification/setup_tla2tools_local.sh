#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENDOR_DIR="${TLA_VENDOR_DIR:-$REPO_ROOT/tools/verification/vendor}"
JAR_PATH="${TLA2TOOLS_JAR_PATH:-$VENDOR_DIR/tla2tools.jar}"
JAR_URL="${TLA2TOOLS_JAR_URL:-https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar}"

mkdir -p "$VENDOR_DIR"

echo "[setup-tla2tools] downloading: $JAR_URL"
curl -fsSL "$JAR_URL" -o "$JAR_PATH"

echo "[setup-tla2tools] validating jar via TLC help..."
set +e
java -cp "$JAR_PATH" tlc2.TLC -help >/dev/null 2>&1
rc=$?
set -e
if [[ "$rc" -ne 0 && "$rc" -ne 1 ]]; then
  echo "[setup-tla2tools] TLC help check failed with rc=$rc" >&2
  exit "$rc"
fi

echo "[setup-tla2tools] ready: $JAR_PATH"
echo "[setup-tla2tools] export TLA2TOOLS_JAR=$JAR_PATH"
