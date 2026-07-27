#!/usr/bin/env bash
#
# build_weaverssh_test_bench.sh
#
# Construct and exercise a test bench for the whole weaverssh system, in phases:
#
#   1. env        record toolchain + paths
#   2. build      make build-all-binaries (5 binaries) + Go contract workbench
#   3. static     go vet per-binary file sets + pytest collect (import sanity)
#   4. unit       pytest "sshx11 and (unit or contract)" + go test sshwb
#   5. runtime    (--bring-up) control/data plane + integrated server, probe, teardown
#   5b. ui        (--ui)       VS Code extension API contract + webterm smokes + dock probe
#   6. system     (--system)  pytest "sshx11 and system" (remote tests self-skip)
#   7. jepsen     (--jepsen)  generate Jepsen SUT fault-injection plan
#
# A JSON report is written under artifacts/reports/. Exit code is non-zero if any
# executed phase fails. All launched processes are torn down on exit.
#
# Usage:
#   tools/verification/build_weaverssh_test_bench.sh [options]
#
# Options:
#   --build-only        Phases 1-2 only (no tests, no runtime).
#   --no-tests          Skip the unit/contract phase.
#   --bring-up          Launch the runtime (plane + integrated server), probe, teardown.
#   --ui                Run UI-surface smokes: extension API contract, webterm
#                       WS/MQTT smokes, dock-core status probe (degrade to WARN
#                       when a surface is not built/running).
#   --system            Also run the system-marked pytest suite.
#   --jepsen            Generate a non-mutating Jepsen SUT fault-injection plan.
#   --keep-up           With --bring-up, leave the runtime running (no teardown).
#   --port N            Integrated server port for bring-up (default: 6055).
#   --report PATH       Report output path (default: artifacts/reports/weaverssh_test_bench.json).
#   -h, --help          Show this help.

set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SERVICE_DOCK_REPO="${WEAVERSSH_SERVICE_DOCK_REPO:-$REPO_ROOT/../weaverssh-service-dock}"
cd "$REPO_ROOT"

# ---- options -----------------------------------------------------------------
DO_TESTS=1
DO_BUILD=1
BRING_UP=0
DO_UI=0
DO_SYSTEM=0
DO_JEPSEN=0
KEEP_UP=0
SRV_PORT=6055
WEBTERM_PORT="${WEBTERM_PORT:-8096}"
REPORT="artifacts/reports/weaverssh_test_bench.json"

while (($#)); do
  case "$1" in
    --build-only) DO_TESTS=0; BRING_UP=0; DO_UI=0; DO_SYSTEM=0; DO_JEPSEN=0; shift ;;
    --no-tests)   DO_TESTS=0; shift ;;
    --bring-up)   BRING_UP=1; shift ;;
    --ui)         DO_UI=1; shift ;;
    --system)     DO_SYSTEM=1; shift ;;
    --jepsen)     DO_JEPSEN=1; shift ;;
    --keep-up)    KEEP_UP=1; shift ;;
    --port)       SRV_PORT="$2"; shift 2 ;;
    --report)     REPORT="$2"; shift 2 ;;
    -h|--help)    awk 'NR>=2{if(/^set -u/)exit; sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

PYTHON="${PYTHON:-python3}"
BIN_DIR="build/bin"
PLANE_STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/weaverssh_bench.XXXXXX")"
SERVER_PID=""
PLANE_STARTED=0
declare -a PHASE_NAMES=()
declare -a PHASE_STATUS=()
declare -a PHASE_DETAIL=()

ts()  { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

record() { # name status detail
  PHASE_NAMES+=("$1"); PHASE_STATUS+=("$2"); PHASE_DETAIL+=("$3")
  printf '   [%s] %s — %s\n' "$2" "$1" "$3"
}

teardown() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ "$PLANE_STARTED" -eq 1 ]]; then
    "$PYTHON" tools/verification/sshx11_plane_service.py \
      --state-file "$PLANE_STATE_DIR/plane_state.json" \
      --control-pid-file "$PLANE_STATE_DIR/control.pid" \
      --data-pid-file "$PLANE_STATE_DIR/data.pid" \
      stop >/dev/null 2>&1 || true
  fi
  [[ -d "$PLANE_STATE_DIR" ]] && rm -rf "$PLANE_STATE_DIR" 2>/dev/null || true
}

write_report() {
  local overall="$1"
  mkdir -p "$(dirname "$REPORT")"
  {
    printf '{\n'
    printf '  "case_id": "WEAVERSSH_SYSTEM_TEST_BENCH",\n'
    printf '  "generated_at": "%s",\n' "$(ts)"
    printf '  "repo_root": "%s",\n' "$REPO_ROOT"
    printf '  "ok": %s,\n' "$overall"
    printf '  "options": {"tests": %d, "bring_up": %d, "ui": %d, "system": %d, "jepsen": %d, "port": %d},\n' \
      "$DO_TESTS" "$BRING_UP" "$DO_UI" "$DO_SYSTEM" "$DO_JEPSEN" "$SRV_PORT"
    printf '  "phases": [\n'
    local i
    for i in "${!PHASE_NAMES[@]}"; do
      local comma=","; [[ "$i" -eq $(( ${#PHASE_NAMES[@]} - 1 )) ]] && comma=""
      printf '    {"name": "%s", "status": "%s", "detail": "%s"}%s\n' \
        "${PHASE_NAMES[$i]}" "${PHASE_STATUS[$i]}" "${PHASE_DETAIL[$i]//\"/\'}" "$comma"
    done
    printf '  ]\n}\n'
  } > "$REPORT"
}

trap teardown EXIT

FAILED=0

# ---- 1. env ------------------------------------------------------------------
log "Phase 1: env"
GO_V="$(go version 2>/dev/null || echo 'go: not found')"
PY_V="$($PYTHON --version 2>&1 || echo 'python: not found')"
record env ok "$GO_V; $PY_V"

# ---- 2. build ----------------------------------------------------------------
if [[ "$DO_BUILD" -eq 1 ]]; then
  log "Phase 2: build"
  if make build-all-binaries >/tmp/wv_bench_build.log 2>&1; then
    built=0
    for b in wv wv-server wv-agent wv-socks; do [[ -x "$BIN_DIR/$b" ]] && built=$((built+1)); done
    [[ -x build/linux-x86_64/wv-client ]] && built=$((built+1))
    record build ok "$built/5 binaries present"
  else
    record build FAIL "make build-all-binaries failed (see /tmp/wv_bench_build.log)"; FAILED=1
  fi
  if (cd tools/verification/go/sshwb && go build ./... >/tmp/wv_bench_sshwb.log 2>&1); then
    record build-sshwb ok "Go contract workbench builds"
  else
    record build-sshwb FAIL "sshwb build failed (see /tmp/wv_bench_sshwb.log)"; FAILED=1
  fi
fi

# ---- 3. static ---------------------------------------------------------------
log "Phase 3: static analysis"
if go vet ./cmd/wv ./internal/app >/tmp/wv_bench_vet.log 2>&1 \
   && go vet ./display/... ./relay/... ./tunnel/... ./padding/... >>/tmp/wv_bench_vet.log 2>&1; then
  record vet ok "go vet clean (cmd/app + packages)"
else
  record vet FAIL "go vet reported issues (see /tmp/wv_bench_vet.log)"; FAILED=1
fi
if "$PYTHON" -m pytest --collect-only -q -p no:cacheprovider >/tmp/wv_bench_collect.log 2>&1; then
  n="$(grep -cE '::' /tmp/wv_bench_collect.log || true)"
  record pytest-collect ok "import/collection sane (${n} tests)"
else
  record pytest-collect FAIL "pytest collection failed (see /tmp/wv_bench_collect.log)"; FAILED=1
fi

# ---- 4. unit/contract --------------------------------------------------------
if [[ "$DO_TESTS" -eq 1 ]]; then
  log "Phase 4: unit + contract tests"
  if "$PYTHON" -m pytest -q -p no:cacheprovider -m "sshx11 and (unit or contract)" \
       >/tmp/wv_bench_unit.log 2>&1; then
    record pytest-unit ok "$(tail -1 /tmp/wv_bench_unit.log)"
  else
    record pytest-unit FAIL "$(tail -1 /tmp/wv_bench_unit.log) (see /tmp/wv_bench_unit.log)"; FAILED=1
  fi
  if (cd tools/verification/go/sshwb && go test ./... >/tmp/wv_bench_gotest.log 2>&1); then
    record gotest-sshwb ok "$(grep -cE '^ok ' /tmp/wv_bench_gotest.log || echo 0) packages ok"
  else
    record gotest-sshwb FAIL "sshwb go test failed (see /tmp/wv_bench_gotest.log)"; FAILED=1
  fi
fi

# ---- 5. runtime bring-up -----------------------------------------------------
if [[ "$BRING_UP" -eq 1 ]]; then
  log "Phase 5: runtime bring-up (control/data plane + integrated server)"
  if "$PYTHON" tools/verification/sshx11_plane_service.py \
        --state-file "$PLANE_STATE_DIR/plane_state.json" \
        --control-pid-file "$PLANE_STATE_DIR/control.pid" \
        --data-pid-file "$PLANE_STATE_DIR/data.pid" \
        --control-log-file "$PLANE_STATE_DIR/control.log" \
        --data-log-file "$PLANE_STATE_DIR/data.log" \
        start >/tmp/wv_bench_plane.log 2>&1; then
    PLANE_STARTED=1
    if curl -fsS "http://127.0.0.1:8101/health" >/dev/null 2>&1; then
      record plane ok "control plane /health responding on :8101"
    else
      record plane WARN "plane started but /health not confirmed"
    fi
  else
    record plane FAIL "plane service failed to start (see /tmp/wv_bench_plane.log)"; FAILED=1
  fi

  if [[ -x "$BIN_DIR/wv" ]]; then
    "$BIN_DIR/wv" -mode hybrid -port "$SRV_PORT" -metrics >"$PLANE_STATE_DIR/wv.log" 2>&1 &
    SERVER_PID=$!
    sleep 2
    if kill -0 "$SERVER_PID" 2>/dev/null; then
      if command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 "$SRV_PORT" 2>/dev/null; then
        record server ok "integrated server (hybrid) listening on :$SRV_PORT (pid $SERVER_PID)"
      else
        record server ok "integrated server up (pid $SERVER_PID); port probe skipped/!nc"
      fi
    else
      record server FAIL "integrated server exited early (see $PLANE_STATE_DIR/wv.log)"; FAILED=1
    fi
  else
    record server FAIL "wv binary missing — build phase incomplete"; FAILED=1
  fi

  if [[ "$KEEP_UP" -eq 1 ]]; then
    record runtime ok "left running (--keep-up); server pid ${SERVER_PID:-none}, plane state $PLANE_STATE_DIR"
    trap - EXIT   # do not tear down on exit
  fi
fi

# ---- 5b. UI-surface smokes ---------------------------------------------------
if [[ "$DO_UI" -eq 1 ]]; then
  log "Phase 5b: UI surfaces (extension contract, webterm, dock)"

  # VS Code extension API contract — requires a compiled dist/extension.js.
  if [[ -f extensions/vscode-sshx11/dist/extension.js ]]; then
    if "$PYTHON" extensions/vscode-sshx11/scripts/smoke_api_contract.py >/tmp/wv_bench_ext.log 2>&1; then
      record ext-api-contract ok "extension API contract in sync"
    else
      record ext-api-contract FAIL "extension API contract failed (see /tmp/wv_bench_ext.log)"; FAILED=1
    fi
  else
    record ext-api-contract WARN "dist/extension.js not built; run 'npm install && npm run compile' in extensions/vscode-sshx11"
  fi

  # Webterm MQTT collab bus — offline config validation (no broker needed).
  if "$PYTHON" tools/verification/webterm_mqtt_smoke.py >/tmp/wv_bench_wtmqtt.log 2>&1; then
    record webterm-mqtt ok "MQTT bus config validated (offline)"
  else
    record webterm-mqtt FAIL "webterm MQTT smoke failed (see /tmp/wv_bench_wtmqtt.log)"; FAILED=1
  fi

  # Webterm WebSocket smoke — only if a webterm is actually listening.
  if command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 "$WEBTERM_PORT" 2>/dev/null; then
    if "$PYTHON" tools/verification/webterm_ws_smoke.py --host 127.0.0.1 --port "$WEBTERM_PORT" \
         --sendline "echo bench" --read-frames 3 >/tmp/wv_bench_wtws.log 2>&1; then
      record webterm-ws ok "PTY-over-WebSocket smoke passed on :$WEBTERM_PORT"
    else
      record webterm-ws FAIL "webterm WS smoke failed (see /tmp/wv_bench_wtws.log)"; FAILED=1
    fi
  else
    record webterm-ws WARN "no webterm on :$WEBTERM_PORT (start_webterm.sh); WS smoke skipped"
  fi

  # Native tray/menu-bar controller moved to the sibling weaverssh-service-dock repo.
  if [[ -d "$SERVICE_DOCK_REPO/src/weaverssh_service_dock" ]]; then
    if WEAVERSSH_REPO_ROOT="$REPO_ROOT" PYTHONPATH="$SERVICE_DOCK_REPO/src" \
         "$PYTHON" -m weaverssh_service_dock.tray --once --json >/tmp/wv_bench_tray.log 2>/dev/null \
       && "$PYTHON" -c "import json,sys; d=json.load(open('/tmp/wv_bench_tray.log')); sys.exit(0 if isinstance(d.get('plane'),dict) and isinstance(d.get('mcp'),dict) else 1)"; then
      record tray-status ok "external service dock tray --once returned a valid status payload (plane+mcp)"
    else
      record tray-status FAIL "external service dock tray probe failed (see /tmp/wv_bench_tray.log)"; FAILED=1
    fi
  else
    record tray-status WARN "external service dock repo not found at $SERVICE_DOCK_REPO"
  fi

  # Dock control core — status probe (works even when services are down).
  if [[ -d "$SERVICE_DOCK_REPO/src/weaverssh_service_dock" ]] && WEAVERSSH_REPO_ROOT="$REPO_ROOT" SERVICE_DOCK_REPO="$SERVICE_DOCK_REPO" "$PYTHON" - >/tmp/wv_bench_dock.log 2>&1 <<'PYDOCK'
import os
import sys
sys.path.insert(0, os.path.join(os.environ["SERVICE_DOCK_REPO"], "src"))
from weaverssh_service_dock import core as d
s = d.dock_status(host="127.0.0.1", control_port=8101, data_port=19090)
assert isinstance(s, dict), f"dock_status returned {type(s)}"
print("dock_status keys:", sorted(s.keys()))
PYDOCK
  then
    record dock-core ok "external dock-core status probe returned ($(tail -1 /tmp/wv_bench_dock.log))"
  else
    record dock-core WARN "external dock-core status probe skipped or failed (repo=$SERVICE_DOCK_REPO; see /tmp/wv_bench_dock.log)"
  fi
fi

# ---- 6. system tests ---------------------------------------------------------
if [[ "$DO_SYSTEM" -eq 1 ]]; then
  log "Phase 6: system tests (remote hosts self-skip without SSH creds)"
  if "$PYTHON" -m pytest -q -p no:cacheprovider -m "sshx11 and system" \
       >/tmp/wv_bench_system.log 2>&1; then
    record pytest-system ok "$(tail -1 /tmp/wv_bench_system.log)"
  else
    record pytest-system FAIL "$(tail -1 /tmp/wv_bench_system.log) (see /tmp/wv_bench_system.log)"; FAILED=1
  fi
fi

# ---- 7. Jepsen SUT fault-injection plan -------------------------------------
if [[ "$DO_JEPSEN" -eq 1 ]]; then
  log "Phase 7: Jepsen SUT fault-injection plan"
  JEP_NODES="${WEAVERSSH_JEPSEN_NODES:-203.0.113.10,203.0.113.20}"
  JEP_USER="${WEAVERSSH_JEPSEN_USER:-kb}"
  JEP_IDENTITY="${WEAVERSSH_JEPSEN_IDENTITY_FILE:-}"
  JEP_OUT="artifacts/jepsen/weaverssh_jepsen_plan.json"
  if "$PYTHON" tools/verification/run_weaverssh_jepsen.py --dry-run         --nodes "$JEP_NODES"         --username "$JEP_USER"         --identity-file "$JEP_IDENTITY"         --output "$JEP_OUT" >/tmp/wv_bench_jepsen.log 2>&1; then
    record jepsen-plan ok "plan written to $JEP_OUT"
  else
    record jepsen-plan FAIL "Jepsen plan failed (see /tmp/wv_bench_jepsen.log)"; FAILED=1
  fi
fi

# ---- report ------------------------------------------------------------------
OVERALL=true; [[ "$FAILED" -ne 0 ]] && OVERALL=false
write_report "$OVERALL"
log "Test bench complete: ok=$OVERALL  report=$REPORT"
exit "$FAILED"
