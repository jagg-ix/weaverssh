#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PYTHON_BIN="${PYTHON_BIN:-python3}"
HOST="${SSHX11_HOST:-127.0.0.1}"
CONTROL_PORT="${SSHX11_CONTROL_PORT:-8101}"
DATA_PORT="${SSHX11_DATA_PORT:-19090}"
REALTIME_PORT="${SSHX11_REALTIME_PORT:-$((DATA_PORT + 1))}"
SOCKS_PORT="${SSHX11_SOCKS_PORT:-1080}"
SOCKS_AGENT_LISTEN="${SSHX11_SOCKS_AGENT_LISTEN:-localhost:6000}"
SOCKS_AGENT_ENDPOINT="${SSHX11_SOCKS_AGENT_ENDPOINT:-$SOCKS_AGENT_LISTEN}"
SOCKS_X11WS_REPO="${SSHX11_X11WS_REPO:-$HOME/weaverssh}"
REVERSE_SOCKS_REMOTE_HOST="${SSHX11_REVERSE_SOCKS_REMOTE_HOST:-${SSHX11_REMOTE_HOST:-}}"
REVERSE_SOCKS_REMOTE_USER="${SSHX11_REVERSE_SOCKS_REMOTE_USER:-${SSHX11_REMOTE_USER:-root}}"
REVERSE_SOCKS_REMOTE_PORT="${SSHX11_REVERSE_SOCKS_REMOTE_PORT:-${SSHX11_REMOTE_PORT:-22}}"
REVERSE_SOCKS_IDENTITY_FILE="${SSHX11_REVERSE_SOCKS_IDENTITY_FILE:-${SSHX11_REMOTE_IDENTITY_FILE:-}}"
REVERSE_SOCKS_INSECURE_HOSTKEY="${SSHX11_REVERSE_SOCKS_INSECURE_HOSTKEY:-${SSHX11_REMOTE_INSECURE_HOSTKEY:-0}}"
REVERSE_SOCKS_SSH_BIN="${SSHX11_REVERSE_SOCKS_SSH_BIN:-${SSH_BIN:-ssh}}"
REVERSE_SOCKS_SSH_CONFIG="${SSHX11_REVERSE_SOCKS_SSH_CONFIG:-${SSHX11_SSH_CONFIG:-}}"
REVERSE_SOCKS_PROXY_JUMP="${SSHX11_REVERSE_SOCKS_PROXY_JUMP:-${SSHX11_PROXY_JUMP:-}}"
REVERSE_SOCKS_PROXY_COMMAND="${SSHX11_REVERSE_SOCKS_PROXY_COMMAND:-${SSHX11_PROXY_COMMAND:-}}"
REVERSE_SOCKS_SSH_VERBOSITY="${SSHX11_REVERSE_SOCKS_SSH_VERBOSITY:-${SSHX11_SSH_VERBOSITY:-}}"
REVERSE_SOCKS_SSH_LOG_LEVEL="${SSHX11_REVERSE_SOCKS_SSH_LOG_LEVEL:-${SSHX11_SSH_LOG_LEVEL:-}}"
REVERSE_SOCKS_SSH_LOG_FILE="${SSHX11_REVERSE_SOCKS_SSH_LOG_FILE:-${SSHX11_SSH_LOG_FILE:-}}"
REVERSE_SOCKS_AGENT_MODE="${SSHX11_REVERSE_SOCKS_AGENT_MODE:-${SSHX11_AGENT_MODE:-auto}}"
REVERSE_SOCKS_FORWARD_AGENT="${SSHX11_REVERSE_SOCKS_FORWARD_AGENT:-${SSHX11_FORWARD_AGENT:-0}}"
REVERSE_SOCKS_IDENTITY_AGENT="${SSHX11_REVERSE_SOCKS_IDENTITY_AGENT:-${SSHX11_IDENTITY_AGENT:-${SSHX11_AGENT_SOCKET:-${SSH_AUTH_SOCK:-}}}}"
REVERSE_SOCKS_REMOTE_PLATFORM="${SSHX11_REVERSE_SOCKS_REMOTE_PLATFORM:-${SSHX11_REMOTE_PLATFORM:-auto}}"
REVERSE_SOCKS_REMOTE_SHELL_BIN="${SSHX11_REVERSE_SOCKS_REMOTE_SHELL_BIN:-${SSHX11_REMOTE_SHELL_BIN:-sh}}"
REVERSE_SOCKS_REMOTE_SHELL_LOGIN="${SSHX11_REVERSE_SOCKS_REMOTE_SHELL_LOGIN:-${SSHX11_REMOTE_SHELL_LOGIN:-1}}"
REVERSE_SOCKS_REMOTE_PYTHON_BIN="${SSHX11_REVERSE_SOCKS_REMOTE_PYTHON_BIN:-${SSHX11_REMOTE_PYTHON_BIN:-}}"
REVERSE_SOCKS_BIND_HOST="${SSHX11_REVERSE_SOCKS_BIND_HOST:-127.0.0.1}"
REVERSE_SOCKS_PORT="${SSHX11_REVERSE_SOCKS_PORT:-19080}"
WEBDAV_HOST="${SSHX11_WEBDAV_HOST:-127.0.0.1}"
WEBDAV_PORT="${SSHX11_WEBDAV_PORT:-8780}"
WEBDAV_ROOT="${SSHX11_WEBDAV_ROOT:-$REPO_ROOT}"
WEBDAV_READ_ONLY="${SSHX11_WEBDAV_READ_ONLY:-1}"
VFS_REGISTRY_FILE="${SSHX11_VFS_REGISTRY_FILE:-verification_results/runtime/sshx11_vfs_registry.json}"
VFS_NAMESPACE_DIR="${SSHX11_VFS_NAMESPACE_DIR:-verification_results/runtime/sshx11_vfs_namespace}"
NINEP_HOST="${SSHX11_9P_HOST:-127.0.0.1}"
NINEP_PORT="${SSHX11_9P_PORT:-5640}"
NINEP_ROOT="${SSHX11_9P_ROOT:-$VFS_NAMESPACE_DIR}"
NINEP_BINARY="${SSHX11_9P_BINARY:-$REPO_ROOT/build/bin/wv-9p}"
NATIVE_FORWARD_BINARY="${SSHX11_NATIVE_FORWARD_BINARY:-$REPO_ROOT/build/bin/wv-native-forward}"
NINEP_RUNTIME="${SSHX11_9P_RUNTIME:-host}"
NINEP_CONTAINER_RUNTIME_BIN="${SSHX11_9P_CONTAINER_RUNTIME_BIN:-}"
NINEP_CONTAINER_IMAGE="${SSHX11_9P_CONTAINER_IMAGE:-weaverssh/wv-9p:local}"
NINEP_CONTAINER_NAME="${SSHX11_9P_CONTAINER_NAME:-}"
NINEP_CONTAINERFILE="${SSHX11_9P_CONTAINERFILE:-$REPO_ROOT/tools/containers/wv-9p.Containerfile}"
NINEP_CONTAINER_PORT="${SSHX11_9P_CONTAINER_PORT:-5640}"
NINEP_CONTAINER_BUILD="${SSHX11_9P_CONTAINER_BUILD:-0}"
NINEP_LOGS_TAIL="${SSHX11_9P_LOGS_TAIL:-120}"
STATE_FILE="${SSHX11_STATE_FILE:-verification_results/runtime/sshx11_plane_state.json}"
CONTROL_EVENT_LOG="${SSHX11_CONTROL_EVENT_LOG:-verification_results/stack_audits/sshx11_control_plane_events.ndjson}"
DATA_EVENT_LOG="${SSHX11_DATA_EVENT_LOG:-verification_results/stack_audits/sshx11_data_plane_events.ndjson}"
REMOTE_ARTIFACT="${SSHX11_REMOTE_ARTIFACT:-verification_results/stack_audits/sshx11_remote_system_test.json}"
TAIL_LINES="${SSHX11_TAIL_LINES:-40}"

CONTROL_DAEMON_LOG="${TMPDIR:-/tmp}/sshx11_control_plane.log"
DATA_DAEMON_LOG="${TMPDIR:-/tmp}/sshx11_data_plane.log"

run_py() {
  local script="$1"
  shift
  "$PYTHON_BIN" "$REPO_ROOT/tools/verification/$script" "$@"
}

is_true() {
  local value="${1:-}"
  case "${value,,}" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

setup_tla_tools() {
  "$REPO_ROOT/tools/verification/setup_tla2tools_local.sh"
}

native_forward_plan() {
  if [[ -x "$NATIVE_FORWARD_BINARY" ]]; then
    "$NATIVE_FORWARD_BINARY" "$@"
    return $?
  fi
  if command -v go >/dev/null 2>&1; then
    (cd "$REPO_ROOT" && go run ./cmd/wv-native-forward "$@")
    return $?
  fi
  echo "error: wv-native-forward not built and go is not available; run 'make build-native-forward'" >&2
  return 2
}

dataplane_firewall() {
  run_py sshx11_dataplane_iptables.py "$@"
}

usage() {
  cat <<'EOF'
sshx11_ops.sh - operator wrapper for SSHX11 test/status/verify/trace

Usage:
  tools/verification/sshx11_ops.sh <command> [args...]

Core commands:
  setup-tla-tools         Download/validate local tla2tools.jar for TLC runs
  service-start            Start local control/data plane daemons
  service-stop             Stop local control/data plane daemons
  service-restart          Restart local control/data plane daemons
  status-local             Print local daemon+API+policy status and summary
  watch-status [seconds]   Loop status-local every N seconds (default: 3)
  plugins-list [args...]   List declared weaverssh feature plugins
  plugins-show <id>        Show one weaverssh feature plugin
  plugins-discover [args...] List plugins with artifact/command availability checks
  native-forward-plan [args...] Generate a contract-checked ssh -L/-R/-D adapter plan
  dataplane-firewall [args...] Render dataplane firewall/OpenFlow connection policy
  deps-check [args...]     Run dependency preflight for WebDAV/SOCKS/backhaul scenarios
  test-local [args...]     Run local end-to-end demo (managed-service)
  bench-local [args...]    Benchmark realtime/bulk transport sockets
  test-remote [args...]    Run remote SSH/SCP end-to-end orchestrator
  socks-fallback-start [args...] Start weaverssh SOCKS-over-SSHX11 fallback service
  socks-fallback-stop [args...]  Stop weaverssh SOCKS-over-SSHX11 fallback service
  socks-fallback-status [args...] Show weaverssh SOCKS-over-SSHX11 fallback status
  test-socks-local [args...] Run local SOCKS5 bidirectional probe (API fallback)
  bench-socks5 [args...]   Run SOCKS5 latency+bandwidth performance battery
  reverse-socks-start [args...] Start reverse SOCKS listener on remote host via SSH
  reverse-socks-stop [args...]  Stop reverse SOCKS listener
  reverse-socks-status [args...] Show reverse SOCKS status
  reverse-socks-smoke [args...] Run one-shot reverse SOCKS start/status/remote-probe flow
  run-9p-socks [args...]   Run dedicated 9P-over-SOCKS runner (native backend default)
  9p-start [args...]        Start repo-native read-only wv-9p service (host or container runtime)
  9p-stop [args...]         Stop repo-native wv-9p service
  9p-status [args...]       Show repo-native wv-9p service status
  9p-plan [args...]         Print repo-native wv-9p launch plan
  9p-image-build [args...]  Build the repo-native wv-9p container image
  9p-logs [args...]         Show repo-native wv-9p host/container logs
  webdav-start [args...]   Start lightweight local WebDAV service
  webdav-stop [args...]    Stop lightweight local WebDAV service
  webdav-status [args...]  Show lightweight local WebDAV service status
  vscode-profile-gen [args...] Generate VS Code env profiles (local, remote, reverse-socks)
  verify-extension-hosts [args...] Verify extension-host routing profiles and connectivity probes
  vfs-agent-start [args...] Start local VFS mesh agent (exports/imports + heartbeat)
  vfs-agent-stop [args...]  Stop local VFS mesh agent
  vfs-agent-status [args...] Show local VFS mesh agent status
  vfs-agent-sync [args...]  One-shot VFS registry/state sync
  vfs-registry-list [args...] Show VFS host registry
  vfs-mesh-build [args...] Build materialized /mesh and /views namespace from registry
  vfs-mesh-status [args...] Show materialized VFS mesh namespace status
  vfs-mesh-clean [args...] Remove materialized VFS mesh namespace
  verify-remote [source]   Validate remote execution vs TLA contract (auto|artifact|plan)
  verify-fsm [args...]     Run FSM Python/TLA verifier
  verify-crypto [args...]  Run crypto cross-layer reverse verifier
  verify-extensions [args...] Run SSHX11 TLA extension-set verifier
  repl-start [args...]     Start collaborative REPL session (fifo|tmux|screen)
  repl-probe [args...]     Probe collaborative terminal backend availability
  repl-send [args...]      Send input to collaborative REPL session
  repl-shortcut [args...]  Send tmux/screen shortcut to collaborative REPL session
  repl-console [args...]   Interactive console mode for collaborative REPL
  repl-status [args...]    Show collaborative REPL status + tail
  repl-tail [args...]      Tail collaborative REPL output log
  repl-stop [args...]      Stop collaborative REPL session
  repl-vhs-probe [args...] Probe VHS recorder availability + publish options
  repl-vhs-record [args...] Render and publish collaborative REPL VHS recording
  trace-local [mode]       Follow local logs (all|control|data|daemon)
  help                     Show this help

Examples:
  tools/verification/sshx11_ops.sh setup-tla-tools
  tools/verification/sshx11_ops.sh service-start
  tools/verification/sshx11_ops.sh watch-status 2
  tools/verification/sshx11_ops.sh deps-check
  tools/verification/sshx11_ops.sh plugins-discover --feature vfs.readonly.9p
  tools/verification/sshx11_ops.sh plugins-show vfs.9p
  tools/verification/sshx11_ops.sh native-forward-plan --mode sshR --remote root@host --proof-subject-id agent --proof-public-key <key> --chain-part origin --chain-part host --proof-x11-cookie <cookie> --format json
  tools/verification/sshx11_ops.sh dataplane-firewall plan --include-webdav --include-9p --format json
  tools/verification/sshx11_ops.sh dataplane-firewall plan --backend ovs-openflow --ovs-bridge br-weaverssh --format shell
  tools/verification/sshx11_ops.sh dataplane-firewall plan --backend cilium-networkpolicy --k8s-namespace weaverssh --format yaml
  tools/verification/sshx11_ops.sh dataplane-firewall inspect-stack --format json
  tools/verification/sshx11_ops.sh trace-local all
  tools/verification/sshx11_ops.sh test-local --l2-required
  tools/verification/sshx11_ops.sh bench-local --realtime-count 200 --bulk-count 80
  tools/verification/sshx11_ops.sh test-remote --host 203.0.113.20 --user root --identity-file ~/.ssh/jag-mbeddix-id_ed25519 --insecure-hostkey
  tools/verification/sshx11_ops.sh socks-fallback-start
  tools/verification/sshx11_ops.sh test-socks-local --managed-service
  tools/verification/sshx11_ops.sh reverse-socks-start --host 203.0.113.20 --user root --identity-file ~/.ssh/id_ed25519
  tools/verification/sshx11_ops.sh reverse-socks-start --host ssh-target --ssh-config ~/.ssh/config --proxy-jump bastion.example.com
  tools/verification/sshx11_ops.sh reverse-socks-start --host ssh-target --ssh-verbosity 2 --ssh-log-level DEBUG2 --ssh-log-file /tmp/sshx11-ssh.log
  tools/verification/sshx11_ops.sh reverse-socks-start --host ssh-target --agent-mode require --forward-agent --identity-agent env:SSH_AUTH_SOCK
  tools/verification/sshx11_ops.sh reverse-socks-start --host aix-host --remote-platform aix --remote-shell-bin ksh --remote-python-bin /opt/freeware/bin/python3
  tools/verification/sshx11_ops.sh reverse-socks-start --host solaris-host --remote-platform solaris --remote-shell-bin /bin/ksh --no-remote-shell-login
  tools/verification/sshx11_ops.sh reverse-socks-start --host zos-host --remote-platform zos --remote-shell-bin sh --remote-python-bin /usr/lpp/cyp/v3r11/pyz/bin/python3
  tools/verification/sshx11_ops.sh reverse-socks-status
  tools/verification/sshx11_ops.sh reverse-socks-smoke --host 203.0.113.20 --user root --identity-file ~/.ssh/id_ed25519 --proxy-command "ssh -W %h:%p jumpbox"
  tools/verification/sshx11_ops.sh reverse-socks-smoke --host ssh-target --agent-mode require --identity-agent pageant:
  tools/verification/sshx11_ops.sh webdav-start --root "$PWD" --read-write
  tools/verification/sshx11_ops.sh webdav-status
  tools/verification/sshx11_ops.sh vscode-profile-gen --profile all --output-dir .vscode/sshx11
  tools/verification/sshx11_ops.sh verify-extension-hosts --remote-host 203.0.113.20 --remote-user root --identity-file ~/.ssh/id_ed25519
  tools/verification/sshx11_ops.sh bench-socks5 --mode mock --scenario smoke
  tools/verification/sshx11_ops.sh bench-socks5 --mode external --socks-port 1080 --target-port 19000
  tools/verification/sshx11_ops.sh run-9p-socks --managed-service
  tools/verification/sshx11_ops.sh 9p-start
  tools/verification/sshx11_ops.sh 9p-status
  SSHX11_9P_RUNTIME=docker tools/verification/sshx11_ops.sh 9p-image-build --dry-run
  SSHX11_9P_RUNTIME=docker SSHX11_9P_CONTAINER_BUILD=1 tools/verification/sshx11_ops.sh 9p-start
  SSHX11_9P_RUNTIME=docker tools/verification/sshx11_ops.sh 9p-logs
  SSHX11_9P_RUNTIME=podman tools/verification/sshx11_ops.sh 9p-plan
  tools/verification/sshx11_ops.sh run-9p-socks --backend qemu --qemu-port 5640 --target-host 127.0.0.1
  tools/verification/sshx11_ops.sh vfs-agent-sync --host-id local --export root=$PWD:rw
  tools/verification/sshx11_ops.sh vfs-agent-start --host-id local --export root=$PWD:rw
  tools/verification/sshx11_ops.sh vfs-agent-status
  tools/verification/sshx11_ops.sh vfs-registry-list
  tools/verification/sshx11_ops.sh vfs-mesh-build
  tools/verification/sshx11_ops.sh webdav-start --root verification_results/runtime/sshx11_vfs_namespace
  tools/verification/sshx11_ops.sh vfs-agent-stop
  tools/verification/sshx11_ops.sh verify-remote artifact
  tools/verification/sshx11_ops.sh verify-extensions
  tools/verification/sshx11_ops.sh verify-extensions --run-tlc --tla2tools-jar /path/to/tla2tools.jar
  tools/verification/sshx11_ops.sh repl-start --session sshx11-collab
  tools/verification/sshx11_ops.sh repl-start --session sshx11-collab --backend tmux --shell bash
  tools/verification/sshx11_ops.sh repl-probe --json
  tools/verification/sshx11_ops.sh repl-send --session sshx11-collab --text "python3 --version"
  tools/verification/sshx11_ops.sh repl-shortcut --session sshx11-collab --shortcut split-horizontal
  tools/verification/sshx11_ops.sh repl-console --session sshx11-collab
  tools/verification/sshx11_ops.sh repl-tail --session sshx11-collab --lines 120
  tools/verification/sshx11_ops.sh repl-vhs-probe --json
  tools/verification/sshx11_ops.sh repl-vhs-record --session sshx11-collab --publish-dir verification_results/published/vhs

Environment overrides:
  SSHX11_HOST, SSHX11_CONTROL_PORT, SSHX11_DATA_PORT, SSHX11_TAIL_LINES
  SSHX11_SOCKS_PORT, SSHX11_SOCKS_AGENT_LISTEN, SSHX11_SOCKS_AGENT_ENDPOINT
  SSHX11_X11WS_REPO
  SSHX11_REVERSE_SOCKS_REMOTE_HOST, SSHX11_REVERSE_SOCKS_REMOTE_USER, SSHX11_REVERSE_SOCKS_REMOTE_PORT
  SSHX11_REVERSE_SOCKS_IDENTITY_FILE, SSHX11_REVERSE_SOCKS_INSECURE_HOSTKEY
  SSHX11_REVERSE_SOCKS_SSH_BIN
  SSHX11_REVERSE_SOCKS_SSH_CONFIG, SSHX11_REVERSE_SOCKS_PROXY_JUMP, SSHX11_REVERSE_SOCKS_PROXY_COMMAND
  SSHX11_REVERSE_SOCKS_SSH_VERBOSITY, SSHX11_REVERSE_SOCKS_SSH_LOG_LEVEL, SSHX11_REVERSE_SOCKS_SSH_LOG_FILE
  SSHX11_REVERSE_SOCKS_AGENT_MODE, SSHX11_REVERSE_SOCKS_FORWARD_AGENT, SSHX11_REVERSE_SOCKS_IDENTITY_AGENT
  SSHX11_REVERSE_SOCKS_REMOTE_PLATFORM, SSHX11_REVERSE_SOCKS_REMOTE_SHELL_BIN, SSHX11_REVERSE_SOCKS_REMOTE_SHELL_LOGIN, SSHX11_REVERSE_SOCKS_REMOTE_PYTHON_BIN
  SSHX11_REMOTE_PLATFORM, SSHX11_REMOTE_SHELL_BIN, SSHX11_REMOTE_SHELL_LOGIN, SSHX11_REMOTE_PYTHON_BIN
  SSHX11_AGENT_MODE, SSHX11_FORWARD_AGENT, SSHX11_IDENTITY_AGENT, SSHX11_AGENT_SOCKET, SSH_AUTH_SOCK
  SSHX11_SSH_VERBOSITY, SSHX11_SSH_LOG_LEVEL, SSHX11_SSH_LOG_FILE
  SSHX11_REVERSE_SOCKS_BIND_HOST, SSHX11_REVERSE_SOCKS_PORT
  SSHX11_WEBDAV_HOST, SSHX11_WEBDAV_PORT, SSHX11_WEBDAV_ROOT, SSHX11_WEBDAV_READ_ONLY
  SSHX11_REMOTE_HOST, SSHX11_REMOTE_USER, SSHX11_REMOTE_PORT, SSHX11_REMOTE_IDENTITY_FILE
  SSHX11_STATE_FILE, SSHX11_CONTROL_EVENT_LOG, SSHX11_DATA_EVENT_LOG
  WEAVERSSH_FEATURE_PLUGIN_MANIFEST
  SSHX11_9P_RUNTIME, SSHX11_9P_CONTAINER_IMAGE, SSHX11_9P_CONTAINER_BUILD
  SSHX11_9P_CONTAINER_RUNTIME_BIN, SSHX11_9P_CONTAINER_NAME, SSHX11_9P_CONTAINERFILE
  SSHX11_9P_CONTAINER_PORT, SSHX11_9P_LOGS_TAIL
  TLA2TOOLS_JAR (used by verify-extensions --run-tlc)
EOF
}

feature_plugins() {
  run_py weaverssh_feature_plugins.py "$@"
}

plugins_list() { feature_plugins list "$@"; }
plugins_show() { feature_plugins show "$@"; }
plugins_discover() { feature_plugins discover "$@"; }

service_start() {
  run_py sshx11_plane_service.py \
    --host "$HOST" \
    --control-port "$CONTROL_PORT" \
    --data-port "$DATA_PORT" \
    --realtime-port "$REALTIME_PORT" \
    --state-file "$STATE_FILE" \
    --control-event-log "$CONTROL_EVENT_LOG" \
    --data-event-log "$DATA_EVENT_LOG" \
    start
}

service_stop() {
  run_py sshx11_plane_service.py \
    --host "$HOST" \
    --control-port "$CONTROL_PORT" \
    --data-port "$DATA_PORT" \
    --realtime-port "$REALTIME_PORT" \
    --state-file "$STATE_FILE" \
    --control-event-log "$CONTROL_EVENT_LOG" \
    --data-event-log "$DATA_EVENT_LOG" \
    stop
}

service_restart() {
  run_py sshx11_plane_service.py \
    --host "$HOST" \
    --control-port "$CONTROL_PORT" \
    --data-port "$DATA_PORT" \
    --realtime-port "$REALTIME_PORT" \
    --state-file "$STATE_FILE" \
    --control-event-log "$CONTROL_EVENT_LOG" \
    --data-event-log "$DATA_EVENT_LOG" \
    restart
}

status_local() {
  local rc=0
  echo "== service status =="
  if ! run_py sshx11_plane_service.py --host "$HOST" --control-port "$CONTROL_PORT" --data-port "$DATA_PORT" --realtime-port "$REALTIME_PORT" status; then
    rc=1
  fi
  echo "== control health =="
  if ! run_py sshx11_plane_ctl.py --host "$HOST" --port "$CONTROL_PORT" health; then
    rc=1
  fi
  echo "== policy =="
  if ! run_py sshx11_plane_ctl.py --host "$HOST" --port "$CONTROL_PORT" policy; then
    rc=1
  fi
  echo "== state =="
  if ! run_py sshx11_plane_ctl.py --host "$HOST" --port "$CONTROL_PORT" state; then
    rc=1
  fi
  echo "== log summary =="
  if ! run_py sshx11_plane_log_summary.py \
    --control-log "$CONTROL_EVENT_LOG" \
    --data-log "$DATA_EVENT_LOG" \
    --state-file "$STATE_FILE"; then
    rc=1
  fi
  return "$rc"
}

watch_status() {
  local interval="${1:-3}"
  while true; do
    echo ""
    date '+%Y-%m-%d %H:%M:%S %z'
    status_local || true
    sleep "$interval"
  done
}

deps_check() {
  local extra=()
  if [[ -n "$REVERSE_SOCKS_IDENTITY_FILE" ]]; then
    extra+=(--identity-file "$REVERSE_SOCKS_IDENTITY_FILE")
  fi
  if is_true "$REVERSE_SOCKS_INSECURE_HOSTKEY"; then
    extra+=(--insecure-hostkey)
  fi
  run_py sshx11_dependency_check.py \
    --host "${REVERSE_SOCKS_REMOTE_HOST:-${SSHX11_REMOTE_HOST:-}}" \
    --user "${REVERSE_SOCKS_REMOTE_USER:-${SSHX11_REMOTE_USER:-root}}" \
    --port "${REVERSE_SOCKS_REMOTE_PORT:-${SSHX11_REMOTE_PORT:-22}}" \
    --webdav-host "$WEBDAV_HOST" \
    --webdav-port "$WEBDAV_PORT" \
    "${extra[@]}" \
    "$@"
}

test_local() {
  run_py run_sshx11_plane_stack_demo.py \
    --host "$HOST" \
    --control-port "$CONTROL_PORT" \
    --data-port "$DATA_PORT" \
    --realtime-port "$REALTIME_PORT" \
    --managed-service \
    "$@"
}

bench_local() {
  run_py benchmark_sshx11_transport_profiles.py \
    --host "$HOST" \
    --control-port "$CONTROL_PORT" \
    --bulk-port "$DATA_PORT" \
    --realtime-port "$REALTIME_PORT" \
    --managed-service \
    "$@"
}

test_remote() {
  run_py sshx11_remote_system_e2e.py "$@"
}

socks_fallback_start() {
  run_py sshx11_socks_fallback_service.py \
    --weaverssh-repo "$SOCKS_X11WS_REPO" \
    --socks-port "$SOCKS_PORT" \
    --agent-listen "$SOCKS_AGENT_LISTEN" \
    --agent-endpoint "$SOCKS_AGENT_ENDPOINT" \
    "$@" \
    start
}

socks_fallback_stop() {
  run_py sshx11_socks_fallback_service.py \
    --weaverssh-repo "$SOCKS_X11WS_REPO" \
    --socks-port "$SOCKS_PORT" \
    --agent-listen "$SOCKS_AGENT_LISTEN" \
    --agent-endpoint "$SOCKS_AGENT_ENDPOINT" \
    "$@" \
    stop
}

socks_fallback_status() {
  run_py sshx11_socks_fallback_service.py \
    --weaverssh-repo "$SOCKS_X11WS_REPO" \
    --socks-port "$SOCKS_PORT" \
    --agent-listen "$SOCKS_AGENT_LISTEN" \
    --agent-endpoint "$SOCKS_AGENT_ENDPOINT" \
    "$@" \
    status
}

test_socks_local() {
  run_py sshx11_socks_fallback_probe.py \
    --socks-host "$HOST" \
    --socks-port "$SOCKS_PORT" \
    --weaverssh-repo "$SOCKS_X11WS_REPO" \
    --agent-listen "$SOCKS_AGENT_LISTEN" \
    --agent-endpoint "$SOCKS_AGENT_ENDPOINT" \
    "$@"
}

bench_socks5() {
  run_py benchmark_sshx11_socks5_flows.py \
    --host "$HOST" \
    --socks-host "$HOST" \
    --socks-port "$SOCKS_PORT" \
    --weaverssh-repo "$SOCKS_X11WS_REPO" \
    --agent-listen "$SOCKS_AGENT_LISTEN" \
    --agent-endpoint "$SOCKS_AGENT_ENDPOINT" \
    "$@"
}

reverse_socks_start() {
  local extra=()
  if [[ -n "$REVERSE_SOCKS_SSH_BIN" ]]; then
    extra+=(--ssh-bin "$REVERSE_SOCKS_SSH_BIN")
  fi
  if [[ -n "$REVERSE_SOCKS_IDENTITY_FILE" ]]; then
    extra+=(--identity-file "$REVERSE_SOCKS_IDENTITY_FILE")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_CONFIG" ]]; then
    extra+=(--ssh-config "$REVERSE_SOCKS_SSH_CONFIG")
  fi
  if [[ -n "$REVERSE_SOCKS_PROXY_JUMP" ]]; then
    extra+=(--proxy-jump "$REVERSE_SOCKS_PROXY_JUMP")
  fi
  if [[ -n "$REVERSE_SOCKS_PROXY_COMMAND" ]]; then
    extra+=(--proxy-command "$REVERSE_SOCKS_PROXY_COMMAND")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_VERBOSITY" ]]; then
    extra+=(--ssh-verbosity "$REVERSE_SOCKS_SSH_VERBOSITY")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_LOG_LEVEL" ]]; then
    extra+=(--ssh-log-level "$REVERSE_SOCKS_SSH_LOG_LEVEL")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_LOG_FILE" ]]; then
    extra+=(--ssh-log-file "$REVERSE_SOCKS_SSH_LOG_FILE")
  fi
  if [[ -n "$REVERSE_SOCKS_AGENT_MODE" ]]; then
    extra+=(--agent-mode "$REVERSE_SOCKS_AGENT_MODE")
  fi
  if is_true "$REVERSE_SOCKS_FORWARD_AGENT"; then
    extra+=(--forward-agent)
  fi
  if [[ -n "$REVERSE_SOCKS_IDENTITY_AGENT" ]]; then
    extra+=(--identity-agent "$REVERSE_SOCKS_IDENTITY_AGENT")
  fi
  if [[ -n "$REVERSE_SOCKS_REMOTE_PLATFORM" ]]; then
    extra+=(--remote-platform "$REVERSE_SOCKS_REMOTE_PLATFORM")
  fi
  if [[ -n "$REVERSE_SOCKS_REMOTE_SHELL_BIN" ]]; then
    extra+=(--remote-shell-bin "$REVERSE_SOCKS_REMOTE_SHELL_BIN")
  fi
  if is_true "$REVERSE_SOCKS_REMOTE_SHELL_LOGIN"; then
    extra+=(--remote-shell-login)
  else
    extra+=(--no-remote-shell-login)
  fi
  if [[ -n "$REVERSE_SOCKS_REMOTE_PYTHON_BIN" ]]; then
    extra+=(--remote-python-bin "$REVERSE_SOCKS_REMOTE_PYTHON_BIN")
  fi
  if is_true "$REVERSE_SOCKS_INSECURE_HOSTKEY"; then
    extra+=(--insecure-hostkey)
  fi
  run_py sshx11_reverse_socks_service.py \
    --host "$REVERSE_SOCKS_REMOTE_HOST" \
    --user "$REVERSE_SOCKS_REMOTE_USER" \
    --port "$REVERSE_SOCKS_REMOTE_PORT" \
    --remote-bind-host "$REVERSE_SOCKS_BIND_HOST" \
    --remote-socks-port "$REVERSE_SOCKS_PORT" \
    "${extra[@]}" \
    "$@" \
    start
}

reverse_socks_stop() {
  local extra=()
  if [[ -n "$REVERSE_SOCKS_SSH_BIN" ]]; then
    extra+=(--ssh-bin "$REVERSE_SOCKS_SSH_BIN")
  fi
  if [[ -n "$REVERSE_SOCKS_IDENTITY_FILE" ]]; then
    extra+=(--identity-file "$REVERSE_SOCKS_IDENTITY_FILE")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_CONFIG" ]]; then
    extra+=(--ssh-config "$REVERSE_SOCKS_SSH_CONFIG")
  fi
  if [[ -n "$REVERSE_SOCKS_PROXY_JUMP" ]]; then
    extra+=(--proxy-jump "$REVERSE_SOCKS_PROXY_JUMP")
  fi
  if [[ -n "$REVERSE_SOCKS_PROXY_COMMAND" ]]; then
    extra+=(--proxy-command "$REVERSE_SOCKS_PROXY_COMMAND")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_VERBOSITY" ]]; then
    extra+=(--ssh-verbosity "$REVERSE_SOCKS_SSH_VERBOSITY")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_LOG_LEVEL" ]]; then
    extra+=(--ssh-log-level "$REVERSE_SOCKS_SSH_LOG_LEVEL")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_LOG_FILE" ]]; then
    extra+=(--ssh-log-file "$REVERSE_SOCKS_SSH_LOG_FILE")
  fi
  if [[ -n "$REVERSE_SOCKS_AGENT_MODE" ]]; then
    extra+=(--agent-mode "$REVERSE_SOCKS_AGENT_MODE")
  fi
  if is_true "$REVERSE_SOCKS_FORWARD_AGENT"; then
    extra+=(--forward-agent)
  fi
  if [[ -n "$REVERSE_SOCKS_IDENTITY_AGENT" ]]; then
    extra+=(--identity-agent "$REVERSE_SOCKS_IDENTITY_AGENT")
  fi
  if [[ -n "$REVERSE_SOCKS_REMOTE_PLATFORM" ]]; then
    extra+=(--remote-platform "$REVERSE_SOCKS_REMOTE_PLATFORM")
  fi
  if [[ -n "$REVERSE_SOCKS_REMOTE_SHELL_BIN" ]]; then
    extra+=(--remote-shell-bin "$REVERSE_SOCKS_REMOTE_SHELL_BIN")
  fi
  if is_true "$REVERSE_SOCKS_REMOTE_SHELL_LOGIN"; then
    extra+=(--remote-shell-login)
  else
    extra+=(--no-remote-shell-login)
  fi
  if [[ -n "$REVERSE_SOCKS_REMOTE_PYTHON_BIN" ]]; then
    extra+=(--remote-python-bin "$REVERSE_SOCKS_REMOTE_PYTHON_BIN")
  fi
  if is_true "$REVERSE_SOCKS_INSECURE_HOSTKEY"; then
    extra+=(--insecure-hostkey)
  fi
  run_py sshx11_reverse_socks_service.py \
    --host "$REVERSE_SOCKS_REMOTE_HOST" \
    --user "$REVERSE_SOCKS_REMOTE_USER" \
    --port "$REVERSE_SOCKS_REMOTE_PORT" \
    --remote-bind-host "$REVERSE_SOCKS_BIND_HOST" \
    --remote-socks-port "$REVERSE_SOCKS_PORT" \
    "${extra[@]}" \
    "$@" \
    stop
}

reverse_socks_status() {
  local extra=()
  if [[ -n "$REVERSE_SOCKS_SSH_BIN" ]]; then
    extra+=(--ssh-bin "$REVERSE_SOCKS_SSH_BIN")
  fi
  if [[ -n "$REVERSE_SOCKS_IDENTITY_FILE" ]]; then
    extra+=(--identity-file "$REVERSE_SOCKS_IDENTITY_FILE")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_CONFIG" ]]; then
    extra+=(--ssh-config "$REVERSE_SOCKS_SSH_CONFIG")
  fi
  if [[ -n "$REVERSE_SOCKS_PROXY_JUMP" ]]; then
    extra+=(--proxy-jump "$REVERSE_SOCKS_PROXY_JUMP")
  fi
  if [[ -n "$REVERSE_SOCKS_PROXY_COMMAND" ]]; then
    extra+=(--proxy-command "$REVERSE_SOCKS_PROXY_COMMAND")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_VERBOSITY" ]]; then
    extra+=(--ssh-verbosity "$REVERSE_SOCKS_SSH_VERBOSITY")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_LOG_LEVEL" ]]; then
    extra+=(--ssh-log-level "$REVERSE_SOCKS_SSH_LOG_LEVEL")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_LOG_FILE" ]]; then
    extra+=(--ssh-log-file "$REVERSE_SOCKS_SSH_LOG_FILE")
  fi
  if [[ -n "$REVERSE_SOCKS_AGENT_MODE" ]]; then
    extra+=(--agent-mode "$REVERSE_SOCKS_AGENT_MODE")
  fi
  if is_true "$REVERSE_SOCKS_FORWARD_AGENT"; then
    extra+=(--forward-agent)
  fi
  if [[ -n "$REVERSE_SOCKS_IDENTITY_AGENT" ]]; then
    extra+=(--identity-agent "$REVERSE_SOCKS_IDENTITY_AGENT")
  fi
  if [[ -n "$REVERSE_SOCKS_REMOTE_PLATFORM" ]]; then
    extra+=(--remote-platform "$REVERSE_SOCKS_REMOTE_PLATFORM")
  fi
  if [[ -n "$REVERSE_SOCKS_REMOTE_SHELL_BIN" ]]; then
    extra+=(--remote-shell-bin "$REVERSE_SOCKS_REMOTE_SHELL_BIN")
  fi
  if is_true "$REVERSE_SOCKS_REMOTE_SHELL_LOGIN"; then
    extra+=(--remote-shell-login)
  else
    extra+=(--no-remote-shell-login)
  fi
  if [[ -n "$REVERSE_SOCKS_REMOTE_PYTHON_BIN" ]]; then
    extra+=(--remote-python-bin "$REVERSE_SOCKS_REMOTE_PYTHON_BIN")
  fi
  if is_true "$REVERSE_SOCKS_INSECURE_HOSTKEY"; then
    extra+=(--insecure-hostkey)
  fi
  run_py sshx11_reverse_socks_service.py \
    --host "$REVERSE_SOCKS_REMOTE_HOST" \
    --user "$REVERSE_SOCKS_REMOTE_USER" \
    --port "$REVERSE_SOCKS_REMOTE_PORT" \
    --remote-bind-host "$REVERSE_SOCKS_BIND_HOST" \
    --remote-socks-port "$REVERSE_SOCKS_PORT" \
    "${extra[@]}" \
    "$@" \
    status
}

reverse_socks_smoke() {
  local extra=()
  if [[ -n "$REVERSE_SOCKS_SSH_BIN" ]]; then
    extra+=(--ssh-bin "$REVERSE_SOCKS_SSH_BIN")
  fi
  if [[ -n "$REVERSE_SOCKS_IDENTITY_FILE" ]]; then
    extra+=(--identity-file "$REVERSE_SOCKS_IDENTITY_FILE")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_CONFIG" ]]; then
    extra+=(--ssh-config "$REVERSE_SOCKS_SSH_CONFIG")
  fi
  if [[ -n "$REVERSE_SOCKS_PROXY_JUMP" ]]; then
    extra+=(--proxy-jump "$REVERSE_SOCKS_PROXY_JUMP")
  fi
  if [[ -n "$REVERSE_SOCKS_PROXY_COMMAND" ]]; then
    extra+=(--proxy-command "$REVERSE_SOCKS_PROXY_COMMAND")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_VERBOSITY" ]]; then
    extra+=(--ssh-verbosity "$REVERSE_SOCKS_SSH_VERBOSITY")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_LOG_LEVEL" ]]; then
    extra+=(--ssh-log-level "$REVERSE_SOCKS_SSH_LOG_LEVEL")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_LOG_FILE" ]]; then
    extra+=(--ssh-log-file "$REVERSE_SOCKS_SSH_LOG_FILE")
  fi
  if [[ -n "$REVERSE_SOCKS_AGENT_MODE" ]]; then
    extra+=(--agent-mode "$REVERSE_SOCKS_AGENT_MODE")
  fi
  if is_true "$REVERSE_SOCKS_FORWARD_AGENT"; then
    extra+=(--forward-agent)
  fi
  if [[ -n "$REVERSE_SOCKS_IDENTITY_AGENT" ]]; then
    extra+=(--identity-agent "$REVERSE_SOCKS_IDENTITY_AGENT")
  fi
  if [[ -n "$REVERSE_SOCKS_REMOTE_PLATFORM" ]]; then
    extra+=(--remote-platform "$REVERSE_SOCKS_REMOTE_PLATFORM")
  fi
  if [[ -n "$REVERSE_SOCKS_REMOTE_SHELL_BIN" ]]; then
    extra+=(--remote-shell-bin "$REVERSE_SOCKS_REMOTE_SHELL_BIN")
  fi
  if is_true "$REVERSE_SOCKS_REMOTE_SHELL_LOGIN"; then
    extra+=(--remote-shell-login)
  else
    extra+=(--no-remote-shell-login)
  fi
  if [[ -n "$REVERSE_SOCKS_REMOTE_PYTHON_BIN" ]]; then
    extra+=(--remote-python-bin "$REVERSE_SOCKS_REMOTE_PYTHON_BIN")
  fi
  if is_true "$REVERSE_SOCKS_INSECURE_HOSTKEY"; then
    extra+=(--insecure-hostkey)
  fi
  run_py verify_sshx11_reverse_socks_smoke.py \
    --host "$REVERSE_SOCKS_REMOTE_HOST" \
    --user "$REVERSE_SOCKS_REMOTE_USER" \
    --port "$REVERSE_SOCKS_REMOTE_PORT" \
    --reverse-socks-host "$REVERSE_SOCKS_BIND_HOST" \
    --reverse-socks-port "$REVERSE_SOCKS_PORT" \
    "${extra[@]}" \
    "$@"
}

run_9p_socks() {
  run_py run_sshx11_9p_over_socks.py \
    --socks-host "$HOST" \
    --socks-port "$SOCKS_PORT" \
    --weaverssh-repo "$SOCKS_X11WS_REPO" \
    --agent-listen "$SOCKS_AGENT_LISTEN" \
    --agent-endpoint "$SOCKS_AGENT_ENDPOINT" \
    "$@"
}

ninep_service() {
  local action="$1"
  shift
  local args=(
    --host "$NINEP_HOST"
    --port "$NINEP_PORT"
    --root "$NINEP_ROOT"
    --binary "$NINEP_BINARY"
    --runtime "$NINEP_RUNTIME"
    --container-image "$NINEP_CONTAINER_IMAGE"
    --containerfile "$NINEP_CONTAINERFILE"
    --container-port "$NINEP_CONTAINER_PORT"
    --logs-tail "$NINEP_LOGS_TAIL"
  )
  if [[ -n "$NINEP_CONTAINER_RUNTIME_BIN" ]]; then
    args+=(--container-runtime-bin "$NINEP_CONTAINER_RUNTIME_BIN")
  fi
  if [[ -n "$NINEP_CONTAINER_NAME" ]]; then
    args+=(--container-name "$NINEP_CONTAINER_NAME")
  fi
  if is_true "$NINEP_CONTAINER_BUILD"; then
    args+=(--container-build)
  fi
  run_py sshx11_9p_service.py "${args[@]}" "$@" "$action"
}

9p_start() { ninep_service start "$@"; }
9p_stop() { ninep_service stop "$@"; }
9p_status() { ninep_service status "$@"; }
9p_plan() { ninep_service plan "$@"; }
9p_image_build() { ninep_service image-build "$@"; }
9p_logs() { ninep_service logs "$@"; }

webdav_start() {
  local mode=()
  local mode_set=0
  local arg=""
  for arg in "$@"; do
    if [[ "$arg" == "--read-only" || "$arg" == "--read-write" ]]; then
      mode_set=1
      break
    fi
  done
  if [[ "$mode_set" -eq 0 ]]; then
    mode=(--read-only)
    if ! is_true "$WEBDAV_READ_ONLY"; then
      mode=(--read-write)
    fi
  fi
  run_py sshx11_webdav_service.py \
    --host "$WEBDAV_HOST" \
    --port "$WEBDAV_PORT" \
    --root "$WEBDAV_ROOT" \
    "${mode[@]}" \
    "$@" \
    start
}

webdav_stop() {
  local mode=()
  local mode_set=0
  local arg=""
  for arg in "$@"; do
    if [[ "$arg" == "--read-only" || "$arg" == "--read-write" ]]; then
      mode_set=1
      break
    fi
  done
  if [[ "$mode_set" -eq 0 ]]; then
    mode=(--read-only)
    if ! is_true "$WEBDAV_READ_ONLY"; then
      mode=(--read-write)
    fi
  fi
  run_py sshx11_webdav_service.py \
    --host "$WEBDAV_HOST" \
    --port "$WEBDAV_PORT" \
    --root "$WEBDAV_ROOT" \
    "${mode[@]}" \
    "$@" \
    stop
}

webdav_status() {
  local mode=()
  local mode_set=0
  local arg=""
  for arg in "$@"; do
    if [[ "$arg" == "--read-only" || "$arg" == "--read-write" ]]; then
      mode_set=1
      break
    fi
  done
  if [[ "$mode_set" -eq 0 ]]; then
    mode=(--read-only)
    if ! is_true "$WEBDAV_READ_ONLY"; then
      mode=(--read-write)
    fi
  fi
  run_py sshx11_webdav_service.py \
    --host "$WEBDAV_HOST" \
    --port "$WEBDAV_PORT" \
    --root "$WEBDAV_ROOT" \
    "${mode[@]}" \
    "$@" \
    status
}

vscode_profile_gen() {
  run_py generate_sshx11_vscode_profile.py \
    --local-socks-host "$HOST" \
    --local-socks-port "$SOCKS_PORT" \
    --reverse-socks-host "$REVERSE_SOCKS_BIND_HOST" \
    --reverse-socks-port "$REVERSE_SOCKS_PORT" \
    "$@"
}

verify_extension_hosts() {
  local extra=()
  if [[ -n "$REVERSE_SOCKS_REMOTE_HOST" ]]; then
    extra+=(--remote-host "$REVERSE_SOCKS_REMOTE_HOST")
    extra+=(--remote-user "$REVERSE_SOCKS_REMOTE_USER")
    extra+=(--remote-port "$REVERSE_SOCKS_REMOTE_PORT")
  fi
  if [[ -n "$REVERSE_SOCKS_IDENTITY_FILE" ]]; then
    extra+=(--identity-file "$REVERSE_SOCKS_IDENTITY_FILE")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_BIN" ]]; then
    extra+=(--ssh-bin "$REVERSE_SOCKS_SSH_BIN")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_CONFIG" ]]; then
    extra+=(--ssh-config "$REVERSE_SOCKS_SSH_CONFIG")
  fi
  if [[ -n "$REVERSE_SOCKS_PROXY_JUMP" ]]; then
    extra+=(--proxy-jump "$REVERSE_SOCKS_PROXY_JUMP")
  fi
  if [[ -n "$REVERSE_SOCKS_PROXY_COMMAND" ]]; then
    extra+=(--proxy-command "$REVERSE_SOCKS_PROXY_COMMAND")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_VERBOSITY" ]]; then
    extra+=(--ssh-verbosity "$REVERSE_SOCKS_SSH_VERBOSITY")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_LOG_LEVEL" ]]; then
    extra+=(--ssh-log-level "$REVERSE_SOCKS_SSH_LOG_LEVEL")
  fi
  if [[ -n "$REVERSE_SOCKS_SSH_LOG_FILE" ]]; then
    extra+=(--ssh-log-file "$REVERSE_SOCKS_SSH_LOG_FILE")
  fi
  if [[ -n "$REVERSE_SOCKS_AGENT_MODE" ]]; then
    extra+=(--agent-mode "$REVERSE_SOCKS_AGENT_MODE")
  fi
  if is_true "$REVERSE_SOCKS_FORWARD_AGENT"; then
    extra+=(--forward-agent)
  fi
  if [[ -n "$REVERSE_SOCKS_IDENTITY_AGENT" ]]; then
    extra+=(--identity-agent "$REVERSE_SOCKS_IDENTITY_AGENT")
  fi
  if [[ -n "$REVERSE_SOCKS_REMOTE_PLATFORM" ]]; then
    extra+=(--remote-platform "$REVERSE_SOCKS_REMOTE_PLATFORM")
  fi
  if [[ -n "$REVERSE_SOCKS_REMOTE_SHELL_BIN" ]]; then
    extra+=(--remote-shell-bin "$REVERSE_SOCKS_REMOTE_SHELL_BIN")
  fi
  if is_true "$REVERSE_SOCKS_REMOTE_SHELL_LOGIN"; then
    extra+=(--remote-shell-login)
  else
    extra+=(--no-remote-shell-login)
  fi
  if [[ -n "$REVERSE_SOCKS_REMOTE_PYTHON_BIN" ]]; then
    extra+=(--remote-python-bin "$REVERSE_SOCKS_REMOTE_PYTHON_BIN")
  fi
  if is_true "$REVERSE_SOCKS_INSECURE_HOSTKEY"; then
    extra+=(--insecure-hostkey)
  fi
  run_py verify_sshx11_extension_host_paths.py \
    --local-socks-host "$HOST" \
    --local-socks-port "$SOCKS_PORT" \
    --reverse-socks-host "$REVERSE_SOCKS_BIND_HOST" \
    --reverse-socks-port "$REVERSE_SOCKS_PORT" \
    "${extra[@]}" \
    "$@"
}

vfs_agent_start() {
  run_py sshx11_vfs_agent.py "$@" start
}

vfs_agent_stop() {
  run_py sshx11_vfs_agent.py "$@" stop
}

vfs_agent_status() {
  run_py sshx11_vfs_agent.py "$@" status
}

vfs_agent_sync() {
  run_py sshx11_vfs_agent.py "$@" sync-once
}

vfs_registry_list() {
  run_py sshx11_vfs_agent.py "$@" list-registry
}

vfs_mesh_build() {
  run_py sshx11_vfs_mesh.py \
    --registry-file "$VFS_REGISTRY_FILE" \
    --namespace-dir "$VFS_NAMESPACE_DIR" \
    "$@" \
    build
}

vfs_mesh_status() {
  run_py sshx11_vfs_mesh.py \
    --registry-file "$VFS_REGISTRY_FILE" \
    --namespace-dir "$VFS_NAMESPACE_DIR" \
    "$@" \
    status
}

vfs_mesh_clean() {
  run_py sshx11_vfs_mesh.py \
    --registry-file "$VFS_REGISTRY_FILE" \
    --namespace-dir "$VFS_NAMESPACE_DIR" \
    "$@" \
    clean
}

verify_remote() {
  local source="${1:-auto}"
  shift || true
  run_py verify_sshx11_remote_execution_tla.py --source "$source" --artifact "$REMOTE_ARTIFACT" "$@"
}

verify_fsm() {
  run_py verify_sshx11_fsm_python_tla.py "$@"
}

verify_crypto() {
  run_py verify_sshx11_crypto_crosslayer_reverse.py "$@"
}

verify_extensions() {
  run_py verify_sshx11_extension_set_tla.py "$@"
}

repl_start() {
  run_py sshx11_collab_terminal.py start "$@"
}

repl_probe() {
  run_py sshx11_collab_terminal.py probe "$@"
}

repl_send() {
  run_py sshx11_collab_terminal.py send "$@"
}

repl_shortcut() {
  run_py sshx11_collab_terminal.py shortcut "$@"
}

repl_console() {
  run_py sshx11_collab_terminal.py console "$@"
}

repl_status() {
  run_py sshx11_collab_terminal.py status "$@"
}

repl_tail() {
  run_py sshx11_collab_terminal.py tail "$@"
}

repl_stop() {
  run_py sshx11_collab_terminal.py stop "$@"
}

repl_vhs_probe() {
  run_py sshx11_vhs_record.py probe "$@"
}

repl_vhs_record() {
  run_py sshx11_vhs_record.py render-publish "$@"
}

trace_local() {
  local mode="${1:-all}"
  case "$mode" in
    control)
      tail -n "$TAIL_LINES" -F "$CONTROL_EVENT_LOG"
      ;;
    data)
      tail -n "$TAIL_LINES" -F "$DATA_EVENT_LOG"
      ;;
    daemon)
      tail -n "$TAIL_LINES" -F "$CONTROL_DAEMON_LOG" "$DATA_DAEMON_LOG"
      ;;
    all)
      trap 'jobs -p | xargs -r kill 2>/dev/null || true' EXIT INT TERM
      tail -n "$TAIL_LINES" -F "$CONTROL_EVENT_LOG" | sed 's/^/[control-event] /' &
      tail -n "$TAIL_LINES" -F "$DATA_EVENT_LOG" | sed 's/^/[data-event] /' &
      tail -n "$TAIL_LINES" -F "$CONTROL_DAEMON_LOG" | sed 's/^/[control-daemon] /' &
      tail -n "$TAIL_LINES" -F "$DATA_DAEMON_LOG" | sed 's/^/[data-daemon] /' &
      wait
      ;;
    *)
      echo "error: unsupported mode '$mode' (expected: all|control|data|daemon)" >&2
      return 2
      ;;
  esac
}

cmd="${1:-help}"
case "$cmd" in
  help|-h|--help)
    usage
    ;;
  setup-tla-tools)
    shift
    setup_tla_tools "$@"
    ;;
  service-start)
    shift
    service_start "$@"
    ;;
  service-stop)
    shift
    service_stop "$@"
    ;;
  service-restart)
    shift
    service_restart "$@"
    ;;
  status-local)
    shift
    status_local "$@"
    ;;
  plugins-list)
    shift
    plugins_list "$@"
    ;;
  plugins-show)
    shift
    plugins_show "$@"
    ;;
  plugins-discover)
    shift
    plugins_discover "$@"
    ;;
  native-forward-plan)
    shift
    native_forward_plan "$@"
    ;;
  dataplane-firewall)
    shift
    dataplane_firewall "$@"
    ;;
  watch-status)
    shift
    watch_status "$@"
    ;;
  deps-check)
    shift
    deps_check "$@"
    ;;
  test-local)
    shift
    test_local "$@"
    ;;
  bench-local)
    shift
    bench_local "$@"
    ;;
  test-remote)
    shift
    test_remote "$@"
    ;;
  socks-fallback-start)
    shift
    socks_fallback_start "$@"
    ;;
  socks-fallback-stop)
    shift
    socks_fallback_stop "$@"
    ;;
  socks-fallback-status)
    shift
    socks_fallback_status "$@"
    ;;
  test-socks-local)
    shift
    test_socks_local "$@"
    ;;
  bench-socks5)
    shift
    bench_socks5 "$@"
    ;;
  reverse-socks-start)
    shift
    reverse_socks_start "$@"
    ;;
  reverse-socks-stop)
    shift
    reverse_socks_stop "$@"
    ;;
  reverse-socks-status)
    shift
    reverse_socks_status "$@"
    ;;
  reverse-socks-smoke)
    shift
    reverse_socks_smoke "$@"
    ;;
  run-9p-socks)
    shift
    run_9p_socks "$@"
    ;;
  9p-start)
    shift
    9p_start "$@"
    ;;
  9p-stop)
    shift
    9p_stop "$@"
    ;;
  9p-status)
    shift
    9p_status "$@"
    ;;
  9p-plan)
    shift
    9p_plan "$@"
    ;;
  9p-image-build)
    shift
    9p_image_build "$@"
    ;;
  9p-logs)
    shift
    9p_logs "$@"
    ;;
  webdav-start)
    shift
    webdav_start "$@"
    ;;
  webdav-stop)
    shift
    webdav_stop "$@"
    ;;
  webdav-status)
    shift
    webdav_status "$@"
    ;;
  vscode-profile-gen)
    shift
    vscode_profile_gen "$@"
    ;;
  verify-extension-hosts)
    shift
    verify_extension_hosts "$@"
    ;;
  vfs-agent-start)
    shift
    vfs_agent_start "$@"
    ;;
  vfs-agent-stop)
    shift
    vfs_agent_stop "$@"
    ;;
  vfs-agent-status)
    shift
    vfs_agent_status "$@"
    ;;
  vfs-agent-sync)
    shift
    vfs_agent_sync "$@"
    ;;
  vfs-registry-list)
    shift
    vfs_registry_list "$@"
    ;;
  vfs-mesh-build)
    shift
    vfs_mesh_build "$@"
    ;;
  vfs-mesh-status)
    shift
    vfs_mesh_status "$@"
    ;;
  vfs-mesh-clean)
    shift
    vfs_mesh_clean "$@"
    ;;
  verify-remote)
    shift
    verify_remote "$@"
    ;;
  verify-fsm)
    shift
    verify_fsm "$@"
    ;;
  verify-crypto)
    shift
    verify_crypto "$@"
    ;;
  verify-extensions)
    shift
    verify_extensions "$@"
    ;;
  repl-start)
    shift
    repl_start "$@"
    ;;
  repl-probe)
    shift
    repl_probe "$@"
    ;;
  repl-send)
    shift
    repl_send "$@"
    ;;
  repl-shortcut)
    shift
    repl_shortcut "$@"
    ;;
  repl-console)
    shift
    repl_console "$@"
    ;;
  repl-status)
    shift
    repl_status "$@"
    ;;
  repl-tail)
    shift
    repl_tail "$@"
    ;;
  repl-stop)
    shift
    repl_stop "$@"
    ;;
  repl-vhs-probe)
    shift
    repl_vhs_probe "$@"
    ;;
  repl-vhs-record)
    shift
    repl_vhs_record "$@"
    ;;
  trace-local)
    shift
    trace_local "$@"
    ;;
  *)
    echo "error: unknown command '$cmd'" >&2
    usage
    exit 2
    ;;
esac
