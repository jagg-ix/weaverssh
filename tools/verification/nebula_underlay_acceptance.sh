#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: nebula_underlay_acceptance.sh [--profile FILE] MODE

Modes:
  preflight  verify public-SSH closure (optional), overlay reachability, SSH banner,
             and ordinary batch-mode SSH authentication
  session    verify signed-node registration, route availability, file round-trip,
             and an optional authorized TCP service
  outage     verify the SSH route is unavailable after the operator stops Nebula
  fallback   verify an ordinary non-Nebula SSH profile remains usable
  all        run preflight and session, plus fallback when configured

Configuration may come from --profile (default: .weaverssh/workspace.json when it
exists) and may be overridden with environment variables:

  WV_BIN                         wv executable (default: wv)
  SSH_BIN                        ssh executable (default: ssh)
  WV_NEBULA_SSH_HOST             SSH alias over Nebula
  WV_NEBULA_OVERLAY_ADDRESS      expected resolved overlay address
  WV_NEBULA_TARGET_NODE          signed WeaverSSH target node
  WV_NEBULA_PUBLIC_ADDRESS       public HOST:PORT expected to reject TCP (optional)
  WV_NEBULA_FALLBACK_SSH_HOST    ordinary SSH alias used by fallback mode
  WV_NEBULA_TCP_ADDRESS          authorized target service HOST:PORT (optional)
  WV_NEBULA_TCP_EXPECT           expected response substring (default: HTTP/)
  WV_NEBULA_REMOTE_TEST_PATH     session path relative to exported root (optional)
  WV_NEBULA_SKIP_FILE_TEST       set to 1 to skip the file round-trip
  WV_NEBULA_SSH_TIMEOUT_SECONDS  SSH/connectivity timeout (default: 5)

Outage mode never stops or starts Nebula. Stop it explicitly, run outage, restore
it, then run preflight again. This keeps service lifecycle under operator control.
USAGE
}

profile=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      profile=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      break
      ;;
  esac
done

[ "$#" -eq 1 ] || { usage; exit 2; }
mode=$1
case "$mode" in
  preflight|session|outage|fallback|all) ;;
  *) echo "nebula acceptance: unknown mode: $mode" >&2; usage; exit 2 ;;
esac

WV_BIN=${WV_BIN:-wv}
SSH_BIN=${SSH_BIN:-ssh}
SSH_TIMEOUT=${WV_NEBULA_SSH_TIMEOUT_SECONDS:-5}

case "$SSH_TIMEOUT" in
  ''|*[!0-9]*) echo "nebula acceptance: timeout must be a positive integer" >&2; exit 2 ;;
esac
[ "$SSH_TIMEOUT" -gt 0 ] || { echo "nebula acceptance: timeout must be positive" >&2; exit 2; }

if [ -z "$profile" ] && [ -f .weaverssh/workspace.json ]; then
  profile=.weaverssh/workspace.json
fi

profile_ssh=
profile_overlay=
profile_target=
profile_tcp=
if [ -n "$profile" ]; then
  [ -f "$profile" ] || { echo "nebula acceptance: profile not found: $profile" >&2; exit 1; }
  mapfile -t profile_fields < <(python3 - "$profile" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    value = json.load(handle)
connection = value.get("connection") or {}
services = value.get("services") or []
fields = [
    connection.get("ssh_host", ""),
    connection.get("overlay_address", ""),
    value.get("target_node", ""),
    services[0].get("address", "") if services and isinstance(services[0], dict) else "",
]
for field in fields:
    field = str(field or "")
    if any(ch in field for ch in "\r\n\0"):
        raise SystemExit("profile contains an unsafe control character")
    print(field)
PY
  )
  profile_ssh=${profile_fields[0]:-}
  profile_overlay=${profile_fields[1]:-}
  profile_target=${profile_fields[2]:-}
  profile_tcp=${profile_fields[3]:-}
fi

SSH_HOST=${WV_NEBULA_SSH_HOST:-$profile_ssh}
OVERLAY_ADDRESS=${WV_NEBULA_OVERLAY_ADDRESS:-$profile_overlay}
TARGET_NODE=${WV_NEBULA_TARGET_NODE:-$profile_target}
TCP_ADDRESS=${WV_NEBULA_TCP_ADDRESS:-$profile_tcp}
FALLBACK_HOST=${WV_NEBULA_FALLBACK_SSH_HOST:-}
PUBLIC_ADDRESS=${WV_NEBULA_PUBLIC_ADDRESS:-}
SKIP_FILE_TEST=${WV_NEBULA_SKIP_FILE_TEST:-0}
TCP_EXPECT=${WV_NEBULA_TCP_EXPECT:-HTTP/}

require_value() {
  value=$1
  name=$2
  [ -n "$value" ] || { echo "nebula acceptance: $name is required for $mode" >&2; exit 2; }
}

connectivity_json() {
  underlay=$1
  host=$2
  shift 2
  args=(connectivity check --json --underlay "$underlay" --ssh-host "$host" --timeout "${SSH_TIMEOUT}s")
  if [ "$#" -gt 0 ] && [ -n "$1" ]; then
    args+=(--overlay-address "$1")
  fi
  "$WV_BIN" "${args[@]}"
}

assert_connectivity_ready() {
  python3 -c '
import json, sys
value = json.load(sys.stdin)
required = ("ssh_config_resolved", "overlay_reachable", "ssh_reachable")
missing = [key for key in required if not value.get(key)]
if missing:
    raise SystemExit("connectivity checks failed: " + ", ".join(missing))
print("connectivity: ssh route ready")
'
}

assert_connectivity_down() {
  python3 -c '
import json, sys
value = json.load(sys.stdin)
if value.get("ssh_reachable") or value.get("overlay_reachable"):
    raise SystemExit("route remained reachable")
print("connectivity: route unavailable as expected")
'
}

assert_public_blocked() {
  address=$1
  python3 - "$address" "$SSH_TIMEOUT" <<'PY'
import socket, sys
address = sys.argv[1]
timeout = float(sys.argv[2])
if address.startswith("["):
    end = address.find("]")
    if end < 0 or end + 2 > len(address) or address[end + 1] != ":":
        raise SystemExit("invalid bracketed public address")
    host, port = address[1:end], int(address[end + 2:])
else:
    host, sep, raw_port = address.rpartition(":")
    if not sep or not host:
        raise SystemExit("public address must be HOST:PORT")
    port = int(raw_port)
try:
    connection = socket.create_connection((host, port), timeout=timeout)
except OSError:
    print("public SSH: blocked as expected")
    raise SystemExit(0)
connection.close()
raise SystemExit("public SSH endpoint unexpectedly accepted TCP")
PY
}

run_preflight() {
  require_value "$SSH_HOST" WV_NEBULA_SSH_HOST
  if [ -n "$PUBLIC_ADDRESS" ]; then
    assert_public_blocked "$PUBLIC_ADDRESS"
  else
    echo "public SSH: not checked (WV_NEBULA_PUBLIC_ADDRESS unset)"
  fi
  output=$(connectivity_json nebula "$SSH_HOST" "$OVERLAY_ADDRESS")
  printf '%s\n' "$output" | assert_connectivity_ready
  "$SSH_BIN" -o BatchMode=yes -o "ConnectTimeout=$SSH_TIMEOUT" -X "$SSH_HOST" true
  echo "ordinary SSH over Nebula: authenticated"
}

assert_registered_target() {
  target=$1
  python3 -c '
import json, sys
target = sys.argv[1]
value = json.load(sys.stdin)
for node in value.get("nodes", []):
    if node.get("id") == target and node.get("registered") is True:
        print("session API: signed target registered")
        raise SystemExit(0)
raise SystemExit("signed target node is not registered: " + target)
' "$target"
}

assert_route_available() {
  target=$1
  service=$2
  python3 -c '
import json, sys
target, service = sys.argv[1:3]
value = json.load(sys.stdin)
if value.get("target_node") != target:
    raise SystemExit("route resolved a different target")
if not value.get("available"):
    raise SystemExit("route is unavailable")
print("session API: %s route available" % service)
' "$target" "$service"
}

file_round_trip() {
  tmp=$(mktemp -d)
  source_file=$tmp/source.txt
  downloaded=$tmp/downloaded.txt
  remote_path=${WV_NEBULA_REMOTE_TEST_PATH:-/.weaverssh-nebula-acceptance-$$-${RANDOM}.txt}
  remote_ref=$TARGET_NODE:$remote_path
  printf 'weaverssh-nebula-acceptance pid=%s random=%s\n' "$$" "$RANDOM" > "$source_file"
  cleanup_file_test() {
    "$WV_BIN" rm "$remote_ref" >/dev/null 2>&1 || true
    rm -rf "$tmp"
  }
  trap cleanup_file_test RETURN
  "$WV_BIN" cp "$source_file" "$remote_ref"
  "$WV_BIN" cp "$remote_ref" "$downloaded"
  cmp "$source_file" "$downloaded"
  "$WV_BIN" rm "$remote_ref"
  rm -rf "$tmp"
  trap - RETURN
  echo "filesystem: upload/read/remove round-trip passed"
}

probe_tcp_service() {
  address=$1
  expect=$2
  python3 - "$WV_BIN" "$TARGET_NODE" "$address" "$expect" <<'PY'
import subprocess, sys
wv, target, address, expected = sys.argv[1:5]
request = b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
try:
    result = subprocess.run(
        [wv, "connect", "--timeout", "10s", target, address],
        input=request,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )
except subprocess.TimeoutExpired as error:
    raise SystemExit("authorized TCP probe timed out") from error
if result.returncode != 0:
    raise SystemExit(result.stderr.decode("utf-8", "replace") or "wv connect failed")
text = result.stdout.decode("utf-8", "replace")
if expected not in text:
    raise SystemExit("authorized TCP response did not contain expected marker: " + expected)
print("TCP service: authorized response received")
PY
}

run_session() {
  require_value "$TARGET_NODE" WV_NEBULA_TARGET_NODE
  describe=$($WV_BIN api --json describe)
  printf '%s\n' "$describe" | assert_registered_target "$TARGET_NODE"
  fs_route=$($WV_BIN api --json route "$TARGET_NODE" fs)
  printf '%s\n' "$fs_route" | assert_route_available "$TARGET_NODE" fs
  if [ "$SKIP_FILE_TEST" = 1 ]; then
    echo "filesystem: skipped by WV_NEBULA_SKIP_FILE_TEST=1"
  else
    file_round_trip
  fi
  if [ -n "$TCP_ADDRESS" ]; then
    tcp_route=$($WV_BIN api --json route "$TARGET_NODE" tcp)
    printf '%s\n' "$tcp_route" | assert_route_available "$TARGET_NODE" tcp
    probe_tcp_service "$TCP_ADDRESS" "$TCP_EXPECT"
  else
    echo "TCP service: not checked (no service in profile and WV_NEBULA_TCP_ADDRESS unset)"
  fi
}

run_outage() {
  require_value "$SSH_HOST" WV_NEBULA_SSH_HOST
  set +e
  output=$(connectivity_json nebula "$SSH_HOST" "$OVERLAY_ADDRESS" 2>/dev/null)
  code=$?
  set -e
  [ "$code" -ne 0 ] || { echo "nebula acceptance: connectivity unexpectedly succeeded during outage" >&2; exit 1; }
  [ -n "$output" ] || { echo "nebula acceptance: wv did not emit outage JSON" >&2; exit 1; }
  printf '%s\n' "$output" | assert_connectivity_down
}

run_fallback() {
  require_value "$FALLBACK_HOST" WV_NEBULA_FALLBACK_SSH_HOST
  output=$(connectivity_json ssh "$FALLBACK_HOST")
  printf '%s\n' "$output" | assert_connectivity_ready
  "$SSH_BIN" -o BatchMode=yes -o "ConnectTimeout=$SSH_TIMEOUT" -X "$FALLBACK_HOST" true
  echo "ordinary SSH fallback: authenticated"
}

case "$mode" in
  preflight) run_preflight ;;
  session) run_session ;;
  outage) run_outage ;;
  fallback) run_fallback ;;
  all)
    run_preflight
    run_session
    if [ -n "$FALLBACK_HOST" ]; then
      run_fallback
    else
      echo "ordinary SSH fallback: not checked (WV_NEBULA_FALLBACK_SSH_HOST unset)"
    fi
    ;;
esac
