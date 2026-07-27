#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
ACCEPTANCE="$ROOT/tools/verification/nebula_underlay_acceptance.sh"
TMP=$(mktemp -d)
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT HUP INT TERM
mkdir -p "$TMP/bin" "$TMP/state"

cat > "$TMP/bin/wv" <<'EOF_FAKE_WV'
#!/usr/bin/env bash
set -euo pipefail
state=${FAKE_WV_STATE:?}
command=${1:-}
shift || true
case "$command" in
  connectivity)
    host=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --ssh-host) host=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    if [ "$host" = outage-host ]; then
      printf '{"version":"weaverssh.connectivity.v1","underlay":"nebula","ssh_host":"outage-host","ssh_config_resolved":true,"overlay_reachable":false,"ssh_reachable":false,"weaverssh_checked":true,"weaverssh_ready":false,"checks":[]}\n'
      exit 1
    fi
    printf '{"version":"weaverssh.connectivity.v1","underlay":"nebula","ssh_host":"%s","resolved_host":"10.80.0.20","overlay_address":"10.80.0.20","ssh_config_resolved":true,"overlay_reachable":true,"ssh_reachable":true,"weaverssh_checked":true,"weaverssh_ready":true,"checks":[]}\n' "$host"
    ;;
  api)
    [ "${1:-}" = --json ] && shift
    method=${1:-}
    shift || true
    case "$method" in
      describe)
        printf '{"protocol":"weaverssh.session-api.v1","binding":"binding-test","current_node":"workstation","current_index":0,"topology":["workstation","dev-node-1"],"nodes":[{"id":"workstation","index":0,"registered":true},{"id":"dev-node-1","index":1,"registered":true,"services":["fs","tcp"]}],"features":[]}\n'
        ;;
      route)
        target=${1:-}
        service=${2:-}
        printf '{"target_node":"%s","target_index":1,"direction":"next","service":"%s","available":true,"uses_current_session":true}\n' "$target" "$service"
        ;;
      *) exit 2 ;;
    esac
    ;;
  cp)
    source_ref=$1
    destination_ref=$2
    if [[ "$source_ref" == *:* ]]; then
      cp "$state/remote" "$destination_ref"
    else
      cp "$source_ref" "$state/remote"
    fi
    ;;
  rm)
    rm -f "$state/remote"
    ;;
  connect)
    cat >/dev/null
    printf 'HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK'
    ;;
  *)
    echo "unexpected fake wv command: $command" >&2
    exit 2
    ;;
esac
EOF_FAKE_WV
chmod +x "$TMP/bin/wv"

cat > "$TMP/bin/ssh" <<'EOF_FAKE_SSH'
#!/bin/sh
exit 0
EOF_FAKE_SSH
chmod +x "$TMP/bin/ssh"

cat > "$TMP/profile.json" <<'EOF_PROFILE'
{
  "version": "weaverssh.workspace.v1",
  "target_node": "dev-node-1",
  "connection": {
    "type": "ssh",
    "ssh_host": "wv-dev-node",
    "underlay": "nebula"
  },
  "remote_root": "/workspace/project",
  "services": [
    {"name": "web", "node": "dev-node-1", "address": "127.0.0.1:3000"}
  ]
}
EOF_PROFILE

export PATH="$TMP/bin:$PATH"
export WV_BIN="$TMP/bin/wv"
export SSH_BIN="$TMP/bin/ssh"
export FAKE_WV_STATE="$TMP/state"
export WV_NEBULA_FALLBACK_SSH_HOST=public-fallback

bash "$ACCEPTANCE" --profile "$TMP/profile.json" all
WV_NEBULA_SSH_HOST=outage-host bash "$ACCEPTANCE" --profile "$TMP/profile.json" outage

printf 'nebula acceptance harness tests: ok\n'
