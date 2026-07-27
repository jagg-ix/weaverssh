#!/bin/sh
set -eu

usage() {
  cat <<'USAGE'
Usage:
  wv-single-hop-example.sh prepare
  wv-single-hop-example.sh host
  wv-single-hop-example.sh attach-command

Environment:
  WV_BIN              wv executable (default: wv)
  WV_EXAMPLE_DIR      workspace (default: ~/.config/weaverssh/example)
  WV_LOCAL_NODE       signed local node ID (default: workstation-42)
  WV_REMOTE_NODE      signed remote node ID (default: compute-node)
  WV_REMOTE_HOST      SSH destination (default: user@compute-node)
  WV_LOCAL_ROOT       local exported root (default: ~/wv-share)
  WV_REMOTE_ROOT      remote exported root (default: ~/wv-share)
  WV_TCP_ALLOW        local final-node TCP allowlist
  WV_REMOTE_TCP_ALLOW remote final-node TCP allowlist
  WV_REMOTE_UDP_ALLOW remote final-node UDP allowlist
  RUN                 set to 1 to execute host; otherwise print the command

The prepare command creates an issuer key and signed local/remote contexts when
those files are absent. It never copies the issuer private key to the remote.

The remote host's sshd must accept the forwarded session identity: add
"AcceptEnv WVORIGIN WVHOP" under /etc/ssh/sshd_config.d/ and restart sshd, or pass
--wvorigin <local-node> to the printed attach command.
USAGE
}

quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\''/g")"
}

print_command() {
  first=1
  for arg do
    if [ "$first" -eq 0 ]; then printf ' '; fi
    quote "$arg"
    first=0
  done
  printf '\n'
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'missing required command: %s\n' "$1" >&2
    exit 2
  }
}

WV_BIN=${WV_BIN:-wv}
WV_EXAMPLE_DIR=${WV_EXAMPLE_DIR:-"$HOME/.config/weaverssh/example"}
WV_LOCAL_NODE=${WV_LOCAL_NODE:-workstation-42}
WV_REMOTE_NODE=${WV_REMOTE_NODE:-compute-node}
WV_REMOTE_HOST=${WV_REMOTE_HOST:-user@compute-node}
WV_LOCAL_ROOT=${WV_LOCAL_ROOT:-"$HOME/wv-share"}
WV_REMOTE_ROOT=${WV_REMOTE_ROOT:-"$HOME/wv-share"}
WV_TCP_ALLOW=${WV_TCP_ALLOW:-127.0.0.1:8080}
WV_REMOTE_TCP_ALLOW=${WV_REMOTE_TCP_ALLOW:-127.0.0.1:3000}
WV_REMOTE_UDP_ALLOW=${WV_REMOTE_UDP_ALLOW:-127.0.0.1:53}
RUN=${RUN:-0}

ISSUER_PRIVATE=$WV_EXAMPLE_DIR/issuer.key
ISSUER_PUBLIC=$WV_EXAMPLE_DIR/issuer.key.pub
LOCAL_CONTEXT=$WV_EXAMPLE_DIR/$WV_LOCAL_NODE.context.json
REMOTE_CONTEXT=$WV_EXAMPLE_DIR/$WV_REMOTE_NODE.context.json

cmd=${1:-}
case "$cmd" in
  prepare)
    require_command "$WV_BIN"
    install -d -m 0700 "$WV_EXAMPLE_DIR"
    if [ ! -f "$ISSUER_PRIVATE" ] || [ ! -f "$ISSUER_PUBLIC" ]; then
      "$WV_BIN" keygen --private "$ISSUER_PRIVATE" --public "$ISSUER_PUBLIC"
      chmod 0600 "$ISSUER_PRIVATE"
      chmod 0644 "$ISSUER_PUBLIC"
    fi
    "$WV_BIN" node-context sign-services \
      --nodes "$WV_LOCAL_NODE,$WV_REMOTE_NODE" \
      --node "$WV_LOCAL_NODE" \
      --capabilities node.context,vfs.mesh,socks.proxy \
      --private-key-file "$ISSUER_PRIVATE" \
      --out "$LOCAL_CONTEXT"
    "$WV_BIN" node-context sign-services \
      --nodes "$WV_LOCAL_NODE,$WV_REMOTE_NODE" \
      --node "$WV_REMOTE_NODE" \
      --capabilities node.context,vfs.mesh,socks.proxy \
      --private-key-file "$ISSUER_PRIVATE" \
      --out "$REMOTE_CONTEXT"
    printf 'prepared:\n  %s\n  %s\n  %s\n' "$ISSUER_PUBLIC" "$LOCAL_CONTEXT" "$REMOTE_CONTEXT"
    printf '\ncopy public material to the remote account:\n'
    print_command scp "$ISSUER_PUBLIC" "$REMOTE_CONTEXT" "$WV_REMOTE_HOST:~/.config/weaverssh/"
    ;;
  host)
    require_command "$WV_BIN"
    require_command ssh
    [ -f "$ISSUER_PUBLIC" ] || { printf 'missing %s; run prepare first\n' "$ISSUER_PUBLIC" >&2; exit 2; }
    [ -f "$LOCAL_CONTEXT" ] || { printf 'missing %s; run prepare first\n' "$LOCAL_CONTEXT" >&2; exit 2; }
    mkdir -p "$WV_LOCAL_ROOT"
    set -- "$WV_BIN" session-host \
      --root "$WV_LOCAL_ROOT" \
      --tcp-allow "$WV_TCP_ALLOW" \
      --node-context "$LOCAL_CONTEXT" \
      --public-key-file "$ISSUER_PUBLIC" \
      -- ssh -X "$WV_REMOTE_HOST"
    if [ "$RUN" = 1 ]; then
      exec "$@"
    fi
    printf 'plan only; run with RUN=1 to execute:\n'
    print_command "$@"
    ;;
  attach-command)
    remote_public='~/.config/weaverssh/issuer.key.pub'
    remote_context="~/.config/weaverssh/$WV_REMOTE_NODE.context.json"
    print_command "$WV_BIN" attach \
      --node-context "$remote_context" \
      --public-key-file "$remote_public" \
      --root "$WV_REMOTE_ROOT" \
      --tcp-allow "$WV_REMOTE_TCP_ALLOW" \
      --udp-allow "$WV_REMOTE_UDP_ALLOW"
    ;;
  -h|--help|help|'')
    usage
    ;;
  *)
    printf 'unknown command: %s\n' "$cmd" >&2
    usage >&2
    exit 2
    ;;
esac
