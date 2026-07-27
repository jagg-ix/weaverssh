#!/bin/sh
set -eu

OPA_BIN=${OPA_BIN:-opa}
BUNDLE=
SOCKET=

usage() {
    cat >&2 <<'EOF'
usage: serve-local.sh --bundle PATH [--socket PATH] [--opa PATH]

Run an operator-installed Open Policy Agent server on a user-private Unix
socket. The script does not download OPA, expose a TCP listener, or modify
WeaverSSH credentials.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --bundle) [ "$#" -ge 2 ] || { usage; exit 2; }; BUNDLE=$2; shift 2 ;;
        --socket) [ "$#" -ge 2 ] || { usage; exit 2; }; SOCKET=$2; shift 2 ;;
        --opa) [ "$#" -ge 2 ] || { usage; exit 2; }; OPA_BIN=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf '%s\n' "serve-local.sh: unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

[ -n "$BUNDLE" ] || { usage; exit 2; }
[ -e "$BUNDLE" ] || { printf '%s\n' "serve-local.sh: bundle does not exist: $BUNDLE" >&2; exit 1; }
command -v "$OPA_BIN" >/dev/null 2>&1 || { printf '%s\n' "serve-local.sh: OPA executable not found: $OPA_BIN" >&2; exit 1; }

if [ -z "$SOCKET" ]; then
    if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
        SOCKET=$XDG_RUNTIME_DIR/weaverssh/opa.sock
    else
        identity=${USER:-local}
        SOCKET=${TMPDIR:-/tmp}/weaverssh-$identity/opa.sock
    fi
fi

case "$SOCKET" in
    /*) ;;
    *) printf '%s\n' "serve-local.sh: socket path must be absolute" >&2; exit 2 ;;
esac

parent=$(dirname "$SOCKET")
umask 077
mkdir -p "$parent"
chmod 700 "$parent"

if [ -e "$SOCKET" ]; then
    if [ -S "$SOCKET" ]; then
        rm -f "$SOCKET"
    else
        printf '%s\n' "serve-local.sh: refusing to replace non-socket path: $SOCKET" >&2
        exit 1
    fi
fi

cleanup() {
    [ ! -S "$SOCKET" ] || rm -f "$SOCKET"
}
trap cleanup EXIT HUP INT TERM

exec "$OPA_BIN" run \
    --server \
    --disable-telemetry \
    --addr="unix://$SOCKET" \
    --bundle "$BUNDLE"
