#!/bin/sh
set -eu

usage() {
  cat <<'USAGE'
Usage: install-manpage.sh [--prefix PREFIX] [--destdir DIR] [--man-dir DIR]

Install man/wv.1 without requiring a package manager.

Defaults:
  PREFIX=/usr/local
  DESTDIR=
  MAN_DIR=$PREFIX/share/man

Examples:
  sudo scripts/install-manpage.sh
  scripts/install-manpage.sh --prefix "$HOME/.local"
  scripts/install-manpage.sh --destdir "$PWD/pkgroot" --prefix /usr
USAGE
}

PREFIX=${PREFIX:-/usr/local}
DESTDIR=${DESTDIR:-}
MAN_DIR=${MAN_DIR:-}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix)
      [ "$#" -ge 2 ] || { printf '%s\n' '--prefix requires a value' >&2; exit 2; }
      PREFIX=$2
      shift 2
      ;;
    --destdir)
      [ "$#" -ge 2 ] || { printf '%s\n' '--destdir requires a value' >&2; exit 2; }
      DESTDIR=$2
      shift 2
      ;;
    --man-dir)
      [ "$#" -ge 2 ] || { printf '%s\n' '--man-dir requires a value' >&2; exit 2; }
      MAN_DIR=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
SOURCE=$REPO_ROOT/man/wv.1

[ -f "$SOURCE" ] || { printf 'missing manpage: %s\n' "$SOURCE" >&2; exit 1; }

if [ -z "$MAN_DIR" ]; then
  MAN_DIR=$PREFIX/share/man
fi

TARGET_DIR=$DESTDIR$MAN_DIR/man1
install -d "$TARGET_DIR"
install -m 0644 "$SOURCE" "$TARGET_DIR/wv.1"

if command -v mandb >/dev/null 2>&1 && [ -z "$DESTDIR" ]; then
  mandb -q "$MAN_DIR" 2>/dev/null || true
fi

printf 'installed %s\n' "$TARGET_DIR/wv.1"
printf 'view with: man -M %s wv\n' "$DESTDIR$MAN_DIR"
