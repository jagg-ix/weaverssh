#!/usr/bin/env bash
set -euo pipefail

# One-shot local setup for OpenCV usable from both Python and Go (GoCV).
#
# What it does:
# 1) Installs native OpenCV toolchain via Homebrew (opencv, pkgconf, cmake)
# 2) Configures PKG_CONFIG_PATH for opencv4.pc in ~/.zshrc (idempotent)
# 3) Installs Python OpenCV binding (default: isolated venv)
# 4) Runs smoke checks:
#    - pkg-config opencv4
#    - python import cv2
#    - go run gocv minimal program
#
# Usage:
#   tools/verification/setup_opencv_python_go_local.sh
#
# Optional env vars:
#   INSTALL_BREW=1|0              (default 1)
#   APPLY_ZSHRC=1|0               (default 1)
#   ZSHRC_PATH=~/.zshrc           (default ~/.zshrc)
#   INSTALL_PYTHON_BINDING=1|0    (default 1)
#   PYTHON_BINDING_MODE=venv|user (default venv)
#   VENV_DIR=.venv-cv             (default repo_root/.venv-cv)
#   RUN_PYTHON_SMOKE=1|0          (default 1)
#   RUN_GO_SMOKE=1|0              (default 1)
#   PYTHON_BIN=python3            (default python3)
#   GO_BIN=go                     (default go)
#   GOCV_VERSION=latest           (default latest)

INSTALL_BREW="${INSTALL_BREW:-1}"
APPLY_ZSHRC="${APPLY_ZSHRC:-1}"
ZSHRC_PATH="${ZSHRC_PATH:-$HOME/.zshrc}"
INSTALL_PYTHON_BINDING="${INSTALL_PYTHON_BINDING:-1}"
PYTHON_BINDING_MODE="${PYTHON_BINDING_MODE:-venv}"
RUN_PYTHON_SMOKE="${RUN_PYTHON_SMOKE:-1}"
RUN_GO_SMOKE="${RUN_GO_SMOKE:-1}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
GO_BIN="${GO_BIN:-go}"
GOCV_VERSION="${GOCV_VERSION:-latest}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV_DIR="${VENV_DIR:-$REPO_ROOT/.venv-cv}"

START_MARKER="# >>> cat-ept opencv config >>>"
END_MARKER="# <<< cat-ept opencv config <<<"

log() { echo "[setup-opencv] $*"; }
err() { echo "[setup-opencv][error] $*" >&2; }

require_cmd() {
  local c="$1"
  command -v "$c" >/dev/null 2>&1 || {
    err "required command not found: $c"
    exit 1
  }
}

append_zshrc_block() {
  local rc_path="$1"
  local opencv_pkg_dir="$2"
  local tmp_file
  mkdir -p "$(dirname "$rc_path")"
  touch "$rc_path"
  tmp_file="$(mktemp)"
  awk -v s="$START_MARKER" -v e="$END_MARKER" '
    $0 == s { skip=1; next }
    $0 == e { skip=0; next }
    !skip { print }
  ' "$rc_path" > "$tmp_file"
  mv "$tmp_file" "$rc_path"
  {
    echo ""
    echo "$START_MARKER"
    echo "export PKG_CONFIG_PATH=\"$opencv_pkg_dir:\$PKG_CONFIG_PATH\""
    echo "$END_MARKER"
  } >> "$rc_path"
}

log "repo root: $REPO_ROOT"
log "python: $PYTHON_BIN"
log "go: $GO_BIN"

require_cmd "$PYTHON_BIN"
require_cmd "$GO_BIN"

if [[ "$INSTALL_BREW" == "1" ]]; then
  require_cmd brew
  log "installing/updating brew packages: opencv pkgconf cmake"
  brew install opencv pkgconf cmake
else
  log "INSTALL_BREW=0, skipping brew install"
fi

require_cmd pkg-config

OPENCV_PREFIX="$(brew --prefix opencv)"
OPENCV_PKGCONFIG_DIR="$OPENCV_PREFIX/lib/pkgconfig"

if [[ ! -d "$OPENCV_PKGCONFIG_DIR" ]]; then
  err "opencv pkgconfig directory not found: $OPENCV_PKGCONFIG_DIR"
  exit 1
fi

export PKG_CONFIG_PATH="$OPENCV_PKGCONFIG_DIR:${PKG_CONFIG_PATH:-}"
log "PKG_CONFIG_PATH now includes: $OPENCV_PKGCONFIG_DIR"

if [[ "$APPLY_ZSHRC" == "1" ]]; then
  append_zshrc_block "$ZSHRC_PATH" "$OPENCV_PKGCONFIG_DIR"
  log "updated $ZSHRC_PATH with opencv pkg-config path (idempotent block)"
else
  log "APPLY_ZSHRC=0, skipping zshrc update"
fi

log "verifying native OpenCV visibility via pkg-config"
pkg-config --modversion opencv4

if [[ "$INSTALL_PYTHON_BINDING" == "1" ]]; then
  if [[ "$PYTHON_BINDING_MODE" == "venv" ]]; then
    log "setting up Python venv at: $VENV_DIR"
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    # shellcheck disable=SC1090
    source "$VENV_DIR/bin/activate"
    python -m pip install -U pip numpy opencv-python
  elif [[ "$PYTHON_BINDING_MODE" == "user" ]]; then
    log "installing Python binding in user environment"
    "$PYTHON_BIN" -m pip install --user --break-system-packages -U pip numpy opencv-python
  else
    err "invalid PYTHON_BINDING_MODE=$PYTHON_BINDING_MODE (expected venv|user)"
    exit 1
  fi
else
  log "INSTALL_PYTHON_BINDING=0, skipping python package install"
fi

if [[ "$RUN_PYTHON_SMOKE" == "1" ]]; then
  log "running Python OpenCV smoke test"
  if [[ "$PYTHON_BINDING_MODE" == "venv" ]]; then
    # shellcheck disable=SC1090
    source "$VENV_DIR/bin/activate"
    python -c "import cv2,sys; print('cv2', cv2.__version__)"
  else
    "$PYTHON_BIN" -c "import cv2,sys; print('cv2', cv2.__version__)"
  fi
else
  log "RUN_PYTHON_SMOKE=0, skipping python smoke"
fi

if [[ "$RUN_GO_SMOKE" == "1" ]]; then
  log "running GoCV smoke test"
  GO_SMOKE_DIR="$(mktemp -d /tmp/gocv-smoke-XXXXXX)"
  trap 'rm -rf "$GO_SMOKE_DIR"' EXIT
  pushd "$GO_SMOKE_DIR" >/dev/null
  "$GO_BIN" mod init gocv-smoke >/dev/null 2>&1
  "$GO_BIN" get "gocv.io/x/gocv@${GOCV_VERSION}"
  cat > main.go <<'EOF'
package main

import (
	"fmt"
	"gocv.io/x/gocv"
)

func main() {
	fmt.Println("gocv", gocv.Version())
}
EOF
  "$GO_BIN" run .
  popd >/dev/null
  rm -rf "$GO_SMOKE_DIR"
  trap - EXIT
else
  log "RUN_GO_SMOKE=0, skipping Go smoke"
fi

log "done"
log "if shell was already open, reload env: source \"$ZSHRC_PATH\""
