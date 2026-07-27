#!/bin/sh
# weaverssh installer - POSIX sh (Linux, macOS, FreeBSD, OpenBSD, NetBSD).
#
# Downloads the prebuilt `wv` binary for this OS/arch from the GitHub release,
# verifies its SHA-256 against the release checksums.txt, and installs it.
#
# Recommended:
#   curl -fsSL https://raw.githubusercontent.com/jagg-ix/weaverssh/main/install.sh | sh
#   wget -qO-  https://raw.githubusercontent.com/jagg-ix/weaverssh/main/install.sh | sh
#
# Pin a version or install dir:
#   curl -fsSL .../install.sh | WEAVERSSH_VERSION=v0.1.1 WEAVERSSH_BIN_DIR="$HOME/.local/bin" sh
#
# Offline install from a local archive:
#   WEAVERSSH_ARCHIVE=./weaverssh_0.1.1_linux_amd64.tar.gz sh install.sh
#
# Environment overrides:
#   WEAVERSSH_REPO       GitHub owner/repo    (default: jagg-ix/weaverssh)
#   WEAVERSSH_VERSION    release tag or latest (default: latest)
#   WEAVERSSH_BIN_DIR    install dir          (default: /usr/local/bin if writable,
#                        else $HOME/.local/bin)
#   WEAVERSSH_ARCHIVE    local path or URL to a release .tar.gz (skips discovery)
#   WEAVERSSH_CHECKSUM   sha256, or checksums file path/URL, for WEAVERSSH_ARCHIVE
#   WEAVERSSH_NO_VERIFY  set to 1 to skip checksum verification (not recommended)
#   WEAVERSSH_DRY_RUN    set to 1 to print install actions without writing
set -eu

REPO="${WEAVERSSH_REPO:-jagg-ix/weaverssh}"
VERSION="${WEAVERSSH_VERSION:-latest}"
ARCHIVE_SOURCE="${WEAVERSSH_ARCHIVE:-}"
CHECKSUM_SOURCE="${WEAVERSSH_CHECKSUM:-}"
NO_VERIFY="${WEAVERSSH_NO_VERIFY:-0}"
DRY_RUN="${WEAVERSSH_DRY_RUN:-0}"
BIN="wv"

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

run() {
  if [ "$DRY_RUN" = "1" ]; then
    printf 'dry-run:'; for a in "$@"; do printf ' %s' "$a"; done; printf '\n'
  else
    "$@"
  fi
}

fetch() { # fetch <url|path> <dst>
  src=$1; dst=$2
  case "$src" in
    http://*|https://*)
      if have curl; then curl -fsSL --retry 3 -o "$dst" "$src"
      elif have wget; then wget -qO "$dst" "$src"
      else return 1; fi ;;
    *) [ -f "$src" ] && cp "$src" "$dst" || return 1 ;;
  esac
}

fetch_stdout() { # print <url> body to stdout
  if have curl; then curl -fsSL --retry 3 "$1"
  elif have wget; then wget -qO- "$1"
  else return 1; fi
}

sha256_of() {
  if have sha256sum; then sha256sum "$1" | awk '{print $1}'
  elif have shasum; then shasum -a 256 "$1" | awk '{print $1}'
  elif have openssl; then openssl dgst -sha256 "$1" | awk '{print $NF}'
  else return 1; fi
}

# ---- detect platform ---------------------------------------------------------
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  linux|darwin|freebsd|openbsd|netbsd) ;;
  *) die "unsupported OS: $os (on native Windows use install.ps1)" ;;
esac
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  i386|i686)     arch=386 ;;
  ppc64le)       arch=ppc64le ;;
  s390x)         arch=s390x ;;
  riscv64)       arch=riscv64 ;;
  *) die "unsupported arch: $arch" ;;
esac
say "Platform: $os/$arch"

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# ---- resolve the release tag -------------------------------------------------
resolve_tag() {
  [ "$VERSION" != "latest" ] && { printf '%s\n' "$VERSION"; return 0; }
  # Prefer the API (exact tag); fall back to the releases/latest redirect.
  tag=$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
        | grep -m1 '"tag_name"' \
        | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
  [ -n "${tag:-}" ] && { printf '%s\n' "$tag"; return 0; }
  if have curl; then
    loc=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
          "https://github.com/$REPO/releases/latest" 2>/dev/null || true)
    case "$loc" in */releases/tag/*) printf '%s\n' "${loc##*/tag/}"; return 0 ;; esac
  fi
  return 1
}

# ---- verify + install --------------------------------------------------------
verify() { # verify <archive> <checksums url|path|sha256>
  archive=$1; sums=$2
  [ "$NO_VERIFY" = "1" ] && { warn "checksum verification skipped (WEAVERSSH_NO_VERIFY=1)"; return 0; }
  [ -n "$sums" ] || { warn "no checksum source; skipping verification"; return 0; }
  # A bare 64-hex value is the checksum itself.
  case "$sums" in
    [0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]*)
      if [ "$(printf %s "$sums" | wc -c | tr -d ' ')" = "64" ]; then want=$sums; fi ;;
  esac
  if [ -z "${want:-}" ]; then
    sumfile="$tmp/checksums.txt"
    fetch "$sums" "$sumfile" || { warn "could not fetch checksums; skipping verification"; return 0; }
    base=$(basename "$archive")
    want=$(awk -v b="$base" '$2==b || $2=="*"b {print $1; exit}' "$sumfile")
  fi
  [ -n "${want:-}" ] || die "no checksum entry for $(basename "$archive")"
  got=$(sha256_of "$archive") || die "need sha256sum, shasum, or openssl to verify"
  [ "$got" = "$want" ] || die "checksum mismatch for $(basename "$archive"): got $got want $want"
  say "Checksum verified"
}

install_archive() { # install_archive <archive url|path> <checksums url|path|sha256>
  arc="$tmp/$(basename "$1")"
  say "Downloading $(basename "$1")"
  fetch "$1" "$arc" || die "download failed: $1"
  verify "$arc" "$2"
  ( cd "$tmp" && tar -xzf "$arc" ) || die "extraction failed"
  [ -f "$tmp/$BIN" ] || die "archive did not contain $BIN"
}

if [ -n "$ARCHIVE_SOURCE" ]; then
  install_archive "$ARCHIVE_SOURCE" "$CHECKSUM_SOURCE"
else
  have curl || have wget || die "need curl or wget to download a release"
  tag=$(resolve_tag) || die "could not resolve latest version; set WEAVERSSH_VERSION=vX.Y.Z"
  ver="${tag#v}"
  base="https://github.com/$REPO/releases/download/$tag"
  say "Installing weaverssh $tag"
  install_archive "$base/weaverssh_${ver}_${os}_${arch}.tar.gz" "$base/checksums.txt"
fi

# ---- choose install dir + place binary ---------------------------------------
bindir="${WEAVERSSH_BIN_DIR:-}"
if [ -z "$bindir" ]; then
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then bindir=/usr/local/bin
  else bindir="$HOME/.local/bin"; fi
fi
run mkdir -p "$bindir"
if have install; then run install -m 0755 "$tmp/$BIN" "$bindir/$BIN"
else run cp "$tmp/$BIN" "$bindir/$BIN" && run chmod 0755 "$bindir/$BIN"; fi
say "Installed $bindir/$BIN"
[ "$DRY_RUN" = "1" ] || "$bindir/$BIN" version || true

case ":$PATH:" in
  *":$bindir:"*) ;;
  *) warn "$bindir is not on your PATH — add it:"; printf '   export PATH="%s:$PATH"\n' "$bindir" ;;
esac

missing=
for dep in ssh xauth; do have "$dep" || missing="$missing $dep"; done
[ -n "$missing" ] && warn "live sessions (wv session-host / wv attach) also need:$missing"
say "Done. Try: $BIN help"
