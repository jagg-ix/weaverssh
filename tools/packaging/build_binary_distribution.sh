#!/bin/sh
# Build a binary-only weaverssh distribution archive.
# The resulting archive is self-contained for testing/installing wv and does not
# assume that a source checkout is present on the target machine.
set -eu
LC_ALL=C
LANG=C
COPYFILE_DISABLE=1
export LC_ALL LANG COPYFILE_DISABLE

usage() {
  cat <<'USAGE'
usage: build_binary_distribution.sh [options]

Options:
  --target GOOS/GOARCH[/vN]   Target platform. Default: current go env target.
  --version VERSION           Release version. Default: WEAVERSSH_VERSION or 0.1.0.
  --release RELEASE           Release number. Default: WEAVERSSH_RELEASE or 1.
  --binary PATH               Use an existing wv binary instead of building from source.
  --dist-dir DIR              Output artifact directory. Default: dist/binary.
  --build-dir DIR             Intermediate build directory. Default: build/binary-dist.
  --security-profile NAME     hardened, compat, or debug. Default: hardened.
  --source-date-epoch EPOCH   Fixed Unix epoch for reproducible metadata/archive timestamps.
  --sign                      Sign the archive; uses --sign-key or gpg.
  --sign-key PATH             OpenSSL private key for detached SHA-256 signature.
  --gpg-key KEYID             GPG key id for detached ASCII-armored signature.
  --go GO                     Go command to use. Default: go.
  -h, --help                  Show this help.

Outputs:
  <dist-dir>/weaverssh-VERSION-RELEASE-GOOS-GOARCH.tar.gz
  <dist-dir>/weaverssh-VERSION-RELEASE-GOOS-GOARCH.tar.gz.sha256
  <dist-dir>/weaverssh-VERSION-RELEASE-GOOS-GOARCH.tar.gz.provenance.json
  Optional signatures: .sig for OpenSSL or .asc for GPG.
USAGE
}

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

format_epoch() {
  if date -u -r "$1" '+%Y-%m-%dT%H:%M:%SZ' >/dev/null 2>&1; then
    date -u -r "$1" '+%Y-%m-%dT%H:%M:%SZ'
  else
    date -u -d "@$1" '+%Y-%m-%dT%H:%M:%SZ'
  fi
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)

version=${WEAVERSSH_VERSION:-0.1.0}
release=${WEAVERSSH_RELEASE:-1}
target=${WEAVERSSH_TARGET:-}
binary=${WEAVERSSH_BINARY:-}
dist_dir=${WEAVERSSH_BINARY_DIST_DIR:-$repo_root/dist/binary}
build_dir=${WEAVERSSH_BINARY_BUILD_DIR:-$repo_root/build/binary-dist}
security_profile=${SECURITY_PROFILE:-hardened}
source_date_epoch=${SOURCE_DATE_EPOCH:-}
go_cmd=${GO:-go}
sign=false
sign_key=
gpg_key=

while [ "$#" -gt 0 ]; do
  case "$1" in
    --target) target=${2:?missing --target value}; shift 2 ;;
    --version) version=${2:?missing --version value}; shift 2 ;;
    --release) release=${2:?missing --release value}; shift 2 ;;
    --binary) binary=${2:?missing --binary value}; shift 2 ;;
    --dist-dir) dist_dir=${2:?missing --dist-dir value}; shift 2 ;;
    --build-dir) build_dir=${2:?missing --build-dir value}; shift 2 ;;
    --security-profile) security_profile=${2:?missing --security-profile value}; shift 2 ;;
    --source-date-epoch) source_date_epoch=${2:?missing --source-date-epoch value}; shift 2 ;;
    --sign) sign=true; shift ;;
    --sign-key) sign=true; sign_key=${2:?missing --sign-key value}; shift 2 ;;
    --gpg-key) sign=true; gpg_key=${2:?missing --gpg-key value}; shift 2 ;;
    --go) go_cmd=${2:?missing --go value}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

case "$security_profile" in hardened|compat|debug) ;; *) die "unsupported --security-profile: $security_profile" ;; esac
have "$go_cmd" || die "go command not found: $go_cmd"

if [ -z "$target" ]; then
  target="$($go_cmd env GOOS)/$($go_cmd env GOARCH)"
fi

old_ifs=$IFS
IFS=/
set -- $target
IFS=$old_ifs
goos=${1:-}
goarch=${2:-}
goarm_raw=${3:-}
[ -n "$goos" ] && [ -n "$goarch" ] || die "target must be GOOS/GOARCH or GOOS/GOARCH/vN: $target"
goarm=
if [ -n "$goarm_raw" ]; then
  case "$goarm_raw" in v*) goarm=${goarm_raw#v} ;; *) die "third target component must be vN for ARM: $target" ;; esac
fi
label_arch=$goarch
if [ "$goarch" = "arm" ] && [ -n "$goarm" ]; then
  label_arch="armv$goarm"
fi
target_label="$goos-$label_arch"
case "$goos" in windows) bin_name=wv.exe ;; *) bin_name=wv ;; esac

safe_version=$(printf '%s' "$version" | tr ' /+' '...')
safe_release=$(printf '%s' "$release" | tr ' /+' '...')
pkg="weaverssh-$safe_version-$safe_release-$target_label"
work_root="$build_dir/$pkg.work.$$"
stage="$work_root/$pkg"
built_binary="$build_dir/$target_label/$bin_name"
archive="$dist_dir/$pkg.tar.gz"
provenance="$archive.provenance.json"

mkdir -p "$dist_dir" "$build_dir/$target_label" "$stage/bin" "$stage/docs" "$stage/scripts"

commit="unknown"
if have git && git -C "$repo_root" rev-parse --short=12 HEAD >/dev/null 2>&1; then
  commit=$(git -C "$repo_root" rev-parse --short=12 HEAD)
fi
dirty=false
if have git && git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if ! git -C "$repo_root" diff --quiet --ignore-submodules -- 2>/dev/null || ! git -C "$repo_root" diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
    dirty=true
  fi
fi
if [ -z "$source_date_epoch" ]; then
  if [ "$dirty" = "false" ] && have git && git -C "$repo_root" show -s --format=%ct HEAD >/dev/null 2>&1; then
    source_date_epoch=$(git -C "$repo_root" show -s --format=%ct HEAD)
  else
    source_date_epoch=$(date -u '+%s')
  fi
fi
case "$source_date_epoch" in ''|*[!0-9]*) die "--source-date-epoch must be Unix epoch seconds" ;; esac
built_at=$(format_epoch "$source_date_epoch")
go_version=$($go_cmd version 2>/dev/null || printf 'unknown')
go_toolchain=$($go_cmd env GOVERSION 2>/dev/null || printf 'unknown')

version_ldflags="-X main.buildVersion=$safe_version -X main.buildRelease=$safe_release -X main.buildCommit=$commit -X main.buildDirty=$dirty -X main.buildDate=$built_at -X main.buildTarget=$target"
pie=false
case "$target" in
  linux/amd64|linux/arm64|linux/ppc64le|darwin/amd64|darwin/arm64|windows/386|windows/amd64|windows/arm64) pie=true ;;
esac
pie_enabled=false
if [ "$security_profile" = "hardened" ] && [ "$pie" = "true" ]; then
  pie_enabled=true
fi

external_binary=false
metadata_injected=true
if [ -n "$binary" ]; then
  external_binary=true
  metadata_injected=false
  [ -f "$binary" ] || die "--binary not found: $binary"
  say "using existing binary: $binary"
  cp "$binary" "$stage/bin/$bin_name"
else
  say "building $target_label wv binary"
  (
    cd "$repo_root"
    if [ -n "$goarm" ]; then
      export GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0
    else
      export GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0
      unset GOARM
    fi
    if [ "$security_profile" = "debug" ]; then
      "$go_cmd" build -ldflags "$version_ldflags" -o "$built_binary" ./cmd/wv
    elif [ "$pie_enabled" = "true" ]; then
      "$go_cmd" build -trimpath -buildvcs=false -ldflags "-s -w $version_ldflags" -buildmode=pie -o "$built_binary" ./cmd/wv
    else
      "$go_cmd" build -trimpath -buildvcs=false -ldflags "-s -w $version_ldflags" -o "$built_binary" ./cmd/wv
    fi
  )
  cp "$built_binary" "$stage/bin/$bin_name"
fi
chmod 0755 "$stage/bin/$bin_name"

# macOS can attach com.apple.* extended attributes to newly built binaries.
# Strip them before checksums/tar creation so Linux extraction is warning-free.
if have xattr; then
  xattr -cr "$stage" 2>/dev/null || true
fi

sha_file() {
  if have openssl; then
    openssl dgst -sha256 -r "$1" | awk '{print $1}'
  elif have sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  elif have shasum; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "need openssl, sha256sum, or shasum"
  fi
}

write_stage_checksums() {
  : > "$stage/CHECKSUMS.txt"
  find "$stage" -type f ! -name CHECKSUMS.txt | LC_ALL=C sort | while IFS= read -r file; do
    rel=${file#"$stage/"}
    printf '%s  %s\n' "$(sha_file "$file")" "$rel"
  done > "$stage/CHECKSUMS.txt"
}

bin_sha=$(sha_file "$stage/bin/$bin_name")

cat > "$stage/README.md" <<README
# weaverssh Binary Distribution

This archive is a binary-only weaverssh distribution for $target_label.
It does not require a source checkout to test or install.

## Contents

- bin/$bin_name: unified weaverssh CLI binary
- scripts/install.sh: local user-home installer
- scripts/smoke-test.sh: source-free smoke test
- scripts/verify.sh: archive verification helper
- MANIFEST.json: build and checksum metadata
- SECURITY.json: cybersecurity/reproducibility metadata
- CHECKSUMS.txt: SHA-256 checksums for archive contents

## Verify Before Installing

From a machine with the archive and sidecar checksum:

\`\`\`sh
scripts/verify.sh --archive ../$pkg.tar.gz --checksum ../$pkg.tar.gz.sha256 --smoke
\`\`\`

## Test Without Installing

From the extracted archive root:

\`\`\`sh
scripts/smoke-test.sh
\`\`\`

## Install For The Current User

\`\`\`sh
scripts/install.sh
\`\`\`

The packaged installer is source-free. It verifies `CHECKSUMS.txt`, copies `wv`,
writes `~/.weaverssh/env.sh`, and appends an install record to
`~/.weaverssh/logs/install.jsonl`.

By default it writes to `\$HOME/.weaverssh/bin`. Override with:

\`\`\`sh
WEAVERSSH_BIN_DIR=\$HOME/.local/bin scripts/install.sh
\`\`\`

For an explicit system install:

\`\`\`sh
WEAVERSSH_INSTALL_SCOPE=system scripts/install.sh
\`\`\`

Preview without writing:

\`\`\`sh
WEAVERSSH_DRY_RUN=1 scripts/install.sh
\`\`\`
README

cat > "$stage/scripts/install.sh" <<'INSTALL'
#!/bin/sh
# Source-free installer included inside a weaverssh binary distribution archive.
set -eu

say()  { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

run() {
  if [ "${WEAVERSSH_DRY_RUN:-0}" = "1" ]; then
    printf 'dry-run:'
    for arg in "$@"; do printf ' %s' "$arg"; done
    printf '\n'
  else
    "$@"
  fi
}

sha256_file() {
  file=$1
  if have openssl; then openssl dgst -sha256 -r "$file" | awk '{print $1}'
  elif have sha256sum; then sha256sum "$file" | awk '{print $1}'
  elif have shasum; then shasum -a 256 "$file" | awk '{print $1}'
  else die "need openssl, sha256sum, or shasum for checksum verification"
  fi
}

verify_embedded_checksum() {
  rel=$1
  src=$2
  sums="$root/CHECKSUMS.txt"
  [ -f "$sums" ] || { warn "CHECKSUMS.txt not found; skipping embedded checksum verification"; return 0; }
  want=$(awk -v rel="$rel" '($2 == rel || $2 == "*" rel) {print $1; exit}' "$sums")
  [ -n "$want" ] || die "CHECKSUMS.txt does not contain $rel"
  got=$(sha256_file "$src")
  [ "$got" = "$want" ] || die "checksum mismatch for $rel: got $got want $want"
  say "Checksum verified: $rel"
}

install_file() {
  src=$1
  dst=$2
  if have install; then
    run install -m 0755 "$src" "$dst"
  else
    run cp "$src" "$dst"
    run chmod 0755 "$dst"
  fi
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
case "$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]')" in
  mingw*|msys*|cygwin*) bin_name=wv.exe ;;
  *) bin_name=wv ;;
esac

src="$root/bin/$bin_name"
rel="bin/$bin_name"
if [ ! -x "$src" ]; then
  if [ -x "$root/bin/wv" ]; then
    src="$root/bin/wv"
    bin_name=wv
    rel="bin/wv"
  else
    die "missing binary under $root/bin"
  fi
fi
verify_embedded_checksum "$rel" "$src"

scope=${WEAVERSSH_INSTALL_SCOPE:-home}
bindir=${WEAVERSSH_BIN_DIR:-}
if [ -z "$bindir" ]; then
  case "$scope" in
    home) bindir="$HOME/.weaverssh/bin" ;;
    system) bindir="/usr/local/bin" ;;
    auto)
      if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then bindir="/usr/local/bin"; else bindir="$HOME/.weaverssh/bin"; fi
      ;;
    *) die "unsupported WEAVERSSH_INSTALL_SCOPE=$scope (use home, system, or auto)" ;;
  esac
fi
if [ "$scope" = "system" ] && [ ! -w "$(dirname "$bindir")" ]; then
  warn "system install selected; $bindir may require elevated privileges"
fi

home_root="$HOME/.weaverssh"
log_file=${WEAVERSSH_INSTALL_LOG:-$home_root/logs/install.jsonl}
run mkdir -p "$bindir"
if [ "${WEAVERSSH_DRY_RUN:-0}" != "1" ]; then
  mkdir -p "$home_root/logs"
fi

install_file "$src" "$bindir/$bin_name"
if [ "${WEAVERSSH_DRY_RUN:-0}" != "1" ]; then
  mkdir -p "$home_root"
  printf 'export PATH="%s:$PATH"\n' "$bindir" > "$home_root/env.sh"
fi

printf 'installed: %s\n' "$bindir/$bin_name"
if [ "${WEAVERSSH_DRY_RUN:-0}" != "1" ] && [ -x "$bindir/$bin_name" ]; then
  "$bindir/$bin_name" version || true
fi
case ":$PATH:" in
  *":$bindir:"*) ;;
  *) printf 'PATH note: export PATH="%s:$PATH"\n' "$bindir"; printf 'PATH note: . "%s/env.sh"\n' "$home_root" ;;
esac

if [ "${WEAVERSSH_DRY_RUN:-0}" != "1" ]; then
  ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date)
  printf '{"event":"install","at":"%s","bindir":"%s","source":"binary-distribution:%s"}\n' "$(json_escape "$ts")" "$(json_escape "$bindir")" "$(json_escape "$(basename "$root")")" >> "$log_file"
fi
printf 'install log: %s\n' "$log_file"
INSTALL

cat > "$stage/scripts/smoke-test.sh" <<'SMOKE'
#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
case "$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]')" in
  mingw*|msys*|cygwin*) bin_name=wv.exe ;;
  *) bin_name=wv ;;
esac
wv="$root/bin/$bin_name"
if [ ! -x "$wv" ]; then
  if [ -x "$root/bin/wv" ]; then wv="$root/bin/wv"; else echo "missing executable wv under $root/bin" >&2; exit 1; fi
fi
tmp=${TMPDIR:-/tmp}/weaverssh-binary-smoke-$$
mkdir -p "$tmp/home"
trap 'rm -rf "$tmp"' EXIT
printf 'smoke: binary=%s\n' "$wv"
"$wv" version >/dev/null
"$wv" help >/dev/null
"$wv" deps status --home-prefix "$tmp/home" --log-file "$tmp/deps.jsonl" >/dev/null
[ -s "$tmp/deps.jsonl" ] || { echo "deps status did not write log" >&2; exit 1; }
printf 'smoke: ok\n'
SMOKE

cp "$repo_root/tools/packaging/verify_binary_distribution.sh" "$stage/scripts/verify.sh"
chmod 0755 "$stage/scripts/install.sh" "$stage/scripts/smoke-test.sh" "$stage/scripts/verify.sh"

cat > "$stage/MANIFEST.json" <<MANIFEST
{
  "name": "weaverssh",
  "version": "$safe_version",
  "release": "$safe_release",
  "target": "$target",
  "target_label": "$target_label",
  "binary": "bin/$bin_name",
  "binary_sha256": "$bin_sha",
  "checksum_algorithm": "sha256",
  "source_commit": "$commit",
  "source_dirty": $dirty,
  "source_date_epoch": $source_date_epoch,
  "built_at": "$built_at",
  "source_required_to_test": false,
  "source_required_to_install": false,
  "default_install_prefix": "\$HOME/.weaverssh/bin"
}
MANIFEST

cat > "$stage/SECURITY.json" <<SECURITY
{
  "schema": "weaverssh.binary.security.v1",
  "checksum_algorithm": "sha256",
  "binary_sha256": "$bin_sha",
  "build": {
    "security_profile": "$security_profile",
    "reproducible_archive": true,
    "source_date_epoch": $source_date_epoch,
    "built_at": "$built_at",
    "target": "$target",
    "go_version": "$(json_escape "$go_version")",
    "go_toolchain": "$(json_escape "$go_toolchain")",
    "cgo_enabled": false,
    "pie_enabled": $pie_enabled,
    "trimpath": true,
    "buildvcs": false,
    "stripped": true,
    "external_binary_input": $external_binary,
    "ldflags_version_metadata_injected": $metadata_injected,
    "deterministic_tar_gzip": true,
    "normalized_uid_gid": true,
    "normalized_mtime": true,
    "macos_xattrs_stripped": true
  },
  "verification": {
    "checksum_file": "CHECKSUMS.txt",
    "archive_checksum_sidecar": "$(basename "$archive").sha256",
    "verify_script": "scripts/verify.sh"
  },
  "signing": {
    "supported": true,
    "openssl_detached_signature": "$(basename "$archive").sig",
    "gpg_detached_signature": "$(basename "$archive").asc"
  }
}
SECURITY

write_stage_checksums

say "creating $archive"
"$go_cmd" run ./tools/packaging/reprotar --source "$stage" --root "$pkg" --output "$archive" --epoch "$source_date_epoch"
archive_sha=$(sha_file "$archive")
printf '%s  %s\n' "$archive_sha" "$(basename "$archive")" > "$archive.sha256"

signature_entries=""
if [ "$sign" = "true" ]; then
  if [ -n "$sign_key" ]; then
    have openssl || die "openssl is required for --sign-key"
    sig="$archive.sig"
    openssl dgst -sha256 -sign "$sign_key" -out "$sig" "$archive"
    sig_sha=$(sha_file "$sig")
    signature_entries="{\"type\":\"openssl-dgst-sha256\",\"path\":\"$(basename "$sig")\",\"sha256\":\"$sig_sha\",\"verify\":\"openssl dgst -sha256 -verify PUBLIC_KEY.pem -signature $(basename "$sig") $(basename "$archive")\"}"
  else
    have gpg || die "gpg is required for --sign without --sign-key"
    sig="$archive.asc"
    if [ -n "$gpg_key" ]; then
      gpg --batch --yes --armor --local-user "$gpg_key" --detach-sign --output "$sig" "$archive"
    else
      gpg --batch --yes --armor --detach-sign --output "$sig" "$archive"
    fi
    sig_sha=$(sha_file "$sig")
    signature_entries="{\"type\":\"gpg-detached-armored\",\"path\":\"$(basename "$sig")\",\"sha256\":\"$sig_sha\",\"verify\":\"gpg --verify $(basename "$sig") $(basename "$archive")\"}"
  fi
fi
signatures_json="[]"
if [ -n "$signature_entries" ]; then
  signatures_json="[$signature_entries]"
fi

cat > "$provenance" <<PROVENANCE
{
  "schema": "weaverssh.binary.provenance.v1",
  "name": "weaverssh",
  "version": "$safe_version",
  "release": "$safe_release",
  "target": "$target",
  "archive": "$(basename "$archive")",
  "archive_sha256": "$archive_sha",
  "checksum_sidecar": "$(basename "$archive").sha256",
  "binary": "bin/$bin_name",
  "binary_sha256": "$bin_sha",
  "source_commit": "$commit",
  "source_dirty": $dirty,
  "source_date_epoch": $source_date_epoch,
  "built_at": "$built_at",
  "security_profile": "$security_profile",
  "reproducible_archive": true,
  "signatures": $signatures_json,
  "verify": [
    "sha256sum -c $(basename "$archive").sha256",
    "tools/packaging/verify_binary_distribution.sh --archive $(basename "$archive") --checksum $(basename "$archive").sha256 --smoke"
  ]
}
PROVENANCE
printf '%s  %s\n' "$(sha_file "$provenance")" "$(basename "$provenance")" > "$provenance.sha256"

printf '{\n'
printf '  "ok": true,\n'
printf '  "archive": "%s",\n' "$archive"
printf '  "checksum": "%s",\n' "$archive.sha256"
printf '  "provenance": "%s",\n' "$provenance"
printf '  "package_root": "%s",\n' "$pkg"
printf '  "target": "%s",\n' "$target"
printf '  "source_date_epoch": %s,\n' "$source_date_epoch"
printf '  "source_required_to_test": false\n'
printf '}\n'
