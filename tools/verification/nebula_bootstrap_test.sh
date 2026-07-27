#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
BOOTSTRAP="$ROOT/deploy/nebula/bootstrap-pki.sh"
TMP=$(mktemp -d)
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT HUP INT TERM

cat > "$TMP/nebula-cert" <<'EOF_FAKE'
#!/bin/sh
set -eu
if [ "${1:-}" = "-version" ]; then
  echo "Version: test"
  exit 0
fi
command=${1:-}
shift || true
case "$command" in
  ca)
    printf 'fake-ca-crt\n' > ca.crt
    printf 'fake-ca-key\n' > ca.key
    ;;
  sign)
    name=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -name) name=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    [ -n "$name" ] || exit 2
    printf 'fake-cert-%s\n' "$name" > "$name.crt"
    printf 'fake-key-%s\n' "$name" > "$name.key"
    ;;
  *)
    echo "unexpected fake nebula-cert command: $command" >&2
    exit 2
    ;;
esac
EOF_FAKE
chmod +x "$TMP/nebula-cert"

bundle="$TMP/bundle"
sh "$BOOTSTRAP" \
  --out-dir "$bundle" \
  --lighthouse-endpoint "lighthouse.example.test:4242" \
  --nebula-cert "$TMP/nebula-cert"

for path in \
  offline-ca/ca.crt offline-ca/ca.key \
  lighthouse-1/ca.crt lighthouse-1/host.crt lighthouse-1/host.key lighthouse-1/config.yaml \
  developer-laptop/ca.crt developer-laptop/host.crt developer-laptop/host.key developer-laptop/config.yaml \
  dev-node-1/ca.crt dev-node-1/host.crt dev-node-1/host.key dev-node-1/config.yaml \
  manifest.txt DISTRIBUTION.txt; do
  [ -f "$bundle/$path" ] || { echo "missing $path" >&2; exit 1; }
done

[ "$(find "$bundle" -type f -name ca.key | wc -l | tr -d ' ')" = 1 ]
[ ! -e "$bundle/lighthouse-1/ca.key" ]
[ ! -e "$bundle/developer-laptop/ca.key" ]
[ ! -e "$bundle/dev-node-1/ca.key" ]
grep -q 'group: weaverssh-client' "$bundle/dev-node-1/config.yaml"
grep -q 'lighthouse.example.test:4242' "$bundle/developer-laptop/config.yaml"
grep -q 'format=weaverssh.nebula-bootstrap.v1' "$bundle/manifest.txt"

file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

[ "$(file_mode "$bundle/offline-ca/ca.key")" = 600 ]
[ "$(file_mode "$bundle/dev-node-1/host.key")" = 600 ]

if sh "$BOOTSTRAP" --out-dir "$bundle" --lighthouse-endpoint "lighthouse.example.test:4242" --nebula-cert "$TMP/nebula-cert" >/dev/null 2>&1; then
  echo "bootstrap unexpectedly replaced an existing output directory" >&2
  exit 1
fi

if sh "$BOOTSTRAP" --out-dir "$TMP/unsafe" --lighthouse-endpoint "lighthouse.example.test:4242" --ca-name 'bad name' --nebula-cert "$TMP/nebula-cert" >/dev/null 2>&1; then
  echo "bootstrap unexpectedly accepted an unsafe CA name" >&2
  exit 1
fi

if sh "$BOOTSTRAP" --out-dir "$TMP/dot-host" --lighthouse-endpoint "lighthouse.example.test:4242" --client-name . --nebula-cert "$TMP/nebula-cert" >/dev/null 2>&1; then
  echo "bootstrap unexpectedly accepted a path-like host name" >&2
  exit 1
fi

printf 'nebula bootstrap tests: ok\n'
