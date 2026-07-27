#!/bin/sh
set -eu

usage() {
  cat >&2 <<'USAGE'
usage: bootstrap-pki.sh --out-dir DIR --lighthouse-endpoint HOST:PORT [options]

Creates one offline Nebula CA and three host bundles:
  lighthouse-1       10.80.0.1/24    group lighthouse
  developer-laptop   10.80.0.10/24   group weaverssh-client
  dev-node-1         10.80.0.20/24   group weaverssh-node

Options:
  --nebula-cert PATH          nebula-cert executable (default: nebula-cert)
  --ca-name NAME              CA name (default: weaverssh-development)
  --lighthouse-name NAME      lighthouse certificate name
  --lighthouse-ip CIDR        lighthouse overlay address
  --client-name NAME          developer certificate name
  --client-ip CIDR            developer overlay address
  --node-name NAME            development-node certificate name
  --node-ip CIDR              development-node overlay address
  -h, --help                  show this help

The output directory must not already exist. The CA private key is written only
under offline-ca/. No binaries are downloaded and no service is started.
USAGE
}

out_dir=
endpoint=
nebula_cert=nebula-cert
ca_name=weaverssh-development
lighthouse_name=lighthouse-1
lighthouse_ip=10.80.0.1/24
client_name=developer-laptop
client_ip=10.80.0.10/24
node_name=dev-node-1
node_ip=10.80.0.20/24

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out-dir) [ "$#" -ge 2 ] || { usage; exit 2; }; out_dir=$2; shift 2 ;;
    --lighthouse-endpoint) [ "$#" -ge 2 ] || { usage; exit 2; }; endpoint=$2; shift 2 ;;
    --nebula-cert) [ "$#" -ge 2 ] || { usage; exit 2; }; nebula_cert=$2; shift 2 ;;
    --ca-name) [ "$#" -ge 2 ] || { usage; exit 2; }; ca_name=$2; shift 2 ;;
    --lighthouse-name) [ "$#" -ge 2 ] || { usage; exit 2; }; lighthouse_name=$2; shift 2 ;;
    --lighthouse-ip) [ "$#" -ge 2 ] || { usage; exit 2; }; lighthouse_ip=$2; shift 2 ;;
    --client-name) [ "$#" -ge 2 ] || { usage; exit 2; }; client_name=$2; shift 2 ;;
    --client-ip) [ "$#" -ge 2 ] || { usage; exit 2; }; client_ip=$2; shift 2 ;;
    --node-name) [ "$#" -ge 2 ] || { usage; exit 2; }; node_name=$2; shift 2 ;;
    --node-ip) [ "$#" -ge 2 ] || { usage; exit 2; }; node_ip=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "bootstrap-pki: unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[ -n "$out_dir" ] || { echo "bootstrap-pki: --out-dir is required" >&2; usage; exit 2; }
[ -n "$endpoint" ] || { echo "bootstrap-pki: --lighthouse-endpoint is required" >&2; usage; exit 2; }

safe_name() {
  case "$1" in
    ''|.|..|-*|*[!A-Za-z0-9._-]*) return 1 ;;
    *) return 0 ;;
  esac
}

safe_cidr() {
  case "$1" in
    *[!0-9A-Fa-f:./]*|'') return 1 ;;
    */*) return 0 ;;
    *) return 1 ;;
  esac
}

safe_endpoint() {
  case "$1" in
    *[!A-Za-z0-9._:\[\]-]*|'') return 1 ;;
    *:*) return 0 ;;
    *) return 1 ;;
  esac
}

safe_name "$ca_name" || { echo "bootstrap-pki: unsafe CA name" >&2; exit 2; }
safe_name "$lighthouse_name" || { echo "bootstrap-pki: unsafe lighthouse name" >&2; exit 2; }
safe_name "$client_name" || { echo "bootstrap-pki: unsafe client name" >&2; exit 2; }
safe_name "$node_name" || { echo "bootstrap-pki: unsafe node name" >&2; exit 2; }
[ "$lighthouse_name" != "$client_name" ] && [ "$lighthouse_name" != "$node_name" ] && [ "$client_name" != "$node_name" ] || {
  echo "bootstrap-pki: host certificate names must be distinct" >&2
  exit 2
}
for reserved_name in offline-ca manifest.txt DISTRIBUTION.txt; do
  [ "$lighthouse_name" != "$reserved_name" ] && [ "$client_name" != "$reserved_name" ] && [ "$node_name" != "$reserved_name" ] || {
    echo "bootstrap-pki: host name conflicts with reserved output: $reserved_name" >&2
    exit 2
  }
done
safe_cidr "$lighthouse_ip" || { echo "bootstrap-pki: invalid lighthouse CIDR" >&2; exit 2; }
safe_cidr "$client_ip" || { echo "bootstrap-pki: invalid client CIDR" >&2; exit 2; }
safe_cidr "$node_ip" || { echo "bootstrap-pki: invalid node CIDR" >&2; exit 2; }
[ "$lighthouse_ip" != "$client_ip" ] && [ "$lighthouse_ip" != "$node_ip" ] && [ "$client_ip" != "$node_ip" ] || {
  echo "bootstrap-pki: host overlay CIDRs must be distinct" >&2
  exit 2
}
safe_endpoint "$endpoint" || { echo "bootstrap-pki: invalid lighthouse endpoint" >&2; exit 2; }

if [ -e "$out_dir" ]; then
  echo "bootstrap-pki: output already exists: $out_dir" >&2
  exit 1
fi

if command -v "$nebula_cert" >/dev/null 2>&1; then
  nebula_cert_path=$(command -v "$nebula_cert")
elif [ -x "$nebula_cert" ]; then
  nebula_cert_path=$nebula_cert
else
  echo "bootstrap-pki: nebula-cert executable not found: $nebula_cert" >&2
  exit 1
fi

parent=$(dirname "$out_dir")
name=$(basename "$out_dir")
[ "$name" != "." ] && [ "$name" != "/" ] && [ -n "$name" ] || {
  echo "bootstrap-pki: unsafe output directory" >&2
  exit 2
}
mkdir -p "$parent"
stage=$(mktemp -d "$parent/.${name}.tmp.XXXXXX")
cleanup() {
  [ -z "${stage:-}" ] || rm -rf "$stage"
}
trap cleanup EXIT HUP INT TERM
umask 077

mkdir -p "$stage/offline-ca" "$stage/$lighthouse_name" "$stage/$client_name" "$stage/$node_name"

(
  cd "$stage/offline-ca"
  "$nebula_cert_path" ca -name "$ca_name"
  "$nebula_cert_path" sign -ca-crt ca.crt -ca-key ca.key -name "$lighthouse_name" -ip "$lighthouse_ip" -groups lighthouse
  "$nebula_cert_path" sign -ca-crt ca.crt -ca-key ca.key -name "$client_name" -ip "$client_ip" -groups weaverssh-client
  "$nebula_cert_path" sign -ca-crt ca.crt -ca-key ca.key -name "$node_name" -ip "$node_ip" -groups weaverssh-node
)

for required in \
  "$stage/offline-ca/ca.crt" \
  "$stage/offline-ca/ca.key" \
  "$stage/offline-ca/$lighthouse_name.crt" \
  "$stage/offline-ca/$lighthouse_name.key" \
  "$stage/offline-ca/$client_name.crt" \
  "$stage/offline-ca/$client_name.key" \
  "$stage/offline-ca/$node_name.crt" \
  "$stage/offline-ca/$node_name.key"; do
  [ -f "$required" ] || { echo "bootstrap-pki: nebula-cert did not create $required" >&2; exit 1; }
done

install_host_bundle() {
  host=$1
  cp "$stage/offline-ca/ca.crt" "$stage/$host/ca.crt"
  mv "$stage/offline-ca/$host.crt" "$stage/$host/host.crt"
  mv "$stage/offline-ca/$host.key" "$stage/$host/host.key"
  chmod 0644 "$stage/$host/ca.crt" "$stage/$host/host.crt"
  chmod 0600 "$stage/$host/host.key"
}

install_host_bundle "$lighthouse_name"
install_host_bundle "$client_name"
install_host_bundle "$node_name"
chmod 0600 "$stage/offline-ca/ca.key"
chmod 0644 "$stage/offline-ca/ca.crt"

lighthouse_overlay=${lighthouse_ip%/*}

cat > "$stage/$lighthouse_name/config.yaml" <<EOF_CONFIG
pki:
  ca: /etc/nebula/ca.crt
  cert: /etc/nebula/host.crt
  key: /etc/nebula/host.key

lighthouse:
  am_lighthouse: true

listen:
  host: 0.0.0.0
  port: 4242

firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: icmp
      host: any
EOF_CONFIG

write_member_config() {
  host=$1
  allow_ssh=$2
  cat > "$stage/$host/config.yaml" <<EOF_CONFIG
pki:
  ca: /etc/nebula/ca.crt
  cert: /etc/nebula/host.crt
  key: /etc/nebula/host.key

static_host_map:
  "$lighthouse_overlay":
    - "$endpoint"

lighthouse:
  am_lighthouse: false
  hosts:
    - "$lighthouse_overlay"

listen:
  host: 0.0.0.0
  port: 0

firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: icmp
      host: any
EOF_CONFIG
  if [ "$allow_ssh" = yes ]; then
    cat >> "$stage/$host/config.yaml" <<'EOF_CONFIG'
    - port: 22
      proto: tcp
      group: weaverssh-client
EOF_CONFIG
  fi
}

write_member_config "$client_name" no
write_member_config "$node_name" yes
chmod 0644 "$stage/$lighthouse_name/config.yaml" "$stage/$client_name/config.yaml" "$stage/$node_name/config.yaml"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo unavailable
  fi
}

nebula_version=$($nebula_cert_path -version 2>/dev/null || true)
cat > "$stage/manifest.txt" <<EOF_MANIFEST
format=weaverssh.nebula-bootstrap.v1
ca_name=$ca_name
lighthouse_name=$lighthouse_name
lighthouse_ip=$lighthouse_ip
lighthouse_endpoint=$endpoint
client_name=$client_name
client_ip=$client_ip
node_name=$node_name
node_ip=$node_ip
nebula_cert_version=$nebula_version
ca_crt_sha256=$(hash_file "$stage/offline-ca/ca.crt")
lighthouse_crt_sha256=$(hash_file "$stage/$lighthouse_name/host.crt")
client_crt_sha256=$(hash_file "$stage/$client_name/host.crt")
node_crt_sha256=$(hash_file "$stage/$node_name/host.crt")
EOF_MANIFEST
chmod 0644 "$stage/manifest.txt"

cat > "$stage/DISTRIBUTION.txt" <<EOF_DISTRIBUTION
Keep offline-ca/ca.key offline and do not copy it to the lighthouse or ordinary nodes.

Copy only each host directory's ca.crt, host.crt, host.key, and config.yaml to that
host. Install them under /etc/nebula with host.key mode 0600. The WeaverSSH node
context, SSH account, and endpoint policy remain separate credentials and controls.
EOF_DISTRIBUTION
chmod 0644 "$stage/DISTRIBUTION.txt"

# Verify that the CA private key exists only in the offline bundle.
ca_key_count=$(find "$stage" -type f -name ca.key | wc -l | tr -d ' ')
[ "$ca_key_count" = 1 ] || { echo "bootstrap-pki: CA private key escaped offline-ca" >&2; exit 1; }
[ -f "$stage/offline-ca/ca.key" ] || { echo "bootstrap-pki: offline CA private key missing" >&2; exit 1; }

mv "$stage" "$out_dir"
stage=
trap - EXIT HUP INT TERM
printf 'Nebula bootstrap bundle created at %s\n' "$out_dir"
printf 'Keep %s/offline-ca/ca.key offline.\n' "$out_dir"
