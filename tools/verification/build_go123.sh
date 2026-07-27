#!/bin/sh
set -eu

GO_BIN=${GO_BIN:-go}
OUTPUT=${OUTPUT:-build/bin/wv-go1.23.2}
ARCHIVE_OUTPUT=${ARCHIVE_OUTPUT:-build/bin/wv-archive-go1.23.2}
FULL_TESTS=${GO123_FULL_TESTS:-0}
EXACT=${GO123_REQUIRE_EXACT:-0}
MQTTGRPC_E2E=${GO123_MQTTGRPC_E2E:-0}

fail() {
    printf '%s\n' "go123-build: $*" >&2
    exit 1
}

command -v "$GO_BIN" >/dev/null 2>&1 || fail "Go executable not found: $GO_BIN"
version=$($GO_BIN env GOVERSION)
case "$version" in
    go1.23.*) ;;
    *) fail "Go 1.23.2-compatible toolchain required; found $version" ;;
esac

patch=${version#go1.23.}
case "$patch" in
    ''|*[!0-9]*) fail "cannot parse Go patch version from $version" ;;
esac
[ "$patch" -ge 2 ] || fail "Go 1.23.2 or later in the 1.23 series is required; found $version"
if [ "$EXACT" = 1 ] && [ "$version" != go1.23.2 ]; then
    fail "exact Go 1.23.2 requested; found $version"
fi

module_go=$($GO_BIN list -m -f '{{.GoVersion}}')
[ "$module_go" = 1.23.2 ] || fail "root go.mod must declare go 1.23.2; found $module_go"

export GOTOOLCHAIN=local

$GO_BIN mod download
$GO_BIN list -m -f '{{if .GoVersion}}{{.Path}} {{.GoVersion}}{{end}}' all |
while IFS=' ' read -r module required; do
    [ -n "$module" ] || continue
    case "$required" in
        0.*|1.[0-9]|1.[0-9].*|1.1[0-9]|1.1[0-9].*|1.2[0-3]|1.2[0-3].*) ;;
        *) fail "module $module requires Go $required, above the Go 1.23 baseline" ;;
    esac
done

mkdir -p "$(dirname "$OUTPUT")" "$(dirname "$ARCHIVE_OUTPUT")"

$GO_BIN test -count=1 \
    ./mqttgrpc ./sessionmqttgrpc ./sessionmqttgrpcproof ./mqttgrpcengine \
    ./sessiontcp ./socketcontrol \
    ./regopolicy ./rules ./pubsub ./streampolicy \
    ./policyexec ./policystore ./storageadapter ./compliance ./evidencebinding \
    ./chronolayer ./chronoprovider ./chronoselect ./sessionchrono ./chronoipc ./chronopubsub \
    ./apicontract ./originruntime ./luksruntime ./sessionapi \
    ./archiveflow ./managedtransfer ./transferflow ./sessionevents ./filebackend ./vfscompose ./vfscrypt ./internal/vfscli ./internal/app \
    ./cmd/wv-archive
if [ "$MQTTGRPC_E2E" = 1 ]; then
    (cd tools/verification/go/mqttgrpc-e2e && GOTOOLCHAIN=local $GO_BIN test -count=1 -timeout 90s ./...)
fi
if [ "$FULL_TESTS" = 1 ]; then
    $GO_BIN test -count=1 ./...
fi

$GO_BIN build -trimpath -buildvcs=false -o "$OUTPUT" ./cmd/wv
$GO_BIN build -trimpath -buildvcs=false -o "$ARCHIVE_OUTPUT" ./cmd/wv-archive

for binary in "$OUTPUT" "$ARCHIVE_OUTPUT"; do
    built_with=$($GO_BIN version -m "$binary" | sed -n '1s/.*: //p')
    case "$built_with" in
        go1.23.*) ;;
        *) fail "built binary $binary reports unexpected toolchain: ${built_with:-unknown}" ;;
    esac
done

printf '%s\n' "go123-build: built $OUTPUT and $ARCHIVE_OUTPUT with $version"
