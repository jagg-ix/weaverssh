#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
WORKDIR=${WEAVERSSH_FABRIC_WORKDIR:-$ROOT/.cache/fabric-evidence}
FABRIC_VERSION=${FABRIC_VERSION:-2.5.16}
FABRIC_CA_VERSION=${FABRIC_CA_VERSION:-1.5.17}
SAMPLES="$WORKDIR/fabric-samples"
NETWORK="$SAMPLES/test-network"
BRIDGE_BIN="$WORKDIR/wv-fabric-anchor-bridge"
BRIDGE_ADDR=${WEAVERSSH_FABRIC_BRIDGE_ADDR:-127.0.0.1:8097}
BRIDGE_TOKEN=${WEAVERSSH_FABRIC_BRIDGE_TOKEN:-weaverssh-integration-token}

mkdir -p "$WORKDIR"
if [[ ! -x "$NETWORK/network.sh" || ! -x "$SAMPLES/bin/peer" ]]; then
  INSTALLER="$WORKDIR/install-fabric.sh"
  curl -fsSLo "$INSTALLER" "https://raw.githubusercontent.com/hyperledger/fabric/v${FABRIC_VERSION}/scripts/install-fabric.sh"
  chmod +x "$INSTALLER"
  (
    cd "$WORKDIR"
    "$INSTALLER" --fabric-version "$FABRIC_VERSION" --ca-version "$FABRIC_CA_VERSION" docker binary samples
  )
fi

bridge_pid=""
cleanup() {
  if [[ -n "$bridge_pid" ]]; then kill "$bridge_pid" 2>/dev/null || true; fi
  if [[ "${WEAVERSSH_KEEP_EVIDENCE_STACK:-0}" != "1" && -x "$NETWORK/network.sh" ]]; then
    (cd "$NETWORK" && ./network.sh down) || true
  fi
}
trap cleanup EXIT

cd "$NETWORK"
./network.sh down
./network.sh up createChannel -ca
./network.sh deployCC -ccn weaverssh-evidence -ccp "$ROOT/deploy/fabric/evidence-chaincode" -ccl go

export PATH="$SAMPLES/bin:$PATH"
export FABRIC_CFG_PATH="$SAMPLES/config"
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_TLS_ROOTCERT_FILE="$NETWORK/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
export CORE_PEER_MSPCONFIGPATH="$NETWORK/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
export CORE_PEER_ADDRESS=localhost:7051

cd "$ROOT"
go build -o "$BRIDGE_BIN" ./cmd/wv-fabric-anchor-bridge
"$BRIDGE_BIN" \
  --listen "$BRIDGE_ADDR" \
  --token "$BRIDGE_TOKEN" \
  --peer "$SAMPLES/bin/peer" \
  --orderer localhost:7050 \
  --orderer-ca "$NETWORK/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
  --peer-address localhost:7051 \
  --peer-tls-root "$CORE_PEER_TLS_ROOTCERT_FILE" \
  --wait-for-event 30s \
  --query-function ReadEvidenceAnchor \
  >"$WORKDIR/fabric-bridge.log" 2>&1 &
bridge_pid=$!

for _ in $(seq 1 60); do
  if curl -fsS "http://$BRIDGE_ADDR/healthz" >/dev/null 2>&1; then break; fi
  sleep 1
done
if ! curl -fsS "http://$BRIDGE_ADDR/healthz" >/dev/null; then
  cat "$WORKDIR/fabric-bridge.log" >&2
  echo "Fabric bridge did not become ready" >&2
  exit 1
fi

export WEAVERSSH_FABRIC_BRIDGE_URL="http://$BRIDGE_ADDR"
export WEAVERSSH_FABRIC_BRIDGE_TOKEN="$BRIDGE_TOKEN"
export WEAVERSSH_FABRIC_CHANNEL=mychannel
export WEAVERSSH_FABRIC_CHAINCODE=weaverssh-evidence
export WEAVERSSH_FABRIC_CONTRACT=EvidenceContract

go test -tags=integration -count=1 -run '^TestLiveFabricAnchor$' ./evidencebinding
