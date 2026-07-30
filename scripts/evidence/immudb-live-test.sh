#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
COMPOSE_FILE="$ROOT/deploy/evidence/docker-compose.immudb.yml"
COMPOSE=(docker compose -f "$COMPOSE_FILE")

cleanup() {
  if [[ "${WEAVERSSH_KEEP_EVIDENCE_STACK:-0}" != "1" ]]; then
    "${COMPOSE[@]}" down -v
  fi
}
trap cleanup EXIT

"${COMPOSE[@]}" up -d

GW_URL=${WEAVERSSH_IMMUGW_URL:-http://127.0.0.1:3323}
USER_B64=$(printf '%s' "${IMMUDB_USER:-immudb}" | base64 | tr -d '\n')
PASS_B64=$(printf '%s' "${IMMUDB_PASSWORD:-immudb}" | base64 | tr -d '\n')
LOGIN_BODY=$(printf '{"user":"%s","password":"%s"}' "$USER_B64" "$PASS_B64")

response=""
for _ in $(seq 1 60); do
  if response=$(curl -fsS -X POST "$GW_URL/v1/immurestproxy/login" -H 'Content-Type: application/json' --data "$LOGIN_BODY" 2>/dev/null); then
    break
  fi
  sleep 2
done
if [[ -z "$response" ]]; then
  "${COMPOSE[@]}" logs
  echo "immugw did not become ready" >&2
  exit 1
fi

WEAVERSSH_IMMUGW_TOKEN=$(python3 -c '
import json,sys
obj=json.load(sys.stdin)
def find(v):
    if isinstance(v,dict):
        for k,x in v.items():
            if k.lower() in {"token","jwt"} and isinstance(x,str): return x
            r=find(x)
            if r: return r
    if isinstance(v,list):
        for x in v:
            r=find(x)
            if r: return r
    return ""
t=find(obj)
if not t: raise SystemExit("login response did not contain a token")
print(t)
' <<<"$response")
export WEAVERSSH_IMMUGW_URL="$GW_URL" WEAVERSSH_IMMUGW_TOKEN

cd "$ROOT"
go test -tags=integration -count=1 -run '^TestLiveImmuDBAnchor$' ./evidencebinding
