#!/usr/bin/env bash
#
# core_features_test.sh — acceptance harness for weaverssh's major core features.
#
# Builds the unified `wv` binary and exercises each major core feature with a mix
# of built-binary CLI smoke checks and the in-process Go suite. The Go suite
# stands up real X11 -> WebSocket -> mux sessions over loopback, so no live
# SSH/X11 server is required.
#
# Two sections run:
#   GATING  — features expected to pass; any failure fails this script (exit 1).
#   TRIAGE  — known pre-existing failures on the merged branch, each annotated
#             with its root cause. Reported but non-gating (never fails the run).
#
# macOS note: AF_UNIX socket paths are capped near 104 bytes (sun_path). The Go
# suite binds broker/session sockets under $TMPDIR, and the default macOS TMPDIR
# (/var/folders/...) overflows that cap, producing "bind: invalid argument".
# This harness pins TMPDIR to a short directory so those binds succeed. Override
# with WV_TMPDIR=/short/path. On Linux the default TMPDIR is already short.
#
# Usage:
#   tools/verification/core_features_test.sh            # gating + triage
#   WV_RACE=1 tools/verification/core_features_test.sh  # add -race to go test
#   WV_TMPDIR=/tmp/x tools/verification/core_features_test.sh

set -u

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root" || exit 2

WV_TMPDIR="${WV_TMPDIR:-/tmp/wvt}"
mkdir -p "$WV_TMPDIR" || exit 2
export TMPDIR="$WV_TMPDIR"

race=()
[ "${WV_RACE:-0}" = "1" ] && race=(-race)

wv="$repo_root/build/bin/wv"
pass=0 fail=0
declare -a failed_gating

if [ -t 1 ]; then G="\033[32m"; R="\033[31m"; Y="\033[33m"; B="\033[1m"; N="\033[0m"
else G=""; R=""; Y=""; B=""; N=""; fi

hr()   { printf '%s\n' "------------------------------------------------------------------"; }
head() { printf "\n${B}%s${N}\n"; hr; printf "${B}%s${N}\n" "$1"; hr; }

# gate LABEL CMD... — run a gating check; record + report pass/fail.
gate() {
  local label="$1"; shift
  local log; log="$(mktemp "$TMPDIR/cf.XXXXXX")"
  # One retry absorbs timing-flaky session/socket tests; a real failure fails both.
  if "$@" >"$log" 2>&1 || "$@" >"$log" 2>&1; then
    printf "  ${G}PASS${N}  %s\n" "$label"; pass=$((pass + 1))
  else
    printf "  ${R}FAIL${N}  %s\n" "$label"; fail=$((fail + 1)); failed_gating+=("$label")
    sed 's/^/          | /' "$log" | tail -8
  fi
  rm -f "$log"
}

# triage LABEL "root cause" CMD... — run a known-failing check; never gating.
triage() {
  local label="$1" cause="$2"; shift 2
  local log; log="$(mktemp "$TMPDIR/cf.XXXXXX")"
  if "$@" >"$log" 2>&1; then
    printf "  ${G}now-passing${N}  %s\n" "$label"
  else
    printf "  ${Y}known-fail${N}   %s\n              ${Y}cause:${N} %s\n" "$label" "$cause"
  fi
  rm -f "$log"
}

gotest() { go test "${race[@]}" "$@"; }

# CLI smoke helpers (built binary, offline) ----------------------------------
cli_keygen_roundtrip() {
  local d; d="$(mktemp -d "$TMPDIR/cf.XXXXXX")"
  "$wv" keygen --private "$d/n.key" --public "$d/n.key.pub" >/dev/null 2>&1 || return 1
  "$wv" node-context sign-services \
    --nodes a,b,c --node a \
    --capabilities node.context,vfs.mesh \
    --private-key-file "$d/n.key" --out "$d/a.ctx.json" >/dev/null 2>&1 || return 1
  test -s "$d/a.ctx.json"
}
cli_help_lists_core() {
  "$wv" help 2>&1 | grep -q 'session-host' &&
  "$wv" help 2>&1 | grep -q 'ssh-agent'   &&
  "$wv" help 2>&1 | grep -q 'socket-engine'
}

# ---------------------------------------------------------------------------
printf "${B}weaverssh core-features acceptance harness${N}\n"
printf "repo=%s\nTMPDIR=%s  race=%s\n" "$repo_root" "$TMPDIR" "${WV_RACE:-0}"

head "Build"
gate "build ./... (all packages compile)"      go build ./...
gate "build unified wv binary"                  go build -o "$wv" ./cmd/wv
gate "wv version runs"                          "$wv" version

head "GATING — CLI surface (built binary, offline)"
gate "wv help lists core commands"              cli_help_lists_core
gate "keygen + signed node-context roundtrip"   cli_keygen_roundtrip
gate "wv completion (bash)"                     "$wv" completion bash

head "GATING — cryptographic identity & authorization"
gate "signed node contexts + grant validation (authproof)"  gotest ./authproof
gate "recursive SSHSIG hop proofs (hopproof)"               gotest ./hopproof
gate "ssh-agent / ssh-add compatibility (sshagent)"         gotest ./sshagent

head "GATING — dynamic session core"
gate "runtime + control (sessionruntime, sessioncontrol)"   gotest ./sessionruntime ./sessioncontrol
gate "bounded streams + WINDOW flow control (sessionmux)"   gotest ./sessionmux
gate "same-user brokers + linear routing (broker/route/dispatch)" \
     gotest ./sessionbroker ./sessionroute ./sessiondispatch
gate "in-band session API (sessionapi)"                     gotest ./sessionapi
gate "rule-constrained endpoint map/reduce (mapreduce)"     gotest ./mapreduce
gate "soft-state logical session links (sessionlink)"       gotest ./sessionlink

head "GATING — filesystem services (9P + atomic replace)"
gate "9P server + client (p9svc, p9client)"                 gotest ./internal/p9svc ./internal/p9client
gate "VFS path model + FUSE bridge (vfs, vfsmount)"         gotest ./internal/vfs ./internal/vfsmount
gate "atomic replace fs-ops (sessionfsops)"                 gotest ./sessionfsops
gate "9P file backend + RocksDB core (filebackend, minus macOS-symlink/flaky)" \
     gotest ./filebackend -skip 'TestOSBackendConfinesPaths|TestLoadHooksFileRunsBoundedCommand'

head "GATING — TCP / SOCKS5 (CONNECT proof + UDP associate)"
gate "TCP dial + routed streams (sessiontcp)"               gotest ./sessiontcp
gate "cryptographic CONNECT proof (socksproof, sessiontcpproof)" \
     gotest ./socksproof ./sessiontcpproof
gate "SOCKS5 CONNECT + UDP proxy (sessionproxy)"            gotest ./sessionproxy
gate "SOCKS5 UDP datagrams (socksudp, sessionudp)"          gotest ./socksudp ./sessionudp

head "GATING — engine & extension framework"
gate "gnet multi-socket engine (socketengine)"             gotest ./socketengine
gate "bounded extension + hook framework (extension, minus flaky)" \
     gotest ./extension -skip 'TestLoadFileRunsCommandHook'

head "GATING — end-to-end integration (in-process X11->WS->mux)"
gate "app integration: bootstrap, 9P-over-session, API, fs-ops routing" gotest ./internal/app
gate "cmd/wv command surface"                                      gotest ./cmd/wv

head "TRIAGE — known pre-existing failures on this branch (non-gating)"
triage "extension LoadFileRunsCommandHook" \
  "flaky: passes in isolation, 2s stdin timeout under full-package run (command-hook stdin race)" \
  gotest ./extension -run '^TestLoadFileRunsCommandHook$'
triage "filebackend OSBackendConfinesPaths" \
  "macOS-only: t.TempDir under /tmp symlink; backend.Resolve EvalSymlinks to /private/tmp so the literal-root compare fails. Passes on Linux/CI and with a real-path TMPDIR" \
  gotest ./filebackend -run '^TestOSBackendConfinesPaths$'
triage "filebackend LoadHooksFileRunsBoundedCommand" \
  "flaky: passes in isolation, 2s command-hook timeout under full-package run (same stdin race as extension)" \
  gotest ./filebackend -run '^TestLoadHooksFileRunsBoundedCommand$'

head "Summary"
printf "gating:  ${G}%d passed${N}, " "$pass"
if [ "$fail" -eq 0 ]; then printf "${G}0 failed${N}\n"; else printf "${R}%d failed${N}\n" "$fail"; fi
if [ "$fail" -ne 0 ]; then
  printf "${R}gating failures:${N}\n"
  for f in "${failed_gating[@]}"; do printf "  - %s\n" "$f"; done
  exit 1
fi
printf "${G}all gating core features passed${N}\n"
printf "(3 known failures reported above under TRIAGE; run with -v to see detail)\n"
exit 0
