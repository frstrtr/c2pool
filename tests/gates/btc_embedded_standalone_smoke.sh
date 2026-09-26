#!/usr/bin/env bash
# btc embedded-standalone daemonless boot smoke.
# ci-steward 2026-08-30. First CI coverage of the btc embedded-standalone
# (daemonless) path proven live as btc.voidbind.com: c2pool-btc with NO
# bitcoind, --coin-p2p-discover + --http :808x, headers climbing, HTTP 200.
# A regression on that path is otherwise invisible until prod.
#
# Boots the already-built c2pool-btc daemonless (no bitcoind, no --coin-rpc-*),
# arms coin-network peer discovery (--coin-p2p-discover) and the operator
# dashboard (--http), then asserts, within a BOUNDED window:
#   1. the process stays up (no early crash / exit),
#   2. the HTTP ENGINE endpoint returns 200 (check ENGINE, i.e. /node_info,
#      NOT /v36_status, per the prod-redline-check-engine convention),
#   3. the HeaderChain tip ADVANCES past the init baseline (headers climbing;
#      canonical line "[BTC] new_headers: ... chain_height=<H>").
#
# Egress-honest: if DNS / P2P egress to the coin network is blocked, emit a
# NAMED, logged skip so a network-isolated runner can never read as a silent
# green. Short smoke, not a soak — bounded by SMOKE_WINDOW.
set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build_ci}"
HTTP_PORT="${HTTP_PORT:-8089}"
BOOT_GRACE="${BOOT_GRACE:-20}"        # seconds to let the engine bind + handshake
SMOKE_WINDOW="${SMOKE_WINDOW:-180}"   # max seconds to observe header progress

# Locate the binary (default cmake layout, with a find fallback).
BIN="${BIN:-$BUILD_DIR/src/c2pool/c2pool-btc}"
if [ ! -x "$BIN" ]; then
  BIN="$(find "$BUILD_DIR" -type f -name c2pool-btc -perm -u+x 2>/dev/null | head -1 || true)"
fi
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "::error::c2pool-btc binary not found under $BUILD_DIR"; exit 1; }

DATA_DIR="$(mktemp -d /tmp/c2pool-btc-smoke.XXXXXX)"
LOG="$DATA_DIR/node.log"
NODE_PID=""
cleanup() {
  if [ -n "$NODE_PID" ]; then
    kill "$NODE_PID" 2>/dev/null || true
    wait "$NODE_PID" 2>/dev/null || true
  fi
  rm -rf "$DATA_DIR" 2>/dev/null || true
}
trap cleanup EXIT

echo "[btc-smoke] binary: $BIN"
echo "[btc-smoke] booting embedded-standalone: --coin-p2p-discover --http 127.0.0.1:$HTTP_PORT (no bitcoind)"
"$BIN" --coin-p2p-discover --http "127.0.0.1:$HTTP_PORT" --data-dir "$DATA_DIR" > "$LOG" 2>&1 &
NODE_PID=$!

# 1) process stays up through the boot grace
sleep "$BOOT_GRACE"
if ! kill -0 "$NODE_PID" 2>/dev/null; then
  echo "::error::c2pool-btc exited during boot grace — engine did not stay up"
  echo "---- node.log ----"; cat "$LOG"; exit 1
fi
echo "[btc-smoke] engine still up after ${BOOT_GRACE}s boot grace"

# Egress-honest NAMED skip: coin-network unreachable => logged skip, not green.
if grep -qiE "no route to host|network is unreachable|name resolution fail|temporary failure in name resolution|dns.*(fail|unreachable)|no seeds|0 peers discovered" "$LOG"; then
  echo "::notice::[btc-smoke] SKIP — coin-network egress blocked (DNS/P2P unreachable). NAMED skip, not a silent green."
  echo "---- node.log (tail) ----"; tail -40 "$LOG"; exit 0
fi

# 2) HTTP ENGINE endpoint returns 200 (ENGINE, not /v36_status)
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/node_info" || true)"
if [ "$code" != "200" ]; then
  echo "::error::HTTP engine endpoint /node_info returned '$code' (expected 200)"
  echo "---- node.log ----"; cat "$LOG"; exit 1
fi
echo "[btc-smoke] HTTP engine endpoint 200 OK (/node_info)"

# baseline header height from the HeaderChain init line
base_h="$(grep -oE '\[BTC\] HeaderChain initialized:.*height=[0-9]+' "$LOG" | grep -oE 'height=[0-9]+' | tail -1 | cut -d= -f2 || true)"
base_h="${base_h:-0}"
echo "[btc-smoke] baseline header height=$base_h"

# 3) HeaderChain tip advances within the bounded window. A slow-but-live node
#    gets up to TIP_ATTEMPTS windows (#1471). Every extra window emits a titled
#    ::warning:: annotation (countable across runs via the check-run annotations
#    API) and the count goes to the step summary, so a pass that needed a retry
#    is never silent and a persistent stall still goes red. Liveness is
#    re-checked before each retry: a dead process or a failing /node_info fails
#    at once. Retries forgive a slow tip, never a broken node.
TIP_ATTEMPTS="${TIP_ATTEMPTS:-3}"
tip_retries=0
cur_h="$base_h"
report_retries() {
  echo "[btc-smoke] tip_advance_retries=$tip_retries (of $(( TIP_ATTEMPTS - 1 )) allowed)"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "btc-smoke tip-advance retries used: $tip_retries of $(( TIP_ATTEMPTS - 1 )) allowed" >> "$GITHUB_STEP_SUMMARY"
  fi
}
for attempt in $(seq 1 "$TIP_ATTEMPTS"); do
  if [ "$attempt" -gt 1 ]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/node_info" || true)"
    if ! kill -0 "$NODE_PID" 2>/dev/null || [ "$code" != "200" ]; then
      echo "::error::node not live before tip-advance attempt $attempt/$TIP_ATTEMPTS (/node_info '$code') — a dead node is never retried"
      report_retries; echo "---- node.log (tail) ----"; tail -120 "$LOG"; exit 1
    fi
    tip_retries=$(( attempt - 1 ))
    echo "::warning title=btc-smoke tip-advance retry::attempt $attempt/$TIP_ATTEMPTS: chain_height=$cur_h (baseline $base_h) after ${SMOKE_WINDOW}s; node live, /node_info 200, re-polling"
  fi
  deadline=$(( SECONDS + SMOKE_WINDOW ))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if ! kill -0 "$NODE_PID" 2>/dev/null; then
      echo "::error::c2pool-btc exited mid-smoke"; report_retries; echo "---- node.log ----"; cat "$LOG"; exit 1
    fi
    cur_h="$(grep -oE '\[BTC\] new_headers:.*chain_height=[0-9]+' "$LOG" | grep -oE 'chain_height=[0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1 || true)"
    cur_h="${cur_h:-0}"
    if [ "$cur_h" -gt "$base_h" ]; then
      if [ "$tip_retries" -gt 0 ]; then
        echo "::warning title=btc-smoke tip-advance retry::PASS only on attempt $attempt/$TIP_ATTEMPTS (retries used: $tip_retries)"
      fi
      echo "[btc-smoke] PASS — HeaderChain tip advanced $base_h -> $cur_h (engine red-line green)"
      report_retries; exit 0
    fi
    sleep 5
  done
done

echo "::error::HeaderChain tip did not advance past $base_h within ${SMOKE_WINDOW}s on any of $TIP_ATTEMPTS attempts (no headers climbing)"
report_retries; echo "---- node.log (tail) ----"; tail -120 "$LOG"; exit 1
