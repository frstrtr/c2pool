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

# 3) HeaderChain tip advances within the bounded window
deadline=$(( SECONDS + SMOKE_WINDOW ))
while [ "$SECONDS" -lt "$deadline" ]; do
  if ! kill -0 "$NODE_PID" 2>/dev/null; then
    echo "::error::c2pool-btc exited mid-smoke"; echo "---- node.log ----"; cat "$LOG"; exit 1
  fi
  cur_h="$(grep -oE '\[BTC\] new_headers:.*chain_height=[0-9]+' "$LOG" | grep -oE 'chain_height=[0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1 || true)"
  cur_h="${cur_h:-0}"
  if [ "$cur_h" -gt "$base_h" ]; then
    echo "[btc-smoke] PASS — HeaderChain tip advanced $base_h -> $cur_h (engine red-line green)"
    exit 0
  fi
  sleep 5
done

echo "::error::HeaderChain tip did not advance past $base_h within ${SMOKE_WINDOW}s (no headers climbing)"
echo "---- node.log (tail) ----"; tail -120 "$LOG"; exit 1
