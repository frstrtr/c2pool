#!/usr/bin/env bash
# dgb embedded-standalone daemonless boot smoke.
# ci-steward 2026-09-04. First CI coverage of the dgb embedded-standalone
# (daemonless) path: c2pool-dgb with NO digibyted, --run --coin-p2p-discover
# + --http :809x. bip110 M1-M3 wired main_dgb to parse --coin-p2p-discover/
# --http; a regression on that boot path is otherwise invisible until prod.
#
# Boots the already-built c2pool-dgb daemonless (no digibyted, no --coin-daemon),
# arms coin-network peer discovery (--coin-p2p-discover) + the operator
# dashboard (--http), then asserts, within a BOUNDED window:
#   1. the process stays up (no early crash / exit),
#   2. coin-network peer discovery ARMED against REAL DGB DNS seeds, and
#   3. the HTTP ENGINE endpoint returns 200 (/node_info).
# A LIVE coin-peer version handshake ("[DGB-CoinP2P] version: ...
# start_height=<H>") is observed BEST-EFFORT and logged when the network
# permits; its absence is NOT a failure (see the downgrade note below).
#
# NOTE (ci-steward 2026-09-04): the dgb standalone header source does NOT
# reliably advance chain_height past 0 within a bounded CI window today
# ("[DGB] standalone header-sync getheaders ... chain_height=0", 40s
# no-progress failover). A btc-style "HeaderChain tip advances" assertion
# would false-red here, so this smoke deliberately gates on boot +
# peer-discovery-ARMED + HTTP-200 — NOT header-climbing. Header-sync-advance
# is a tracked follow-up once the standalone header source progresses.
#
# Egress-honest: if DNS / P2P egress to the DGB network is fully blocked, emit
# a NAMED, logged skip so a network-isolated runner can never read as a silent
# green. Short smoke, not a soak — bounded by SMOKE_WINDOW.
#
# DOWNGRADE (ci-steward 2026-09-04, #1467 post-mortem / #1469 CI-red): the live
# coin-peer version handshake was previously a hard red-line, but GH-hosted
# runners cannot reliably reach the public DGB DNS seeds (7 of 8 seeds return
# "Host not found"; only seed.digibyte.io resolves), which made the gate a
# public-network flake generator. The handshake is now BEST-EFFORT. The gate's
# structural red-lines — process stays up, peer discovery ARMS, /node_info
# returns 200 — still fail hard on a missing or broken binary.
set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build_ci}"
HTTP_PORT="${HTTP_PORT:-8092}"
BOOT_GRACE="${BOOT_GRACE:-25}"        # seconds to let the engine bind + arm discovery
SMOKE_WINDOW="${SMOKE_WINDOW:-60}"    # max seconds to best-effort observe a live coin-peer handshake

# Locate the binary (default cmake layout, with a find fallback).
BIN="${BIN:-$BUILD_DIR/src/c2pool/c2pool-dgb}"
if [ ! -x "$BIN" ]; then
  BIN="$(find "$BUILD_DIR" -type f -name c2pool-dgb -perm -u+x 2>/dev/null | head -1 || true)"
fi
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "::error::c2pool-dgb binary not found under $BUILD_DIR"; exit 1; }

DATA_DIR="$(mktemp -d /tmp/c2pool-dgb-smoke.XXXXXX)"
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

echo "[dgb-smoke] binary: $BIN"
echo "[dgb-smoke] booting embedded-standalone: --run --coin-p2p-discover --http 127.0.0.1:$HTTP_PORT (no digibyted)"
"$BIN" --run --coin-p2p-discover --http "127.0.0.1:$HTTP_PORT" --data-dir "$DATA_DIR" > "$LOG" 2>&1 &
NODE_PID=$!

# 1) process stays up through the boot grace
sleep "$BOOT_GRACE"
if ! kill -0 "$NODE_PID" 2>/dev/null; then
  echo "::error::c2pool-dgb exited during boot grace — engine did not stay up"
  echo "---- node.log ----"; cat "$LOG"; exit 1
fi
echo "[dgb-smoke] engine still up after ${BOOT_GRACE}s boot grace"

# Egress-honest NAMED skip: coin-network unreachable => logged skip, not green.
# All 8 DNS seeds failing / zero peers added is the network-isolated signature.
if grep -qiE "no route to host|network is unreachable|temporary failure in name resolution" "$LOG" \
   || grep -qE "DNS seeds:.* 0 (new peers added|total)" "$LOG" \
   || grep -qE "DgbCoinPeerManager started: 0 peers" "$LOG"; then
  echo "::notice::[dgb-smoke] SKIP — DGB coin-network egress blocked (DNS/P2P unreachable). NAMED skip, not a silent green."
  echo "---- node.log (tail) ----"; tail -40 "$LOG"; exit 0
fi

# Assert peer discovery ARMED against real peers (structural red-line).
if ! grep -qE "\[DGB\] coin-network peer discovery ARMED" "$LOG"; then
  echo "::error::coin-network peer discovery did not ARM under --coin-p2p-discover"
  echo "---- node.log ----"; cat "$LOG"; exit 1
fi
echo "[dgb-smoke] coin-network peer discovery ARMED"

# 2) HTTP ENGINE endpoint returns 200 (/node_info)
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/node_info" || true)"
if [ "$code" != "200" ]; then
  echo "::error::HTTP engine endpoint /node_info returned '$code' (expected 200)"
  echo "---- node.log ----"; cat "$LOG"; exit 1
fi
echo "[dgb-smoke] HTTP engine endpoint 200 OK (/node_info)"

# 3) BEST-EFFORT live-peer observation (network-dependency downgrade,
#    ci-steward 2026-09-04, #1469 CI-red). A LIVE coin-peer version handshake
#    ("[DGB-CoinP2P] version: ... start_height=<H>") proves real network reach,
#    but GH-hosted runners cannot reliably resolve the public DGB DNS seeds, so
#    REQUIRING a handshake made this gate a public-network flake generator. The
#    structural red-lines above (process up, discovery ARMED, /node_info 200)
#    already fail on a missing/broken binary; a live handshake is logged as a
#    BONUS when observed, and its absence is NOT a failure. The process must
#    stay up through the observation window.
deadline=$(( SECONDS + SMOKE_WINDOW ))
handshake=0
while [ "$SECONDS" -lt "$deadline" ]; do
  if ! kill -0 "$NODE_PID" 2>/dev/null; then
    echo "::error::c2pool-dgb exited mid-smoke"; echo "---- node.log ----"; cat "$LOG"; exit 1
  fi
  if grep -qE "\[DGB-CoinP2P\] version:.*start_height=[0-9]+" "$LOG"; then
    sh="$(grep -oE 'start_height=[0-9]+' "$LOG" | grep -oE '[0-9]+' | sort -n | tail -1)"
    echo "[dgb-smoke] live DGB coin peer handshake observed (peer start_height=$sh) — real network reach confirmed"
    handshake=1
    break
  fi
  sleep 5
done

# A late crash must still red even if an early handshake short-circuited the loop.
if ! kill -0 "$NODE_PID" 2>/dev/null; then
  echo "::error::c2pool-dgb exited before end of smoke window"; echo "---- node.log ----"; cat "$LOG"; exit 1
fi

if [ "$handshake" -eq 1 ]; then
  echo "[dgb-smoke] PASS — daemonless boot red-line green (process up + discovery ARMED + /node_info 200) WITH live peer handshake"
else
  echo "::notice::[dgb-smoke] no live DGB coin-peer handshake within ${SMOKE_WINDOW}s — GH-hosted DGB DNS-seed egress is unreliable; handshake is best-effort, not a red-line. Structural red-lines all held."
  echo "[dgb-smoke] PASS — daemonless boot red-line green (process up + discovery ARMED + /node_info 200)"
fi
exit 0
