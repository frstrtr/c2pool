#!/usr/bin/env bash
# doge embedded-standalone daemonless boot smoke.
# ci-steward 2026-11-12. First CI coverage of the embedded DOGE (merged-mining
# child) boot path: c2pool-ltc in its default integrated mode, where embedded
# DOGE is on by default and auto-adds the DOGE:98 merged spec, with NO
# dogecoind and NO litecoind. There is no c2pool-doge binary (DOGE ships inside
# c2pool-ltc), and tests/gates/doge_aux_smoke.sh only runs gtests, so nothing
# else boots the embedded DOGE node. A regression on that path is otherwise
# invisible until prod.
#
# Boots the already-built c2pool-ltc with no daemon, then asserts, within a
# BOUNDED window:
#   1. the process stays up (no early crash / exit),
#   2. the embedded DOGE node comes up: the "[EMB-DOGE] EMBEDDED DOGE NODE"
#      banner, the DOGE HeaderChain started (genesis seeded or loaded), and the
#      DOGE merged broadcaster started ("[DOGE] Multi-peer broadcaster started"),
#   3. the HTTP engine endpoint /node_info returns 200.
# A live DOGE peer ("[EMB-DOGE] Received N headers from" or "[DOGE] Header
# sync: H/T") is observed BEST-EFFORT within SMOKE_WINDOW.
#
# Egress-honest: the structural red-lines above are asserted FIRST. If no live
# peer shows up AND the log shows DNS/P2P egress failure, the network part ends
# in a NAMED, logged skip ("egress blocked"), never a silent green. Short smoke,
# not a soak: bounded by BOOT_GRACE + ARM_WAIT + SMOKE_WINDOW.
set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build_ci}"
HTTP_PORT="${HTTP_PORT:-8094}"
P2P_PORT="${P2P_PORT:-19326}"
STRATUM_PORT="${STRATUM_PORT:-19327}"
BOOT_GRACE="${BOOT_GRACE:-25}"        # seconds to let the engine bind + init the header chains
ARM_WAIT="${ARM_WAIT:-90}"            # extra seconds for the DOGE merged broadcaster to start
SMOKE_WINDOW="${SMOKE_WINDOW:-120}"   # max seconds to best-effort observe a live DOGE peer

BIN="${BIN:-$BUILD_DIR/src/c2pool/c2pool-ltc}"
if [ ! -x "$BIN" ]; then
  BIN="$(find "$BUILD_DIR" -type f -name c2pool-ltc -perm -u+x 2>/dev/null | head -1 || true)"
fi
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "::error::c2pool-ltc binary not found under $BUILD_DIR"; exit 1; }

DATA_DIR="$(mktemp -d /tmp/c2pool-doge-smoke.XXXXXX)"
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

die() { echo "::error::$1"; echo "---- node.log (tail) ----"; tail -200 "$LOG"; exit 1; }

echo "[doge-smoke] binary: $BIN"
echo "[doge-smoke] booting embedded-standalone (default integrated, embedded LTC + embedded DOGE, no dogecoind/litecoind) web 127.0.0.1:$HTTP_PORT"
"$BIN" --data-dir "$DATA_DIR" \
  --http-host 127.0.0.1 --web-port "$HTTP_PORT" \
  --p2pool-port "$P2P_PORT" --worker-port "$STRATUM_PORT" > "$LOG" 2>&1 &
NODE_PID=$!

# 1) process stays up through the boot grace
sleep "$BOOT_GRACE"
kill -0 "$NODE_PID" 2>/dev/null || die "c2pool-ltc exited during boot grace — engine did not stay up"
echo "[doge-smoke] engine still up after ${BOOT_GRACE}s boot grace"

# 2) embedded DOGE node up + DOGE HeaderChain started + DOGE merged broadcaster
# started (structural red-line), POLLED: the merged broadcaster starts after
# the DOGE HeaderChain and UTXO open.
arm_deadline=$(( SECONDS + ARM_WAIT ))
armed=0
while [ "$SECONDS" -lt "$arm_deadline" ]; do
  kill -0 "$NODE_PID" 2>/dev/null || die "c2pool-ltc exited while starting the embedded DOGE node"
  if grep -qE "\[DOGE\] Multi-peer broadcaster started" "$LOG"; then
    armed=1; break
  fi
  sleep 3
done
grep -qE "\[EMB-DOGE\] EMBEDDED DOGE NODE" "$LOG" \
  || die "embedded DOGE node did not come up (no [EMB-DOGE] banner) within $(( BOOT_GRACE + ARM_WAIT ))s"
if grep -qE "\[DOGE\] HeaderChain: genesis seed rejected" "$LOG"; then
  die "embedded DOGE HeaderChain rejected its genesis seed"
fi
grep -qE "\[DOGE\] HeaderChain: genesis block seeded \(height 0\)|DOGE HeaderChain: [0-9]+ headers \(height=[0-9]+\)" "$LOG" \
  || die "embedded DOGE HeaderChain did not start within $(( BOOT_GRACE + ARM_WAIT ))s"
[ "$armed" -eq 1 ] || die "embedded DOGE merged broadcaster did not start within $(( BOOT_GRACE + ARM_WAIT ))s"
echo "[doge-smoke] $(grep -oE '\[DOGE\] HeaderChain: genesis block seeded \(height 0\)|DOGE HeaderChain: [0-9]+ headers \(height=[0-9]+\)' "$LOG" | head -1)"
echo "[doge-smoke] $(grep -oE '\[DOGE\] Multi-peer broadcaster started.*' "$LOG" | head -1)"

# 3) HTTP engine endpoint returns 200 (/node_info, not /v36_status)
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/node_info" || true)"
[ "$code" = "200" ] || die "HTTP engine endpoint /node_info returned '$code' (expected 200)"
echo "[doge-smoke] HTTP engine endpoint 200 OK (/node_info)"

# 4) BEST-EFFORT live DOGE peer; the process must stay up throughout.
deadline=$(( SECONDS + SMOKE_WINDOW ))
live=0
while [ "$SECONDS" -lt "$deadline" ]; do
  kill -0 "$NODE_PID" 2>/dev/null || die "c2pool-ltc exited mid-smoke"
  if grep -qE "\[EMB-DOGE\] Received [0-9]+ headers|\[DOGE\] Header sync: [0-9]+/[0-9]+" "$LOG"; then
    live=1; break
  fi
  sleep 5
done

# A late crash must still red even if an early peer short-circuited the loop.
kill -0 "$NODE_PID" 2>/dev/null || die "c2pool-ltc exited before end of smoke window"

if [ "$live" -eq 1 ]; then
  echo "[doge-smoke] live DOGE peer observed: $(grep -oE '\[EMB-DOGE\] Received [0-9]+ headers|\[DOGE\] Header sync: [0-9]+/[0-9]+' "$LOG" | head -1)"
  echo "[doge-smoke] PASS — process up + embedded DOGE node + DOGE HeaderChain + DOGE broadcaster started + /node_info 200, WITH live DOGE peer"
  exit 0
fi

if grep -qiE "\[DNS\] Seed resolution complete: 0 total peers|\[DNS\] Failed to resolve|\[DNS\] .* (failed|timed out)|no route to host|network is unreachable|temporary failure in name resolution|host not found" "$LOG"; then
  echo "::notice::[doge-smoke] SKIP — DOGE coin-network egress blocked (no live peer, DNS/P2P unreachable). NAMED skip of the network part only; structural red-lines held."
  echo "---- node.log (DNS / DOGE peer lines) ----"; grep -E "\[DNS\]|\[DOGE\] (Connecting|Disconnecting) P2P peer" "$LOG" | tail -40 || true
  exit 0
fi

echo "::notice::[doge-smoke] no live DOGE peer within ${SMOKE_WINDOW}s and no egress error logged; best-effort only."
echo "[doge-smoke] PASS — process up + embedded DOGE node + DOGE HeaderChain + DOGE broadcaster started + /node_info 200"
exit 0
