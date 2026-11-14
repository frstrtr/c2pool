#!/usr/bin/env bash
# dash embedded-standalone daemonless boot smoke.
# ci-steward 2026-11-11. First CI coverage of the dash embedded-standalone
# (daemonless) boot path: c2pool-dash with NO dashd, --run --coin-p2p-discover
# + --web-port. coin-matrix.yml's dash-daemonless cell runs replay/fold gtests
# only; nothing boots the binary daemonless, so a regression on that path is
# otherwise invisible until prod.
#
# Boots the already-built c2pool-dash with no dashd RPC arm, arms coin-network
# peer discovery (--coin-p2p-discover) and the web dashboard (--web-port), then
# asserts, within a BOUNDED window:
#   1. the process stays up (no early crash / exit),
#   2. DashCoinPeerManager started (seed-based discovery armed), and
#   3. the HTTP engine endpoint /node_info returns 200.
# A live coin-peer handshake ("[COIN-P2P] handshake complete with ...
# height=<H>") is observed BEST-EFFORT and logged when the network permits;
# its absence is NOT a failure (same downgrade as the dgb smoke, #1469:
# public DNS-seed reach from GH-hosted runners is not reliable).
#
# Egress-honest: if DNS / P2P egress to the DASH network is fully blocked
# (peer manager starts with 0 peers AND a resolver/route error is logged), emit
# a NAMED, logged skip so a network-isolated runner can never read as a silent
# green. Short smoke, not a soak: bounded by BOOT_GRACE + ARM_WAIT + SMOKE_WINDOW.
set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build_ci}"
HTTP_PORT="${HTTP_PORT:-8093}"
BOOT_GRACE="${BOOT_GRACE:-25}"        # seconds to let the engine bind + start discovery
ARM_WAIT="${ARM_WAIT:-45}"            # extra seconds for synchronous DNS-seed resolution
SMOKE_WINDOW="${SMOKE_WINDOW:-60}"    # max seconds to best-effort observe a live coin-peer handshake

BIN="${BIN:-$BUILD_DIR/src/c2pool/c2pool-dash}"
if [ ! -x "$BIN" ]; then
  BIN="$(find "$BUILD_DIR" -type f -name c2pool-dash -perm -u+x 2>/dev/null | head -1 || true)"
fi
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "::error::c2pool-dash binary not found under $BUILD_DIR"; exit 1; }

DATA_DIR="$(mktemp -d /tmp/c2pool-dash-smoke.XXXXXX)"
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

die() { echo "::error::$1"; echo "---- node.log ----"; cat "$LOG"; exit 1; }

echo "[dash-smoke] binary: $BIN"
echo "[dash-smoke] booting embedded-standalone: --run --coin-p2p-discover --web-port $HTTP_PORT (no dashd)"
"$BIN" --data-dir "$DATA_DIR" --run --coin-p2p-discover \
  --web-host 127.0.0.1 --web-port "$HTTP_PORT" > "$LOG" 2>&1 &
NODE_PID=$!

# 1) process stays up through the boot grace
sleep "$BOOT_GRACE"
kill -0 "$NODE_PID" 2>/dev/null || die "c2pool-dash exited during boot grace — engine did not stay up"
echo "[dash-smoke] engine still up after ${BOOT_GRACE}s boot grace"

# 2) peer discovery started (structural red-line), POLLED: DNS seeds resolve
# synchronously before the "started" line, so it can land after the boot grace.
arm_deadline=$(( SECONDS + ARM_WAIT ))
armed=0
while [ "$SECONDS" -lt "$arm_deadline" ]; do
  kill -0 "$NODE_PID" 2>/dev/null || die "c2pool-dash exited while starting coin-network peer discovery"
  if grep -qE "\[DASH\] DashCoinPeerManager started: 0 peers" "$LOG" \
     && grep -qiE "no route to host|network is unreachable|temporary failure in name resolution|host not found" "$LOG"; then
    echo "::notice::[dash-smoke] SKIP — DASH coin-network egress blocked (0 peers, DNS/P2P unreachable). NAMED skip, not a silent green."
    echo "---- node.log (tail) ----"; tail -40 "$LOG"; exit 0
  fi
  if grep -qE "\[DASH\] DashCoinPeerManager started: [0-9]+ peers" "$LOG"; then
    armed=1; break
  fi
  sleep 3
done
[ "$armed" -eq 1 ] || die "DashCoinPeerManager did not start under --coin-p2p-discover within $(( BOOT_GRACE + ARM_WAIT ))s"
echo "[dash-smoke] $(grep -oE '\[DASH\] DashCoinPeerManager started: [0-9]+ peers[^)]*\)' "$LOG" | head -1)"

# 3) HTTP engine endpoint returns 200 (/node_info)
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/node_info" || true)"
[ "$code" = "200" ] || die "HTTP engine endpoint /node_info returned '$code' (expected 200)"
echo "[dash-smoke] HTTP engine endpoint 200 OK (/node_info)"

# 4) BEST-EFFORT live coin-peer handshake; the process must stay up throughout.
deadline=$(( SECONDS + SMOKE_WINDOW ))
handshake=0
while [ "$SECONDS" -lt "$deadline" ]; do
  kill -0 "$NODE_PID" 2>/dev/null || die "c2pool-dash exited mid-smoke"
  if grep -qE "\[COIN-P2P\] handshake complete with .*height=[0-9]+" "$LOG"; then
    h="$(grep -oE 'handshake complete with .*height=[0-9]+' "$LOG" | grep -oE 'height=[0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1)"
    echo "[dash-smoke] live DASH coin peer handshake observed (peer height=$h)"
    handshake=1
    break
  fi
  sleep 5
done

# A late crash must still red even if an early handshake short-circuited the loop.
kill -0 "$NODE_PID" 2>/dev/null || die "c2pool-dash exited before end of smoke window"

if [ "$handshake" -eq 1 ]; then
  echo "[dash-smoke] PASS — process up + discovery started + /node_info 200, WITH live peer handshake"
else
  echo "::notice::[dash-smoke] no live DASH coin-peer handshake within ${SMOKE_WINDOW}s; best-effort only. Structural red-lines all held."
  echo "[dash-smoke] PASS — process up + discovery started + /node_info 200"
fi
exit 0
