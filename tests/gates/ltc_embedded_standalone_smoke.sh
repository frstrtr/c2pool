#!/usr/bin/env bash
# ltc embedded-standalone daemonless boot smoke.
# ci-steward 2026-11-12. First CI coverage of the ltc embedded-standalone
# (daemonless) boot path: c2pool-ltc in its default integrated mode with the
# embedded LTC SPV node (no litecoind, no --coin-rpc-*) and the web dashboard.
# Nothing else boots the binary daemonless, so a regression on that path is
# otherwise invisible until prod.
#
# Boots the already-built c2pool-ltc with no daemon, then asserts, within a
# BOUNDED window:
#   1. the process stays up (no early crash / exit),
#   2. the embedded LTC HeaderChain initializes and the seed-based coin
#      broadcaster starts ("[LTC] Embedded broadcaster started, ... dns_seeds=N"),
#   3. the HTTP engine endpoint /node_info returns 200.
# A live coin peer ("[LTC] Peer reports chain height <H>" or "[EMB-LTC]
# Received N headers") is observed BEST-EFFORT within SMOKE_WINDOW.
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
BOOT_GRACE="${BOOT_GRACE:-25}"        # seconds to let the engine bind + init the HeaderChain
ARM_WAIT="${ARM_WAIT:-60}"            # extra seconds for the coin broadcaster to start
SMOKE_WINDOW="${SMOKE_WINDOW:-90}"    # max seconds to best-effort observe a live coin peer

BIN="${BIN:-$BUILD_DIR/src/c2pool/c2pool-ltc}"
if [ ! -x "$BIN" ]; then
  BIN="$(find "$BUILD_DIR" -type f -name c2pool-ltc -perm -u+x 2>/dev/null | head -1 || true)"
fi
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "::error::c2pool-ltc binary not found under $BUILD_DIR"; exit 1; }

DATA_DIR="$(mktemp -d /tmp/c2pool-ltc-smoke.XXXXXX)"
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

echo "[ltc-smoke] binary: $BIN"
echo "[ltc-smoke] booting embedded-standalone (default integrated, embedded LTC SPV, no litecoind) web 127.0.0.1:$HTTP_PORT"
"$BIN" --data-dir "$DATA_DIR" \
  --http-host 127.0.0.1 --web-port "$HTTP_PORT" \
  --p2pool-port "$P2P_PORT" --worker-port "$STRATUM_PORT" > "$LOG" 2>&1 &
NODE_PID=$!

# 1) process stays up through the boot grace
sleep "$BOOT_GRACE"
kill -0 "$NODE_PID" 2>/dev/null || die "c2pool-ltc exited during boot grace — engine did not stay up"
echo "[ltc-smoke] engine still up after ${BOOT_GRACE}s boot grace"

# 2) embedded HeaderChain initialized + coin broadcaster started (structural
# red-line), POLLED: the broadcaster starts after the HeaderChain/UTXO open.
arm_deadline=$(( SECONDS + ARM_WAIT ))
armed=0
while [ "$SECONDS" -lt "$arm_deadline" ]; do
  kill -0 "$NODE_PID" 2>/dev/null || die "c2pool-ltc exited while starting the embedded LTC node"
  if grep -qE "\[LTC\] Embedded broadcaster started, daemon=" "$LOG"; then
    armed=1; break
  fi
  sleep 3
done
grep -qE "\[EMB-LTC\] HeaderChain initialized: size=[0-9]+ height=[0-9]+" "$LOG" \
  || die "embedded LTC HeaderChain did not initialize within $(( BOOT_GRACE + ARM_WAIT ))s"
[ "$armed" -eq 1 ] || die "embedded LTC coin broadcaster did not start within $(( BOOT_GRACE + ARM_WAIT ))s"
echo "[ltc-smoke] $(grep -oE '\[EMB-LTC\] HeaderChain initialized: size=[0-9]+ height=[0-9]+' "$LOG" | head -1)"
echo "[ltc-smoke] $(grep -oE '\[LTC\] Embedded broadcaster started, daemon=.*' "$LOG" | head -1)"

# 3) HTTP engine endpoint returns 200 (/node_info, not /v36_status)
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/node_info" || true)"
[ "$code" = "200" ] || die "HTTP engine endpoint /node_info returned '$code' (expected 200)"
echo "[ltc-smoke] HTTP engine endpoint 200 OK (/node_info)"

# 4) BEST-EFFORT live coin peer; the process must stay up throughout.
deadline=$(( SECONDS + SMOKE_WINDOW ))
live=0
while [ "$SECONDS" -lt "$deadline" ]; do
  kill -0 "$NODE_PID" 2>/dev/null || die "c2pool-ltc exited mid-smoke"
  if grep -qE "\[LTC\] Peer reports chain height [0-9]+|\[EMB-LTC\] Received [0-9]+ headers from" "$LOG"; then
    live=1; break
  fi
  sleep 5
done

# A late crash must still red even if an early peer short-circuited the loop.
kill -0 "$NODE_PID" 2>/dev/null || die "c2pool-ltc exited before end of smoke window"

if [ "$live" -eq 1 ]; then
  h="$(grep -oE '\[LTC\] Peer reports chain height [0-9]+' "$LOG" | grep -oE '[0-9]+$' | sort -n | tail -1 || true)"
  echo "[ltc-smoke] live LTC coin peer observed (peer height=${h:-n/a})"
  echo "[ltc-smoke] PASS — process up + HeaderChain init + broadcaster started + /node_info 200, WITH live coin peer"
  exit 0
fi

if grep -qiE "\[DNS\] Seed resolution complete: 0 total peers|\[DNS\] Failed to resolve|\[DNS\] .* (failed|timed out)|no route to host|network is unreachable|temporary failure in name resolution|host not found" "$LOG"; then
  echo "::notice::[ltc-smoke] SKIP — LTC coin-network egress blocked (no live peer, DNS/P2P unreachable). NAMED skip of the network part only; structural red-lines held."
  echo "---- node.log (DNS / peer lines) ----"; grep -E "\[DNS\]|Connecting to P2P peer|Disconnecting P2P peer" "$LOG" | tail -40 || true
  exit 0
fi

echo "::notice::[ltc-smoke] no live LTC coin peer within ${SMOKE_WINDOW}s and no egress error logged; best-effort only."
echo "[ltc-smoke] PASS — process up + HeaderChain init + broadcaster started + /node_info 200"
exit 0
