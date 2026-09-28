#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# dash_v36_isolated_e2e.sh -- two-node end-to-end rig for the private/isolated
# DASH v36 sharechain (a custom --network-id). Two REAL c2pool-dash processes on
# 127.0.0.1, a FRESH random --network-id/--prefix per run (never a public, a
# testnet or the reserved future v36 identity), no coin daemon and no coin
# network: --coin-p2p-connect points at a dead loopback port, so the nodes are
# daemonless and have no work source (they cannot mint over stratum).
#
# The chain is minted by the seeder KAT DashV36E2E.SeedStoreForLoopbackRig
# (test_dash_node): a real dash::NodeImpl mints COUNT v36 shares (real X11 at
# the PRODUCTION testnet share floor, 2^20 hashes per share) through the node's
# own mint hook into <data-dir>/dash_testnet_<id>_v36, exactly the store a real
# process opens. --testnet is required for that reason only: the mainnet share
# floor (diff-1) cannot be ground in a test; the isolated profile itself is
# keyed on the identity alone.
#
#   BIN=/path/to/c2pool-dash TEST_DASH_NODE=/path/to/test_dash_node \
#   [MASTER_BIN=/path/to/master/c2pool-dash] [W=/tmp/dash-v36-e2e] \
#   [COUNT=104] [THREADS=8] scripts/dash_v36_isolated_e2e.sh
#
# The whole sequence runs TWICE: node A holds (seeds) the genesis chain, then
# node B does. Phases (each asserts; exit non-zero on the first failure):
#   1 seed:    the seeder mints COUNT shares; the seed node reloads them
#              ("Loaded COUNT persisted DASH shares", best share = manifest tip)
#   2 sync:    the other node --connects, downloads the chain over the real
#              socket, verifies every share (its own gentx rebuild must match
#              the seeder's committed gentx) and elects the same tip
#   3 coinbase: /current_payouts (the v36 PPLNS split of the next block) is
#              identical on both nodes and equals the seeder's expected split;
#              /sharechain/window is identical on both (hash, version, bits,
#              absheight, verified flag)
#   4 restart: the follower restarts, reloads COUNT shares from its
#              identity-scoped store with pre_verified=COUNT, keeps the tip,
#              re-peers, and downloads nothing again
#   5 stall:   the manifest's stall share (minted after a 700 s gap: emergency
#              decay) carries an easier max_bits than the no-stall job, and
#              both real nodes verified it
#   6 old peers: stand-in peers advertising protocol 1700 (p2pool-dash) and
#              3600 (a c2pool-dash build without v36 isolated support) are
#              refused at the handshake (EOF, "peer protocol below min-protocol
#              floor: peer build lacks v36 isolated support -- upgrade"), one
#              advertising 3601 (this build) is admitted; nobody is banned, the
#              real pair stays peered
#   7 master:  (MASTER_BIN only) a master-built c2pool-dash with the SAME
#              identity advertises 3600 and is refused at the handshake by the
#              seed node ("peer build lacks v36 isolated support"): it never
#              receives a share ('version unsupported' x0), stays chainless,
#              neither side bans and both stay up; a master node on the PUBLIC
#              testnet identity cannot even frame a message ("prefix doesn't
#              match")
#   8 loopback: 0 non-loopback coin-p2p connections
# Runtime ~5-10 min (two seedings at 2^20 X11 per share); not in CI.
set -u
BIN="${BIN:?set BIN to the c2pool-dash under test}"
TEST_DASH_NODE="${TEST_DASH_NODE:?set TEST_DASH_NODE to the test_dash_node binary (the seeder)}"
MASTER_BIN="${MASTER_BIN:-}"
W="${W:-/tmp/dash-v36-e2e}"
COUNT="${COUNT:-104}"
THREADS="${THREADS:-8}"
HERE="$(cd "$(dirname "$0")" && pwd)"

PIDS=()
fail() { echo "E2E FAIL: $*"; cleanup; exit 1; }
pass() { echo "E2E PASS: $*"; }
cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  sleep 1
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
}
trap cleanup EXIT

start() {   # start NAME LOG CMD... ; sets NAME_PID
  local name="$1" log="$2"; shift 2
  "$@" >"$log" 2>&1 &
  local pid=$!
  PIDS+=("$pid")
  eval "${name}_PID=$pid"
}
stop() {    # stop NAME
  local v="${1}_PID"; local pid="${!v:-}"
  [ -z "$pid" ] && return
  kill "$pid" 2>/dev/null
  for _ in $(seq 1 40); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
  kill -9 "$pid" 2>/dev/null
  eval "${1}_PID="
}
alive() { local v="${1}_PID"; local pid="${!v:-}"; [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; }
wait_for() {  # wait_for SECONDS DESC CMD...
  local secs="$1" desc="$2"; shift 2
  local end=$((SECONDS + secs))
  while [ $SECONDS -lt $end ]; do "$@" && return 0; sleep 1; done
  fail "timeout ($secs s) waiting for: $desc"
}
count() { local n; n=$(grep -c -- "$1" "$2" 2>/dev/null); echo "${n:-0}"; }
get() { curl -s --max-time 5 "http://127.0.0.1:$1$2"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval('d'+sys.argv[1]))" "$1"; }
peers_of() { local v; v=$(get "$1" /local_stats | jget '["peers"]["incoming"]+d["peers"]["outgoing"]' 2>/dev/null); echo "${v:-0}"; }
peers_ge() { [ "$(peers_of "$1")" -ge "$2" ] 2>/dev/null; }
peers_zero() { [ "$(peers_of "$1")" = 0 ]; }
# /sharechain/window reduced to what both nodes must agree on, one line per share.
window() {
  get "$1" /sharechain/window | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("best", d.get("best_hash", ""), "total", d.get("total", 0))
for s in sorted(d.get("shares", []), key=lambda s: s["a"]):
    print(s["a"], s["H"], "V=%s" % s["V"], "b=%08x" % s["b"], "v=%s" % s["v"], "dv=%s" % s["dv"])'
}
synced() {  # synced PORT TIP COUNT -> every share present and verified, tallest head == tip
  get "$1" /sharechain/window | python3 -c '
import json, sys
d = json.load(sys.stdin)
tip, n = sys.argv[1], int(sys.argv[2])
sh = d.get("shares", [])
ok = d.get("best_hash") == tip and d.get("total") == n and len(sh) == n and all(s["v"] == 1 and s["V"] == 36 for s in sh)
sys.exit(0 if ok else 1)' "$2" "$3" 2>/dev/null
}
payouts() { get "$1" /current_payouts | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin), sort_keys=True))'; }
manifest() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(eval('d'+sys.argv[2]))" "$1" "$2"; }

RESERVED="7242ef345e1bed6b 3b3e1286f446b891 b6deb1e543fe2427 198b644f6821e3b3 ac2785363c0180b8 8d8516bac9edd280"
fresh_hex() {
  local h
  while :; do
    h=$(python3 -c 'import secrets; print(secrets.token_hex(8))')
    case " $RESERVED " in *" $h "*) continue ;; esac
    [ -z "${h//0/}" ] && continue
    echo "$h"; return
  done
}

rm -rf "$W"; mkdir -p "$W"
echo "== rig: BIN=$BIN"
echo "== rig: TEST_DASH_NODE=$TEST_DASH_NODE MASTER_BIN=${MASTER_BIN:-<unset>} COUNT=$COUNT"

run_once() {   # run_once SEEDER(A|B)
  local SEED="$1" FOLLOW
  [ "$SEED" = A ] && FOLLOW=B || FOLLOW=A
  local D="$W/genesis-$SEED"
  mkdir -p "$D/A" "$D/B" "$D/M" "$D/P"
  NETID=$(fresh_hex); PREFIX=$(fresh_hex)
  while [ "$PREFIX" = "$NETID" ]; do PREFIX=$(fresh_hex); done
  local SUB="dash_testnet_${NETID}_v36"
  local COMMON=(--run --testnet --network-id "$NETID" --prefix "$PREFIX" --web-host 127.0.0.1
                --coin-p2p-connect 127.0.0.1:1)
  declare -A P2P=([A]=19811 [B]=19812) WEB=([A]=19091 [B]=19092) STR=([A]=19921 [B]=19922)
  echo "== genesis held by node $SEED: network-id=$NETID prefix=$PREFIX subdir=$SUB"

  # ── 1. seed ──────────────────────────────────────────────────────────────
  local t0=$SECONDS
  C2POOL_DASH_V36_E2E_SEED_DIR="$D/$SEED" C2POOL_DASH_V36_E2E_NETID="$NETID" \
  C2POOL_DASH_V36_E2E_PREFIX="$PREFIX" C2POOL_DASH_V36_E2E_COUNT="$COUNT" \
  C2POOL_DASH_V36_E2E_THREADS="$THREADS" \
    "$TEST_DASH_NODE" --gtest_filter=DashV36E2E.SeedStoreForLoopbackRig >"$D/seed.log" 2>&1
  grep -q "^\[  PASSED  \] 1 test" "$D/seed.log" || { tail -30 "$D/seed.log"; fail "seeder did not pass"; }
  local MF="$D/$SEED/manifest.json"
  [ -f "$MF" ] || fail "no manifest"
  local TIP; TIP=$(manifest "$MF" '["tip"]')
  [ "$(manifest "$MF" '["count"]')" = "$COUNT" ] || fail "manifest count"
  [ -d "$D/$SEED/$SUB/sharechain_leveldb" ] || [ -d "$D/$SEED/$SUB" ] || fail "no store under $SUB"
  pass "1a seeder: $COUNT v36 shares minted at the testnet share floor in $((SECONDS - t0)) s, tip=${TIP:0:16}"

  start_node() {  # start_node NODE LOGTAG [extra args...]
    local n="$1" tag="$2"; shift 2
    start "$n" "$D/$n.log.$tag" "$BIN" "${COMMON[@]}" --data-dir "$D/$n" \
      --listen "127.0.0.1:${P2P[$n]}" --web-port "${WEB[$n]}" --stratum "127.0.0.1:${STR[$n]}" "$@"
  }
  start_node "$SEED" 1
  local SL="$D/$SEED.log.1"
  wait_for 60 "seed node profile banner" grep -q "private/isolated DASH sharechain profile: mints share v36" "$SL"
  wait_for 90 "seed node reloads $COUNT shares" grep -q "Loaded $COUNT persisted DASH shares" "$SL"
  wait_for 30 "seed node seeds best from the persisted chain" grep -q "Seeded best share from persisted chain: ${TIP:0:16}" "$SL"
  wait_for 60 "seed node web" synced "${WEB[$SEED]}" "$TIP" "$COUNT"
  pass "1b seed node $SEED: $(grep -m1 -o "Loaded $COUNT persisted DASH shares.*" "$SL")"

  # ── 2. sync over the real socket ──────────────────────────────────────────
  t0=$SECONDS
  start_node "$FOLLOW" 1 --connect "127.0.0.1:${P2P[$SEED]}"
  local FL="$D/$FOLLOW.log.1"
  wait_for 90 "$FOLLOW<->$SEED peering" peers_ge "${WEB[$SEED]}" 1
  wait_for 240 "$FOLLOW downloads + verifies all $COUNT shares, tip ${TIP:0:16}" synced "${WEB[$FOLLOW]}" "$TIP" "$COUNT"
  local RX; RX=$(grep -o "Received [0-9]* share(s)" "$FL" | awk '{s+=$2} END {print s+0}')
  [ "$(count "share from .* rejected" "$FL")" = 0 ] || { grep -m5 "share from .* rejected" "$FL"; fail "follower rejected shares"; }
  [ "$(count "banning peer" "$FL")$(count "banning peer" "$SL")" = "00" ] || fail "a node banned its peer"
  pass "2 sync: $FOLLOW downloaded the chain over the socket in $((SECONDS - t0)) s (replies carried $RX shares incl. re-requests), all $COUNT verified (V=36, v=1), tip ${TIP:0:16}; 0 rejected, 0 bans"
  grep -m3 "Received [0-9]* share(s)" "$FL" | sed 's/^/   /'

  # ── 3. identical coinbases ────────────────────────────────────────────────
  local PA PB PM
  PA=$(payouts "${WEB[A]}"); PB=$(payouts "${WEB[B]}")
  PM=$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["expected_current_payouts"], sort_keys=True))' "$MF")
  [ -n "$PA" ] && [ "$PA" != "{}" ] || fail "empty /current_payouts on A"
  [ "$PA" = "$PB" ] || fail "/current_payouts differ: A=$PA B=$PB"
  [ "$PA" = "$PM" ] || fail "/current_payouts != seeder expected: node=$PA seeder=$PM"
  window "${WEB[A]}" >"$D/window.A"; window "${WEB[B]}" >"$D/window.B"
  cmp -s "$D/window.A" "$D/window.B" || { diff "$D/window.A" "$D/window.B" | head; fail "/sharechain/window differs"; }
  pass "3 coinbase: /current_payouts identical on A and B and equal to the seeder's split: $PA"
  pass "3 window: /sharechain/window identical on A and B ($(($(wc -l <"$D/window.A") - 1)) shares, sha256 $(sha256sum "$D/window.A" | cut -c1-16))"

  # ── 4. restart the follower ───────────────────────────────────────────────
  stop "$FOLLOW"
  start_node "$FOLLOW" 2 --connect "127.0.0.1:${P2P[$SEED]}"
  local FL2="$D/$FOLLOW.log.2"
  wait_for 90 "$FOLLOW reloads $COUNT shares pre_verified=$COUNT" \
    grep -Eq "Loaded $COUNT persisted DASH shares .*pre_verified=$COUNT " "$FL2"
  wait_for 30 "$FOLLOW seeds the tip from its store" grep -q "Seeded best share from persisted chain: ${TIP:0:16}" "$FL2"
  wait_for 90 "$FOLLOW re-peers" peers_ge "${WEB[$FOLLOW]}" 1
  wait_for 60 "$FOLLOW window after restart" synced "${WEB[$FOLLOW]}" "$TIP" "$COUNT"
  sleep 10
  [ "$(count "Received [0-9]* share(s)" "$FL2")" = 0 ] || fail "restarted follower re-downloaded shares"
  pass "4 restart: $(grep -m1 -o "Loaded $COUNT persisted DASH shares.*" "$FL2"); tip kept, re-peered, 0 shares re-downloaded"

  # ── 5. the emergency-decay share ──────────────────────────────────────────
  local SI; SI=$(manifest "$MF" '["stall_index"]')
  if [ "$SI" -ge 0 ]; then
    local SH SMB NMB
    SH=$(manifest "$MF" "[\"shares\"][$SI][\"hash\"]")
    SMB=$(manifest "$MF" "[\"shares\"][$SI][\"max_bits\"]")
    NMB=$(manifest "$MF" "[\"shares\"][$SI][\"no_stall_job_max_bits\"]")
    python3 - "$SMB" "$NMB" <<'PY' || fail "stall share max_bits not easier than the no-stall job"
import sys
def t(b):
    b = int(b); return (b & 0xffffff) << (8 * ((b >> 24) - 3))
sys.exit(0 if t(sys.argv[1]) > t(sys.argv[2]) else 1)
PY
    grep -q " $SH V=36 .* v=1 " "$D/window.A" && grep -q " $SH V=36 .* v=1 " "$D/window.B" \
      || fail "stall share not verified on both nodes"
    pass "5 stall: share #$SI ${SH:0:16} (700 s gap) max_bits=$(printf %08x "$SMB") vs no-stall job $(printf %08x "$NMB") (easier), verified on A and B"
  else
    echo "E2E SKIP: 5 stall (COUNT < 104)"
  fi

  # ── 6. old peers (p2pool-dash 1700, build without v36 isolated support 3600) at the handshake
  # grep the ASCII part of the refusal only (the full line carries an em dash).
  local REFUSE="peer build lacks v36 isolated support"
  local before; before=$(count "disconnected: peer protocol below min-protocol floor" "$SL")
  local ubefore; ubefore=$(count "$REFUSE" "$SL")
  local R1700 R3600 R3601
  R1700=$(python3 "$HERE/dash_v36_peer_standin.py" --port "${P2P[$SEED]}" --prefix "$PREFIX" --proto 1700 --hold 5)
  R3600=$(python3 "$HERE/dash_v36_peer_standin.py" --port "${P2P[$SEED]}" --prefix "$PREFIX" --proto 3600 --hold 5)
  R3601=$(python3 "$HERE/dash_v36_peer_standin.py" --port "${P2P[$SEED]}" --prefix "$PREFIX" --proto 3601 --hold 5)
  case "$R1700" in "EOF after"*) ;; *) fail "1700 peer not refused: $R1700" ;; esac
  case "$R3600" in "EOF after"*) ;; *) fail "3600 peer (build without v36 isolated support) not refused: $R3600" ;; esac
  case "$R3601" in "still open"*) ;; *) fail "3601 peer not admitted: $R3601" ;; esac
  wait_for 10 "seed log records both floor refusals" \
    sh -c "[ \$(grep -c 'disconnected: peer protocol below min-protocol floor' '$SL') -ge $((before + 2)) ]"
  wait_for 10 "seed log names the missing v36 isolated support twice" \
    sh -c "[ \$(grep -c '$REFUSE' '$SL') -ge $((ubefore + 2)) ]"
  [ "$(count "banning peer" "$SL")" = 0 ] || fail "seed node banned a peer"
  peers_ge "${WEB[$SEED]}" 1 || fail "the real pair lost its peering"
  alive "$SEED" && alive "$FOLLOW" || fail "a node died"
  pass "6 old peers: proto 1700 -> '$R1700'; proto 3600 -> '$R3600'; proto 3601 -> '$R3601'; seed node: 0 bans, real pair still peered"
  grep "$REFUSE" "$SL" | tail -2 | sed 's/^/   /'

  # ── 7. master-built node ──────────────────────────────────────────────────
  if [ -n "$MASTER_BIN" ]; then
    local mbefore; mbefore=$(count "$REFUSE" "$SL")
    start M "$D/M.log" "$MASTER_BIN" "${COMMON[@]}" --data-dir "$D/M" --listen 127.0.0.1:19813 \
      --web-port 19093 --stratum 127.0.0.1:19923 --connect "127.0.0.1:${P2P[$SEED]}"
    wait_for 90 "seed node refuses the master build at the handshake" \
      sh -c "[ \$(grep -c '$REFUSE' '$SL') -gt $mbefore ]"
    sleep 20
    local MR; MR=$(( $(count "$REFUSE" "$SL") - mbefore ))
    [ "$(count "version unsupported" "$D/M.log")" = 0 ] \
      || { grep -m3 "version unsupported" "$D/M.log"; fail "master node was sent type-36 shares"; }
    local MT; MT=$(get 19093 /sharechain/window | jget '["total"]' 2>/dev/null)
    [ "${MT:-0}" = 0 ] || fail "master node holds $MT shares of the v36 chain"
    [ "$(count "banning peer" "$D/M.log")$(count "banning peer" "$SL")" = "00" ] || fail "ban on master interop"
    alive M && alive "$SEED" || fail "a node died on master interop"
    # Not a single sample: the master build redials, and on each connect the two
    # version messages cross (it may register the seed for a moment before EOF).
    wait_for 15 "master node is not left peered after the refusal" peers_zero 19093
    peers_ge "${WEB[$SEED]}" 1 || fail "the real pair lost its peering"
    pass "7a master (same identity): refused at handshake ('$REFUSE') x$MR, 'version unsupported' x0, 0 shares, 0 bans, master unpeered"
    grep "$REFUSE" "$SL" | tail -1 | sed 's/^/   /'
    stop M
    local pbefore; pbefore=$(count "prefix doesn't match" "$SL")
    start P "$D/P.log" "$MASTER_BIN" --run --testnet --web-host 127.0.0.1 --coin-p2p-connect 127.0.0.1:1 \
      --data-dir "$D/P" --listen 127.0.0.1:19814 --web-port 19094 --stratum 127.0.0.1:19924 \
      --connect "127.0.0.1:${P2P[$SEED]}"
    wait_for 90 "seed node drops the public-identity peer on its prefix" \
      sh -c "[ \$(grep -c \"prefix doesn't match\" '$SL') -gt $pbefore ]"
    alive "$SEED" || fail "seed node died"
    pass "7b master (public testnet identity): refused at framing"
    grep -m1 "prefix doesn't match" "$SL" | sed 's/^/   /'
    stop P
  else
    echo "E2E SKIP: 7 master interop (MASTER_BIN unset)"
  fi

  stop "$FOLLOW"; stop "$SEED"
  pass "genesis held by $SEED: all phases"
}

run_once A
run_once B

EXT=$(grep -h "COIN-P2P\] connected to" "$W"/genesis-*/*.log* 2>/dev/null | grep -vc "connected to 127\.0\.0\.1" || true)
[ "$EXT" = "0" ] || fail "a node dialled $EXT non-loopback coin peer(s)"
pass "8 rig stayed on loopback: 0 non-loopback coin-p2p connections"
echo "E2E ALL PASSED"
