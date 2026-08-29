#!/usr/bin/env bash
# dgb_g3b_regtest_taproot_active_proof.sh -- DGB G3b: GENUINE BIP9 taproot activation
# on an isolated regtest, driven defined -> started -> locked_in -> active by mined
# bit-2 blocks. This is the operator's "REAL consensus active on the isolated net"
# hard condition (integrator UID approving option (b), 2026-06-26).
#
# WHY THIS IS NEEDED, AND WHY IT IS NOT A CHEAT:
#   DGB regtest ships taproot as ALWAYS_ACTIVE (kernel/chainparams.cpp ~L655:
#   nStartTime = ALWAYS_ACTIVE). The operator/integrator bar EXPLICITLY rejects that
#   height-0 always-on default -- taproot must reach ACTIVE through genuine BIP9
#   signaling. Bitcoin/DGB Core expose exactly one regtest-only knob for this:
#       -vbparams=taproot:<start>:<end>
#   which INSTALLS a real BIP9 window on regtest (DEBUG_ONLY, regtest-gated -- see
#   chainparamsbase.cpp:20). Using it is the same category as the initialTarget
#   tuning already blessed for the isolated net: an isolated-net PARAMETER, not a
#   threshold relax (the 108/144 window + threshold are UNTOUCHED).
#
#   ANTI-CHEAT ASSERTIONS (a force-flip / always-active config would FAIL these):
#     S0  at genesis (height 0) taproot status == "defined"  AND  active == false
#         -> proves we did NOT inherit the always-active default.
#     S1  after crossing a period boundary with MTP >= start: status == "started".
#     S2  after one signaling window: status == "locked_in" AND statistics.count
#         >= the real 108 threshold (genuine bit-2 miner signaling, not forced).
#     S3  after the activation window: status == "active" AND active == true,
#         confirmed by getdeploymentinfo.
#
# The 108/144 BIP9 threshold/window are the stock regtest consensus values
# (nRuleChangeActivationThreshold=108, nMinerConfirmationWindow=144) -- NOT relaxed.
# Only the start/end times are set (the window must exist to be signaled at all).
#
# PER-COIN ISOLATION: DGB only. Localhost-only. Self-service creds. Ports outside the
# bitcoin-family regtest band. Additive/fenced: no consensus, shared-base, build.yml
# or CMake surface -- a scripts/ evidence harness.
set -euo pipefail

CLI_BIN="${DGB_CLI:-digibyte-cli}"
DAEMON_BIN="${DGB_DAEMON:-digibyted}"

DATADIR_A="${DGB_REGTEST_DATADIR:-$HOME/.c2pool-dgb-regtest-taproot}"
DATADIR_B="${DATADIR_A}-peer"
RPCPORT_A=${DGB_RPCPORT_A:-18903}
RPCPORT_B=${DGB_RPCPORT_B:-18913}
P2PPORT_A=${DGB_P2PPORT_A:-18904}
P2PPORT_B=${DGB_P2PPORT_B:-18914}

# Stock regtest BIP9 consensus values -- asserted, NOT changed.
BIP9_WINDOW=${BIP9_WINDOW:-144}
BIP9_THRESHOLD=${BIP9_THRESHOLD:-108}

log()  { echo "[dgb-taproot $(printf "%(%H:%M:%S)T")] $*" >&2; }
die()  { echo "[dgb-taproot FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing binary: $1"; }

cli_a() { "$CLI_BIN" -regtest -datadir="$DATADIR_A" -rpcport=$RPCPORT_A "$@"; }
cli_b() { "$CLI_BIN" -regtest -datadir="$DATADIR_B" -rpcport=$RPCPORT_B "$@"; }

# Parse getdeploymentinfo for taproot status / active / signaling count.
tap_status() { cli_a getdeploymentinfo | python3 -c 'import sys,json;d=json.load(sys.stdin)["deployments"]["taproot"];print(d.get("bip9",{}).get("status","?"))'; }
tap_active() { cli_a getdeploymentinfo | python3 -c 'import sys,json;d=json.load(sys.stdin)["deployments"]["taproot"];print(str(d.get("active",False)).lower())'; }
tap_count()  { cli_a getdeploymentinfo | python3 -c 'import sys,json;d=json.load(sys.stdin)["deployments"]["taproot"];print(d.get("bip9",{}).get("statistics",{}).get("count",-1))'; }
tap_bit()    { cli_a getdeploymentinfo | python3 -c 'import sys,json;d=json.load(sys.stdin)["deployments"]["taproot"];print(d.get("bip9",{}).get("bit",-1))'; }

cleanup() { cli_a stop >/dev/null 2>&1 || true; cli_b stop >/dev/null 2>&1 || true; }
trap cleanup EXIT

need "$DAEMON_BIN"; need "$CLI_BIN"; need openssl; need python3

provision() {
  local dd="$1" rpcport="$2"
  rm -rf "$dd"; mkdir -p "$dd"; chmod 700 "$dd"
  local pass; pass="$(openssl rand -hex 24)"
  cat > "$dd/digibyte.conf" <<CONF
regtest=1
server=1
rpcuser=c2pool
rpcpassword=$pass
fallbackfee=0.01
[regtest]
rpcport=$rpcport
CONF
  chmod 600 "$dd/digibyte.conf"
}
provision "$DATADIR_A" "$RPCPORT_A"
provision "$DATADIR_B" "$RPCPORT_B"

wait_rpc() { local n=0; until "$@" getblockcount >/dev/null 2>&1; do n=$((n+1)); [ $n -gt 80 ] && die "rpc never came up: $*"; sleep 0.5; done; }

# ---- choose a genuine BIP9 window -------------------------------------------------
# START sits in the future relative to the genesis median-time, so the deployment is
# DEFINED at height 0 and only advances once we drive mocktime past START. END is far
# beyond START so the window never times out mid-proof.
TAP_START=${TAP_START:-1800000000}   # ~2027-01-15
TAP_END=${TAP_END:-1900000000}       # ~2030-03-17
VBPARAMS="taproot:${TAP_START}:${TAP_END}"

start_node() {
  local dd="$1" rpcport="$2" p2p="$3"; shift 3
  # tuned dgb-g3 build is no-sqlite -> legacy BDB wallets via -deprecatedrpc=create_bdb
  "$DAEMON_BIN" -regtest -dandelion=0 -datadir="$dd" -rpcport=$rpcport -port=$p2p \
                -vbparams="$VBPARAMS" -deprecatedrpc=create_bdb -daemon "$@" >/dev/null
}
log "installing GENUINE BIP9 taproot window via -vbparams=$VBPARAMS (regtest-only knob; window/threshold $BIP9_THRESHOLD/$BIP9_WINDOW UNCHANGED)"
start_node "$DATADIR_A" "$RPCPORT_A" "$P2PPORT_A"
wait_rpc cli_a
start_node "$DATADIR_B" "$RPCPORT_B" "$P2PPORT_B" -connect=127.0.0.1:$P2PPORT_A
wait_rpc cli_b

# legacy BDB wallet (descriptors=false) -- tuned build lacks sqlite descriptor support
cli_a createwallet tap false false "" false false >/dev/null 2>&1 \
  || cli_a createwallet tap >/dev/null 2>&1 \
  || cli_a loadwallet tap >/dev/null 2>&1 || true
ADDR_A="$(cli_a getnewaddress tap legacy)"

GEN_TIME="$(cli_a getblock "$(cli_a getblockhash 0)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["time"])')"
log "regtest genesis time=$GEN_TIME ; taproot bit=$(tap_bit)"

# ---- S0: genesis must be DEFINED (NOT always-active) ------------------------------
S0_STATUS="$(tap_status)"; S0_ACTIVE="$(tap_active)"
log "S0 @h0: taproot status=$S0_STATUS active=$S0_ACTIVE"
[ "$S0_STATUS" = "defined" ] || die "S0 FAIL: taproot status=$S0_STATUS at genesis, expected 'defined' -- vbparams window did not install / inherited always-active default"
[ "$S0_ACTIVE" = "false" ] || die "S0 FAIL: taproot active=$S0_ACTIVE at genesis -- this is the disallowed always-active path"
log "S0 OK: taproot is genuinely DEFINED at genesis (not always-active) -- BIP9 window installed"

mine_window() { cli_a generatetoaddress "$1" "$ADDR_A" >/dev/null; }

# count_bit2 FROM N -- directly inspect block nVersion over [FROM, FROM+N) and count
# how many blocks set BIP9 bit 2 (taproot). This is genuine signaling evidence,
# independent of getdeploymentinfo's transient statistics field.
count_bit2() {
  local from="$1" n="$2"
  cli_a getblockhash "$from" >/dev/null
  python3 - "$from" "$n" <<'PY'
import sys,subprocess,json,os
frm=int(sys.argv[1]); n=int(sys.argv[2])
cli=[os.environ["DGB_CLI"],"-regtest","-datadir="+os.environ["DD"],"-rpcport="+os.environ["RP"]]
c=0
for h in range(frm,frm+n):
    bh=subprocess.check_output(cli+["getblockhash",str(h)]).decode().strip()
    v=json.loads(subprocess.check_output(cli+["getblockheader",bh]))["version"]
    if (v>>2)&1: c+=1
print(c)
PY
}
sync_b() { local h; h="$(cli_a getblockcount)"; local n=0; until [ "$(cli_b getblockcount)" -ge "$h" ]; do n=$((n+1)); [ $n -gt 240 ] && die "node B never synced to A height $h"; sleep 0.5; done; }
# set mocktime on BOTH nodes -- peer B must share A's clock or it rejects A's
# (future-dated) blocks as time-too-new and never syncs.
set_time() { cli_a setmocktime "$1" >/dev/null; cli_b setmocktime "$1" >/dev/null; }

# Keep block times BEFORE the start time: deployment stays DEFINED across a full window.
set_time $((TAP_START - 50000))
mine_window $((BIP9_WINDOW + 4))
DEF_STATUS="$(tap_status)"
log "after one window with MTP<start: taproot status=$DEF_STATUS (expect still 'defined')"
[ "$DEF_STATUS" = "defined" ] || die "anti-cheat FAIL: status advanced to $DEF_STATUS while MTP < start -- not genuine BIP9"

# ---- S1..S3: advance mocktime past start, then mine ONE window at a time so the
#      genuine defined->started->locked_in->active progression is OBSERVED at each
#      BIP9 boundary (not skipped by bulk mining). ------------------------------------
set_time $((TAP_START + 100))
SEQ="defined"          # the confirmed genesis/pre-start state
export DGB_CLI DD="$DATADIR_A" RP="$RPCPORT_A"
SAW_STARTED=0; SAW_LOCKEDIN=0; LOCK_COUNT=-1; S3_ACTIVE=false
for i in 1 2 3 4 5 6; do
  mine_window "$BIP9_WINDOW"
  ST="$(tap_status)"; H="$(cli_a getblockcount)"
  log "window $i (h=$H) -> taproot status=$ST"
  [ "$ST" = "${SEQ##* }" ] || SEQ="$SEQ -> $ST"
  case "$ST" in
    started)   SAW_STARTED=1 ;;
    locked_in) SAW_LOCKEDIN=1
               if [ "$LOCK_COUNT" -lt 0 ]; then
                 # the signaling window that locked us in == the 'started' window just closed
                 LOCK_COUNT="$(count_bit2 $((H - BIP9_WINDOW)) "$BIP9_WINDOW")"
                 log "  lock-in window [$((H-BIP9_WINDOW)),$H): bit-2 signaled blocks = $LOCK_COUNT / $BIP9_THRESHOLD"
               fi ;;
    active)    S3_ACTIVE="$(tap_active)"; break ;;
  esac
done
log "observed BIP9 progression: $SEQ"
[ "$SAW_STARTED" = 1 ]   || die "S1 FAIL: never observed 'started' -- start boundary not crossed genuinely"
[ "$SAW_LOCKEDIN" = 1 ]  || die "S2 FAIL: never observed 'locked_in' -- bit-2 signaling never reached threshold"
[ "$LOCK_COUNT" -ge "$BIP9_THRESHOLD" ] || die "S2 FAIL: signaling count $LOCK_COUNT < threshold $BIP9_THRESHOLD -- not genuine"
S3_STATUS="$(tap_status)"
[ "$S3_STATUS" = "active" ] || die "S3 FAIL: taproot status=$S3_STATUS, expected 'active'"
[ "$S3_ACTIVE" = "true" ]   || die "S3 FAIL: getdeploymentinfo active=$S3_ACTIVE, expected true"
S2_COUNT="$LOCK_COUNT"
sync_b
log "S1/S2/S3 OK: taproot defined->started->locked_in->active via GENUINE bit-2 signaling (lock-in count $LOCK_COUNT>=$BIP9_THRESHOLD), confirmed by getdeploymentinfo active=true"

HEIGHT="$(cli_a getblockcount)"
echo "TAPROOT_ACTIVE_PROOF result=PASS height=$HEIGHT path='defined->started->locked_in->active' window=$BIP9_WINDOW threshold=$BIP9_THRESHOLD signaled=$S2_COUNT genesis_status=$S0_STATUS"
log "G3b taproot-active hard condition SATISFIED on isolated regtest. Next: c2pool-dgb FOUND+ASSEMBLED+ACCEPTED dual-path won-block leg on this same active-taproot net (reuses dgb_regtest_won_block_soak_segwit.sh assembly)."
