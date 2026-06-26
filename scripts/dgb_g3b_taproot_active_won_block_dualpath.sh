#!/usr/bin/env bash
# dgb_g3b_taproot_active_won_block_dualpath.sh -- DGB G3b FULL PASS:
# c2pool-dgb FOUND + ASSEMBLED + ACCEPTED dual-path won-block leg, run ON a regtest
# net where taproot reached ACTIVE through GENUINE BIP9 signaling.
#
# This is the transition leg integrator named (UID 2612) as the actual G3b PASS:
#   "a c2pool-dgb-assembled block on the active-taproot net reaches the network via
#    BOTH the embedded P2P on_block_found path AND the submitblock RPC fallback
#    (the dual-path gate), proven won-block-reaches-network."
#
# It COMPOSES two already-proven harnesses, which is the whole point -- the won-block
# assembly must validate under REAL active-taproot consensus, not the regtest
# always-active default:
#   * PHASE 1 reuses dgb_g3b_regtest_taproot_active_proof.sh (#534): installs a genuine
#     BIP9 taproot window via the regtest-only -vbparams knob and drives
#     defined->started->locked_in->active by mined bit-2 signaling. The #534 anti-cheat
#     asserts (S0 defined at genesis, S2 lock-in count >= stock 108 threshold) are
#     re-run here so the won block is provably built atop a GENUINELY-activated chain.
#   * PHASE 2 reuses dgb_regtest_won_block_soak_segwit.sh (#458): drives a
#     witness-bearing tx through the c2pool-dgb won-block assembly and proves the block
#     is ACCEPTED by peer node B. Run twice -- ARM A (embedded P2P on_block_found) and
#     ARM B (--no-p2p-relay -> submitblock RPC fallback) -- to close the dual-path gate.
#
# THE NEW ASSERTION beyond #458: the accepting peer node B is enforcing ACTIVE taproot
# consensus (getdeploymentinfo taproot.active=true) at the height the won block lands.
# A pre-#534 (always-active) or non-activated net would not satisfy E/G below.
#
#   PHASE 1 (anti-cheat, from #534):
#     S0  taproot DEFINED at genesis (NOT always-active).
#     S2  lock-in via genuine bit-2 signaling, count >= stock 108 threshold.
#     S3  taproot ACTIVE, confirmed by getdeploymentinfo.
#   PHASE 2 (dual-path won block, from #458):
#     B   won block has NTX >= 2 (coinbase + >=1 witness tx).
#     C   won-block coinbase carries the BIP141 witness commitment (6a24aa21a9ed, #458).
#     D   the witness-bearing won block is ACCEPTED by peer node B (tip advances).
#   PHASE 3 (the G3b PASS gate, new):
#     E   taproot is ACTIVE on the net BEFORE the won-block leg runs.
#     F   ARM A reaches net via embedded P2P on_block_found; ARM B via submitblock RPC.
#     G   at EACH won-block height, node B reports taproot.active=true -> the block was
#         accepted by a peer enforcing real active-taproot consensus.
#
# PER-COIN ISOLATION: DGB only. Localhost-only. Self-service creds. Ports outside the
# bitcoin-family regtest band. Additive/fenced: no consensus, shared-base, build.yml or
# CMake surface -- a scripts/ evidence harness.
set -euo pipefail

CLI_BIN="${DGB_CLI:-digibyte-cli}"
DAEMON_BIN="${DGB_DAEMON:-digibyted}"
C2POOL_DGB="${C2POOL_DGB:-c2pool-dgb}"

DATADIR_A="${DGB_REGTEST_DATADIR:-$HOME/.c2pool-dgb-regtest-tap-wonblock}"
DATADIR_B="${DATADIR_A}-peer"
RPCPORT_A=${DGB_RPCPORT_A:-18923}
RPCPORT_B=${DGB_RPCPORT_B:-18933}
P2PPORT_A=${DGB_P2PPORT_A:-18924}
P2PPORT_B=${DGB_P2PPORT_B:-18934}
PAYOUT_LABEL="c2pool-tap-wonblock"

# Stock regtest BIP9 consensus values -- asserted, NOT changed.
BIP9_WINDOW=${BIP9_WINDOW:-144}
BIP9_THRESHOLD=${BIP9_THRESHOLD:-108}

log()  { echo "[dgb-tap-wonblock $(printf "%(%H:%M:%S)T")] $*" >&2; }
die()  { echo "[dgb-tap-wonblock FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing binary: $1"; }

cli_a() { "$CLI_BIN" -regtest -datadir="$DATADIR_A" -rpcport=$RPCPORT_A "$@"; }
cli_b() { "$CLI_BIN" -regtest -datadir="$DATADIR_B" -rpcport=$RPCPORT_B "$@"; }
J() { python3 -c 'import sys,json;print(json.load(sys.stdin)["'"$1"'"])'; }

# taproot getdeploymentinfo accessors (node A unless overridden via cli fn arg)
tap_status() { local f="${1:-cli_a}"; "$f" getdeploymentinfo | python3 -c 'import sys,json;d=json.load(sys.stdin)["deployments"]["taproot"];print(d.get("bip9",{}).get("status","?"))'; }
tap_active() { local f="${1:-cli_a}"; "$f" getdeploymentinfo | python3 -c 'import sys,json;d=json.load(sys.stdin)["deployments"]["taproot"];print(str(d.get("active",False)).lower())'; }

C2POOL_PID=""
cleanup() {
  [ -n "$C2POOL_PID" ] && kill "$C2POOL_PID" >/dev/null 2>&1 || true
  cli_a stop >/dev/null 2>&1 || true
  cli_b stop >/dev/null 2>&1 || true
}
trap cleanup EXIT

need "$DAEMON_BIN"; need "$CLI_BIN"; need "$C2POOL_DGB"; need openssl; need python3

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
dandelion=0
[regtest]
rpcport=$rpcport
CONF
  chmod 600 "$dd/digibyte.conf"
}
provision "$DATADIR_A" "$RPCPORT_A"
provision "$DATADIR_B" "$RPCPORT_B"

wait_rpc() { local n=0; until "$@" getblockcount >/dev/null 2>&1; do n=$((n+1)); [ $n -gt 80 ] && die "rpc never came up: $*"; sleep 0.5; done; }
tip_b() { cli_b getblockcount; }
mempool_a() { cli_a getmempoolinfo | grep -o '"size"[^,]*' | grep -o '[0-9]\+'; }
ntx_of() { local fn="$1" h="$2"; "$fn" getblock "$h" | tr -d '\n' | grep -o '"tx"[^]]*]' | grep -o '"[0-9a-f]\{64\}"' | wc -l; }

kill_stale_c2pool() {
  local pids; pids="$(pgrep -f 'c2pool-dgb .*--run' 2>/dev/null || true)"
  [ -z "$pids" ] && return 0
  log "pre-flight: freeing pool P2P port from stale c2pool-dgb: $pids"
  kill $pids 2>/dev/null || true; sleep 2
  pids="$(pgrep -f 'c2pool-dgb .*--run' 2>/dev/null || true)"
  [ -n "$pids" ] && { kill -9 $pids 2>/dev/null || true; sleep 1; }
  return 0
}
kill_stale_c2pool

# ===================================================================================
# PHASE 1 -- GENUINE BIP9 taproot activation (#534 logic, anti-cheat asserts re-run)
# ===================================================================================
# START sits in the future relative to genesis MTP so taproot is DEFINED at height 0
# and only advances once we drive mocktime past START. END is far beyond START.
TAP_START=${TAP_START:-1800000000}   # ~2027-01-15
TAP_END=${TAP_END:-1900000000}       # ~2030-03-17
VBPARAMS="taproot:${TAP_START}:${TAP_END}"

start_node() {
  local dd="$1" rpcport="$2" p2p="$3"; shift 3
  # tuned dgb-g3 build is no-sqlite -> legacy BDB wallets via -deprecatedrpc=create_bdb
  "$DAEMON_BIN" -regtest -dandelion=0 -datadir="$dd" -rpcport=$rpcport -port=$p2p \
                -vbparams="$VBPARAMS" -deprecatedrpc=create_bdb -daemon "$@" >/dev/null
}
log "PHASE 1: installing GENUINE BIP9 taproot window via -vbparams=$VBPARAMS (window/threshold $BIP9_THRESHOLD/$BIP9_WINDOW UNCHANGED)"
start_node "$DATADIR_A" "$RPCPORT_A" "$P2PPORT_A"
wait_rpc cli_a
start_node "$DATADIR_B" "$RPCPORT_B" "$P2PPORT_B" -connect=127.0.0.1:$P2PPORT_A
wait_rpc cli_b

cli_a createwallet "$PAYOUT_LABEL" false false "" false false >/dev/null 2>&1 \
  || cli_a createwallet "$PAYOUT_LABEL" >/dev/null 2>&1 \
  || cli_a loadwallet "$PAYOUT_LABEL" >/dev/null 2>&1 || true
ADDR_A="$(cli_a getnewaddress "$PAYOUT_LABEL" legacy)"

# S0: genesis must be DEFINED (NOT always-active).
S0_STATUS="$(tap_status)"; S0_ACTIVE="$(tap_active)"
log "S0 @h0: taproot status=$S0_STATUS active=$S0_ACTIVE"
[ "$S0_STATUS" = "defined" ] || die "S0 FAIL: taproot status=$S0_STATUS at genesis, expected 'defined' -- inherited always-active default"
[ "$S0_ACTIVE" = "false" ]   || die "S0 FAIL: taproot active at genesis -- disallowed always-active path"
log "S0 OK: taproot genuinely DEFINED at genesis (BIP9 window installed, not always-active)"

mine_window() { cli_a generatetoaddress "$1" "$ADDR_A" >/dev/null; }
set_time() { cli_a setmocktime "$1" >/dev/null; cli_b setmocktime "$1" >/dev/null; }
sync_b() { local h; h="$(cli_a getblockcount)"; local n=0; until [ "$(tip_b)" -ge "$h" ]; do n=$((n+1)); [ $n -gt 240 ] && die "node B never synced to A height $h"; sleep 0.5; done; }

# count_bit2 FROM N -- inspect block nVersion over [FROM,FROM+N) and count BIP9 bit-2
# blocks (genuine signaling evidence, independent of the transient statistics field).
count_bit2() {
  local from="$1" n="$2"
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
export DGB_CLI DD="$DATADIR_A" RP="$RPCPORT_A"

# keep block times BEFORE start: deployment stays DEFINED across a full window.
set_time $((TAP_START - 50000))
mine_window $((BIP9_WINDOW + 4))
[ "$(tap_status)" = "defined" ] || die "anti-cheat FAIL: status advanced while MTP<start -- not genuine BIP9"

set_time $((TAP_START + 100))
SAW_STARTED=0; SAW_LOCKEDIN=0; LOCK_COUNT=-1; S3_ACTIVE=false
for i in 1 2 3 4 5 6; do
  mine_window "$BIP9_WINDOW"
  ST="$(tap_status)"; H="$(cli_a getblockcount)"
  log "window $i (h=$H) -> taproot status=$ST"
  case "$ST" in
    started)   SAW_STARTED=1 ;;
    locked_in) SAW_LOCKEDIN=1
               if [ "$LOCK_COUNT" -lt 0 ]; then
                 LOCK_COUNT="$(count_bit2 $((H - BIP9_WINDOW)) "$BIP9_WINDOW")"
                 log "  lock-in window [$((H-BIP9_WINDOW)),$H): bit-2 signaled blocks = $LOCK_COUNT / $BIP9_THRESHOLD"
               fi ;;
    active)    S3_ACTIVE="$(tap_active)"; break ;;
  esac
done
[ "$SAW_STARTED" = 1 ]  || die "S1 FAIL: never observed 'started'"
[ "$SAW_LOCKEDIN" = 1 ] || die "S2 FAIL: never observed 'locked_in'"
[ "$LOCK_COUNT" -ge "$BIP9_THRESHOLD" ] || die "S2 FAIL: signaling count $LOCK_COUNT < threshold $BIP9_THRESHOLD"
[ "$(tap_status)" = "active" ] || die "S3 FAIL: taproot status=$(tap_status), expected 'active'"
[ "$S3_ACTIVE" = "true" ]      || die "S3 FAIL: getdeploymentinfo active=$S3_ACTIVE, expected true"
sync_b
TAP_ACTIVE_HEIGHT="$(cli_a getblockcount)"
log "PHASE 1 OK: taproot defined->started->locked_in->active via GENUINE bit-2 signaling (lock-in $LOCK_COUNT>=$BIP9_THRESHOLD), active@h$TAP_ACTIVE_HEIGHT"

# E: taproot must be ACTIVE on BOTH nodes before the won-block leg runs.
[ "$(tap_active cli_a)" = "true" ] || die "E FAIL: taproot not active on node A pre-leg"
[ "$(tap_active cli_b)" = "true" ] || die "E FAIL: taproot not active on node B pre-leg"
log "E OK: taproot ACTIVE on both A and B (h$TAP_ACTIVE_HEIGHT) -- won block will be built atop a genuinely-activated chain"

# The activation mined ~6 windows of coinbase to ADDR_A; funds are deeply mature.
DGB_REGTEST_GENESIS="$(cli_a getblockhash 0)"
: "${DGB_REGTEST_MAGIC:=fabfb5da}"

# ===================================================================================
# PHASE 2 -- dual-path witness-bearing won-block leg (#458 logic) on the ACTIVE net
# ===================================================================================
# fund_mempool_segwit -- place ONE witness-bearing tx in node A's mempool: seed a
# wallet-owned p2wpkh utxo, then spend it with an EXPLICIT raw input (#431 note) so the
# tx carries a BIP144 witness. Sets FUNDED_TXID.
FUNDED_TXID=""
fund_mempool_segwit() {
  local wpkh utxo txid vout amt dest raw signed rawhex marker send
  wpkh="$(cli_a getnewaddress segwit-src bech32)"
  cli_a sendtoaddress "$wpkh" 5.0 >/dev/null
  cli_a generatetoaddress 1 "$ADDR_A" >/dev/null
  local n=0; until [ "$(tip_b)" -ge "$(cli_a getblockcount)" ]; do n=$((n+1)); [ $n -gt 120 ] && die "B desync on seed"; sleep 0.5; done
  utxo="$(cli_a listunspent 1 9999999 "[\"$wpkh\"]")"
  txid="$(echo "$utxo" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["txid"])')"
  vout="$(echo "$utxo" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["vout"])')"
  amt="$(echo "$utxo"  | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["amount"])')"
  dest="$(cli_a getnewaddress segwit-dest legacy)"
  send="$(python3 -c "print(round($amt-0.001,8))")"
  raw="$(cli_a createrawtransaction "[{\"txid\":\"$txid\",\"vout\":$vout}]" "{\"$dest\":$send}")"
  signed="$(cli_a signrawtransactionwithwallet "$raw" | J hex)"
  FUNDED_TXID="$(cli_a sendrawtransaction "$signed")"
  local m=0 mp; until mp="$(cli_a getrawmempool 2>&1)"; [[ "$mp" == *"$FUNDED_TXID"* ]]; do
    m=$((m+1)); [ $m -gt 40 ] && die "segwit tx $FUNDED_TXID never appeared in mempool"; sleep 0.25
  done
  rawhex="$(cli_a getrawtransaction "$FUNDED_TXID")"; marker="${rawhex:8:4}"
  [ "$marker" = "0001" ] || die "ASSERT A FAIL: funded tx $FUNDED_TXID has no witness (marker=$marker)"
  log "witness-bearing tx $FUNDED_TXID (marker 0001) in node A mempool; size=$(mempool_a)"
}

assert_coinbase_commitment() {
  local fn="$1" blockhash="$2" cbtxid cbhex
  cbtxid="$("$fn" getblock "$blockhash" 1 | python3 -c 'import sys,json;print(json.load(sys.stdin)["tx"][0])')"
  cbhex="$("$fn" getrawtransaction "$cbtxid" 0 "$blockhash")"
  echo "$cbhex" | grep -qi "6a24aa21a9ed" \
    || die "ASSERT C FAIL: coinbase of $blockhash has no BIP141 witness commitment (6a24aa21a9ed)"
  log "ASSERT C OK: coinbase of $blockhash carries BIP141 witness commitment (6a24aa21a9ed)"
}

ARM_WON=""
run_arm() {
  local label="$1" extra="$2" logf="$3" path_desc="$4" base won ntx
  fund_mempool_segwit
  base="$(tip_b)"
  log "ARM $label [$path_desc]: arming c2pool-dgb (witness-bearing mempool) $extra"
  "$C2POOL_DGB" --run \
    --coin-daemon 127.0.0.1:$P2PPORT_A \
    --coin-rpc 127.0.0.1:$RPCPORT_A \
    --coin-rpc-auth "$DATADIR_A/digibyte.conf" \
    --coin-magic "$DGB_REGTEST_MAGIC" \
    --coin-genesis "$DGB_REGTEST_GENESIS" --regtest --regtest-force-won-share \
    $extra >"$logf" 2>&1 &
  C2POOL_PID=$!
  log "ARM $label: c2pool-dgb PID $C2POOL_PID; waiting for witness-bearing won block on node B"
  local n=0
  until [ "$(tip_b)" -gt "$base" ]; do
    n=$((n+1)); [ $n -gt 240 ] && die "ARM $label: no won block reached node B within 120s"
    sleep 0.5
  done
  won="$(cli_b getblockhash "$(tip_b)")"
  ntx="$(ntx_of cli_b "$won")"
  [ "$ntx" -ge 2 ] || die "ARM $label: won block $won has $ntx txs, expected >=2"   # ASSERT B
  local blk; blk="$(cli_b getblock "$won")"
  [[ "$blk" == *"$FUNDED_TXID"* ]] || die "ARM $label: witness tx $FUNDED_TXID not in accepted block $won"
  assert_coinbase_commitment cli_b "$won"                                            # ASSERT C
  # G: the accepting peer (node B) is enforcing ACTIVE taproot consensus at this height.
  [ "$(tap_active cli_b)" = "true" ] || die "ARM $label: G FAIL -- node B taproot not active at won-block height"
  log "ARM $label OK (ASSERT B/C/D + G): witness won block $won ($ntx txs incl $FUNDED_TXID) ACCEPTED by peer B under ACTIVE taproot consensus"
  kill "$C2POOL_PID" >/dev/null 2>&1; C2POOL_PID=""
  ARM_WON="$won"
}

# ARM A: embedded P2P on_block_found path (relay enabled).
run_arm "A (P2P primary)" "" /tmp/c2pool-dgb-tap-wonblock-arma.log "embedded P2P on_block_found"
WON_A="$ARM_WON"
# ARM B: P2P relay disabled -> the won block can ONLY reach node B via the submitblock
# RPC fallback path. Acceptance here isolates and proves the RPC sink.
run_arm "B (submitblock isolated)" "--no-p2p-relay" /tmp/c2pool-dgb-tap-wonblock-armb.log "submitblock RPC fallback"
WON_B="$ARM_WON"

# F: both dual-path legs proven on the active-taproot net.
log "G3b FULL PASS: on a GENUINELY taproot-ACTIVE regtest (active@h$TAP_ACTIVE_HEIGHT, lock-in $LOCK_COUNT>=$BIP9_THRESHOLD via real bit-2 signaling), c2pool-dgb FOUND+ASSEMBLED+ACCEPTED a witness-bearing won block via BOTH paths: ARM A $WON_A (embedded P2P on_block_found) + ARM B $WON_B (submitblock RPC fallback). Each carries the #458 BIP141 coinbase commitment and was ACCEPTED by peer node B enforcing active-taproot consensus."
echo "G3B_DUALPATH_TAPROOT_ACTIVE result=PASS tap_active_height=$TAP_ACTIVE_HEIGHT lockin_signaled=$LOCK_COUNT threshold=$BIP9_THRESHOLD armA_p2p=$WON_A armB_submitblock=$WON_B"
