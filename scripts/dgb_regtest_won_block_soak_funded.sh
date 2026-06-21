#!/usr/bin/env bash
# dgb_regtest_won_block_soak_funded.sh -- DGB #82 TX-BEARING won-block dual-path soak.
#
# Sibling of dgb_regtest_won_block_soak.sh. That script proves PROP-1 (coinbase-only
# is ACCEPTED, not a silent malformed-block drop). This script proves the stronger,
# #82-closeable bar from integrator (UID1801/UID1817): a won block carrying a
# NON-coinbase tx must be reconstructed (#300 per-job template-capture + #302
# merkle-link + #303 captured-tx wiring) and ACCEPTED by a peer down BOTH arms.
#
#   ASSERT: won block on node B has NTX >= 2 (coinbase + >=1 funded tx), both arms.
#
# BIP141 ISOLATION (legacy txs first, per integrator): the maturity coinbases AND
# the funded spend both use LEGACY (P2PKH) addresses, so the funded tx carries NO
# witness data. This isolates plain tx-inclusion + merkle-path correctness from the
# segwit witness-commitment path; a segwit-tx variant is a follow-up only after this
# legacy gate is green.
#
# PER-COIN ISOLATION: DGB only. Localhost-only. Self-service creds. Ports outside the
# bitcoin-family 1844x regtest band.
set -euo pipefail

CLI_BIN="${DGB_CLI:-digibyte-cli}"
DAEMON_BIN="${DGB_DAEMON:-digibyted}"
C2POOL_DGB="${C2POOL_DGB:-c2pool-dgb}"

DATADIR_A="${DGB_REGTEST_DATADIR:-$HOME/.c2pool-dgb-regtest-funded}"
DATADIR_B="${DATADIR_A}-peer"
RPCPORT_A=${DGB_RPCPORT_A:-18863}
RPCPORT_B=${DGB_RPCPORT_B:-18873}
P2PPORT_A=${DGB_P2PPORT_A:-18864}
P2PPORT_B=${DGB_P2PPORT_B:-18874}
PAYOUT_LABEL="c2pool-soak-funded"

log()  { echo "[dgb-funded-soak $(printf "%(%H:%M:%S)T")] $*" >&2; }
die()  { echo "[dgb-funded-soak FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing binary: $1"; }

cli_a() { "$CLI_BIN" -regtest -datadir="$DATADIR_A" -rpcport=$RPCPORT_A "$@"; }
cli_b() { "$CLI_BIN" -regtest -datadir="$DATADIR_B" -rpcport=$RPCPORT_B "$@"; }

C2POOL_PID=""
cleanup() {
  [ -n "$C2POOL_PID" ] && kill "$C2POOL_PID" >/dev/null 2>&1 || true
  cli_a stop >/dev/null 2>&1 || true
  cli_b stop >/dev/null 2>&1 || true
}
trap cleanup EXIT

need "$DAEMON_BIN"; need "$CLI_BIN"; need "$C2POOL_DGB"; need openssl

provision() {
  local dd="$1" rpcport="$2"
  # fresh datadir each run -> predictable heights, no mempool/chain carryover
  rm -rf "$dd"
  mkdir -p "$dd"; chmod 700 "$dd"
  if [ ! -f "$dd/digibyte.conf" ]; then
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
  fi
}
provision "$DATADIR_A" "$RPCPORT_A"
provision "$DATADIR_B" "$RPCPORT_B"

wait_rpc() { local n=0; until "$@" getblockcount >/dev/null 2>&1; do n=$((n+1)); [ $n -gt 60 ] && die "rpc never came up: $*"; sleep 0.5; done; }
tip_b() { cli_b getblockcount; }
mempool_a() { cli_a getmempoolinfo | grep -o '"size"[^,]*' | grep -o '[0-9]\+'; }

ntx_of() { # ntx_of <cli_fn> <blockhash> -> number of txs in block
  local fn="$1" h="$2"
  "$fn" getblock "$h" | tr -d '\n' | grep -o '"tx"[^]]*]' | grep -o '"[0-9a-f]\{64\}"' | wc -l
}

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

# --- substrate: two peered regtest nodes --------------------------------------
log "starting node A (regtest RPC $RPCPORT_A / P2P $P2PPORT_A)"
"$DAEMON_BIN" -regtest -dandelion=0 -datadir="$DATADIR_A" -rpcport=$RPCPORT_A -port=$P2PPORT_A -daemon >/dev/null
wait_rpc cli_a
log "starting node B (regtest RPC $RPCPORT_B / P2P $P2PPORT_B), peering to A"
"$DAEMON_BIN" -regtest -dandelion=0 -datadir="$DATADIR_B" -rpcport=$RPCPORT_B -port=$P2PPORT_B \
              -connect=127.0.0.1:$P2PPORT_A -daemon >/dev/null
wait_rpc cli_b

cli_a createwallet "$PAYOUT_LABEL" >/dev/null 2>&1 || cli_a loadwallet "$PAYOUT_LABEL" >/dev/null 2>&1 || true
# LEGACY (P2PKH) coinbase + spend -> funded tx carries no witness (BIP141 isolated).
ADDR_A="$(cli_a getnewaddress "$PAYOUT_LABEL" legacy)"
# Mine 110 so blocks 1..10 coinbases are mature (spendable) -> enough legacy UTXOs
# to fund a distinct tx for each arm without a 100-block re-wait between arms.
log "mining 110 maturity blocks to legacy addr $ADDR_A"
cli_a generatetoaddress 110 "$ADDR_A" >/dev/null
HEIGHT_A="$(cli_a getblockcount)"
n=0; until [ "$(tip_b)" -ge "$HEIGHT_A" ]; do
  n=$((n+1)); [ $n -gt 120 ] && die "node B never synced to A height $HEIGHT_A (got $(tip_b))"; sleep 0.5
done

DGB_REGTEST_GENESIS="$(cli_a getblockhash 0)"
: "${DGB_REGTEST_MAGIC:=fabfb5da}"

# fund_mempool_legacy -- broadcast ONE legacy (non-witness) tx into node A mempool
# and confirm it landed (via getrawmempool, unambiguous), so the c2pool
# getblocktemplate capture includes it. Sets global FUNDED_TXID. NOTE: must run in
# the PARENT shell (NOT a $() subshell) so a die() actually aborts the soak.
FUNDED_TXID=""
fund_mempool_legacy() {
  local dest amt
  dest="$(cli_a getnewaddress funded legacy)"
  amt="1.0"
  local sendout; sendout="$(cli_a sendtoaddress "$dest" "$amt" 2>&1)" || true
  FUNDED_TXID="$sendout"
  log "DEBUG send dest=$dest -> [$sendout]"
  # NB: no `cli | grep -q` -- grep -q closes the pipe early, SIGPIPEs cli, and under
  # `set -o pipefail` the pipeline reports failure even on a match. Capture + match.
  local n=0 mp; until mp="$(cli_a getrawmempool 2>&1)"; [[ "$mp" == *"$FUNDED_TXID"* ]]; do
    n=$((n+1)); [ $n -gt 40 ] && { log "DEBUG rawmempool=[$mp] mempoolinfo=[$(cli_a getmempoolinfo 2>&1 | tr '\n' ' ')] balance=[$(cli_a getbalance 2>&1)]"; die "funded tx $FUNDED_TXID never appeared in node A mempool"; }; sleep 0.25
  done
  # legacy/no-witness assertion via raw-tx serialization: a segwit tx carries
  # the BIP144 marker+flag (0001) immediately after the 4-byte version; a legacy
  # tx has its input-count varint there instead. (Core removed getmempoolentry's
  # "size" field, so the old size==vsize discriminator is no longer queryable.)
  local rawhex marker
  rawhex="$(cli_a getrawtransaction "$FUNDED_TXID")"
  marker="${rawhex:8:4}"
  [ "$marker" != "0001" ] || die "funded tx $FUNDED_TXID carries a witness (marker=$marker) -- BIP141 isolation broken"
  log "funded legacy tx $FUNDED_TXID in node A mempool (no-witness marker ok); mempool size=$(mempool_a)"
}

# run_arm -- runs in the PARENT shell (no $() capture) so die() aborts. Sets global
# ARM_WON to the accepted block hash.
ARM_WON=""
run_arm() { # run_arm <label> <extra c2pool flags> <logfile>
  local label="$1" extra="$2" logf="$3" base won ntx
  base="$(tip_b)"
  fund_mempool_legacy
  log "ARM $label: arming c2pool-dgb (funded mempool has the legacy tx) $extra"
  "$C2POOL_DGB" --run \
    --coin-daemon 127.0.0.1:$P2PPORT_A \
    --coin-rpc 127.0.0.1:$RPCPORT_A \
    --coin-rpc-auth "$DATADIR_A/digibyte.conf" \
    --coin-magic "$DGB_REGTEST_MAGIC" \
    --coin-genesis "$DGB_REGTEST_GENESIS" --regtest --regtest-force-won-share \
    --soak-regrind $extra >"$logf" 2>&1 &
  C2POOL_PID=$!
  log "ARM $label: c2pool-dgb PID $C2POOL_PID; waiting for tx-bearing won block on node B"
  local n=0
  until [ "$(tip_b)" -gt "$base" ]; do
    n=$((n+1)); [ $n -gt 240 ] && die "ARM $label: no won block reached node B within 120s"
    sleep 0.5
  done
  won="$(cli_b getblockhash "$(tip_b)")"
  ntx="$(ntx_of cli_b "$won")"
  [ "$ntx" -ge 2 ] || die "ARM $label: won block $won has $ntx txs, expected >=2 (coinbase + funded legacy tx) -- captured-template tx-wire (#300/#302/#303) did not carry the mempool tx into the reconstructed block"
  local blk; blk="$(cli_b getblock "$won")"
  [[ "$blk" == *"$FUNDED_TXID"* ]] \
    || die "ARM $label: funded tx $FUNDED_TXID not present in accepted block $won"
  log "ARM $label OK: tx-bearing won block $won ($ntx txs incl funded $FUNDED_TXID) ACCEPTED by peer node B"
  kill "$C2POOL_PID" >/dev/null 2>&1; C2POOL_PID=""
  ARM_WON="$won"
}

run_arm "A (P2P primary)" "" /tmp/c2pool-dgb-funded-soak-arma.log
WON_A="$ARM_WON"
run_arm "B (submitblock isolated)" "--no-p2p-relay" /tmp/c2pool-dgb-funded-soak-armb.log
WON_B="$ARM_WON"

log "BOTH ARMS PROVEN (TX-BEARING): ARM A (P2P relay) block $WON_A + ARM B (submitblock isolated) block $WON_B each carry a funded legacy tx and were ACCEPTED by peer node B. #82 tx-bearing dual-path gate satisfied."
echo "FUNDED_SOAK_RESULT armA=$WON_A armB=$WON_B"
