#!/usr/bin/env bash
# dgb_regtest_won_block_soak_segwit.sh -- DGB G3b POPULATED (SegWit) won-block proof.
#
# The segwit-tx follow-up promised by dgb_regtest_won_block_soak_funded.sh. That
# legacy gate deliberately isolated plain tx-inclusion + merkle correctness from the
# BIP141 witness-commitment path. This script closes the witness path: it drives a
# WITNESS-BEARING tx through the c2pool-dgb won-block assembly and proves the block
# is ACCEPTED by a peer node.
#
# WHY THIS IS THE #458 PROOF: before PR #458, the reconstructed won block emitted a
# stripped (non-witness) coinbase while carrying a witness tx -> digibyted rejected it
# with "unexpected-witness" (bad-witness-nonce-size / unexpected witness data). #458
# injects the BIP141 coinbase witness commitment + reserved value when the block body
# carries any witness, so the block now validates. This harness FAILS on a pre-#458
# binary (won block never reaches node B -> timeout) and PASSES on #458 -- regtest only,
# NO scrypt rigs required (orthogonal to the rig-gated live testnet re-prove).
#
#   ASSERT A: funded tx carries a witness (BIP144 marker 0001) -- segwit path engaged.
#   ASSERT B: won block on node B has NTX >= 2 (coinbase + >=1 witness tx).
#   ASSERT C: won block coinbase carries the BIP141 witness commitment output
#             (scriptPubKey OP_RETURN 0x6a24 + magic aa21a9ed) -- the #458 injection.
#   ASSERT D: the witness-bearing won block is ACCEPTED by peer node B (tip advances).
#
# PER-COIN ISOLATION: DGB only. Localhost-only. Self-service creds. Ports outside the
# bitcoin-family 1844x regtest band. Additive/fenced: no consensus, shared-base,
# build.yml or CMake surface.
set -euo pipefail

CLI_BIN="${DGB_CLI:-digibyte-cli}"
DAEMON_BIN="${DGB_DAEMON:-digibyted}"
C2POOL_DGB="${C2POOL_DGB:-c2pool-dgb}"

DATADIR_A="${DGB_REGTEST_DATADIR:-$HOME/.c2pool-dgb-regtest-segwit}"
DATADIR_B="${DATADIR_A}-peer"
RPCPORT_A=${DGB_RPCPORT_A:-18883}
RPCPORT_B=${DGB_RPCPORT_B:-18893}
P2PPORT_A=${DGB_P2PPORT_A:-18884}
P2PPORT_B=${DGB_P2PPORT_B:-18894}
PAYOUT_LABEL="c2pool-soak-segwit"

log()  { echo "[dgb-segwit-soak $(printf "%(%H:%M:%S)T")] $*" >&2; }
die()  { echo "[dgb-segwit-soak FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing binary: $1"; }

cli_a() { "$CLI_BIN" -regtest -datadir="$DATADIR_A" -rpcport=$RPCPORT_A "$@"; }
cli_b() { "$CLI_BIN" -regtest -datadir="$DATADIR_B" -rpcport=$RPCPORT_B "$@"; }
J() { python3 -c 'import sys,json;print(json.load(sys.stdin)["'"$1"'"])'; }

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
  rm -rf "$dd"
  mkdir -p "$dd"; chmod 700 "$dd"
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

wait_rpc() { local n=0; until "$@" getblockcount >/dev/null 2>&1; do n=$((n+1)); [ $n -gt 60 ] && die "rpc never came up: $*"; sleep 0.5; done; }
tip_b() { cli_b getblockcount; }
mempool_a() { cli_a getmempoolinfo | grep -o '"size"[^,]*' | grep -o '[0-9]\+'; }

ntx_of() {
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

log "starting node A (regtest RPC $RPCPORT_A / P2P $P2PPORT_A)"
"$DAEMON_BIN" -regtest -dandelion=0 -datadir="$DATADIR_A" -rpcport=$RPCPORT_A -port=$P2PPORT_A -daemon >/dev/null
wait_rpc cli_a
log "starting node B (regtest RPC $RPCPORT_B / P2P $P2PPORT_B), peering to A"
"$DAEMON_BIN" -regtest -dandelion=0 -datadir="$DATADIR_B" -rpcport=$RPCPORT_B -port=$P2PPORT_B \
              -connect=127.0.0.1:$P2PPORT_A -daemon >/dev/null
wait_rpc cli_b

cli_a createwallet "$PAYOUT_LABEL" >/dev/null 2>&1 || cli_a loadwallet "$PAYOUT_LABEL" >/dev/null 2>&1 || true
# coinbase to LEGACY so maturity utxos are plain; the WITNESS comes from spending a
# wallet-owned bech32 (p2wpkh) utxo that we pre-seed below.
ADDR_A="$(cli_a getnewaddress "$PAYOUT_LABEL" legacy)"
log "mining 110 maturity blocks to legacy addr $ADDR_A"
cli_a generatetoaddress 110 "$ADDR_A" >/dev/null
HEIGHT_A="$(cli_a getblockcount)"
n=0; until [ "$(tip_b)" -ge "$HEIGHT_A" ]; do
  n=$((n+1)); [ $n -gt 120 ] && die "node B never synced to A height $HEIGHT_A (got $(tip_b))"; sleep 0.5
done

DGB_REGTEST_GENESIS="$(cli_a getblockhash 0)"
: "${DGB_REGTEST_MAGIC:=fabfb5da}"

# fund_mempool_segwit -- deterministically place ONE witness-bearing tx in node A's
# mempool. We pre-seed a wallet-owned p2wpkh utxo, then spend it with an EXPLICIT raw
# input (coin-selection is nondeterministic; #431 note: witness txs need explicit raw
# inputs) so the resulting tx carries a BIP144 witness. Sets global FUNDED_TXID.
FUNDED_TXID=""
fund_mempool_segwit() {
  local wpkh seed_txid raw signed
  wpkh="$(cli_a getnewaddress segwit-src bech32)"
  # seed: fund the bech32 addr from a mature legacy coinbase, confirm it
  cli_a sendtoaddress "$wpkh" 5.0 >/dev/null
  cli_a generatetoaddress 1 "$ADDR_A" >/dev/null
  n=0; until [ "$(tip_b)" -ge "$(cli_a getblockcount)" ]; do n=$((n+1)); [ $n -gt 120 ] && die "B desync on seed"; sleep 0.5; done
  # pick the wallet-owned p2wpkh utxo and spend it (explicit input => witness on tx)
  local utxo txid vout amt dest
  utxo="$(cli_a listunspent 1 9999999 "[\"$wpkh\"]")"
  txid="$(echo "$utxo" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["txid"])')"
  vout="$(echo "$utxo" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["vout"])')"
  amt="$(echo "$utxo"  | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["amount"])')"
  dest="$(cli_a getnewaddress segwit-dest legacy)"
  local send; send="$(python3 -c "print(round($amt-0.001,8))")"
  raw="$(cli_a createrawtransaction "[{\"txid\":\"$txid\",\"vout\":$vout}]" "{\"$dest\":$send}")"
  signed="$(cli_a signrawtransactionwithwallet "$raw" | J hex)"
  FUNDED_TXID="$(cli_a sendrawtransaction "$signed")"
  local m=0 mp; until mp="$(cli_a getrawmempool 2>&1)"; [[ "$mp" == *"$FUNDED_TXID"* ]]; do
    m=$((m+1)); [ $m -gt 40 ] && die "segwit tx $FUNDED_TXID never appeared in mempool"; sleep 0.25
  done
  # ASSERT A: the funded tx MUST carry a witness (BIP144 marker 0001 after 4B version)
  local rawhex marker
  rawhex="$(cli_a getrawtransaction "$FUNDED_TXID")"
  marker="${rawhex:8:4}"
  [ "$marker" = "0001" ] || die "ASSERT A FAIL: funded tx $FUNDED_TXID has no witness (marker=$marker) -- segwit path not engaged"
  log "ASSERT A OK: witness-bearing tx $FUNDED_TXID (marker 0001) in node A mempool; size=$(mempool_a)"
}

# assert_coinbase_commitment -- ASSERT C: the accepted block's coinbase must carry the
# BIP141 witness commitment output (OP_RETURN 6a24 + aa21a9ed magic). This is exactly
# the output #458 injects; its presence on the ACCEPTED block is the #458 fingerprint.
assert_coinbase_commitment() {
  local fn="$1" blockhash="$2"
  local cbtxid cbhex
  cbtxid="$("$fn" getblock "$blockhash" 1 | python3 -c 'import sys,json;print(json.load(sys.stdin)["tx"][0])')"
  cbhex="$("$fn" getrawtransaction "$cbtxid" 0 "$blockhash")"
  echo "$cbhex" | grep -qi "6a24aa21a9ed" \
    || die "ASSERT C FAIL: coinbase of $blockhash has no BIP141 witness commitment (6a24aa21a9ed) -- #458 injection missing"
  log "ASSERT C OK: coinbase of $blockhash carries BIP141 witness commitment (6a24aa21a9ed)"
}

ARM_WON=""
run_arm() {
  local label="$1" extra="$2" logf="$3" base won ntx
  fund_mempool_segwit
  # capture base AFTER funding: fund_mempool_segwit mines a seed block to confirm the
  # bech32 utxo, so the tip-advance signal must only fire on c2pool's won block.
  base="$(tip_b)"
  log "ARM $label: arming c2pool-dgb (witness-bearing mempool) $extra"
  "$C2POOL_DGB" --run \
    --coin-daemon 127.0.0.1:$P2PPORT_A \
    --coin-rpc 127.0.0.1:$RPCPORT_A \
    --coin-rpc-auth "$DATADIR_A/digibyte.conf" \
    --coin-magic "$DGB_REGTEST_MAGIC" \
    --coin-genesis "$DGB_REGTEST_GENESIS" --regtest --regtest-force-won-share \
    --soak-regrind $extra >"$logf" 2>&1 &
  C2POOL_PID=$!
  log "ARM $label: c2pool-dgb PID $C2POOL_PID; waiting for witness-bearing won block on node B"
  local n=0
  until [ "$(tip_b)" -gt "$base" ]; do
    n=$((n+1)); [ $n -gt 240 ] && die "ARM $label: no won block reached node B within 120s -- on a pre-#458 binary this is the unexpected-witness reject"
    sleep 0.5
  done
  # ASSERT D: block reached B == ACCEPTED (a rejected block would not advance the tip)
  won="$(cli_b getblockhash "$(tip_b)")"
  ntx="$(ntx_of cli_b "$won")"
  # ASSERT B
  [ "$ntx" -ge 2 ] || die "ARM $label: won block $won has $ntx txs, expected >=2 (coinbase + witness tx)"
  local blk; blk="$(cli_b getblock "$won")"
  [[ "$blk" == *"$FUNDED_TXID"* ]] || die "ARM $label: witness tx $FUNDED_TXID not present in accepted block $won"
  assert_coinbase_commitment cli_b "$won"
  log "ARM $label OK (ASSERT B/C/D): witness-bearing won block $won ($ntx txs incl $FUNDED_TXID) ACCEPTED by peer node B"
  kill "$C2POOL_PID" >/dev/null 2>&1; C2POOL_PID=""
  ARM_WON="$won"
}

run_arm "A (P2P primary)" "" /tmp/c2pool-dgb-segwit-soak-arma.log
WON_A="$ARM_WON"
run_arm "B (submitblock isolated)" "--no-p2p-relay" /tmp/c2pool-dgb-segwit-soak-armb.log
WON_B="$ARM_WON"

log "BOTH ARMS PROVEN (WITNESS-BEARING): ARM A (P2P relay) block $WON_A + ARM B (submitblock isolated) block $WON_B each carry a witness tx, the #458 BIP141 coinbase commitment, and were ACCEPTED by peer node B. G3b populated-block (segwit) gate satisfied on regtest -- the witness path #458 fixes."
echo "SEGWIT_SOAK_RESULT armA=$WON_A armB=$WON_B"
