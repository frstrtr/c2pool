#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# dash_v36_regtest_block_rig.sh -- the DASH v36 network mints REAL DASH blocks
# that carry the template's transactions.
#
# Two dashd -regtest nodes (official Dash Core release binaries), peered with
# each other, a funded wallet on d1 and real mempool transactions; two
# c2pool-dash processes on the DASH v36 network (a FRESH random
# --network-id/--prefix per run), A with --coin-rpc to d1, B with --coin-rpc to
# d2, B --connect'ed to A over the sharechain; an X11 stratum miner
# (scripts/dash_v36_x11_stratum_miner.py) on A's stratum port. On regtest the
# block target (0x207fffff) is far easier than any share target, and the miner
# submits only hashes under the share floor / margin, so every solve is both a
# DASH block and a v36 share.
#
#   BIN=/path/to/c2pool-dash DASHD=/path/to/dashd DASHCLI=/path/to/dash-cli \
#   PYX11=/dir/with/x11_hash [W=/tmp/dash-v36-regtest] [WORKERS=6] [MARGIN=32] \
#   scripts/dash_v36_regtest_block_rig.sh
#
# Rounds (each asserts; exit non-zero on the first failure):
#   1  three mempool txs (P2SH+nulldata, P2SH, P2PKH) -> the found block carries
#      them: ntx == 4, all three txids present, merkleroot == header, d1 and d2
#      best block == it; A: BLOCK FOUND txs=3 + share minted with the block
#      hash; B: the share is in its sharechain, verified, V=36, and B's tracker
#      arm refused to rebuild the block (not the finder), never submitted it
#   2  two fresh mempool txs -> a second block carrying them (ntx == 3)
#   3  empty mempool -> a coinbase-only block (ntx == 1) still mints
#   4  the v36 network without --coin-rpc: stratum is NOT started
# Every command and the block hashes are printed for the evidence record.
set -u
BIN="${BIN:?set BIN to the c2pool-dash under test}"
DASHD="${DASHD:?set DASHD to an official dashd}"
DASHCLI="${DASHCLI:?set DASHCLI to the matching dash-cli}"
PYX11="${PYX11:?set PYX11 to a directory holding the x11_hash module}"
W="${W:-/tmp/dash-v36-regtest}"
WORKERS="${WORKERS:-6}"
MARGIN="${MARGIN:-32}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MINER="$HERE/dash_v36_x11_stratum_miner.py"

PIDS=()
fail() { echo "RIG FAIL: $*"; cleanup; exit 1; }
pass() { echo "RIG PASS: $*"; }
cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  sleep 2
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
}
trap cleanup EXIT
start() {   # start NAME LOG CMD...
  local name="$1" log="$2"; shift 2
  echo "+ $*" | sed -E 's/rpcpassword=[^ ]*/rpcpassword=***/'
  "$@" >"$log" 2>&1 &
  local pid=$!
  PIDS+=("$pid")
  eval "${name}_PID=$pid"
}
wait_for() {  # wait_for SECONDS DESC CMD...
  local secs="$1" desc="$2"; shift 2
  local end=$((SECONDS + secs))
  while [ $SECONDS -lt $end ]; do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  fail "timeout ($secs s) waiting for: $desc"
}
get() { curl -s --max-time 5 "http://127.0.0.1:$1$2"; }
fresh_hex() { python3 -c 'import secrets; print(secrets.token_hex(8))'; }

rm -rf "$W"; mkdir -p "$W/d1" "$W/d2" "$W/A" "$W/B"
RPCPASS=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
declare -A P2P=([d1]=29999 [d2]=29997) RPC=([d1]=29998 [d2]=29996)
for d in d1 d2; do
  cat >"$W/$d/dash.conf" <<EOF
regtest=1
server=1
rpcuser=c2pool_v36_rig
rpcpassword=$RPCPASS
rpcport=${RPC[$d]}
[regtest]
rpcport=${RPC[$d]}
port=${P2P[$d]}
listen=1
fallbackfee=0.0001
EOF
done
cli() { local d="$1"; shift; "$DASHCLI" -regtest -datadir="$W/$d" -conf="$W/$d/dash.conf" -rpcport="${RPC[$d]}" "$@"; }
w1() { cli d1 -rpcwallet=w "$@"; }

echo "== rig: BIN=$BIN"
echo "== rig: DASHD=$DASHD ($("$DASHD" --version | head -1)) sha256=$(sha256sum "$DASHD" | cut -c1-16)"
start D1 "$W/d1.log" "$DASHD" -regtest -datadir="$W/d1" -conf="$W/d1/dash.conf" -port="${P2P[d1]}" \
  -rpcport="${RPC[d1]}" -connect=127.0.0.1:"${P2P[d2]}" -listen=1 -printtoconsole=0
start D2 "$W/d2.log" "$DASHD" -regtest -datadir="$W/d2" -conf="$W/d2/dash.conf" -port="${P2P[d2]}" \
  -rpcport="${RPC[d2]}" -connect=127.0.0.1:"${P2P[d1]}" -listen=1 -printtoconsole=0
wait_for 60 "d1 RPC" cli d1 getblockcount
wait_for 60 "d2 RPC" cli d2 getblockcount
[ "$(cli d1 getblockchaininfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["chain"])')" = regtest ] \
  || fail "refusing to run off regtest"
wait_for 60 "d1<->d2 peered" sh -c "[ \$($DASHCLI -regtest -datadir=$W/d1 -conf=$W/d1/dash.conf -rpcport=${RPC[d1]} getconnectioncount) -ge 1 ]"
pass "0 two dashd -regtest peered (d1 p2p ${P2P[d1]} rpc ${RPC[d1]}; d2 p2p ${P2P[d2]} rpc ${RPC[d2]})"

# ── fund d1 ──────────────────────────────────────────────────────────────────
cli d1 createwallet w >/dev/null || fail "createwallet"
FUND=$(w1 getnewaddress)
w1 generatetoaddress 130 "$FUND" >/dev/null || fail "generatetoaddress"
wait_for 60 "d2 syncs 130 blocks" sh -c "[ \"\$($DASHCLI -regtest -datadir=$W/d2 -conf=$W/d2/dash.conf -rpcport=${RPC[d2]} getbestblockhash)\" = \"$(cli d1 getbestblockhash)\" ]"
pass "0 funded: height $(cli d1 getblockcount), balance $(w1 getbalance)"

mempool_has() {  # mempool_has NODE TXID...
  local d="$1"; shift
  local mp; mp=$(cli "$d" getrawmempool)
  for t in "$@"; do echo "$mp" | grep -q "$t" || return 1; done
}

# ── two c2pool-dash nodes on the DASH v36 network ──────────────────────────
NETID=$(fresh_hex); PREFIX=$(fresh_hex)
COMMON=(--run --testnet --network-id "$NETID" --prefix "$PREFIX" --web-host 127.0.0.1
        --coin-p2p-connect 127.0.0.1:1)
start A "$W/A.log" "$BIN" "${COMMON[@]}" --data-dir "$W/A" --listen 127.0.0.1:19811 --web-port 19091 \
  --stratum 127.0.0.1:19921 --coin-rpc 127.0.0.1:"${RPC[d1]}" --coin-rpc-auth "$W/d1/dash.conf"
start B "$W/B.log" "$BIN" "${COMMON[@]}" --data-dir "$W/B" --listen 127.0.0.1:19812 --web-port 19092 \
  --stratum 127.0.0.1:19922 --coin-rpc 127.0.0.1:"${RPC[d2]}" --coin-rpc-auth "$W/d2/dash.conf" \
  --connect 127.0.0.1:19811
wait_for 60 "A: DASH v36 profile banner" grep -q "mints share v36" "$W/A.log"
wait_for 60 "A: dashd-templates-only policy" grep -q "the DASH v36 network takes mining work from dashd getblocktemplate only" "$W/A.log"
wait_for 60 "A: stratum listening" grep -q "stratum listening on 127.0.0.1:19921" "$W/A.log"
peers() { get "$1" /local_stats | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["peers"]["incoming"]+d["peers"]["outgoing"])' 2>/dev/null || echo 0; }
wait_for 90 "A<->B sharechain peering" sh -c "[ \$(curl -s --max-time 5 http://127.0.0.1:19091/local_stats | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[\"peers\"][\"incoming\"]+d[\"peers\"][\"outgoing\"])' 2>/dev/null || echo 0) -ge 1 ]"
pass "0 c2pool A+B on the DASH v36 network network-id=$NETID prefix=$PREFIX, peered; $(grep -m1 -o 'the DASH v36 network takes mining work[^)]*)' "$W/A.log")"

MINER_ADDR=$(w1 getnewaddress)
case "$MINER_ADDR" in y*) ;; *) fail "miner address is not a regtest P2PKH (y...): $MINER_ADDR" ;; esac

in_window() {  # in_window WEBPORT HASH -> the share is present, V=36, verified
  get "$1" /sharechain/window | python3 -c '
import json, sys
d = json.load(sys.stdin); h = sys.argv[1]
sys.exit(0 if any(s["H"] == h and s["V"] == 36 and s["v"] == 1 for s in d.get("shares", [])) else 1)' "$2"
}

mine_round() {  # mine_round TAG WANT_NTX MIN_BRANCHES MAX_BRANCHES TXID...
  local tag="$1" want="$2" minb="$3" maxb="$4"; shift 4
  local before; before=$(cli d1 getbestblockhash)
  local blocks_before; blocks_before=$(grep -c "BLOCK FOUND" "$W/A.log")
  echo "+ PYTHONPATH=$PYX11 python3 $MINER --port 19921 --user $MINER_ADDR --workers $WORKERS --margin $MARGIN --shares 1 --min-branches $minb --max-branches $maxb"
  PYTHONPATH="$PYX11" timeout 1500 python3 "$MINER" --port 19921 --user "$MINER_ADDR" --workers "$WORKERS" \
    --margin "$MARGIN" --shares 1 --min-branches "$minb" --max-branches "$maxb" --timeout 1400 \
    >"$W/miner.$tag.log" 2>&1 || { tail -20 "$W/miner.$tag.log"; fail "$tag: miner found no accepted solve"; }
  grep '"event": "submit"' "$W/miner.$tag.log" | tail -1
  wait_for 60 "$tag: d1 tip moves" sh -c "[ \"\$($DASHCLI -regtest -datadir=$W/d1 -conf=$W/d1/dash.conf -rpcport=${RPC[d1]} getbestblockhash)\" != \"$before\" ]"
  BH=$(cli d1 getbestblockhash)
  cli d1 getblock "$BH" 2 >"$W/block.$tag.json"
  cli d1 getblockheader "$BH" >"$W/header.$tag.json"
  python3 - "$W/block.$tag.json" "$W/header.$tag.json" "$want" "$@" <<'PY' || fail "$tag: block assertions"
import json, sys
b = json.load(open(sys.argv[1])); h = json.load(open(sys.argv[2])); want = int(sys.argv[3])
txids = [t["txid"] for t in b["tx"]]
print(f"   block {b['hash']} height {b['height']} ntx {len(txids)} merkleroot {b['merkleroot']}")
assert len(txids) == want, f"ntx {len(txids)} != {want}"
for t in sys.argv[4:]:
    assert t in txids, f"mempool tx {t} missing from the block"
assert b["merkleroot"] == h["merkleroot"], "merkleroot != header"
print("   txs:", " ".join(x[:16] for x in txids))
PY
  wait_for 90 "$tag: A logs the found block" sh -c "[ \$(grep -c 'BLOCK FOUND' $W/A.log) -gt $blocks_before ]"
  local found; found=$(grep "BLOCK-LEDGER\] event=found" "$W/A.log" | tail -1)
  echo "   A: $found"
  echo "$found" | grep -q "hash=${BH:0:16}" || fail "$tag: the found-block ledger line names another hash"
  echo "$found" | grep -q " txs=$((want - 1)) " || fail "$tag: the found block does not carry $((want - 1)) template txs"
  wait_for 60 "$tag: A mints the share = the block" grep -q "\[MINT\] share ${BH:0:16}" "$W/A.log"
  grep -m1 "\[MINT\] share ${BH:0:16}" "$W/A.log" | sed 's/^/   A: /'
  grep "DASH-STRATUM-BLOCK\] relayed\|submitblock" "$W/A.log" | grep -i "${BH:0:16}\|rpc=" | tail -2 | sed 's/^/   A: /'
  wait_for 90 "$tag: d2 follows the block over dashd p2p" sh -c "[ \"\$($DASHCLI -regtest -datadir=$W/d2 -conf=$W/d2/dash.conf -rpcport=${RPC[d2]} getbestblockhash)\" = \"$BH\" ]"
  wait_for 90 "$tag: B holds the share, verified, V=36" in_window 19092 "$BH"
  in_window 19091 "$BH" || fail "$tag: A's own window lacks the share"
  if [ ! -s "$W/blocks.txt" ]; then
    # The first block of the rig is the sharechain GENESIS share (prev = 0):
    # the tracker arm cannot recompute a coinbase without a parent PPLNS
    # window, so BOTH nodes decline to rebuild it there (the stratum arm of
    # the finder already submitted the full block above).
    for n in A B; do
      wait_for 30 "$tag: $n's tracker arm skips the genesis share (parent not in-chain)" \
        grep -q "won-block ${BH:0:16} parent not in-chain" "$W/$n.log"
      grep -m1 "won-block ${BH:0:16} parent not in-chain" "$W/$n.log" | sed "s/^/   $n: /"
    done
  else
    if [ "$want" -gt 1 ]; then
      wait_for 30 "$tag: B's tracker arm refused the tx-committing block (not the finder)" \
        grep -q "v36 won-block ${BH:0:16} commits a .*holds no template bodies" "$W/B.log"
      grep -m1 "v36 won-block ${BH:0:16}" "$W/B.log" | sed 's/^/   B: /'
      # Only the tracker-arm rebuild line ("[EMB-DASH] GOT BLOCK FROM POOL!
      # <hash16> reconstructed N bytes") means a node assembled the block; the
      # "[DASH] GOT BLOCK FROM POOL! height=.. hash=.." found-notice every node
      # prints for a peer's winning share is not a rebuild, so match
      # "reconstructed" explicitly.
      ! grep -q "GOT BLOCK FROM POOL! ${BH:0:16} reconstructed" "$W/B.log" \
        || fail "$tag: B rebuilt/submitted a block it holds no bodies for"
    fi
    wait_for 30 "$tag: A's tracker arm (the finder) rebuilt the full block from its frozen job" \
      grep -q "GOT BLOCK FROM POOL! ${BH:0:16} reconstructed" "$W/A.log"
    grep -m1 "GOT BLOCK FROM POOL! ${BH:0:16} reconstructed" "$W/A.log" | sed 's/^/   A (tracker arm, finder): /'
  fi
  pass "$tag: block $BH (ntx=$want) accepted by d1 and d2; it IS share ${BH:0:16} (A minted it, B verified it V=36)"
  echo "$BH" >>"$W/blocks.txt"
}

# ── round 1: three mempool txs ───────────────────────────────────────────────
K1=$(w1 getaddressinfo "$(w1 getnewaddress)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["pubkey"])')
K2=$(w1 getaddressinfo "$(w1 getnewaddress)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["pubkey"])')
MS=$(w1 createmultisig 1 "[\"$K1\",\"$K2\"]" | python3 -c 'import sys,json;print(json.load(sys.stdin)["address"])')
DATA=$(printf 'c2pool-dash-v36-template-txs' | xxd -p | tr -d '\n')
RAW=$(w1 createrawtransaction '[]' "{\"$MS\":5,\"data\":\"$DATA\"}")
FUNDED=$(w1 fundrawtransaction "$RAW" | python3 -c 'import sys,json;print(json.load(sys.stdin)["hex"])')
SIGNED=$(w1 signrawtransactionwithwallet "$FUNDED" | python3 -c 'import sys,json;print(json.load(sys.stdin)["hex"])')
T1=$(w1 sendrawtransaction "$SIGNED") || fail "send T1"
T2=$(w1 sendtoaddress "$MS" 6) || fail "send T2"
T3=$(w1 sendtoaddress "$(w1 getnewaddress)" 7) || fail "send T3"
wait_for 60 "d1 mempool holds T1..T3" mempool_has d1 "$T1" "$T2" "$T3"
wait_for 60 "d2 mempool holds T1..T3" mempool_has d2 "$T1" "$T2" "$T3"
pass "1 mempool: T1(P2SH+nulldata)=$T1 T2(P2SH)=$T2 T3(P2PKH)=$T3 on d1 and d2"
mine_round r1 4 2 99 "$T1" "$T2" "$T3"

# ── round 2: two fresh txs ──────────────────────────────────────────────────
T4=$(w1 sendtoaddress "$(w1 getnewaddress)" 3) || fail "send T4"
T5=$(w1 sendtoaddress "$MS" 4) || fail "send T5"
wait_for 60 "d1 mempool holds T4,T5" mempool_has d1 "$T4" "$T5"
pass "2 mempool: T4=$T4 T5=$T5"
mine_round r2 3 2 99 "$T4" "$T5"

# ── round 3: coinbase-only ──────────────────────────────────────────────────
[ "$(cli d1 getmempoolinfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["size"])')" = 0 ] \
  || fail "3: mempool not empty"
mine_round r3 1 0 0

# ── round 4: the v36 network without --coin-rpc serves no mining work ──────
start C "$W/C.log" "$BIN" --run --testnet --network-id "$(fresh_hex)" --prefix "$(fresh_hex)" --web-host 127.0.0.1 \
  --coin-p2p-connect 127.0.0.1:1 --data-dir "$W/C" --listen 127.0.0.1:19813 --web-port 19093 --stratum 127.0.0.1:19923
wait_for 60 "C: requires --coin-rpc" grep -q "is REQUIRED; stratum NOT started" "$W/C.log"
grep -m1 "is REQUIRED; stratum NOT started" "$W/C.log" | sed 's/^/   C: /'
! grep -q "stratum listening" "$W/C.log" || fail "4: stratum started without --coin-rpc"
pass "4 the DASH v36 network without --coin-rpc: stratum not started"

echo "== blocks: $(tr '\n' ' ' <"$W/blocks.txt")"
echo "RIG DONE"
