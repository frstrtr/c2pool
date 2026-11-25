#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# G3b LTC+DOGE live-regtest harness (VM220). Canonical; supersedes the
# placeholder driver scripts/ltc_g3b_live_regtest_blockprod_driver.sh
# (removed here; on master it still passed the stale --ltc flag
# and left the crossing + aux-drop legs as log-only checkpoints).
#
# Legs (all against real litecoind/dogecoind -regtest, real cpuminer scrypt):
#   L1 genuine blocks : c2pool-submitted populated LTC blocks + populated DOGE auxpow blocks
#                       accepted; >=1 LTC block carries the aux commit and >=1 LTC PPLNS
#                       coinbase pays both miners (pre-switch blocks can pay only M1 until
#                       B's shares are in the window); 0 rejects (REJ_RE below).
#   L2 v35->v36 cross : two peered c2pool nodes (A --genesis, B -n A) start in
#                       AutoRatchet VOTING minting v35 (desired=36). Regtest pool
#                       params = testnet (CHAIN_LENGTH 400, share_period 4s), so
#                       the window fills and A/B must reach ACTIVATED -> CONFIRMED.
#                       Two nodes are REQUIRED: the distinct-origin guard (#920/#930)
#                       refuses activation on a single-origin window.
#                       PASS = both nodes CONFIRMED; PPLNS-HOOK using=v35 before and
#                       using=v36 after on both; 0 cross-node share-verify failures
#                       (each node recomputes the other's gentx = PPLNS check);
#                       LTC blocks on both sides of the switch pay both miners (>=1 each side);
#                       A and B end on the same best share (no fork).
#   L3 parent lost    : orphan an LTC parent P that carried the aux commit of an
#                       accepted DOGE block D (invalidateblock P + a longer non-c2pool
#                       branch), then orphan D on dogecoind. Scored by
#                       g3b_l3_score.sh from the node logs: PASS = the node logs P
#                       ORPHANED and the DOGE orphan banner for D, never re-submits
#                       D after the orphan step, dogecoind has D at confirmations<0,
#                       and no /recent_blocks row says P is "confirmed" (RPC mode
#                       never writes a row verdict, so rows stay "pending").
#
# Regtest difficulty is trivial (every hash is a share AND a block) and c2pool
# clamps stratum difficulty DOWN to the pool-share difficulty (so
# --stratum-min-diff has no effect): minerd then submits every ~24 hashes, every
# submit is a block, the template changes each time and nearly all submits go
# DOA -- run1123 reached only 2/400 shares in 10 min. Miners here are the paced
# genuine-scrypt stratum miner (g3b_paced_scrypt_miner.py, same dir): real PoW
# on real jobs at a 2^-13 work floor, one share per ~PACE_S+3 s per miner.
#
# Usage: ltc_g3b_vm220_harness.sh <c2pool-ltc binary> <out dir> [legs=123]
#   env: PACE_S (default 8; two miners => ~4 s share period), CROSS_TIMEOUT_S (default+floor 10800; G3B_ALLOW_SHORT_TIMEOUT=1 to go below)
set -u
BIN=${1:?c2pool-ltc binary}; P=${2:?out dir}; LEGS=${3:-123}
PACE_S=${PACE_S:-8}; CROSS_TIMEOUT_S=${CROSS_TIMEOUT_S:-10800}
# L2 needs ACTIVATED (~45 min) plus the 800-share confirm window (~95 min at the
# paced share rate) on BOTH nodes; anything under 3h times out mid-confirm and the
# EXIT trap tears the nodes down. Clamp up unless G3B_ALLOW_SHORT_TIMEOUT=1.
CROSS_TIMEOUT_FLOOR_S=10800
if [ "$CROSS_TIMEOUT_S" -lt "$CROSS_TIMEOUT_FLOOR_S" ] && [ "${G3B_ALLOW_SHORT_TIMEOUT:-0}" != 1 ]; then
  CROSS_TIMEOUT_REQ=$CROSS_TIMEOUT_S; CROSS_TIMEOUT_S=$CROSS_TIMEOUT_FLOOR_S
fi
MINER="$(cd "$(dirname "$0")" && pwd)/g3b_paced_scrypt_miner.py"
L3SCORE="$(cd "$(dirname "$0")" && pwd)/g3b_l3_score.sh"
mkdir -p "$P"; exec >>"$P/driver.log" 2>&1
log(){ printf "[%s] %s\n" "$(date -u +%FT%TZ)" "$*"; }
res(){ echo "$*" >> "$P/VERDICT"; log "RESULT $*"; }
rm -f "$P/VERDICT"
log "BIN=$BIN legs=$LEGS pace=${PACE_S}s cross_timeout=$CROSS_TIMEOUT_S"
[ -n "${CROSS_TIMEOUT_REQ:-}" ] && log "CROSS_TIMEOUT_S=$CROSS_TIMEOUT_REQ below floor, clamped to $CROSS_TIMEOUT_S"
[ -f "$MINER" ] || { echo "L0 FAIL missing $MINER" >> "$P/VERDICT"; exit 1; }
"$BIN" --help 2>&1 | grep -q -- "--regtest" || { res "L0 FAIL binary lacks --regtest"; exit 1; }

# ---------------------------------------------------------------- daemons
rm -rf "$P"/{ltc,doge,ltcpeer,dogepeer,dataA,dataB}; mkdir -p "$P"/{ltc,doge,ltcpeer,dogepeer,dataA,dataB}
pw(){ head -c16 /dev/urandom | od -An -tx1 | tr -d " \n"; }
LP=$(pw); DP=$(pw)
printf "regtest=1\nserver=1\ntxindex=1\n[regtest]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport=19453\nport=19454\nlisten=1\nbind=127.0.0.1\nrpcuser=g3b\nrpcpassword=%s\nfallbackfee=0.0002\nmaxtxfee=100\nrpcworkqueue=64\npersistmempool=0\nvbparams=mweb:9999999999:9999999999\n" "$LP" > "$P/ltc/litecoin.conf"
printf "regtest=1\nserver=1\ntxindex=1\nlisten=1\nbind=127.0.0.1\nport=18557\nrpcuser=g3b\nrpcpassword=%s\nrpcport=18332\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nfallbackfee=0.01\nrpcthreads=8\n" "$DP" > "$P/doge/dogecoin.conf"
# MWEB: regtest BIP9 window=144 -> MWEB ACTIVE at h432; the first HogEx (empty vin, fixed txid
# 58338ec7) then fails TestBlockValidity bad-txns-vin-empty in litecoind CreateNewBlock and
# GBT dies for good. Pin MWEB never-active on BOTH ltc daemons (consensus params must match).
# peer daemons: litecoind 0.21.4 regtest GBT refuses with 0 peers (-9 not connected)
printf "regtest=1\nserver=1\n[regtest]\nlisten=0\nport=19455\nrpcport=19456\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcuser=g3b\nrpcpassword=%s\nconnect=127.0.0.1:19454\nvbparams=mweb:9999999999:9999999999\n" "$LP" > "$P/ltcpeer/litecoin.conf"
printf "regtest=1\nserver=1\nlisten=0\nport=18558\nrpcport=18559\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcuser=g3b\nrpcpassword=%s\nconnect=127.0.0.1:18557\n" "$DP" > "$P/dogepeer/dogecoin.conf"
for d in ltc ltcpeer; do litecoind -datadir="$P/$d" -conf="$P/$d/litecoin.conf" -daemon; done
for d in doge dogepeer; do dogecoind -datadir="$P/$d" -conf="$P/$d/dogecoin.conf" -daemon; done
LC(){ litecoin-cli -datadir="$P/ltc" -conf="$P/ltc/litecoin.conf" "$@"; }
LW(){ LC -rpcwallet=g3b "$@"; }
DC(){ dogecoin-cli -datadir="$P/doge" -conf="$P/doge/dogecoin.conf" -rpcport=18332 "$@"; }
J(){ python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }
cleanup(){
  [ -n "${POPPID:-}" ] && kill "$POPPID" 2>/dev/null
  for p in ${MINERS:-} ${NODES:-}; do kill "$p" 2>/dev/null; done; sleep 3
  LC stop >/dev/null 2>&1; DC stop >/dev/null 2>&1
  litecoin-cli -datadir="$P/ltcpeer" -conf="$P/ltcpeer/litecoin.conf" stop >/dev/null 2>&1
  dogecoin-cli -datadir="$P/dogepeer" -conf="$P/dogepeer/dogecoin.conf" -rpcport=18559 stop >/dev/null 2>&1
  log DONE
}
trap cleanup EXIT
for i in $(seq 1 60); do LC getblockcount >/dev/null 2>&1 && DC getblockcount >/dev/null 2>&1 && break; sleep 2; done
for i in $(seq 1 60); do [ "$(LC getconnectioncount 2>/dev/null || echo 0)" -ge 1 ] && [ "$(DC getconnectioncount 2>/dev/null || echo 0)" -ge 1 ] && break; sleep 2; done
log "PEERS ltc=$(LC getconnectioncount) doge=$(DC getconnectioncount)"
LC createwallet g3b >/dev/null
GEN=$(LW getnewaddress "" legacy); LC generatetoaddress 115 "$GEN" >/dev/null; DC generatetoaddress 120 "$(DC getnewaddress)" >/dev/null
M1=$(LW getnewaddress "" legacy); M2=$(LW getnewaddress "" legacy); D1=$(DC getnewaddress); D2=$(DC getnewaddress)
LS=$(LC getblockcount); DS=$(DC getblockcount)
log "PRIMED LTC_START=$LS DOGE_START=$DS M1=$M1 M2=$M2 D1=$D1 D2=$D2"

# ---------------------------------------------------------------- populate
pop(){
 A1=$(LW getnewaddress "" legacy); A2=$(LW getnewaddress "" p2sh-segwit); A3=$(LW getnewaddress "" bech32)
 K1=$(LW getaddressinfo "$(LW getnewaddress)" | J "d['pubkey']"); K2=$(LW getaddressinfo "$(LW getnewaddress)" | J "d['pubkey']")
 A4=$(LW addmultisigaddress 2 "[\"$K1\",\"$K2\"]" "" bech32 | J "d['address']")
 echo "LTC $(LW sendtoaddress "$A1" 1.1) $(LW sendtoaddress "$A2" 1.2) $(LW sendtoaddress "$A3" 1.3) $(LW sendtoaddress "$A4" 1.4)"
 INS=$(LW listunspent 1 9999999 | python3 -c "
import sys,json;u=sorted([x for x in json.load(sys.stdin) if x['spendable'] and x['amount']>=0.1],key=lambda x:x['amount'])[:3]
print(json.dumps([{'txid':x['txid'],'vout':x['vout']} for x in u]));print(sum(x['amount'] for x in u))")
 IJ=$(echo "$INS"|sed -n 1p); IS=$(echo "$INS"|sed -n 2p); OUT=$(python3 -c "print(round($IS-0.001,8))")
 # guard (legs1124 defect): send only with exactly 3 inputs, positive output, complete
 # signature, decoded vin==3 and testmempoolaccept allowed. A vin-empty tx in the mempool
 # breaks every later CreateNewBlock (bad-txns-vin-empty) and freezes the sharechain.
 NIN=$(echo "$IJ" | J "len(d)" 2>/dev/null || echo 0)
 if [ "$NIN" != 3 ] || ! python3 -c "import sys;sys.exit(0 if $OUT>0.01 else 1)" 2>/dev/null; then
   echo "LTC multi-in3 SKIP nin=$NIN out=$OUT"
 else
   RAW=$(LW createrawtransaction "$IJ" "[{\"$(LW getnewaddress "" bech32)\":$OUT},{\"data\":\"6733622d706f70756c61746564\"}]") || RAW=""
   SIG=""; [ -n "$RAW" ] && SIG=$(LW signrawtransactionwithwallet "$RAW" | J "d['hex'] if d.get('complete') else ''" 2>/dev/null)
   VIN=0; [ -n "$SIG" ] && VIN=$(LC decoderawtransaction "$SIG" | J "len(d['vin'])" 2>/dev/null || echo 0)
   OK=""; [ "$VIN" = 3 ] && OK=$(LC testmempoolaccept "[\"$SIG\"]" | J "d[0]['allowed']" 2>/dev/null)
   if [ "$OK" = True ]; then echo "LTC multi-in3+opreturn $(LC sendrawtransaction "$SIG")"
   else echo "LTC multi-in3 SKIP vin=$VIN accept=$OK"; fi
 fi
 B1=$(DC getnewaddress); BM=$(DC addmultisigaddress 1 "[\"$B1\",\"$(DC getnewaddress)\"]")
 echo "DOGE $(DC sendtoaddress "$B1" 1000) $(DC sendtoaddress "$BM" 2000)"
}
pop > "$P/populate.log" 2>&1
( while :; do sleep 30; pop >> "$P/populate.log" 2>&1; done ) & POPPID=$!

# ---------------------------------------------------------------- nodes + miners
node(){ # name data p2p worker web addr dogepay extra...
  local n=$1 d=$2 pp=$3 wp=$4 hp=$5 a=$6 dp=$7; shift 7
  "$BIN" --integrated --regtest --no-embedded-ltc --no-embedded-doge "$@" \
    --data-dir "$d" --address "$a" \
    --rpchost 127.0.0.1 --rpcport 19453 --rpcuser g3b --rpcpassword "$LP" --coind-p2p-port 0 \
    --merged "DOGE:98:127.0.0.1:18332:g3b:$DP:0" --merged-payout-address "DOGE:$dp" \
    --p2pool-port "$pp" --worker-port "$wp" --web-port "$hp" --http-host 127.0.0.1 \
    > "$P/node$n.log" 2>&1 &
  echo $!
}
NA=$(node A "$P/dataA" 29336 29337 28090 "$M1" "$D1" --genesis); sleep 20
NB=$(node B "$P/dataB" 29346 29347 28091 "$M2" "$D2" -n 127.0.0.1:29336); NODES="$NA $NB"; sleep 20
kill -0 "$NA" 2>/dev/null && kill -0 "$NB" 2>/dev/null || { res "L0 FAIL node down A=$(kill -0 $NA 2>/dev/null && echo up) B=$(kill -0 $NB 2>/dev/null && echo up)"; exit 1; }
python3 "$MINER" 127.0.0.1 29337 "$M1" "$PACE_S" > "$P/minerA.log" 2>&1 & MA=$!
python3 "$MINER" 127.0.0.1 29347 "$M2" "$PACE_S" > "$P/minerB.log" 2>&1 & MB=$!
MINERS="$MA $MB"
log "UP nodeA=$NA nodeB=$NB minerA=$MA minerB=$MB"

state(){ grep -o "\[AutoRatchet\] [A-Z]* -> [A-Z]*" "$P/node$1.log" | tail -1; }
win(){ grep -o "window=[0-9]*/[0-9]*" "$P/node$1.log" | tail -1; }
tipnorm(){ tr -d '"[:space:]'; }
hex64(){ [[ $1 =~ ^[0-9a-f]{64}$ ]] && [[ $1 =~ [1-9a-f] ]]; }   # 64 lower-hex, not all zero
STRICT='expected_gentx=|\[verify_share\] hash mismatch|pow_hash recompute: hash mismatch|run_think: banning peer|Cross-check FAILED'

# ---------------------------------------------------------------- L2 crossing (runs while L1 blocks accrue)
T0=$(date +%s); CROSS_LTC_H=""
while :; do
  sleep 30; el=$(( $(date +%s) - T0 ))
  sa=$(state A); sb=$(state B)
  log "PROGRESS t=${el}s A[$(win A) ${sa:-VOTING}] B[$(win B) ${sb:-VOTING}] ltc_h=$(LC getblockcount) doge_h=$(DC getblockcount)"
  if [ -z "$CROSS_LTC_H" ] && grep -q "VOTING -> ACTIVATED\|VOTING -> CONFIRMED" "$P/nodeA.log"; then
    CROSS_LTC_H=$(LC getblockcount); log "CROSS A activated at ltc_h=$CROSS_LTC_H"; fi
  grep -q "\-> CONFIRMED" "$P/nodeA.log" && grep -q "\-> CONFIRMED" "$P/nodeB.log" && break
  [ "$el" -ge "$CROSS_TIMEOUT_S" ] && break
  if LC getblocktemplate '{"rules":["segwit","mweb"]}' >/dev/null 2>"$P/gbt.err"; then GBTBAD=0
  else GBTBAD=$(( ${GBTBAD:-0} + 1 )); log "GBT_UNHEALTHY #$GBTBAD $(head -c 200 "$P/gbt.err" | tr '\n' ' ')"
    [ "$GBTBAD" -ge 4 ] && { res "L2 HARNESS-ABORT gbt unhealthy x4 (harness, not a c2pool verdict)"; break; }; fi
  kill -0 "$NA" 2>/dev/null && kill -0 "$NB" 2>/dev/null || { log "node died"; break; }
done
LX=$(LC getblockcount); DX=$(DC getblockcount)

# ---------------------------------------------------------------- L1 extract
for h in $(seq $((LS+1)) "$LX"); do LC getblock "$(LC getblockhash "$h")" 2 > "$P/ltc$h.json"; done
for h in $(seq $((DS+1)) "$DX"); do DC getblock "$(DC getblockhash "$h")" true > "$P/doge$h.json"; done
python3 - "$P" "$LS" "$LX" "$DS" "$DX" "$M1" "$M2" "${CROSS_LTC_H:-0}" > "$P/extract.txt" <<'PY'
import json,sys
P,LS,LE,DS,DE,M1,M2,CX=sys.argv[1],*map(int,sys.argv[2:6]),sys.argv[6],sys.argv[7],int(sys.argv[8])
pop=aux=both=0; side={'pre':[0,0],'post':[0,0]}
for h in range(LS+1,LE+1):
    b=json.load(open(f"{P}/ltc{h}.json")); cb=b["tx"][0]
    ad=set()
    for o in cb["vout"]:
        s=o["scriptPubKey"]; ad|=set(s.get("addresses",[]))|({s["address"]} if "address" in s else set())
    a="fabe6d6d" in cb["vin"][0]["coinbase"]; p2={M1,M2}<=ad
    pop+=len(b["tx"])>1; aux+=a; both+=p2
    k='post' if CX and h>CX else 'pre'; side[k][0]+=1; side[k][1]+=p2
    if h<LS+8 or (CX and abs(h-CX)<4) or h>LE-3:
        print(f"LTC h{h} {b['hash']} nTx={len(b['tx'])} aux={a} pays_M1+M2={p2}")
dx=dp=0
for h in range(DS+1,DE+1):
    d=json.load(open(f"{P}/doge{h}.json")); x="auxpow" in d
    dx+=x; dp+=x and len(d["tx"])>1   # DOGE G3a: a merged-mined DOGE block that carries txs
print(f"L1SUM ltc_blocks={LE-LS} populated={pop} auxcommit={aux} pays_both={both} doge_blocks={DE-DS} doge_auxpow={dx} doge_populated={dp}")
print(f"L2PAY pre_switch={side['pre'][1]}/{side['pre'][0]} post_switch={side['post'][1]}/{side['post'][0]}")
PY
LACC=$(grep -c "submit_block_hex accepted" "$P/nodeA.log" "$P/nodeB.log" | awk -F: '{s+=$2}END{print s}')
DACC=$(cat "$P"/node?.log | grep -c "\[MM:DOGE\] submitblock ACCEPTED")
# Reject lines, verbatim from the source (core log prefix "[HH:MM:SS.ffffff][sev] "):
#   LTC  ltc/coin/rpc.cpp   "submit_block_hex result: <json>", "Block submittal result: ..."
#   core web_server.cpp     "submitblock: coin daemon rejected the block"; "[error] submitblock
#                           failed: <what>" (stratum RPC transport; core only, DOGE never logs it)
#   DOGE merged_mining.cpp  "[MM:DOGE] submitblock REJECTED by daemon:" (BIP22 reject string),
#                           "submitblock refused:" (JSON-RPC error, e.g. -22 Block decode failed),
#                           "submitblock: no answer (" (timeout, unparsable, non -22 RPC error),
#                           "Merged block refused:" (commit check), "Merged block REFUSED:"
#                           (oversize), "Merged block assembly failed:", "submit threw".
# On purpose, "submitblock: no answer" COUNTS. Against a loopback regtest daemon it means the
# submit channel failed or the daemon answered with a verify error, so the submit path proved
# nothing (the same verdict kind as "submit threw"). "submitblock INCONCLUSIVE" does NOT count:
# the daemon validated and stored the block, it is just not on its best chain. That is the
# two-node race for one DOGE height (each node submits its own merged block), and the LTC side
# treats "inconclusive" as accepted too (core::coin::submitblock_result_accepted). It is
# reported as doge_inconclusive so the stale rate stays visible.
REJ_RE="submit_block_hex result:|Block submittal result:|submitblock: coin daemon rejected|\] submitblock failed:|\[MM:[A-Z0-9]+\] (submitblock (REJECTED by daemon|refused):|submitblock: no answer \(|Merged block (refused|REFUSED):|Merged block assembly failed:|submit threw)|submitblock via RPC: REJECTED"
REJ=$(cat "$P"/node?.log | grep -Ec "$REJ_RE")
DINC=$(cat "$P"/node?.log | grep -c "\[MM:DOGE\] submitblock INCONCLUSIVE")
S1=$(grep L1SUM "$P/extract.txt")
# Every L1SUM counter that L1 PASS claims must be >=1. populated= is anchored, so
# doge_populated= cannot satisfy it.
l1sum_ok(){ local k; for k in populated auxcommit pays_both doge_auxpow doge_populated; do echo "$1" | grep -Eq "(^| )$k=[1-9]" || return 1; done; }
if [ "$LACC" -ge 1 ] && [ "$DACC" -ge 1 ] && [ "$REJ" -eq 0 ] && l1sum_ok "$S1"; then
  res "L1 PASS $S1 ltc_acc=$LACC doge_acc=$DACC rejects=$REJ doge_inconclusive=$DINC"; else res "L1 FAIL $S1 ltc_acc=$LACC doge_acc=$DACC rejects=$REJ doge_inconclusive=$DINC"; fi

# ---------------------------------------------------------------- L2 verdict
if [[ $LEGS == *2* ]]; then
  CA=$(grep -c "\-> CONFIRMED" "$P/nodeA.log"); CB=$(grep -c "\-> CONFIRMED" "$P/nodeB.log")
  REV=$(cat "$P"/node?.log | grep -c "ACTIVATED -> VOTING\|CONFIRMED but network is")
  V35A=$(grep -c "using=v35" "$P/nodeA.log"); V35B=$(grep -c "using=v35" "$P/nodeB.log")
  V36A=$(grep -c "using=v36" "$P/nodeA.log"); V36B=$(grep -c "using=v36" "$P/nodeB.log")
  BADA=$(grep -cE "$STRICT" "$P/nodeA.log"); BADB=$(grep -cE "$STRICT" "$P/nodeB.log")
  XNB=$(cat "$P"/node?.log | grep -c "Cross-check mismatch (non-blocking)")
  PAY=$(grep L2PAY "$P/extract.txt")
  # no-fork check: both nodes must report the same best share. The miners are still
  # running, so a sample can catch one node a share ahead; sample up to 12 times, 5s
  # apart, and accept the first sample where the two tips are equal and non-zero.
  # /web/best_share_hash answers a JSON string "<64 hex>". Strip only the quotes and
  # whitespace, then require exactly 64 lower-hex on BOTH sides: an error body such as
  # {"error":"Internal error"} must never reduce to a comparable "hash".
  TIPEQ=0; BA=""; BB=""
  for i in $(seq 1 12); do
    BA=$(curl -s --max-time 5 http://127.0.0.1:28090/web/best_share_hash | tipnorm)
    BB=$(curl -s --max-time 5 http://127.0.0.1:28091/web/best_share_hash | tipnorm)
    echo "tip sample $i A=$BA B=$BB" >> "$P/tips.txt"
    if hex64 "$BA" && hex64 "$BB" && [ "$BA" = "$BB" ]; then TIPEQ=1; break; fi
    sleep 5
  done
  for n in A B; do grep -E "\[AutoRatchet\] (VOTING|ACTIVATED|CONFIRMED) ->|\[AutoRatchet\] ACTIVATED:" "$P/node$n.log" > "$P/ratchet$n.txt"; done
  L2="confirmed A=$CA B=$CB reverts=$REV hook v35 A=$V35A B=$V35B v36 A=$V36A B=$V36B verify_fail A=$BADA B=$BADB xcheck_nonblocking=$XNB $PAY tipA=${BA:0:16} tipB=${BB:0:16} tip_equal=$TIPEQ cross_ltc_h=${CROSS_LTC_H:-none}"
  if [ "$CA" -ge 1 ] && [ "$CB" -ge 1 ] && [ "$REV" -eq 0 ] && [ "$V35A" -ge 1 ] && [ "$V35B" -ge 1 ] && [ "$V36A" -ge 1 ] && [ "$V36B" -ge 1 ] \
     && [ "$TIPEQ" -eq 1 ] && [ "$BADA" -eq 0 ] && [ "$BADB" -eq 0 ] && echo "$PAY" | grep -qE "pre_switch=[1-9][0-9]*/[0-9]+ post_switch=[1-9][0-9]*/[0-9]+"; then
    res "L2 PASS $L2"; else res "L2 FAIL $L2"; fi
fi

# ---------------------------------------------------------------- L3 parent lost -> aux dropped
if [[ $LEGS == *3* ]]; then
  # newest c2pool DOGE block D (auxpow) and its LTC parent P (the LTC block whose coinbase commits D's chain merkle root)
  read -r PH DH DHH < <(python3 - "$P" "$LS" "$LX" "$DS" "$DX" <<'PY'
import json,sys
P,LS,LE,DS,DE=sys.argv[1],*map(int,sys.argv[2:])
ltc={}
for h in range(LS+1,LE+1):
    b=json.load(open(f"{P}/ltc{h}.json")); ltc[b["hash"]]=h
import hashlib
for h in range(DE,DS,-1):
    b=json.load(open(f"{P}/doge{h}.json")); ap=b.get("auxpow")
    if not ap or not ap.get("parentblock"): continue
    hdr=bytes.fromhex(ap["parentblock"])[:80]
    lh=hashlib.sha256(hashlib.sha256(hdr).digest()).digest()[::-1].hex()
    if lh in ltc: print(lh,b["hash"],h); sys.exit()
PY
)
  if [ -z "${PH:-}" ]; then res "L3 FAIL no (LTC parent, DOGE aux) pair found"; else
    log "L3 pair P=$PH D=$DH doge_h=$DHH"
    kill $MINERS 2>/dev/null; MINERS=""; sleep 10
    curl -s http://127.0.0.1:28090/recent_blocks > "$P/recent_blocks.before.json"
    # orphan the parent: invalidate P and build a longer competing branch without c2pool
    PHH=$(LC getblockheader "$PH" | J "d['height']"); TIP=$(LC getblockcount)
    # resubmits of D are counted from here: record each node log's line count, so the
    # scorer reads only lines written after this point (no clock or midnight dependence)
    echo "$(wc -l < "$P/nodeA.log") $(wc -l < "$P/nodeB.log")" > "$P/l3.lines"
    LC invalidateblock "$PH"; LC generatetoaddress $((TIP-PHH+8)) "$GEN" >/dev/null
    # orphan D on the aux chain too (aux block whose parent was lost must not stand)
    DC invalidateblock "$DH"; DC generatetoaddress 10 "$(DC getnewaddress)" >/dev/null
    log "L3 orphaned P (ltc h=$PHH, tip now $(LC getblockcount)) and D (doge h=$DHH, tip now $(DC getblockcount))"
    sleep 180   # FoundBlock verifiers run at +30s/+120s
    curl -s http://127.0.0.1:28090/recent_blocks > "$P/recent_blocks.after.json"
    DCHAIN=$(DC getblock "$DH" 2>/dev/null | J "d['confirmations']")
    L3=$("$L3SCORE" "$P" "$PH" "$DH" "$DCHAIN" | tee "$P/l3.txt")
    log "$L3"; res "$L3"
  fi
fi
log "VERDICT $(tr '\n' ' ' < "$P/VERDICT")"
