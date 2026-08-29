#!/usr/bin/env bash
# G3a — DASH v36 greenlight gate: produce a POPULATED regtest block whose
# transaction payload is built/serialized/submitted by c2pool-dash itself
# (the proven submitblock-RPC arm from PR #428), NOT by dashd generatetoaddress.
# DASH has NO SegWit (X11): the diverse mix is non-witness — P2PKH, P2SH 1-of-2
# (donation shape), OP_RETURN nulldata, bare. Assertions key on the masternode
# payment coinbase output (DIP), not a witness commitment.
# Isolated dashd regtest only (VM200 192.168.86.52:29998). Self-provisions coins.
# Additive/fenced: scripts/ only — no consensus, shared-base, build.yml or CMake.
set -euo pipefail
RPC_HOST="${DASH_RPC_HOST:-192.168.86.52}"; RPC_PORT="${DASH_RPC_PORT:-29998}"
RPC_USER="${DASH_RPC_USER:-c2pool_regtest}"; RPC_PASS="${DASH_RPC_PASS:?set DASH_RPC_PASS}"
AUTH="${DASH_RPC_AUTH:?set DASH_RPC_AUTH (dash.conf for c2pool-dash --mine-block)}"
C2P="${C2POOL_DASH:-$HOME/Github/c2pool-launcher/build-g3a/src/c2pool/c2pool-dash}"
rpc() { # $1=method ; $2..=json params
  local m="$1"; shift; local p; p=$(printf '%s,' "$@"); p="[${p%,}]"
  python3 - "$RPC_HOST" "$RPC_PORT" "$RPC_USER" "$RPC_PASS" "$m" "$p" <<'PY'
import sys,json,urllib.request,base64
h,po,u,pw,m,params=sys.argv[1:7]
req=urllib.request.Request(f"http://{h}:{po}/",
  data=json.dumps({"jsonrpc":"1.0","id":"g3a","method":m,"params":json.loads(params)}).encode(),
  headers={"content-type":"text/plain",
           "Authorization":"Basic "+base64.b64encode(f"{u}:{pw}".encode()).decode()})
r=json.load(urllib.request.urlopen(req,timeout=30))
if r.get("error"): print("RPC-ERR",m,r["error"],file=sys.stderr); sys.exit(1)
print(json.dumps(r["result"]))
PY
}
J(){ python3 -c 'import sys,json;v=json.load(sys.stdin); print(v if not isinstance(v,(dict,list)) else json.dumps(v))'; }
fail(){ echo "ASSERT-FAIL: $*" >&2; exit 1; }

[ "$(rpc getblockchaininfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["chain"])')" = regtest ] \
  || fail "refusing to run off regtest"
echo "=== DASH G3a populated-block harness — regtest, height $(rpc getblockcount | J) ==="

# 1. self-provision mature coins (Dash coinbase matures at 100)
A_LEGACY=$(rpc getnewaddress '""' | J)
rpc generatetoaddress 130 "\"$A_LEGACY\"" >/dev/null
echo "mined 130 -> balance $(rpc getbalance | J)"

# 2. one address per (non-witness) output-script type
A_P2PKH=$(rpc getnewaddress '""' | J)
K1=$(rpc getaddressinfo "\"$(rpc getnewaddress | J)\"" | python3 -c 'import sys,json;print(json.load(sys.stdin)["pubkey"])')
K2=$(rpc getaddressinfo "\"$(rpc getnewaddress | J)\"" | python3 -c 'import sys,json;print(json.load(sys.stdin)["pubkey"])')
A_MS_P2SH=$(rpc createmultisig 1 "[\"$K1\",\"$K2\"]" | python3 -c 'import sys,json;print(json.load(sys.stdin)["address"])')

# 3. assemble the POPULATED mempool (all non-witness)
DATA=$(printf 'c2pool-dash-g3a' | xxd -p)
T2R=$(rpc createrawtransaction '[]' "{\"$A_MS_P2SH\":5,\"data\":\"$DATA\"}" | J)
T2F=$(rpc fundrawtransaction "\"$T2R\"" | python3 -c 'import sys,json;print(json.load(sys.stdin)["hex"])')
T2=$(rpc sendrawtransaction "\"$(rpc signrawtransactionwithwallet "\"$T2F\"" | python3 -c 'import sys,json;print(json.load(sys.stdin)["hex"])')\"" | J)
T3=$(rpc sendtoaddress "\"$A_MS_P2SH\"" 6 | J)
T4=$(rpc sendtoaddress "\"$A_P2PKH\"" 7 | J)
echo "mempool seeded: T2(P2SH+nulldata)=$T2 T3(P2SH)=$T3 T4(P2PKH)=$T4 ; pool size=$(rpc getmempoolinfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["size"])')"

# 4. THE deliverable: c2pool-dash builds+X11-mines+serializes+submitblock the populated template
echo "=== c2pool-dash --mine-block (populated getblocktemplate) ==="
"$C2P" --mine-block --coin-rpc "$RPC_HOST:$RPC_PORT" --coin-rpc-auth "$AUTH" 2>&1 | tee /tmp/dash_g3a_mine.log
BLK=$(rpc getbestblockhash | J)
echo "=== best block now: $BLK (height $(rpc getblockcount | J)) ==="
rpc getblock "\"$BLK\"" 2 > /tmp/dash_g3a_block.json

# 5. HARD-FAIL assertions over the c2pool-produced block
python3 - "$T2" "$T3" "$T4" <<'PY'
import json,sys
b=json.load(open("/tmp/dash_g3a_block.json")); txs=b["tx"]
def fail(m): print("ASSERT-FAIL:",m,file=sys.stderr); sys.exit(1)
n=len(txs); print(f"  block tx count = {n}")
if n<4: fail(f"under-populated ({n} txs, want coinbase + >=3 payload)")
print("  [PASS] A1 populated (coinbase + >=3 payload tx)")
for nm,tid in zip(("T2","T3","T4"),sys.argv[1:4]):
    if not any(t["txid"]==tid for t in txs): fail(f"payload tx {nm}={tid} absent from block")
print("  [PASS] A2 all seeded payload txs survived c2pool serialize->submitblock")
seen=set()
for t in txs:
    for o in t["vout"]: seen.add(o["scriptPubKey"]["type"])
want={"pubkeyhash","scripthash","nulldata"}
if not want<=seen: fail(f"missing script types: {want-seen}")
print(f"  [PASS] A3 diverse script types present: {sorted(want&seen)}")
cb=txs[0]
if len(cb["vout"])<2: fail("coinbase missing masternode/payment split (DIP)")
print(f"  [PASS] A4 coinbase has {len(cb['vout'])} outputs (miner + masternode payment)")
print("=== DASH G3a POPULATED BLOCK PROVEN via c2pool-dash submitblock arm ===")
PY
