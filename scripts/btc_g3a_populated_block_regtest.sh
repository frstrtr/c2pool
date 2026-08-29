#!/usr/bin/env bash
# G3a — BTC v36 greenlight gate: produce a POPULATED regtest block with a
# diverse transaction mix and HARD-FAIL assertions that every output-script
# type and the SegWit witness data survive a full serialize->node->deserialize
# round-trip. Isolated bitcoind regtest only (off-prod); self-provisions coins.
# Additive/fenced: no consensus, shared-base, build.yml or CMake surface.
set -euo pipefail
CLI="${BTC_CLI:-bitcoin-cli -datadir=$HOME/.bitcoin-regtest -regtest}"
W="${BTC_WALLET:-g3a}"
J() { python3 -c 'import sys,json;print(json.load(sys.stdin)["'"$1"'"])'; }
fail() { echo "ASSERT-FAIL: $*" >&2; exit 1; }

echo "=== G3a populated-block harness — chain=$($CLI getblockchaininfo | J chain) ==="
[ "$($CLI getblockchaininfo | J chain)" = "regtest" ] || fail "refusing to run off regtest"

# --- 0. ensure an isolated wallet (BTC regtest ships none by default) --------
$CLI loadwallet "$W" 2>/dev/null || $CLI createwallet "$W" >/dev/null 2>&1 || true
WCLI() { $CLI -rpcwallet="$W" "$@"; }

# --- 1. self-provision mature coins -----------------------------------------
A_LEGACY=$(WCLI getnewaddress "" legacy)
WCLI generatetoaddress 130 "$A_LEGACY" >/dev/null
echo "mined 130 -> spendable balance: $(WCLI getbalance)"

# --- 2. one address per output-script type ----------------------------------
A_P2PKH=$(WCLI getnewaddress "" legacy)                         # pubkeyhash
A_P2WPKH=$(WCLI getnewaddress "" bech32)                        # witness_v0_keyhash (wallet-owned)
A_P2SHWPKH=$(WCLI getnewaddress "" p2sh-segwit)                 # scripthash, witness when spent
K1=$(WCLI getaddressinfo "$(WCLI getnewaddress)" | J pubkey)
K2=$(WCLI getaddressinfo "$(WCLI getnewaddress)" | J pubkey)
A_MS_P2SH=$(WCLI createmultisig 1 "[\"$K1\",\"$K2\"]" legacy | J address)    # scripthash (1-of-2, donation shape)
A_MS_P2WSH=$(WCLI createmultisig 1 "[\"$K1\",\"$K2\"]" bech32 | J address)   # witness_v0_scripthash

# --- 3. pre-seed wallet-owned SEGWIT utxos (spent in the block => witnesses) -
WCLI sendmany "" "{\"$A_P2WPKH\":25,\"$A_P2SHWPKH\":25}" >/dev/null
WCLI generatetoaddress 1 "$A_LEGACY" >/dev/null

pick_utxo() {   # $1=address -> "txid vout"
  WCLI listunspent 1 9999999 "[\"$1\"]" | python3 -c 'import sys,json;u=json.load(sys.stdin)[0];print(u["txid"],u["vout"])'
}

# --- 4. assemble the POPULATED block's mempool ------------------------------
# T1: spend P2WPKH utxo -> native-segwit witness tx (txid != wtxid)
read -r I1T I1V < <(pick_utxo "$A_P2WPKH")
T1R=$(WCLI createrawtransaction "[{\"txid\":\"$I1T\",\"vout\":$I1V}]" "{\"$A_P2PKH\":24.9}")
T1=$(WCLI sendrawtransaction "$(WCLI signrawtransactionwithwallet "$T1R" | J hex)" 0)
# T5: spend P2SH-P2WPKH utxo -> wrapped-segwit witness tx (txid != wtxid)
read -r I5T I5V < <(pick_utxo "$A_P2SHWPKH")
T5R=$(WCLI createrawtransaction "[{\"txid\":\"$I5T\",\"vout\":$I5V}]" "{\"$A_P2PKH\":24.9}")
T5=$(WCLI sendrawtransaction "$(WCLI signrawtransactionwithwallet "$T5R" | J hex)" 0)
# T2: bare-funded raw tx -> P2SH 1-of-2 multisig output + OP_RETURN data carrier
DATA=$(printf 'c2pool-btc-g3a' | xxd -p)
T2R=$(WCLI createrawtransaction "[]" "{\"$A_MS_P2SH\":5,\"data\":\"$DATA\"}")
T2F=$(WCLI fundrawtransaction "$T2R" | J hex)
T2=$(WCLI sendrawtransaction "$(WCLI signrawtransactionwithwallet "$T2F" | J hex)" 0)
# T3: native P2WSH output   T4: native P2WPKH output
T3=$(WCLI sendtoaddress "$A_MS_P2WSH" 6)
T4=$(WCLI sendtoaddress "$A_P2WPKH" 7)
echo "mempool: T1=$T1 T5=$T5 T2=$T2 T3=$T3 T4=$T4"

# --- 5. mine ONE block capturing the whole mempool = the deliverable block ---
BLK=$(WCLI generatetoaddress 1 "$A_LEGACY" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0])')
echo "=== deliverable populated block: $BLK ==="
WCLI getblock "$BLK" 2 > /tmp/btc_g3a_block.json

# --- 6. HARD-FAIL assertions ------------------------------------------------
python3 - "$T1" "$T5" <<'PY'
import json,sys
b=json.load(open("/tmp/btc_g3a_block.json")); txs=b["tx"]; T1,T5=sys.argv[1],sys.argv[2]
def fail(m): print("ASSERT-FAIL:",m,file=sys.stderr); sys.exit(1)
n=len(txs); print(f"  block tx count = {n}")
if n<6: fail(f"under-populated ({n} txs, want >=6)")
print("  [PASS] A1 populated (coinbase + >=5 payload tx)")
cb=txs[0]
if not any(o["scriptPubKey"]["hex"].startswith("6a24aa21a9ed") for o in cb["vout"]):
    fail("coinbase missing segwit witness commitment")
print("  [PASS] A2 coinbase witness-commitment present")
seg=sum(1 for t in txs[1:] if any("txinwitness" in v for v in t["vin"]))
for nm,need in (("T1",T1),("T5",T5)):
    tt=[t for t in txs if t["txid"]==need]
    if not tt: fail(f"witness tx {nm}={need} absent")
    if tt[0]["txid"]==tt[0]["hash"]: fail(f"{nm} txid==wtxid (witness lost)")
print(f"  [PASS] A3 {seg} witness tx(s); txid!=wtxid holds for T1,T5")
want={"pubkeyhash","scripthash","witness_v0_keyhash","witness_v0_scripthash","nulldata"}
got=set(o["scriptPubKey"].get("type") for t in txs for o in t["vout"] if o["scriptPubKey"].get("type"))
print("  output types survived round-trip:",sorted(got))
miss=want-got
if miss: fail(f"types lost on round-trip: {miss}")
print("  [PASS] A4 all 5 core script types survived node serialize->deserialize")
print("\nG3A RESULT: PASS — block %s height=%d txs=%d witness=%d types=%s"%(b["hash"],b["height"],n,seg,sorted(got)))
PY
echo "=== G3a complete (height $($CLI getblockcount)) ==="
