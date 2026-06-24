#!/usr/bin/env bash
# G3b — DGB v36 greenlight gate: produce a POPULATED block with a diverse
# transaction mix and HARD-FAIL assertions that every output-script type and
# the SegWit witness data survive a full serialize->node->deserialize round
# trip, on the TESTNET chain params (chain=="test") rather than regtest. This
# exercises the real DigiByte testnet consensus net + Scrypt PoW + DigiShield
# retarget path that regtest (G3a) bypasses.
#
# Live DGB testnet at genesis difficulty (0.000244, == testnet powLimit floor)
# is NOT CPU-mineable: a single `generatetoaddress 1` exhausts the default 1M
# nMaxTries in ~5.5 min and finds nothing, and coinbase maturity needs ~130
# blocks. That is the "hashrate-unrealistic" case. Run this against an ISOLATED
# TUNED testnet: a digibyted built with the testnet powLimit relaxed to a
# CPU-mineable floor (kernel/chainparams.cpp CTestNetParams powLimit), genesis
# literals UNCHANGED (genesis hash/nBits untouched -> existing datadir valid).
# That is the integrator-authorized "isolated tuned net" fallback.
#
# Additive/fenced: no consensus, shared-base, build.yml or CMake surface.
set -euo pipefail

CLI_BIN="${DGB_CLI:-$HOME/Github/digibyte/src/digibyte-cli}"
DATADIR="${DGB_DATADIR:-}"
WALLET="${DGB_WALLET:-g3b}"
MATURITY="${DGB_MATURITY:-130}"
CLIARGS=(); [ -n "$DATADIR" ] && CLIARGS+=("-datadir=$DATADIR")
CLI()  { "$CLI_BIN" "${CLIARGS[@]}" "$@"; }
WCLI() { "$CLI_BIN" "${CLIARGS[@]}" "-rpcwallet=$WALLET" "$@"; }
J() { python3 -c 'import sys,json;print(json.load(sys.stdin)["'"$1"'"])'; }
fail() { echo "ASSERT-FAIL: $*" >&2; exit 1; }

CHAIN=$(CLI getblockchaininfo | J chain)
echo "=== G3b populated-block harness — chain=$CHAIN ==="
[ "$CHAIN" = "test" ] || fail "refusing to run off the testnet chain params (chain=$CHAIN)"

# loop generatetoaddress until the tip actually advances (a tuned-net block may
# still occasionally exhaust nMaxTries; never assume one call mines one block)
mine() {  # $1=count $2=address
  local want now target; target=$(($(CLI getblockcount) + $1))
  while now=$(CLI getblockcount); [ "$now" -lt "$target" ]; do
    CLI generatetoaddress $(( target - now )) "$2" >/dev/null || true
  done
}

CLI createwallet "$WALLET" 2>/dev/null || CLI loadwallet "$WALLET" 2>/dev/null || true

# --- 1. self-provision mature coins -----------------------------------------
A_LEGACY=$(WCLI getnewaddress "" legacy)
mine "$MATURITY" "$A_LEGACY"
echo "mined $MATURITY -> spendable balance: $(WCLI getbalance)"

# --- 2. one address per output-script type ----------------------------------
A_P2PKH=$(WCLI getnewaddress "" legacy)                          # pubkeyhash
A_P2WPKH=$(WCLI getnewaddress "" bech32)                         # witness_v0_keyhash
A_P2SHWPKH=$(WCLI getnewaddress "" p2sh-segwit)                  # scripthash, witness when spent
K1=$(WCLI getaddressinfo "$(WCLI getnewaddress)" | J pubkey)
K2=$(WCLI getaddressinfo "$(WCLI getnewaddress)" | J pubkey)
A_MS_P2SH=$(WCLI createmultisig 1 "[\"$K1\",\"$K2\"]" legacy | J address)   # scripthash 1-of-2 (donation shape)
A_MS_P2WSH=$(WCLI createmultisig 1 "[\"$K1\",\"$K2\"]" bech32 | J address)  # witness_v0_scripthash

# --- 3. pre-seed wallet-owned SEGWIT utxos (spent in block => witnesses) -----
WCLI sendmany "" "{\"$A_P2WPKH\":25,\"$A_P2SHWPKH\":25}" >/dev/null
mine 1 "$A_LEGACY"
pick_utxo() { WCLI listunspent 1 9999999 "[\"$1\"]" | python3 -c 'import sys,json;u=json.load(sys.stdin)[0];print(u["txid"],u["vout"])'; }

# --- 4. assemble the POPULATED block's mempool ------------------------------
read -r I1T I1V < <(pick_utxo "$A_P2WPKH")                        # T1 native-segwit (txid != wtxid)
T1R=$(WCLI createrawtransaction "[{\"txid\":\"$I1T\",\"vout\":$I1V}]" "{\"$A_P2PKH\":24.9}")
T1=$(WCLI sendrawtransaction "$(WCLI signrawtransactionwithwallet "$T1R" | J hex)")
read -r I5T I5V < <(pick_utxo "$A_P2SHWPKH")                      # T5 wrapped-segwit (txid != wtxid)
T5R=$(WCLI createrawtransaction "[{\"txid\":\"$I5T\",\"vout\":$I5V}]" "{\"$A_P2PKH\":24.9}")
T5=$(WCLI sendrawtransaction "$(WCLI signrawtransactionwithwallet "$T5R" | J hex)")
DATA=$(printf 'c2pool-dgb-g3b' | xxd -p)                         # T2 P2SH 1-of-2 + OP_RETURN
T2R=$(WCLI createrawtransaction "[]" "{\"$A_MS_P2SH\":5,\"data\":\"$DATA\"}")
T2F=$(WCLI fundrawtransaction "$T2R" | J hex)
T2=$(WCLI sendrawtransaction "$(WCLI signrawtransactionwithwallet "$T2F" | J hex)")
T3=$(WCLI sendtoaddress "$A_MS_P2WSH" 6)                          # T3 native P2WSH
T4=$(WCLI sendtoaddress "$A_P2WPKH" 7)                            # T4 native P2WPKH
echo "mempool: T1=$T1 T5=$T5 T2=$T2 T3=$T3 T4=$T4"

# --- 5. mine ONE block capturing the whole mempool = the deliverable block ---
BEFORE=$(CLI getblockcount); mine 1 "$A_LEGACY"
BLK=$(CLI getblockhash $((BEFORE + 1)))
echo "=== deliverable populated block: $BLK ==="
CLI getblock "$BLK" 2 > /tmp/g3b_block.json

# --- 6. HARD-FAIL assertions (identical surface to G3a) ----------------------
python3 - "$T1" "$T5" <<'PY'
import json,sys
b=json.load(open("/tmp/g3b_block.json")); txs=b["tx"]; T1,T5=sys.argv[1],sys.argv[2]
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
print("\nG3B RESULT: PASS — block %s height=%d txs=%d witness=%d types=%s"%(b["hash"],b["height"],n,seg,sorted(got)))
PY
echo "=== G3b complete (height $(CLI getblockcount), chain=$CHAIN) ==="
