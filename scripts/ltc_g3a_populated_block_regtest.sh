#!/usr/bin/env bash
# G3a — LTC populated-block production live arm: produce a POPULATED litecoind
# regtest block with a diverse transaction mix and HARD-FAIL assertions that
# every output-script type AND the SegWit witness data survive a full
# serialize -> node -> deserialize round-trip on the real LTC parent chain.
#
# This is the opt-in live counterpart to the network-free CI arm
# (ctest LtcG3aPopulated). Isolated litecoind regtest ONLY (off-prod);
# self-provisions coins. Mirrors scripts/dgb_g3a_populated_block_regtest.sh.
#
# DOGE merged-aux (submitauxblock) is a FUTURE extension of this arm, gated on
# the dogecoind live-testbed standup; this parent arm does not depend on it.
# MWEB is not asserted here (inactive on the c2pool regtest); the diverse mix
# covers the SegWit-active surface.
#
# Additive/fenced: scripts/ only — no consensus, shared-base, build.yml or CMake.
set -euo pipefail

LTC_CLI="${LTC_CLI:-$HOME/litecoin-0.21.5.6/bin/litecoin-cli}"
LTC_DATADIR="${LTC_DATADIR:-$HOME/.litecoin-regtest-c2pool}"
LTC_RPC_PORT="${LTC_RPC_PORT:-19443}"
LTC_WALLET="${LTC_WALLET:-g3a_ltc_parent}"

L() { "$LTC_CLI" -regtest -datadir="$LTC_DATADIR" -rpcport="$LTC_RPC_PORT" \
        -rpcwallet="$LTC_WALLET" "$@"; }
J() { python3 -c 'import sys,json;print(json.load(sys.stdin)["'"$1"'"])'; }
fail() { echo "ASSERT-FAIL: $*" >&2; exit 1; }

# 0. hard refuse to touch anything but an isolated regtest chain.
[ "$(L getblockchaininfo | J chain)" = "regtest" ] || fail "refusing to run off regtest"
echo "=== LTC G3a populated-block harness — chain=regtest height=$(L getblockcount) wallet=$LTC_WALLET ==="

# 1. self-provision mature coins (LTC coinbase matures at 100)
A_LEGACY=$(L getnewaddress "" legacy)
L generatetoaddress 130 "$A_LEGACY" >/dev/null
L settxfee 0.0001 >/dev/null   # regtest has no fee history; pin a low explicit rate
echo "mined 130 -> spendable balance: $(L getbalance)"

# 2. one address per output-script type
A_P2PKH=$(L getnewaddress "" legacy)                          # pubkeyhash
A_P2WPKH=$(L getnewaddress "" bech32)                         # witness_v0_keyhash (wallet-owned)
A_P2SHWPKH=$(L getnewaddress "" p2sh-segwit)                  # scripthash, witness when spent
K1=$(L getaddressinfo "$(L getnewaddress)" | J pubkey)
K2=$(L getaddressinfo "$(L getnewaddress)" | J pubkey)
A_MS_P2SH=$(L createmultisig 1 "[\"$K1\",\"$K2\"]" legacy | J address)   # scripthash (1-of-2, donation shape)
A_MS_P2WSH=$(L createmultisig 1 "[\"$K1\",\"$K2\"]" bech32 | J address)  # witness_v0_scripthash

# 3. pre-seed wallet-owned SEGWIT utxos (spent in the block => real witnesses)
L sendtoaddress "$A_P2WPKH" 25 >/dev/null
L sendtoaddress "$A_P2SHWPKH" 25 >/dev/null
L generatetoaddress 1 "$A_LEGACY" >/dev/null

pick_utxo() {   # $1=address -> "txid vout"
  L listunspent 1 9999999 "[\"$1\"]" | python3 -c 'import sys,json;u=json.load(sys.stdin)[0];print(u["txid"],u["vout"])'
}

# 4. assemble the POPULATED block's mempool
# T1: spend P2WPKH utxo -> native-segwit witness tx (txid != wtxid)
read -r I1T I1V < <(pick_utxo "$A_P2WPKH")
T1R=$(L createrawtransaction "[{\"txid\":\"$I1T\",\"vout\":$I1V}]" "{\"$A_P2PKH\":24.9999}")
T1=$(L sendrawtransaction "$(L signrawtransactionwithwallet "$T1R" | J hex)")
# T5: spend P2SH-P2WPKH utxo -> wrapped-segwit witness tx (txid != wtxid)
read -r I5T I5V < <(pick_utxo "$A_P2SHWPKH")
T5R=$(L createrawtransaction "[{\"txid\":\"$I5T\",\"vout\":$I5V}]" "{\"$A_P2PKH\":24.9999}")
T5=$(L sendrawtransaction "$(L signrawtransactionwithwallet "$T5R" | J hex)")
# T2: bare-funded raw tx -> P2SH 1-of-2 multisig output + OP_RETURN data carrier
DATA=$(printf 'c2pool-ltc-g3a' | xxd -p)
T2R=$(L createrawtransaction "[]" "{\"$A_MS_P2SH\":5,\"data\":\"$DATA\"}")
T2F=$(L fundrawtransaction "$T2R" | J hex)
T2=$(L sendrawtransaction "$(L signrawtransactionwithwallet "$T2F" | J hex)")
# T3: native P2WSH output   T4: native P2WPKH output
T3=$(L sendtoaddress "$A_MS_P2WSH" 6)
T4=$(L sendtoaddress "$A_P2WPKH" 7)
echo "mempool: T1=$T1 T5=$T5 T2=$T2 T3=$T3 T4=$T4"

# 5. mine ONE block capturing the whole mempool = the deliverable block
BLK=$(L generatetoaddress 1 "$A_LEGACY" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0])')
echo "=== deliverable populated block: $BLK ==="
L getblock "$BLK" 2 > /tmp/ltc_g3a_block.json

# 6. HARD-FAIL assertions over the produced block
python3 - "$T1" "$T5" <<'PY'
import json,sys
b=json.load(open("/tmp/ltc_g3a_block.json")); txs=b["tx"]; T1,T5=sys.argv[1],sys.argv[2]
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
print("\nLTC G3A RESULT: PASS — block %s height=%d txs=%d witness=%d types=%s"%(b["hash"],b["height"],n,seg,sorted(got)))
PY
echo "=== LTC G3a complete (height $(L getblockcount)) ==="
