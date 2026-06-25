#!/usr/bin/env bash
# G3b — DASH v36 greenlight gate: produce a POPULATED block with a diverse
# DASH output-script mix (P2PKH + P2SH 1-of-2 donation-shape + OP_RETURN, the
# exact G3a block-271 mix) and HARD-FAIL assertions that every script type
# survives a full serialize->node->deserialize round trip, on the TESTNET
# chain params (chain=="test") rather than regtest (G3a). This exercises the
# real DASH testnet consensus net + X11 PoW + DGW retarget that regtest bypasses.
#
# CRUCIAL DISTINCTION vs DGB G3b: the deliverable block is WON BY c2pool-dash,
# not by dashd `generatetoaddress`. `c2pool-dash --mine-block` pulls the dashd
# GBT (which now carries our populated mempool), builds the coinbase, X11-mines
# the nonce, and on a win auto-fires NodeRPC::submit_block_hex (submitblock) at
# the daemon -- the same dual-path won-block sink proved in G3a. generatetoaddress
# is used ONLY to self-provision spendable coinbase (funding), never for the
# deliverable block.
#
# Live DASH testnet3 at the minimum difficulty (~0.0003, == testnet powLimit
# floor) is X11-CPU-mineable in a few M nonces, BUT coinbase maturity is 100
# blocks and there is no faucet in-loop -- so populating the mempool with
# *spend* txs is not self-sufficient there. That is the "hashrate-realistic but
# unfunded" case. Run this against an ISOLATED TUNED testnet: a dashd built with
# CTestNetParams powLimit relaxed to a CPU-mineable floor, genesis literals
# UNCHANGED (genesis hash/nBits untouched -> existing datadir stays valid). That
# is the integrator-authorized "isolated tuned net" fallback, identical posture
# to DGB G3b. With a funded testnet3 wallet, set DASH_DATADIR at the real
# testnet3 daemon and skip the self-provision step -- the c2pool win+submit path
# is identical.
#
# Additive/fenced: no consensus, shared-base, build.yml or CMake surface.
set -euo pipefail

CLI_BIN="${DASH_CLI:-$HOME/.dashcore/dash-cli}"
C2POOL="${C2POOL_DASH:-$HOME/Github/c2pool-launcher/build/src/c2pool/c2pool-dash}"
DATADIR="${DASH_DATADIR:-}"
WALLET="${DASH_WALLET:-g3b}"
MATURITY="${DASH_MATURITY:-100}"
COIN_RPC="${COIN_RPC:-127.0.0.1:19998}"        # host:port c2pool-dash dials
COIN_RPC_AUTH="${COIN_RPC_AUTH:-$HOME/Github/c2pool-launcher/.g3b/testnet-auth.conf}"
PAYOUT_PKH="${PAYOUT_PKH:-9f0b9fd45f53b76722d1eda8301bcc74e027438d}"  # hash160 of the g3b payout addr
MAX_NONCE="${MAX_NONCE:-8000000}"              # ~6x the diff-0.0003 expectation; loop refetches on miss

CLIARGS=("-testnet"); [ -n "$DATADIR" ] && CLIARGS+=("-datadir=$DATADIR")
CLI()  { "$CLI_BIN" "${CLIARGS[@]}" "$@"; }
WCLI() { "$CLI_BIN" "${CLIARGS[@]}" "-rpcwallet=$WALLET" "$@"; }
J() { python3 -c 'import sys,json;print(json.load(sys.stdin)["'"$1"'"])'; }
fail() { echo "ASSERT-FAIL: $*" >&2; exit 1; }

CHAIN=$(CLI getblockchaininfo | J chain)
echo "=== DASH G3b populated-block harness — chain=$CHAIN ==="
[ "$CHAIN" = "test" ] || fail "refusing to run off the testnet chain params (chain=$CHAIN)"

CLI createwallet "$WALLET" 2>/dev/null || CLI loadwallet "$WALLET" 2>/dev/null || true

# --- 1. self-provision mature coins (funding only; tuned-net generatetoaddress)
A_FUND=$(WCLI getnewaddress "" legacy)
need=$(( MATURITY + 5 ))
have=$(CLI getblockcount)
target=$(( have + need ))
while now=$(CLI getblockcount); [ "$now" -lt "$target" ]; do
  CLI generatetoaddress $(( target - now )) "$A_FUND" >/dev/null || true
done
echo "funded -> spendable balance: $(WCLI getbalance)"

# --- 2. one address per DASH output-script type (no SegWit on X11/DASH) -------
A_P2PKH=$(WCLI getnewaddress "" legacy)                                   # pubkeyhash
K1=$(WCLI getaddressinfo "$(WCLI getnewaddress)" | J pubkey)
K2=$(WCLI getaddressinfo "$(WCLI getnewaddress)" | J pubkey)
A_MS_P2SH=$(WCLI createmultisig 1 "[\"$K1\",\"$K2\"]" legacy | J address)  # scripthash 1-of-2 (donation shape)

# --- 3. assemble the POPULATED block's mempool (>=4 payload tx) ---------------
DATA=$(printf 'c2pool-dash-g3b' | xxd -p)
T_OPRET=$(WCLI sendmany "" "{\"$A_P2PKH\":5}" 0 "" "[]" false 1 unset "{\"data\":\"$DATA\"}" 2>/dev/null) \
  || { R=$(WCLI createrawtransaction "[]" "{\"$A_P2PKH\":5,\"data\":\"$DATA\"}"); \
       T_OPRET=$(WCLI sendrawtransaction "$(WCLI signrawtransactionwithwallet "$(WCLI fundrawtransaction "$R" | J hex)" | J hex)"); }
T_P2SH=$(WCLI sendtoaddress "$A_MS_P2SH" 6)                               # -> scripthash
T_P2PKH1=$(WCLI sendtoaddress "$A_P2PKH" 7)                               # -> pubkeyhash
T_P2PKH2=$(WCLI sendtoaddress "$A_P2PKH" 8)                               # -> pubkeyhash
echo "mempool seeded: OP_RETURN=$T_OPRET P2SH=$T_P2SH P2PKH=$T_P2PKH1,$T_P2PKH2"
MS=$(CLI getmempoolinfo | J size); echo "mempool size=$MS"; [ "$MS" -ge 4 ] || fail "mempool under-seeded ($MS<4)"

# --- 4. WIN the populated block via c2pool-dash --mine-block (auto-submits) ---
BEFORE=$(CLI getblockcount)
won=0
for attempt in 1 2 3 4 5 6; do
  echo "--- c2pool-dash --mine-block attempt $attempt (max_nonce=$MAX_NONCE) ---"
  if "$C2POOL" --mine-block --testnet --coin-rpc "$COIN_RPC" --coin-rpc-auth "$COIN_RPC_AUTH" \
        --payout-pubkey-hash "$PAYOUT_PKH" --max-nonce "$MAX_NONCE" 2>&1 | tee /tmp/g3b_mine.log \
        | grep -q "submitblock ACCEPTED"; then won=1; break; fi
  grep -q "WON:" /tmp/g3b_mine.log && echo "(won but submit not ACCEPTED -- inspect)" && break
done
[ "$won" = 1 ] || fail "c2pool-dash did not win+submit a block in 6 attempts (raise MAX_NONCE / check bits)"
AFTER=$(CLI getblockcount)
[ "$AFTER" -gt "$BEFORE" ] || fail "tip did not advance ($BEFORE -> $AFTER) despite ACCEPTED"
BLK=$(CLI getblockhash "$AFTER")
echo "=== deliverable populated block (c2pool-WON): $BLK height=$AFTER ==="
CLI getblock "$BLK" 2 > /tmp/g3b_block.json

# --- 5. HARD-FAIL assertions (G3a surface, on testnet params) ----------------
python3 - "$T_OPRET" "$T_P2SH" <<'PY'
import json,sys
b=json.load(open("/tmp/g3b_block.json")); txs=b["tx"]
def fail(m): print("ASSERT-FAIL:",m,file=sys.stderr); sys.exit(1)
n=len(txs); print(f"  block tx count = {n}")
if n<5: fail(f"under-populated ({n} txs, want >=5 = coinbase + >=4 payload)")
print("  [PASS] A1 populated (coinbase + >=4 payload tx)")
cb=txs[0]
if not cb["vin"][0].get("coinbase"): fail("tx[0] is not a coinbase")
print("  [PASS] A2 coinbase present (DASH X11; no segwit commitment expected)")
want={"pubkeyhash","scripthash","nulldata"}
got=set(o["scriptPubKey"].get("type") for t in txs for o in t["vout"] if o["scriptPubKey"].get("type"))
print("  output types survived round-trip:",sorted(got))
miss=want-got
if miss: fail(f"diverse types lost on round-trip: {miss}")
print("  [PASS] A3 P2PKH + P2SH + OP_RETURN all present and round-tripped")
print("\nG3B RESULT: PASS — block %s height=%d txs=%d types=%s (c2pool-WON via --mine-block, submitblock ACCEPTED)"
      %(b["hash"],b["height"],n,sorted(got)))
PY
echo "=== DASH G3b complete (height $(CLI getblockcount), chain=$CHAIN) ==="
