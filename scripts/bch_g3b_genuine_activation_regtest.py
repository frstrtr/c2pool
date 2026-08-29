#!/usr/bin/env python3
# G3b -- BCH v36 greenlight gate: prove GENUINE Upgrade9 (CashTokens) ACTIVATION
# on an isolated regtest, not always-on acceptance. The node is started with
# -upgrade9activationheight=<N> (N>0), overriding regtest's default
# upgrade9Height=0 (always-on). We then demonstrate the activation BOUNDARY:
#
#   * pre-activation (tip < N): a CashToken FT-genesis tx is HARD-REJECTED by
#     mempool policy with reject-reason "txn-tokens-before-activation"
#     (BCHN policy.cpp:108) -- proof the consensus rule genuinely GATES.
#   * post-activation (tip >= N): the SAME signed tx is ACCEPTED, lands in the
#     won-block, and its tokenData survives a full node round-trip.
#
# The reject-at-height>0 is IMPOSSIBLE under the default always-on regtest, so
# observing it proves the override took effect and activation is real, not
# a regtest convenience. Mirrors the DGB G3b genuine-BIP9 taproot-active proof
# (#534/#535) for the BCH height-based upgrade-schedule equivalent.
#
# WALLET-LESS BCHN v29 regtest (--disable-wallet), self-funding via
# test_framework keys + signrawtransactionwithkey. Isolated regtest only.
# Additive/fenced: no consensus, shared-base, build.yml or CMake surface.
import subprocess, json, sys, os
sys.path.insert(0, "/home/ubuntu/Github/bitcoin-cash-node/test/functional")
from test_framework.key import ECKey
from test_framework.address import key_to_p2pkh, byte_to_base58, hash160

BCLI = ["/home/ubuntu/Github/bitcoin-cash-node/build/src/bitcoin-cli",
        "-conf=/home/ubuntu/bch-regtest/bitcoin.conf",
        "-datadir=/home/ubuntu/bch-regtest"]
# activation height override the node MUST have been started with (see runner)
OVERRIDE = int(os.environ.get("BCH_UPGRADE9_HEIGHT", "230"))

def rpc(*a):
    o = subprocess.run(BCLI + [str(x) for x in a], text=True, capture_output=True)
    if o.returncode != 0:
        raise RuntimeError(o.stderr.strip() or o.stdout.strip())
    s = o.stdout.strip()
    try: return json.loads(s)
    except Exception: return s
def fail(m): print("ASSERT-FAIL:", m, file=sys.stderr); sys.exit(1)

assert rpc("getblockchaininfo")["chain"] == "regtest", "refusing off-regtest"
print(f"=== G3b BCH genuine-activation harness  upgrade9 override height={OVERRIDE} ===")

# --- deterministic-per-run key + funding ------------------------------------
k = ECKey(); k.generate()
wif = byte_to_base58(k.get_bytes() + b"\x01", 239)
pub = k.get_pubkey().get_bytes()
addr = key_to_p2pkh(pub)
my_spk = "76a914" + hash160(pub).hex() + "88ac"

# fund: mine maturity well below OVERRIDE so we control the crossing precisely
rpc("generatetoaddress", 120, addr)
tip = rpc("getblockcount")
if tip >= OVERRIDE - 2:
    fail(f"tip {tip} already at/over override {OVERRIDE}; need a fresh datadir")
# pick one mature coinbase utxo (vout 0 => valid CashToken genesis outpoint)
u = None
for h in range(1, tip - 100):
    b = rpc("getblock", rpc("getblockhash", h), 2)
    o0 = b["tx"][0]["vout"][0]
    if o0["scriptPubKey"]["hex"] == my_spk:
        u = dict(txid=b["tx"][0]["txid"], vout=0, amount=o0["value"],
                 spk=o0["scriptPubKey"]["hex"]); break
if not u: fail("no mature own-coinbase utxo found")
print(f"  funding utxo {u['txid'][:16]}.. amount={u['amount']}")

# --- build ONE signed CashToken FT-genesis tx, reused across the boundary ----
FEE = 0.001
cat = u["txid"]   # category id == genesis input txid (input is vout 0 => valid)
outs = [{addr: {"amount": round(u["amount"]-FEE, 8),
                "tokenData": {"category": cat, "amount": 1000000}}}]
raw = rpc("createrawtransaction", json.dumps([{"txid":u["txid"],"vout":0}]), json.dumps(outs))
prevtxs = [dict(txid=u["txid"], vout=0, scriptPubKey=u["spk"], amount=u["amount"])]
s = rpc("signrawtransactionwithkey", raw, json.dumps([wif]), json.dumps(prevtxs))
if not s.get("complete"): fail("token-genesis sign incomplete: "+json.dumps(s.get("errors","")))
token_tx = s["hex"]
print(f"  signed FT-genesis tx built (category={cat[:16]}..)")

def mempool_check():
    r = rpc("testmempoolaccept", json.dumps([token_tx]))[0]
    return r.get("allowed", False), r.get("reject-reason", "")

# --- 1. PRE-ACTIVATION: assert genuine gate up to the boundary ---------------
saw_reject = False
while rpc("getblockcount") < OVERRIDE - 1:
    allowed, reason = mempool_check()
    h = rpc("getblockcount")
    if allowed:
        fail(f"token tx accepted PRE-activation at tip {h} (override {OVERRIDE}) -- gate not genuine")
    if "txn-tokens-before-activation" not in reason:
        fail(f"pre-activation reject reason at tip {h} = '{reason}', expected 'txn-tokens-before-activation'")
    saw_reject = True
    rpc("generatetoaddress", 1, addr)
if not saw_reject:
    fail("never observed a pre-activation reject (override too low / always-on) -- not a genuine boundary")
print(f"  [PASS] B1 pre-activation gate: token tx HARD-REJECTED 'txn-tokens-before-activation' "
      f"up to tip {rpc('getblockcount')} (impossible under always-on regtest)")

# --- 2. CROSS THE BOUNDARY: mine to >= OVERRIDE, assert flip to ACCEPT --------
while True:
    allowed, reason = mempool_check()
    h = rpc("getblockcount")
    if allowed:
        print(f"  [PASS] B2 activation flip: token tx ACCEPTED at tip {h} (>= override {OVERRIDE-1})")
        break
    if h > OVERRIDE + 2:
        fail(f"token tx still rejected ('{reason}') at tip {h}, well past override {OVERRIDE}")
    rpc("generatetoaddress", 1, addr)

# --- 3. WON-BLOCK: broadcast + mine the activated token tx into a block -------
txid = rpc("sendrawtransaction", token_tx)
blk = rpc("generatetoaddress", 1, addr)[0]
b = rpc("getblock", blk, 2)
height = b["height"]
landed = next((t for t in b["tx"] if t["txid"] == txid), None)
if not landed: fail(f"activated token tx {txid[:16]}.. did not land in block {blk}")
td = landed["vout"][0].get("tokenData")
if not td or td.get("category") != cat or str(td.get("amount")) != "1000000":
    fail(f"tokenData lost/mangled in won-block: {td}")
print(f"  [PASS] B3 won-block {blk} @h{height}: token tx landed, "
      f"tokenData survives (category={td['category'][:16]}.. amount={td['amount']})")

# --- 4. coinbase invariant: no segwit witness commitment (BCH) ----------------
cb = b["tx"][0]
if any(o["scriptPubKey"]["hex"].startswith("6a24aa21a9ed") for o in cb["vout"]):
    fail("won-block coinbase carries a segwit witness commitment -- BCH must NOT")
print("  [PASS] B4 no segwit witness commitment (BCH invariant)")

json.dump(b, open("/tmp/bch_g3b_block.json", "w"))
print(f"=== G3b GENUINE-ACTIVATION DELIVERABLE OK: override={OVERRIDE} "
      f"won-block={blk} h={height} category={cat[:16]}.. ===")
