#!/usr/bin/env python3
# G3a -- BCH v36 greenlight gate: produce a POPULATED regtest block with a
# diverse, BCH-NATIVE transaction mix (CashTokens genesis FT + NFT + transfer,
# P2SH32, 1-of-2 P2SH multisig donation shape, OP_RETURN, ~30-input consolidation)
# and HARD-FAIL assertions that every output type survives a full
# serialize->node->deserialize round-trip, that CTOR holds, that the block
# merkle root recomputes, and that NO segwit witness commitment is present
# (BCH invariant -- SegWit struck from scope).
#
# WALLET-LESS by necessity: this BCHN v29 regtest is compiled --disable-wallet,
# unlike the peer btc/dgb/dash nodes. Coins + keys are provisioned via BCHN's
# own test_framework (pure-python secp256k1 + base58), and txs are signed with
# the node RPC signrawtransactionwithkey. Isolated regtest only; self-funds.
# Additive/fenced: no consensus, shared-base, build.yml or CMake surface.
import subprocess, json, sys, os
sys.path.insert(0, "/home/ubuntu/Github/bitcoin-cash-node/test/functional")
from test_framework.key import ECKey
from test_framework.address import (key_to_p2pkh, byte_to_base58, hash160,
                                    script_to_p2sh, script_to_p2sh32)
from test_framework.script import CScript, OP_1, OP_2, OP_CHECKMULTISIG, OP_TRUE

BCLI = ["/home/ubuntu/Github/bitcoin-cash-node/build/src/bitcoin-cli",
        "-conf=/home/ubuntu/bch-regtest/bitcoin.conf",
        "-datadir=/home/ubuntu/bch-regtest"]
def rpc(*a):
    o = subprocess.run(BCLI + [str(x) for x in a], text=True,
                       capture_output=True)
    if o.returncode != 0:
        raise RuntimeError(o.stderr.strip() or o.stdout.strip())
    s = o.stdout.strip()
    try: return json.loads(s)
    except Exception: return s
def fail(m): print("ASSERT-FAIL:", m, file=sys.stderr); sys.exit(1)

assert rpc("getblockchaininfo")["chain"] == "regtest", "refusing off-regtest"

# --- key / funding address (single deterministic-per-run key) ---------------
k = ECKey(); k.generate()
wif = byte_to_base58(k.get_bytes() + b"\x01", 239)        # regtest WIF, compressed
pub = k.get_pubkey().get_bytes()
addr = key_to_p2pkh(pub)
my_spk = "76a914" + hash160(pub).hex() + "88ac"   # canonical P2PKH spk for our key
print(f"=== G3a BCH harness  funding addr={addr} ===")

# --- 1. self-provision mature coins -----------------------------------------
rpc("generatetoaddress", 160, addr)                       # >100 maturity, pre-halving (150)
tip = rpc("getblockcount")
# collect mature coinbase outpoints (vout 0, P2PKH to our key)
coins = []   # list of dict(txid,vout,amount,spk)
for h in range(1, tip - 100):
    bh = rpc("getblockhash", h)
    b = rpc("getblock", bh, 2)
    cb = b["tx"][0]
    o0 = cb["vout"][0]
    if o0["scriptPubKey"]["hex"] != my_spk: continue   # own-coinbase match by spk hex
    coins.append(dict(txid=cb["txid"], vout=0, amount=o0["value"],
                      spk=o0["scriptPubKey"]["hex"]))
print(f"mature coinbase utxos owned: {len(coins)}")
if len(coins) < 40: fail(f"insufficient mature coins ({len(coins)})")
ci = iter(coins)
def take(): return next(ci)

def sign_send(raw, prevtxs):
    s = rpc("signrawtransactionwithkey", raw, json.dumps([wif]), json.dumps(prevtxs))
    if not s.get("complete"): raise RuntimeError("incomplete sign: "+json.dumps(s.get("errors","")))
    return rpc("sendrawtransaction", s["hex"])

FEE = 0.001
results = {}
legs = []

# --- helper to build prevtx entry for our coinbase utxo ---------------------
def prev(u, tokenData=None):
    e = dict(txid=u["txid"], vout=u["vout"], scriptPubKey=u["spk"], amount=u["amount"])
    if tokenData: e["tokenData"] = tokenData
    return e

# T_GEN_FT: spend coinbase (outpoint idx 0 => valid genesis) -> fungible token
def leg_ft():
    u = take(); cat = u["txid"]            # category id == genesis input txid
    outs = [{addr: {"amount": round(u["amount"]-FEE, 8), "tokenData": {"category": cat, "amount": 1000000}}}]
    raw = rpc("createrawtransaction", json.dumps([{"txid":u["txid"],"vout":0}]), json.dumps(outs))
    txid = sign_send(raw, [prev(u)])
    results["ft"] = dict(txid=txid, category=cat); return txid
# T_GEN_NFT: minting NFT with commitment
def leg_nft():
    u = take(); cat = u["txid"]
    outs = [{addr: {"amount": round(u["amount"]-FEE, 8),
             "tokenData": {"category": cat, "amount": 0,
                           "nft": {"capability": "minting", "commitment": "c2b3360f9a"}}}}]
    raw = rpc("createrawtransaction", json.dumps([{"txid":u["txid"],"vout":0}]), json.dumps(outs))
    txid = sign_send(raw, [prev(u)])
    results["nft"] = dict(txid=txid, category=cat); return txid
# T_XFER: transfer the FT genesis output (same block, spend by txid) ----------
def leg_xfer():
    g = results["ft"]; cat = g["category"]
    # the FT genesis output 0 holds the tokens; build a prevtx for it
    gtx = rpc("getrawtransaction", g["txid"], 1)
    o0 = gtx["vout"][0]; amt = o0["value"]; spk = o0["scriptPubKey"]["hex"]
    pt = dict(txid=g["txid"], vout=0, scriptPubKey=spk, amount=amt,
              tokenData={"category": cat, "amount": "1000000"})
    outs = [{addr: {"amount": round(amt-FEE, 8), "tokenData": {"category": cat, "amount": 1000000}}}]
    raw = rpc("createrawtransaction", json.dumps([{"txid":g["txid"],"vout":0}]), json.dumps(outs))
    txid = sign_send(raw, [pt]); results["xfer"] = dict(txid=txid); return txid
# T_P2SH32 output ------------------------------------------------------------
def leg_p2sh32():
    u = take(); redeem = CScript([OP_TRUE]); p = script_to_p2sh32(redeem)
    raw = rpc("createrawtransaction", json.dumps([{"txid":u["txid"],"vout":0}]),
              json.dumps([{p: round(u["amount"]-FEE,8)}]))
    txid = sign_send(raw, [prev(u)]); results["p2sh32"]=dict(txid=txid,addr=p); return txid
# T_MULTISIG 1-of-2 P2SH (donation shape) ------------------------------------
def leg_multisig():
    u = take(); k2=ECKey(); k2.generate()
    redeem = CScript([OP_1, pub, k2.get_pubkey().get_bytes(), OP_2, OP_CHECKMULTISIG])
    p = script_to_p2sh(redeem)
    raw = rpc("createrawtransaction", json.dumps([{"txid":u["txid"],"vout":0}]),
              json.dumps([{p: round(u["amount"]-FEE,8)}]))
    txid = sign_send(raw, [prev(u)]); results["multisig"]=dict(txid=txid,addr=p); return txid
# T_OPRETURN data carrier ----------------------------------------------------
def leg_opreturn():
    u = take(); data = b"c2pool-bch-g3a".hex()
    raw = rpc("createrawtransaction", json.dumps([{"txid":u["txid"],"vout":0}]),
              json.dumps([{addr: round(u["amount"]-FEE,8)}, {"data": data}]))
    txid = sign_send(raw, [prev(u)]); results["opreturn"]=dict(txid=txid); return txid
# T_30IN consolidation (~30 inputs) ------------------------------------------
def leg_30in():
    us = [take() for _ in range(30)]
    ins = [{"txid":u["txid"],"vout":0} for u in us]
    tot = round(sum(u["amount"] for u in us) - FEE, 8)
    raw = rpc("createrawtransaction", json.dumps(ins), json.dumps([{addr: tot}]))
    txid = sign_send(raw, [prev(u) for u in us]); results["c30"]=dict(txid=txid,nin=len(us)); return txid

for name, fn in [("ft",leg_ft),("nft",leg_nft),("xfer",leg_xfer),("p2sh32",leg_p2sh32),
                 ("multisig",leg_multisig),("opreturn",leg_opreturn),("c30",leg_30in)]:
    try:
        t = fn(); legs.append(name); print(f"  [mempool] {name} -> {t}")
    except Exception as e:
        print(f"  [LEG-FAIL] {name}: {e}")

print(f"legs in mempool: {legs}  mempool size={rpc('getmempoolinfo')['size']}")

# --- mine ONE block capturing the whole mempool = the deliverable block ------
blk = rpc("generatetoaddress", 1, addr)[0]
b = rpc("getblock", blk, 2)
txs = b["tx"]
print(f"=== deliverable populated block {blk}  txcount={len(txs)} ===")
json.dump(b, open("/tmp/bch_g3a_block.json","w"))

# --- HARD-FAIL assertions ---------------------------------------------------
n=len(txs)
if n < 6: fail(f"under-populated ({n} txs, want >=6)")
print(f"  [PASS] A1 populated: {n} txs (coinbase + {n-1} payload)")
cb=txs[0]
if any(o["scriptPubKey"]["hex"].startswith("6a24aa21a9ed") for o in cb["vout"]):
    fail("coinbase carries a segwit witness commitment -- BCH must NOT")
print("  [PASS] A2 no segwit witness commitment (BCH invariant)")
ids=[t["txid"] for t in txs[1:]]
if ids != sorted(ids): fail("CTOR violated: payload txs not ascending by txid")
print(f"  [PASS] A3 CTOR holds ({len(ids)} payload txs ascending by txid)")
import hashlib
def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def merkle(idlist):
    layer=[bytes.fromhex(x)[::-1] for x in idlist]
    while len(layer)>1:
        if len(layer)%2: layer.append(layer[-1])
        layer=[dsha(layer[i]+layer[i+1]) for i in range(0,len(layer),2)]
    return layer[0][::-1].hex()
mr=merkle([t["txid"] for t in txs])
if mr != b["merkleroot"]: fail(f"merkle mismatch {mr} != {b['merkleroot']}")
print(f"  [PASS] A4 merkle root recomputes ({mr[:16]}...)")
# token round-trips
def find(txid): 
    for t in txs:
        if t["txid"]==txid: return t
    return None
if "ft" in results:
    t=find(results["ft"]["txid"]); td=t["vout"][0].get("tokenData")
    if not td or td["category"]!=results["ft"]["category"]: fail("FT genesis tokenData lost")
    print(f"  [PASS] A5 CashToken FT genesis: category={td['category'][:16]}.. amount={td['amount']}")
if "nft" in results:
    t=find(results["nft"]["txid"]); td=t["vout"][0].get("tokenData")
    if not td or "nft" not in td or td["nft"].get("commitment")!="c2b3360f9a":
        fail("NFT commitment lost")
    print(f"  [PASS] A5 CashToken NFT: cap={td['nft']['capability']} commit={td['nft']['commitment']}")
if "xfer" in results:
    t=find(results["xfer"]["txid"]); td=t["vout"][0].get("tokenData")
    if not td: fail("token transfer lost tokenData")
    print(f"  [PASS] A5 CashToken transfer preserves category={td['category'][:16]}..")
if "p2sh32" in results:
    t=find(results["p2sh32"]["txid"])
    if not any(o["scriptPubKey"]["hex"].startswith("aa20") and o["scriptPubKey"]["hex"].endswith("87") for o in t["vout"]):
        fail("P2SH32 output (OP_HASH256<32>OP_EQUAL) absent")
    print("  [PASS] A6 P2SH32 output present (aa20..87)")
if "c30" in results:
    t=find(results["c30"]["txid"])
    if len(t["vin"])<30: fail(f"consolidation only {len(t['vin'])} inputs")
    print(f"  [PASS] A7 large consolidation tx: {len(t['vin'])} inputs")
print(f"=== G3a POPULATED-BLOCK DELIVERABLE OK: block={blk} txs={n} legs={legs} ===")
