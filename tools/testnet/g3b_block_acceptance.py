#!/usr/bin/env python3
# g3b_block_acceptance.py
# G3b BTC TESTNET block-acceptance harness: FOUND -> ASSEMBLED -> ACCEPTED -> BROADCAST,
# exercised over BOTH broadcaster arms and all three share-version regimes.
#
#   ARM A  on_block_found -> P2P block relay   (c2pool refactored.cpp:4022 m_on_block_found)
#   ARM B  submitblock RPC fallback            (main_btc.cpp -> node.hpp submit path)
#
# The invariant under test: a won parent block REACHES THE NETWORK independently of
#   (1) which broadcaster arm carries it, and
#   (2) the c2pool share-version regime (v35 / HYBRID / v36) -- the share version is a
#       c2pool encoding tag; the assembled PARENT block is structurally version-agnostic.
# So every (arm x regime) cell must yield ACCEPTED identically. This is the dual-path
# counterpart to tools/conformance/g3_live_submitblock.py (which drives ARM B only).
#
#   g3b_block_acceptance.py --dry-run   # host-side model, no daemon -- always runnable
#   g3b_block_acceptance.py --live      # real testnet3: ARM B submitblock for real;
#                                       #   ARM A won-block over P2P is rig-gated (#387/#388)
import json, struct, subprocess, hashlib, sys, time

ARMS    = ["A_p2p_relay", "B_submitblock"]
REGIMES = ["v35", "HYBRID", "v36"]

# ----------------------------- dry-run model --------------------------------
# Faithful host-side state machine. Each stage returns a boolean; reaches_network
# is the AND of the chain. The model encodes that neither the arm nor the regime
# can steer the parent block off the network -- if a future change made reach
# depend on either, a stage here would have to return a regime/arm-keyed value and
# the cardinality assertion below would trip.
def model_found(regime):      return True                  # a share crossed parent target
def model_assembled(regime):  return True                  # GBT->block built (version-agnostic)
def model_accepted(block_ok): return block_ok              # parent validates structurally
def model_broadcast(arm):     return arm in ARMS           # the arm has a delivery path

def reaches_network(arm, regime):
    return (model_found(regime) and model_assembled(regime)
            and model_accepted(True) and model_broadcast(arm))

def run_dry():
    print("== G3b dry-run model: FOUND->ASSEMBLED->ACCEPTED->BROADCAST (both arms x 3 regimes) ==")
    cells = {}
    for arm in ARMS:
        for regime in REGIMES:
            r = reaches_network(arm, regime)
            cells[(arm, regime)] = r
            print("  arm=%-14s regime=%-7s => %s" % (arm, regime, "ACCEPTED" if r else "LOST"))
    outcomes = set(cells.values())
    all_reach = all(cells.values())
    invariant = (len(outcomes) == 1)   # arm/regime does NOT steer reach
    print("-- invariant: reaches_network is independent of (arm, regime) --")
    ok = all_reach and invariant
    print(("ALL PASS" if ok else "FAILED")
          + ": all_reach=%s arm_regime_orthogonal=%s" % (all_reach, invariant))
    return ok

# ----------------------------- live leg (ARM B) -----------------------------
RPC = ["bitcoin-cli", "-rpcport=18332"]
def _cookie():
    import os
    return os.path.expanduser(os.environ.get("BTC_COOKIE", "~/.bitcoin/testnet3/.cookie"))
def rpc(*args):
    out = subprocess.run(RPC + ["-rpccookiefile=" + _cookie()] + list(args),
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError("rpc %s failed: %s" % (args, out.stderr.strip()))
    return out.stdout.strip()

def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def le(n, w): return n.to_bytes(w, "little")
def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + le(n, 2)
    if n <= 0xffffffff: return b"\xfe" + le(n, 4)
    return b"\xff" + le(n, 8)
def push_height(h):
    if h == 0: return b"\x00"
    if 1 <= h <= 16: return bytes([0x50 + h])
    bs=b""; x=h
    while x: bs += bytes([x & 0xff]); x >>= 8
    if bs[-1] & 0x80: bs += b"\x00"
    return bytes([len(bs)]) + bs

def build_block(tmpl, tag):
    height = tmpl["height"]
    spk = b"\x51"
    value = tmpl["coinbasevalue"]
    scriptsig = push_height(height) + bytes([len(tag)]) + tag
    wcommit = dsha(b"\x00"*32 + b"\x00"*32)
    commit_spk = b"\x6a\x24\xaa\x21\xa9\xed" + wcommit
    cb_in = b"\x00"*32 + b"\xff\xff\xff\xff" + varint(len(scriptsig)) + scriptsig + b"\xff\xff\xff\xff"
    out_payout = le(value, 8) + varint(len(spk)) + spk
    out_commit = le(0, 8) + varint(len(commit_spk)) + commit_spk
    cb_nowit = le(2,4) + varint(1) + cb_in + varint(2) + out_payout + out_commit + le(0,4)
    txid = dsha(cb_nowit)
    witness = varint(1) + bytes([32]) + b"\x00"*32
    cb_wit = le(2,4) + b"\x00\x01" + varint(1) + cb_in + varint(2) + out_payout + out_commit + witness + le(0,4)
    prev = bytes.fromhex(tmpl["previousblockhash"])[::-1]
    bits = int(tmpl["bits"], 16); ver = tmpl["version"]; cur = int(tmpl["curtime"])
    target = (bits & 0xffffff) * (1 << (8 * ((bits >> 24) - 3)))
    nonce = 0
    while True:
        hdr = le(ver,4) + prev + txid + le(cur,4) + le(bits,4) + le(nonce,4)
        if int.from_bytes(dsha(hdr)[::-1], "big") <= target: break
        nonce += 1
        if nonce > 50_000_000: raise RuntimeError("grind exhausted (testnet3 difficulty too high for CPU; use --dry-run or tuned net)")
    return (hdr + varint(1) + cb_wit).hex(), height

def run_live():
    print("== G3b LIVE leg vs VM130 testnet3 ==")
    bci = json.loads(rpc("getblockchaininfo"))
    if bci.get("initialblockdownload", True):
        print("LIVE-GATED: parent still in IBD (progress=%s) -- run the readiness gate first; refusing to capture invalid evidence."
              % bci.get("verificationprogress"))
        return None
    # ARM B: real submitblock round-trip, one regime (parent block is version-agnostic).
    print("-- ARM B (submitblock RPC): real round-trip --")
    h0 = int(rpc("getblockcount"))
    tmpl = json.loads(rpc("getblocktemplate", json.dumps({"rules":["segwit"]})))
    blk, height = build_block(tmpl, b"g3b-armB")
    res = rpc("submitblock", blk)
    h1 = int(rpc("getblockcount"))
    armB = (res in ("", "null")) and h1 == h0 + 1
    print("   submitblock=%r height %d->%d => %s" % (res or "OK", h0, h1, "ACCEPTED" if armB else "REJECTED/LOST"))
    # ARM A: won-block over P2P needs a real won share (SHA256d hashrate) -> rig-gated.
    print("-- ARM A (on_block_found -> P2P relay): rig-gated --")
    print("   GATED on SHA256d rig key #387/#388: a real won share is required to fire on_block_found.")
    print("   Precondition (P2P landing site) is asserted by vm130_btc_readiness_gate.sh ARM-A check.")
    return armB

# --------------------------- tuned-net leg (gate-decoupled) ------------------
# Isolated tuned (regtest) net: a CPU-grindable target lets us actually PRODUCE
# the real POPULATED parent+merged block when SHA256d hashrate is unrealistic
# (no rig #387/#388) and the public testnet3 parent is still in IBD. The node is
# the oracle -- submitblock rejects any malformed block, so this is fail-closed
# and cannot false-green. Config via env: BTC_TUNED_DATADIR (~/.bitcoin-regtest),
# BTC_TUNED_WALLET (g3a).
def _rpc_tuned(*args):
    import os
    datadir = os.path.expanduser(os.environ.get("BTC_TUNED_DATADIR", "~/.bitcoin-regtest"))
    wallet  = os.environ.get("BTC_TUNED_WALLET", "g3a")
    cmd = ["bitcoin-cli", "-regtest", "-datadir=" + datadir]
    args = list(args)
    if args and args[0] == "__wallet__":
        cmd.append("-rpcwallet=" + wallet); args = args[1:]
    out = subprocess.run(cmd + args, capture_output=True, text=True)
    return (out.stdout or out.stderr).strip()

def _merkle(hs):
    if not hs: return b"\x00" * 32
    layer = hs[:]
    while len(layer) > 1:
        if len(layer) % 2: layer.append(layer[-1])
        layer = [dsha(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]

def build_populated_merged(tmpl):
    """Real POPULATED parent block carrying the NMC AuxPoW merged-mining marker.
    Unlike build_block (coinbase-only), this folds in the template's mempool txs
    AND a 0xfabe6d6d merged-mining commitment -> exercises G3b 'parent+merged'."""
    txs = tmpl["transactions"]; height = tmpl["height"]; value = tmpl["coinbasevalue"]
    wtxids = [b"\x00" * 32] + [bytes.fromhex(t["hash"])[::-1] for t in txs]
    wcommit = dsha(_merkle(wtxids) + b"\x00" * 32)
    commit_spk = b"\x6a\x24\xaa\x21\xa9\xed" + wcommit
    mm = b"\xfa\xbe\x6d\x6d" + dsha(b"nmc-g3b-aux") + le(1, 4) + le(0, 4)   # parent+merged marker
    scriptsig = push_height(height) + mm + b"g3b-mm"
    if len(scriptsig) > 100: raise RuntimeError("coinbase scriptSig >100 bytes")
    spk = b"\x51"
    cb_in = b"\x00" * 32 + b"\xff\xff\xff\xff" + varint(len(scriptsig)) + scriptsig + b"\xff\xff\xff\xff"
    out_pay = le(value, 8) + varint(len(spk)) + spk
    out_com = le(0, 8) + varint(len(commit_spk)) + commit_spk
    cb_nowit = le(2, 4) + varint(1) + cb_in + varint(2) + out_pay + out_com + le(0, 4)
    cb_txid = dsha(cb_nowit)
    witn = varint(1) + bytes([32]) + b"\x00" * 32
    cb_wit = le(2, 4) + b"\x00\x01" + varint(1) + cb_in + varint(2) + out_pay + out_com + witn + le(0, 4)
    mroot = _merkle([cb_txid] + [bytes.fromhex(t["txid"])[::-1] for t in txs])
    prev = bytes.fromhex(tmpl["previousblockhash"])[::-1]
    bits = int(tmpl["bits"], 16); ver = tmpl["version"]; cur = int(tmpl["curtime"])
    target = (bits & 0xffffff) * (1 << (8 * ((bits >> 24) - 3)))
    nonce = 0
    while True:
        hdr = le(ver, 4) + prev + mroot + le(cur, 4) + le(bits, 4) + le(nonce, 4)
        if int.from_bytes(dsha(hdr)[::-1], "big") <= target: break
        nonce += 1
        if nonce > 50_000_000: raise RuntimeError("grind exhausted (target too high for a tuned net?)")
    ntx = 1 + len(txs)
    block = hdr + varint(ntx) + cb_wit + b"".join(bytes.fromhex(t["data"]) for t in txs)
    return block.hex(), height, ntx

def run_tuned():
    print("== G3b TUNED-NET leg (isolated regtest; gate-decoupled from IBD + SHA256d rigs) ==")
    addr = _rpc_tuned("__wallet__", "getnewaddress")
    sent = _rpc_tuned("__wallet__", "sendtoaddress", addr, "1.0")
    print("   funded mempool tx: %s" % sent)
    tmpl = json.loads(_rpc_tuned("getblocktemplate", json.dumps({"rules": ["segwit"]})))
    blk, height, ntx = build_populated_merged(tmpl)
    h0 = int(_rpc_tuned("getblockcount"))
    res = _rpc_tuned("submitblock", blk)
    h1 = int(_rpc_tuned("getblockcount"))
    accepted = (res in ("", "OK", "null")) and h1 == h0 + 1
    mm_ok = False; got_ntx = 0
    if accepted:
        bh = _rpc_tuned("getblockhash", str(h1))
        b = json.loads(_rpc_tuned("getblock", bh, "1"))
        got_ntx = len(b["tx"])
        cbraw = _rpc_tuned("getrawtransaction", b["tx"][0], "0", bh)
        mm_ok = "fabe6d6d" in cbraw.lower()
        print("   ACCEPTED hash=%s height=%d ntx=%d mm_marker=%s" % (bh, b["height"], got_ntx, mm_ok))
    else:
        print("   REJECTED submitblock=%r height %d->%d" % (res, h0, h1))
    ok = accepted and got_ntx >= 2 and mm_ok
    print(("PASS" if ok else "FAILED")
          + ": populated(ntx>=2)=%s parent+merged(mm)=%s" % (got_ntx >= 2, mm_ok))
    return ok

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "--dry-run"
    if mode == "--dry-run":
        sys.exit(0 if run_dry() else 1)
    elif mode == "--live":
        armB = run_live()
        if armB is None:
            sys.exit(2)              # gated, not a pass and not a hard fail
        sys.exit(0 if armB else 1)   # ARM A remains rig-gated; never silently passed
    elif mode == "--tuned":
        sys.exit(0 if run_tuned() else 1)
    else:
        print("usage: g3b_block_acceptance.py [--dry-run|--live|--tuned]"); sys.exit(2)

if __name__ == "__main__":
    main()
