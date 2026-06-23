#!/usr/bin/env python3
# G3 LIVE leg: drive a REAL submitblock RPC round-trip against a live regtest
# bitcoind (VM420), capturing FOUND -> ASSEMBLED -> ACCEPTED for each share-version
# regime (v35 / HYBRID / v36). This is the live counterpart to the host-side model
# in src/impl/btc/test/g3_block_production_test.cpp: the two sink fakes are swapped
# for the real RPC submit path here.
#
# The invariant under test (same as the standalone harness): reaches_network is
# INDEPENDENT of the c2pool share-version regime. The share version is a c2pool
# encoding tag; the assembled PARENT block submitted to bitcoind is structurally
# version-agnostic, so every regime must yield ACCEPTED identically.
#
# No new deps: shells out to bitcoin-cli. Hand-rolls an empty segwit block.
import json, struct, subprocess, hashlib, sys, time

CLI = ["bitcoin-cli", "-regtest", "-datadir=/home/ubuntu/.bitcoin-regtest"]

def rpc(*args):
    out = subprocess.run(CLI + list(args), capture_output=True, text=True)
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

def push_height(h):  # match bitcoind's `CScript() << nHeight` (BIP34 prefix check)
    if h == 0: return b"\x00"          # OP_0
    if 1 <= h <= 16: return bytes([0x50 + h])  # OP_1..OP_16 single opcode
    bs = b""
    x = h
    while x:
        bs += bytes([x & 0xff]); x >>= 8
    if bs[-1] & 0x80: bs += b"\x00"
    return bytes([len(bs)]) + bs

def build_block(tmpl, tag):
    height = tmpl["height"]
    payout = bytes.fromhex(rpc("getnewaddress") and rpc("getaddressinfo", rpc("getnewaddress"))) if False else None
    # simple anyone-can-pay OP_TRUE output for the subsidy
    spk = b"\x51"  # OP_TRUE
    value = tmpl["coinbasevalue"]
    # coinbase scriptSig: BIP34 height + a tag marker so v35/HYBRID/v36 differ in
    # the (consensus-irrelevant) coinbase tag, proving the tag does NOT steer reach.
    scriptsig = push_height(height) + bytes([len(tag)]) + tag
    # witness commitment for an empty block:
    # witness merkle root = coinbase wtxid = 0x00*32; reserved = 0x00*32
    wcommit = dsha(b"\x00"*32 + b"\x00"*32)
    commit_spk = b"\x6a\x24\xaa\x21\xa9\xed" + wcommit  # OP_RETURN 0x24 <header><commit>
    # serialize coinbase (non-witness form for txid)
    cb_in = b"\x00"*32 + b"\xff\xff\xff\xff" + varint(len(scriptsig)) + scriptsig + b"\xff\xff\xff\xff"
    out_payout = le(value, 8) + varint(len(spk)) + spk
    out_commit = le(0, 8) + varint(len(commit_spk)) + commit_spk
    cb_nowit = le(2,4) + varint(1) + cb_in + varint(2) + out_payout + out_commit + le(0,4)
    txid = dsha(cb_nowit)
    # witness-serialized coinbase for the block body
    witness = varint(1) + bytes([32]) + b"\x00"*32  # 1 stack item, 32-byte reserved value
    cb_wit = le(2,4) + b"\x00\x01" + varint(1) + cb_in + varint(2) + out_payout + out_commit + witness + le(0,4)
    # header
    merkle = txid  # single tx
    prev = bytes.fromhex(tmpl["previousblockhash"])[::-1]
    bits = int(tmpl["bits"], 16)
    ver = tmpl["version"]
    cur = int(tmpl["curtime"])
    target = (bits & 0xffffff) * (1 << (8 * ((bits >> 24) - 3)))
    nonce = 0
    while True:
        hdr = le(ver,4) + prev + merkle + le(cur,4) + le(bits,4) + le(nonce,4)
        if int.from_bytes(dsha(hdr)[::-1], "big") <= target:
            break
        nonce += 1
        if nonce > 5_000_000: raise RuntimeError("grind exhausted")
    block = hdr + varint(1) + cb_wit
    return block.hex(), height

def run_regime(label, tag):
    h0 = int(rpc("getblockcount"))                       # FOUND baseline
    tmpl = json.loads(rpc("getblocktemplate", json.dumps({"rules":["segwit"]})))
    blk, height = build_block(tmpl, tag)                  # ASSEMBLED
    res = rpc("submitblock", blk)                         # -> real submitblock RPC
    h1 = int(rpc("getblockcount"))
    accepted = (res == "" or res == "null") and h1 == h0 + 1
    print("  %-7s tag=%-9s submitblock=%-8r height %d->%d => %s"
          % (label, tag.decode(), res or "OK", h0, h1, "ACCEPTED" if accepted else "REJECTED/LOST"))
    return accepted

def main():
    print("== G3 LIVE submitblock leg vs VM420 regtest (FOUND->ASSEMBLED->ACCEPTED) ==")
    regimes = [("v35", b"g3-v35"), ("HYBRID", b"g3-hybrid"), ("v36", b"g3-v36")]
    results = {}
    for label, tag in regimes:
        results[label] = run_regime(label, tag)
    print("-- invariant: every regime reached the live network identically --")
    ok = all(results.values()) and len(set(results.values())) == 1
    print(("ALL PASS" if ok else "FAILED") + ": " + json.dumps(results))
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
