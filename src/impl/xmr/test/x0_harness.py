#!/usr/bin/env python3
# X0 feasibility proof harness for the v37 "Family B: XMR lane".
#
# Reproduces, against a REAL Monero mainnet block, the triple that a v37
# Work-Receipts verifier must recompute for a RandomX/Monero carrier:
#   (a) hashing_blob = serialize(block_header) || tree_root(32) || varint(n_tx)
#   (b) block_id     = Keccak256( varint(len(hashing_blob)) || hashing_blob )
#   (c) miner_tx hash (coinbase, v2 RCTTypeNull three-hash form)
# and demonstrates the KECCAK-MIDSTATE coinbase-opening: absorb the miner_tx
# prefix up to tx_extra, EXPORT the sponge state, then (as a verifier would,
# holding only midstate + the tx_extra tail) resume -> prefix hash -> tx hash
# -> Monero tree_branch -> tree_root, and confirm root == the one committed in
# the block header (and hence in block_id / the RandomX PoW input).
#
# Pure Python, ZERO third-party deps: Keccak-f[1600] is implemented inline
# BECAUSE the midstate export/resume needs raw access to the 1600-bit sponge
# state, which no stock hashlib/pycryptodome API exposes.
#
# Keccak parameters and the tree_hash / tree_branch algorithms are ported
# faithfully from monero-project/monero src/crypto/keccak.c and tree-hash.c
# (BSD-3-Clause, (c) 2014-2024 The Monero Project) -- see PROVENANCE.md.
#
# Author: v37-dev-steward (X0 leg). Reference data fetched live from a public
# monerod (get_block); the proof is self-checking against block_header.hash
# and miner_tx_hash returned by that daemon.

import json, sys, os

# --------------------------------------------------------------------------
# Keccak-f[1600] permutation (24 rounds). Constants == keccak.c keccakf_rndc.
# --------------------------------------------------------------------------
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
M64 = (1 << 64) - 1

def _rotl(x, n):
    return ((x << n) | (x >> (64 - n))) & M64

def keccakf(st):
    # st: list[25] uint64, laid out st[x + 5*y] (x=col, y=row) -- matches keccak.c
    A = [[st[x + 5 * y] for y in range(5)] for x in range(5)]
    for rnd in range(24):
        # theta
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rotl(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]
        # rho + pi
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rotl(A[x][y], ROT[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) & M64
        # iota
        A[0][0] ^= RC[rnd]
    for x in range(5):
        for y in range(5):
            st[x + 5 * y] = A[x][y]

# --------------------------------------------------------------------------
# Keccak-256 sponge, Monero cn_fast_hash flavour: rate = 136 B, capacity 512,
# padding byte 0x01 (NOT SHA3's 0x06) at the message end, 0x80 at rate-1.
# Incremental form mirrors keccak.c keccak_init/keccak_update/keccak_finish so
# that a partial absorb can be frozen as a portable midstate.
# --------------------------------------------------------------------------
RATE = 136  # KECCAK_BLOCKLEN

class Keccak256:
    def __init__(self, state=None, buf=b""):
        self.st = list(state) if state is not None else [0] * 25   # 25 uint64 lanes
        self.buf = bytearray(buf)                                  # < RATE unabsorbed bytes

    def _absorb_block(self, block):  # block: exactly RATE bytes
        for i in range(17):          # rsizw = RATE/8 = 17 words
            self.st[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        keccakf(self.st)

    def update(self, data):
        self.buf += data
        while len(self.buf) >= RATE:
            self._absorb_block(self.buf[:RATE])
            del self.buf[:RATE]
        return self

    def export_midstate(self):
        # Portable freeze point: the 200-byte permuted state + the <RATE tail
        # not yet absorbed. Everything before this point is a fixed cost.
        st_bytes = b"".join(x.to_bytes(8, "little") for x in self.st)
        return {"state": st_bytes.hex(), "buf": bytes(self.buf).hex(),
                "absorbed_blocks_after_state": None}

    @staticmethod
    def from_midstate(mid):
        st = [int.from_bytes(bytes.fromhex(mid["state"])[8 * i:8 * i + 8], "little")
              for i in range(25)]
        return Keccak256(state=st, buf=bytes.fromhex(mid["buf"]))

    def digest(self):
        # Pad the final (partial) block: temp[rest] = 0x01 ; temp[RATE-1] |= 0x80
        temp = bytearray(RATE)
        rest = len(self.buf)
        temp[:rest] = self.buf
        temp[rest] ^= 0x01
        temp[RATE - 1] ^= 0x80
        st = list(self.st)
        for i in range(17):
            st[i] ^= int.from_bytes(temp[8 * i:8 * i + 8], "little")
        keccakf(st)
        return b"".join(st[i].to_bytes(8, "little") for i in range(4))  # 32 bytes

def cn_fast_hash(data):
    return Keccak256().update(data).digest()

NULL_HASH = b"\x00" * 32

# --------------------------------------------------------------------------
# CryptoNote varint (base-128 LE, 7 bits/byte, high bit = continue)
# --------------------------------------------------------------------------
def read_varint(b, o):
    shift = 0; val = 0
    while True:
        c = b[o]; o += 1
        val |= (c & 0x7F) << shift
        if not (c & 0x80):
            break
        shift += 7
    return val, o

def write_varint(v):
    out = bytearray()
    while True:
        c = v & 0x7F; v >>= 7
        if v:
            out.append(c | 0x80)
        else:
            out.append(c); break
    return bytes(out)

# --------------------------------------------------------------------------
# Monero block / miner_tx deserialization (only what the coinbase needs).
# --------------------------------------------------------------------------
def parse_block(blob):
    o = 0
    B = {}
    B["major_version"], o = read_varint(blob, o)
    B["minor_version"], o = read_varint(blob, o)
    B["timestamp"], o = read_varint(blob, o)
    B["prev_id"] = blob[o:o + 32]; o += 32
    B["nonce"] = blob[o:o + 4]; o += 4              # 4 raw LE bytes (NOT a varint)
    hdr_end = o
    B["header_blob"] = blob[:hdr_end]               # exactly get_block_hashing_blob's header part
    # miner_tx (transaction) --------------------------------------------------
    tx = {}
    tx_start = o
    tx["version"], o = read_varint(blob, o)
    tx["unlock_time"], o = read_varint(blob, o)
    vin_cnt, o = read_varint(blob, o)
    vins = []
    for _ in range(vin_cnt):
        tag = blob[o]; o += 1
        if tag == 0xFF:                             # txin_gen
            h, o = read_varint(blob, o)
            vins.append(("txin_gen", h))
        else:
            raise ValueError("coinbase vin tag != 0xFF (txin_gen): 0x%02x" % tag)
    tx["vin"] = vins
    vout_cnt, o = read_varint(blob, o)
    vouts = []
    for _ in range(vout_cnt):
        amt, o = read_varint(blob, o)
        ttag = blob[o]; o += 1
        if ttag == 0x02:                            # txout_to_key
            key = blob[o:o + 32]; o += 32
            vouts.append(("txout_to_key", amt, key.hex(), None))
        elif ttag == 0x03:                          # txout_to_tagged_key (HF15+ view tags)
            key = blob[o:o + 32]; o += 32
            vt = blob[o]; o += 1
            vouts.append(("txout_to_tagged_key", amt, key.hex(), vt))
        else:
            raise ValueError("unexpected vout target tag 0x%02x" % ttag)
    tx["vout"] = vouts
    extra_len, o = read_varint(blob, o)
    extra_start = o                                 # <-- MIDSTATE BOUNDARY (start of tx_extra bytes)
    tx["extra"] = blob[o:o + extra_len]; o += extra_len
    prefix_end = o                                  # transaction_prefix ends right here
    tx["prefix_blob"] = blob[tx_start:prefix_end]
    tx["extra_start_in_prefix"] = extra_start - tx_start
    # rct_signatures: coinbase is RCTTypeNull -> a single type byte 0x00
    tx["rct_type"] = blob[o]; o += 1
    tx["tx_end"] = o
    B["miner_tx"] = tx
    B["miner_tx_end"] = o
    # tx_hashes vector (non-coinbase) ----------------------------------------
    n, o = read_varint(blob, o)
    hashes = []
    for _ in range(n):
        hashes.append(blob[o:o + 32]); o += 32
    B["tx_hashes"] = hashes
    B["trailing_bytes"] = len(blob) - o
    return B

def parse_tx_extra(extra):
    """Parse the tx_extra TLV stream enough to surface the tx public key R."""
    o = 0; fields = []
    while o < len(extra):
        tag = extra[o]; o += 1
        if tag == 0x00:                             # padding: run of zero bytes to end
            z = 0
            while o < len(extra) and extra[o] == 0x00:
                o += 1; z += 1
            fields.append(("padding", z))
        elif tag == 0x01:                           # tx public key R = r*G
            R = extra[o:o + 32]; o += 32
            fields.append(("pubkey", R.hex()))
        elif tag == 0x02:                           # extra nonce: varint(size) + bytes
            ln, o = read_varint(extra, o)
            fields.append(("extra_nonce", extra[o:o + ln].hex())); o += ln
        elif tag == 0x03:                           # merge-mining: varint(len) + varint(depth) + 32B root
            flen, o = read_varint(extra, o)
            fend = o + flen
            depth, o = read_varint(extra, o)
            root = extra[o:o + 32]; o += 32
            fields.append(("merge_mining", {"depth": depth, "merkle_root": root.hex()}))
            o = fend                                 # skip any residue inside the length-prefixed field
        elif tag == 0x04:                           # additional pubkeys
            cnt, o = read_varint(extra, o)
            ks = []
            for _ in range(cnt):
                ks.append(extra[o:o + 32].hex()); o += 32
            fields.append(("additional_pubkeys", ks))
        else:
            fields.append(("unknown_tag_stop", "0x%02x" % tag, extra[o:].hex()))
            break
    return fields

# --------------------------------------------------------------------------
# miner_tx (coinbase) hash: v2, rct_signatures.type == RCTTypeNull (== 0).
# calculate_transaction_hash: res = cn_fast_hash( H_prefix || H_base || H_prun )
#   H_prefix = cn_fast_hash(serialize(transaction_prefix))
#   H_base   = cn_fast_hash(rct base blob); for RCTTypeNull the base blob is the
#              single type byte 0x00 (serialize_rctsig_base writes only `type`).
#   H_prun   = null_hash (no prunable data in a coinbase).
# --------------------------------------------------------------------------
def prefix_hash(tx):
    return cn_fast_hash(tx["prefix_blob"])

def miner_tx_hash(tx):
    h0 = prefix_hash(tx)
    h1 = cn_fast_hash(bytes([tx["rct_type"]]))      # rct base blob == b'\x00'
    h2 = NULL_HASH
    return cn_fast_hash(h0 + h1 + h2), (h0, h1, h2)

# --------------------------------------------------------------------------
# Monero tree_hash / tree_branch / tree_branch_hash  (ported from tree-hash.c)
# --------------------------------------------------------------------------
def tree_hash_cnt(count):
    assert count >= 3
    pow_ = 2
    while pow_ < count:
        pow_ <<= 1
    return pow_ >> 1                                # 1 << floor(log2(count))

def tree_hash(hashes):
    count = len(hashes)
    assert count > 0
    if count == 1:
        return hashes[0]
    if count == 2:
        return cn_fast_hash(hashes[0] + hashes[1])
    cnt = tree_hash_cnt(count)
    ints = [b""] * cnt
    k = 2 * cnt - count
    for i in range(k):
        ints[i] = hashes[i]
    i = k; j = k
    while j < cnt:
        ints[j] = cn_fast_hash(hashes[i] + hashes[i + 1]); i += 2; j += 1
    assert i == count
    while cnt > 2:
        cnt >>= 1
        i = 0
        for j in range(cnt):
            ints[j] = cn_fast_hash(ints[i] + ints[i + 1]); i += 2
    return cn_fast_hash(ints[0] + ints[1])

def tree_branch(hashes, target):
    """Return (branch[list32], depth, path) proving `target` under tree_hash."""
    count = len(hashes)
    idx = next(k for k in range(count) if hashes[k] == target)
    branch = []; depth = 0; path = 0
    if count == 1:
        return branch, 0, 0
    if count == 2:
        return [hashes[idx ^ 1]], 1, (0 if idx == 0 else 1)
    cnt = tree_hash_cnt(count)
    ints = [b""] * cnt
    k = 2 * cnt - count
    for i in range(k):
        ints[i] = hashes[i]
    i = k; j = k
    while j < cnt:
        if idx == i or idx == i + 1:
            branch.append(hashes[i + 1 if idx == i else i]); depth += 1
            path = (path << 1) | (0 if idx == i else 1); idx = j
        ints[j] = cn_fast_hash(hashes[i] + hashes[i + 1]); i += 2; j += 1
    while cnt > 2:
        cnt >>= 1
        i = 0
        for j in range(cnt):
            if idx == i or idx == i + 1:
                branch.append(ints[i + 1 if idx == i else i]); depth += 1
                path = (path << 1) | (0 if idx == i else 1); idx = j
            ints[j] = cn_fast_hash(ints[i] + ints[i + 1]); i += 2
    if idx in (0, 1):
        branch.append(ints[1 if idx == 0 else 0]); depth += 1
        path = (path << 1) | (0 if idx == 0 else 1); idx = 0
    return branch, depth, path

def tree_branch_hash(leaf, branch, depth, path):
    partial = leaf
    for d in range(depth):
        if (path >> (depth - d - 1)) & 1:
            buf = branch[d] + partial
        else:
            buf = partial + branch[d]
        partial = cn_fast_hash(buf)
    return partial

# --------------------------------------------------------------------------
# hashing_blob + block_id
# --------------------------------------------------------------------------
def get_block_hashing_blob(B, tree_root):
    return B["header_blob"] + tree_root + write_varint(len(B["tx_hashes"]) + 1)

def get_block_id(hashing_blob):
    return cn_fast_hash(write_varint(len(hashing_blob)) + hashing_blob)

# --------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------
def hx(b):
    return b.hex() if isinstance(b, (bytes, bytearray)) else b

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    height = int(sys.argv[1]) if len(sys.argv) > 1 else 3000000
    raw = json.load(open(os.path.join(here, "block_%d.raw.json" % height)))
    blob = bytes.fromhex(raw["blob"])
    rpc_block_id = raw["block_header"]["hash"]
    rpc_miner_tx_hash = raw["miner_tx_hash"]
    rpc_tx_hashes = raw.get("tx_hashes", [])

    checks = []
    def check(name, got, want):
        ok = (got == want)
        checks.append(ok)
        print("  [%s] %-22s %s" % ("OK" if ok else "FAIL", name, got))
        if not ok:
            print("        expected             %s" % want)
        return ok

    print("=" * 74)
    print("Keccak-256 self-test (original Keccak, NOT SHA3):")
    empty = cn_fast_hash(b"").hex()
    # Known Keccak-256("") (the value Ethereum/Monero use):
    check("keccak256('')", empty, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

    print("=" * 74)
    print("Block %d  (from public monerod get_block)" % height)
    B = parse_block(blob)
    tx = B["miner_tx"]
    print("  major/minor           %d/%d" % (B["major_version"], B["minor_version"]))
    print("  timestamp             %d" % B["timestamp"])
    print("  nonce (LE u32)        %d (0x%s)" % (int.from_bytes(B["nonce"], "little"), B["nonce"].hex()))
    print("  header_blob (%d B)    %s" % (len(B["header_blob"]), B["header_blob"].hex()))
    print("  miner_tx version      %d  unlock_time %d  (= height + %d)"
          % (tx["version"], tx["unlock_time"], tx["unlock_time"] - B["major_version"] * 0 - height))
    print("  miner_tx vin          %s" % (tx["vin"],))
    print("  miner_tx vout[0]      %s amount=%d view_tag=%s"
          % (tx["vout"][0][0], tx["vout"][0][1], tx["vout"][0][3]))
    print("  rct_type              %d (0=RCTTypeNull)" % tx["rct_type"])
    print("  tx_extra (%d B)       %s" % (len(tx["extra"]), tx["extra"].hex()))
    print("  tx_extra parsed       %s" % (parse_tx_extra(tx["extra"]),))
    print("  n tx (incl coinbase)  %d" % (len(B["tx_hashes"]) + 1))
    print("  trailing bytes        %d (must be 0)" % B["trailing_bytes"])
    check("trailing_bytes==0", B["trailing_bytes"], 0)

    print("-" * 74)
    print("(c) miner_tx (coinbase) hash  [v2 / RCTTypeNull three-hash form]")
    mth, (h0, h1, h2) = miner_tx_hash(tx)
    print("      H(prefix)   = %s" % h0.hex())
    print("      H(rct_base) = %s   (== keccak(0x00))" % h1.hex())
    print("      H(prunable) = %s   (== null_hash)" % h2.hex())
    check("miner_tx_hash", mth.hex(), rpc_miner_tx_hash)

    print("-" * 74)
    print("tree_hash over [miner_tx_hash] + %d tx_hashes  ->  tree_root" % len(B["tx_hashes"]))
    leaves = [mth] + [bytes.fromhex(h) for h in rpc_tx_hashes]
    tree_root = tree_hash(leaves)
    print("      tree_root   = %s" % tree_root.hex())

    print("-" * 74)
    print("(a) hashing_blob = header || tree_root || varint(n_tx)")
    hb = get_block_hashing_blob(B, tree_root)
    print("      len         = %d B" % len(hb))
    print("      hashing_blob= %s" % hb.hex())

    print("-" * 74)
    print("(b) block_id = keccak( varint(len) || hashing_blob )")
    bid = get_block_id(hb)
    check("block_id", bid.hex(), rpc_block_id)

    print("=" * 74)
    print("KECCAK-MIDSTATE coinbase-opening")
    print("  Split the miner_tx PREFIX at the tx_extra boundary. A verifier is")
    print("  handed only {frozen sponge midstate} + {tx_extra tail} and must")
    print("  finish -> prefix hash -> tx hash -> tree_branch -> tree_root.")
    pb = tx["prefix_blob"]
    cut = tx["extra_start_in_prefix"]
    head, tail = pb[:cut], pb[cut:]                 # head = up to (excl) tx_extra bytes
    print("  prefix total %d B ; head(pre-extra) %d B ; tail(extra) %d B"
          % (len(pb), len(head), len(tail)))
    # PROVER: absorb head, freeze midstate
    sp = Keccak256().update(head)
    full_blocks = (len(head)) // RATE
    mid = sp.export_midstate()
    mid["absorbed_blocks_after_state"] = 0          # buffered-tail carried in `buf`
    print("  midstate: %d complete %d-B Keccak block(s) absorbed; %d B buffered in tail"
          % (full_blocks, RATE, len(bytes.fromhex(mid["buf"]))))
    print("  midstate.state = %s" % mid["state"])
    print("  midstate.buf   = %s" % mid["buf"])
    # VERIFIER: resume from midstate ONLY, add tail, finish
    sp2 = Keccak256.from_midstate(mid)
    sp2.update(tail)
    ph_mid = sp2.digest()
    check("prefix_hash via midstate", ph_mid.hex(), h0.hex())
    # continue the opening to the committed root
    h1b = cn_fast_hash(bytes([tx["rct_type"]]))
    mth2 = cn_fast_hash(ph_mid + h1b + NULL_HASH)
    check("miner_tx_hash via midstate", mth2.hex(), rpc_miner_tx_hash)
    branch, depth, path = tree_branch(leaves, mth2)
    root2 = tree_branch_hash(mth2, branch, depth, path)
    print("  tree_branch depth=%d path=0b%s  (%d sibling hashes, %d B)"
          % (depth, format(path, "0%db" % max(depth, 1)), len(branch), 32 * len(branch)))
    check("root via branch", root2.hex(), tree_root.hex())
    check("root == block-committed", root2.hex(), tree_root.hex())

    print("=" * 74)
    allok = all(checks)
    print("RESULT: %s  (%d/%d checks passed)"
          % ("ALL GREEN" if allok else "FAILURES PRESENT", sum(checks), len(checks)))

    # ---- emit KAT json --------------------------------------------------
    kat = {
        "_comment": "X0 feasibility KAT: real Monero mainnet block, recomputed "
                    "hashing_blob/block_id/miner_tx_hash + Keccak-midstate "
                    "coinbase-opening. Ground truth = monerod get_block.",
        "network": "monero-mainnet",
        "source_rpc_method": "get_block",
        "height": height,
        "major_version": B["major_version"],
        "minor_version": B["minor_version"],
        "timestamp": B["timestamp"],
        "prev_id": B["prev_id"].hex(),
        "nonce_le_u32": int.from_bytes(B["nonce"], "little"),
        "difficulty": raw["block_header"].get("difficulty"),
        "n_tx_including_coinbase": len(B["tx_hashes"]) + 1,
        "full_block_blob_len": len(blob),
        "header_blob": B["header_blob"].hex(),
        "miner_tx": {
            "version": tx["version"],
            "unlock_time": tx["unlock_time"],
            "unlock_minus_height": tx["unlock_time"] - height,
            "vin": [["txin_gen", tx["vin"][0][1]]],
            "vout0_type": tx["vout"][0][0],
            "vout0_amount_piconero": tx["vout"][0][1],
            "vout0_view_tag": tx["vout"][0][3],
            "rct_type": tx["rct_type"],
            "prefix_blob": tx["prefix_blob"].hex(),
            "prefix_len": len(tx["prefix_blob"]),
            "extra": tx["extra"].hex(),
            "extra_start_in_prefix": tx["extra_start_in_prefix"],
            "extra_parsed": parse_tx_extra(tx["extra"]),
            "H_prefix": h0.hex(),
            "H_rct_base": h1.hex(),
            "H_prunable": h2.hex(),
            "miner_tx_hash": mth.hex(),
        },
        "tree_root": tree_root.hex(),
        "tree_branch_leaf0": {
            "leaf": mth.hex(),
            "depth": depth,
            "path_bits": format(path, "0%db" % max(depth, 1)),
            "branch": [b.hex() for b in branch],
        },
        "hashing_blob": hb.hex(),
        "hashing_blob_len": len(hb),
        "block_id": bid.hex(),
        "keccak_midstate_opening": {
            "boundary": "start of tx_extra (last transaction_prefix field)",
            "head_len_bytes": len(head),
            "tail_len_bytes": len(tail),
            "complete_keccak_blocks_before_boundary": full_blocks,
            "midstate_state_200B": mid["state"],
            "midstate_buffer": mid["buf"],
            "recovered_prefix_hash": ph_mid.hex(),
            "recovered_miner_tx_hash": mth2.hex(),
            "recovered_tree_root": root2.hex(),
        },
        "ground_truth_from_daemon": {
            "block_id": rpc_block_id,
            "miner_tx_hash": rpc_miner_tx_hash,
            "num_txes": raw["block_header"].get("num_txes"),
        },
        "all_checks_passed": allok,
    }
    outp = os.path.join(here, "x0-kat-%d.json" % height)
    json.dump(kat, open(outp, "w"), indent=1)
    print("wrote %s" % outp)
    sys.exit(0 if allok else 1)

if __name__ == "__main__":
    main()
