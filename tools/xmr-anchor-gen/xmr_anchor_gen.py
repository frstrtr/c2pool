#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
#
# ---------------------------------------------------------------------------
# tools/xmr-anchor-gen/xmr_anchor_gen.py
#
# Mints a trust-anchor bundle (src/impl/xmr/native/contracts/anchor.hpp
# AnchorBundle) from a synced monerod over READ-ONLY RPC, and writes it in the
# canonical `.inc` form that src/impl/xmr/native/anchor/xmr_anchor_codec.hpp
# reads.
#
# WHY A SCRIPT AND NOT ONLY THE C++ GENERATOR. anchor/xmr_anchor_generate.hpp
# holds the generation RULES (which heights, which windows, which consistency
# checks) behind an abstract MoneroDaemonRpc port, because those rules are
# consensus-adjacent and belong in the tree that the loader lives in. What it
# deliberately does not hold is an HTTP client and a JSON parser -- the whole
# native/ family is STL-only, and a release-time capture tool is the wrong
# reason to end that. This script is that transport: it speaks monerod's
# JSON-RPC, applies the SAME rules, and emits the same bytes.
#
# THE TWO ARE CROSS-CHECKED, NOT TRUSTED. The bundle this script writes is read
# back by xmr_anchor_self_check_kat, which re-serialises it with the C++ writer
# (anchor_body_text) and asserts the body is byte-identical and hashes to the
# digest line. A disagreement between this file and the C++ canonical form is
# therefore a RED KAT, not a silent divergence.
#
# READ-ONLY. Every method used here is a query: get_info, get_block_header_by_
# height, get_block_headers_range, get_miner_data, get_coinbase_tx_sum. The tool
# never submits, never mines, never touches the daemon's wallet or peers.
#
# USAGE
#   xmr_anchor_gen.py --rpc http://127.0.0.1:38081 --net stagenet \
#                     [--height H | --bury N] --out xmr_chain_anchor_stagenet.inc
#
#   --bury N   pick height = tip - N (default 720, about a day on Monero), so
#              the anchor is far below any plausible reorg. --height overrides.
# ---------------------------------------------------------------------------
"""Mint a c2pool native-XMR trust-anchor bundle from a synced monerod."""

import argparse
import datetime
import hashlib
import json
import sys
import urllib.request

# --- the pinned window sizes (contracts/anchor.hpp) --------------------------
ANCHOR_DIFFICULTY_WINDOW = 735
ANCHOR_SHORT_TERM_WEIGHTS = 100
ANCHOR_LONG_TERM_WEIGHTS = 100000
ANCHOR_MAX_SEED_IDS = 2
# The highest format this build reads. Format 2 APPENDS the committed output-set
# / spent-set roots and is emitted only when a set is present, so a bundle
# without one stays byte-identical to a format-1 file (contracts/anchor.hpp).
ANCHOR_INC_FORMAT_VERSION = 2


def anchor_inc_format_of(b):
    """2 when the bundle carries a committed output set, 1 otherwise -- the
    presence rule that keeps existing format-1 .inc byte-for-byte unchanged."""
    return 2 if b.get("output_set_leaves") else 1


def anchor_expected_rows(h_a):
    """The exact window lengths a genesis-booted node holds at height h_a: one
    row per block seen, genesis (block 0) included, capped at the full window.
    Mirrors contracts/anchor.hpp anchor_expected_rows -- 735/100/100000 for a
    mature height, shorter on a young (regtest) chain."""
    avail = h_a + 1
    return (min(ANCHOR_DIFFICULTY_WINDOW, avail),
            min(ANCHOR_SHORT_TERM_WEIGHTS, avail),
            min(ANCHOR_LONG_TERM_WEIGHTS, avail))


# --- the SHIPPED v37 lane MMR + leaf discipline, ported for the output set ----
# Byte-for-byte ::v37::Lane (src/sharechain/v37/v37_lane.hpp) and
# chain/xmr_output_set.hpp: sha256d, leaf = sha256d(0x00||payload), interior =
# sha256d(0x01||l||r), binary-counter append, right-fold bag. Pinned against the
# C++ producer by xmr_native_output_set_kat's PART E selftest vector.
def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def mmr_leaf_hash(payload):
    return sha256d(b"\x00" + payload)


def mmr_interior(l, r):
    return sha256d(b"\x01" + l + r)


class Mmr:
    """Append-only MMR peaks (tallest first), matching ::v37::PeakSet."""

    def __init__(self):
        self.peaks = []
        self.leaf_count = 0

    def append(self, leaf):
        h = leaf
        n = self.leaf_count
        while n & 1:
            h = mmr_interior(self.peaks.pop(), h)
            n >>= 1
        self.peaks.append(h)
        self.leaf_count += 1

    def bag(self):
        if not self.peaks:
            return b"\x00" * 32
        r = self.peaks[-1]
        for i in range(len(self.peaks) - 2, -1, -1):
            r = mmr_interior(self.peaks[i], r)
        return r


def _u32le(x):
    return x.to_bytes(4, "little")


def _u64le(x):
    return x.to_bytes(8, "little")


def output_leaf(height, block_id, first_output_index, records):
    """One connected block's OUTPUT leaf. `records` is a list of
    (pubkey32, commitment32, unlock_time) in global order (coinbase first).
    Mirrors ChainOutputSet::on_block_connected exactly."""
    rows = b"".join(pk + cm + _u64le(ut) for (pk, cm, ut) in records)
    compose = sha256d(rows)
    p = b"XMRO" + b"\x01" + _u64le(height) + block_id \
        + _u64le(first_output_index) + _u32le(len(records)) + compose
    return mmr_leaf_hash(p)


def spent_leaf(height, block_id, key_images):
    """One connected block's SPENT leaf. Key images are SORTED ascending before
    hashing, exactly as ChainOutputSet does."""
    kis = sorted(key_images)
    compose = sha256d(b"".join(kis))
    p = b"XMRK" + b"\x01" + _u64le(height) + block_id \
        + _u32le(len(kis)) + compose
    return mmr_leaf_hash(p)


# ChainOutputSet::serialize() form (SER_VER=1), so a node re-derives the set and
# checks it against the anchor's committed roots.
OUTPUT_SET_SER_VER = 1


def serialize_output_set(base, tip_height, tip_id, outputs, out_leaves_first,
                         out_leaves, ki_leaves, spent):
    """Bytes identical to ChainOutputSet::serialize(). `outputs` is a list of
    (pubkey32, commitment32, unlock_time, height); `out_leaves`/`ki_leaves` are
    the per-block leaf hashes; `out_leaves_first` the per-block first index;
    `spent` the set of key images (bytes)."""
    s = bytearray()
    s.append(OUTPUT_SET_SER_VER)
    s += _u64le(base)
    s += _u64le(tip_height)
    s += tip_id
    s += _u64le(len(outputs))
    for (pk, cm, ut, h) in outputs:
        s += pk + cm + _u64le(ut) + _u64le(h)
    s += _u64le(len(out_leaves))
    for i in range(len(out_leaves)):
        s += out_leaves[i] + _u64le(out_leaves_first[i])
    s += _u64le(len(ki_leaves))
    for lf in ki_leaves:
        s += lf
    s += _u64le(len(spent))
    for ki in spent:
        s += ki
    return bytes(s)

# consensus/xmr_epoch.hpp
SEEDHASH_EPOCH_BLOCKS = 2048
SEEDHASH_EPOCH_LAG = 64

FRAME_OPEN = 'R"ANCHOR('
FRAME_CLOSE = ')ANCHOR"'

HEADERS_CHUNK = 1000


def rx_seedheight(height):
    """(h - 65) & ~2047 -- consensus/xmr_epoch.hpp, floored at 0."""
    if height < SEEDHASH_EPOCH_LAG + 1:
        return 0
    return (height - (SEEDHASH_EPOCH_LAG + 1)) & ~(SEEDHASH_EPOCH_BLOCKS - 1)


class Rpc:
    """Minimal monerod JSON-RPC client, queries only."""

    def __init__(self, base, timeout=600):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self._id = 0

    def _post(self, path, payload):
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.base + path, data=body,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode())

    def json_rpc(self, method, params=None):
        self._id += 1
        out = self._post("/json_rpc", {
            "jsonrpc": "2.0", "id": str(self._id),
            "method": method, "params": params or {}})
        if "error" in out:
            raise RuntimeError("%s: %s" % (method, out["error"]))
        return out["result"]

    def plain(self, path, params=None):
        out = self._post(path, params or {})
        if out.get("status") not in (None, "OK"):
            raise RuntimeError("%s: %s" % (path, out.get("status")))
        return out


def wide_to_int(hdr, wide_key, lo_key, top_key):
    """monerod prints 128-bit fields three ways; prefer the unambiguous one."""
    w = hdr.get(wide_key)
    if isinstance(w, str) and w:
        return int(w, 16)          # monerod prints these as "0x..."
    return (int(hdr.get(top_key, 0)) << 64) | int(hdr[lo_key])


def header_tuple(h):
    """The fields the bundle needs, normalised."""
    return {
        "height": int(h["height"]),
        "hash": h["hash"],
        "prev_hash": h["prev_hash"],
        "timestamp": int(h["timestamp"]),
        "major_version": int(h["major_version"]),
        "reward": int(h["reward"]),
        "block_weight": int(h.get("block_weight", h.get("block_size", 0))),
        "long_term_weight": int(h.get("long_term_weight", 0)),
        "cumdiff": wide_to_int(h, "wide_cumulative_difficulty",
                               "cumulative_difficulty",
                               "cumulative_difficulty_top64"),
    }


def fetch_headers(rpc, lo, hi, note=""):
    """Inclusive [lo, hi], oldest first, in chunks; continuity enforced."""
    out = []
    at = lo
    while at <= hi:
        end = min(at + HEADERS_CHUNK - 1, hi)
        res = rpc.json_rpc("get_block_headers_range",
                           {"start_height": at, "end_height": end})
        got = [header_tuple(h) for h in res["headers"]]
        if len(got) != end - at + 1:
            raise RuntimeError("headers_range %d..%d returned %d rows"
                               % (at, end, len(got)))
        out.extend(got)
        at = end + 1
        if note and (len(out) % 20000 == 0 or at > hi):
            print("  %s %d/%d" % (note, len(out), hi - lo + 1), file=sys.stderr)
    for i in range(1, len(out)):
        if out[i]["height"] != out[i - 1]["height"] + 1:
            raise RuntimeError("height gap at %d" % out[i]["height"])
        if out[i]["prev_hash"] != out[i - 1]["hash"]:
            raise RuntimeError("prev_hash break at %d" % out[i]["height"])
        if out[i]["cumdiff"] < out[i - 1]["cumdiff"]:
            raise RuntimeError("cumulative difficulty went backwards at %d"
                               % out[i]["height"])
    return out


# --- the canonical body ------------------------------------------------------
# Byte-for-byte the same text as anchor_body_text() in xmr_anchor_codec.hpp.
# Any change here is a change there; the KAT compares them.

def u64_hex(v):
    return "0" if v == 0 else "%x" % v


def u128_text(v):
    return u64_hex(v >> 64) + " " + u64_hex(v & 0xFFFFFFFFFFFFFFFF)


def run_encode_ltw(values, per_line=20):
    on_line = 0
    parts = []

    def emit(tok):
        nonlocal on_line
        if on_line == 0:
            parts.append("ltw")
        parts.append(" ")
        parts.append(tok)
        on_line += 1
        if on_line == per_line:
            parts.append("\n")
            on_line = 0

    i = 0
    n = len(values)
    while i < n:
        j = i
        while j < n and values[j] == values[i]:
            j += 1
        run = j - i
        if run >= 4:
            if on_line != 0:
                parts.append("\n")
                on_line = 0
            parts.append("ltw %dx%d\n" % (run, values[i]))
        else:
            for _ in range(run):
                emit(str(values[i]))
        i = j
    if on_line != 0:
        parts.append("\n")
    return "".join(parts)


def anchor_body_text(b):
    s = []
    s.append("format %d\n" % anchor_inc_format_of(b))
    s.append("network %s\n" % b["network"])
    s.append("height %d\n" % b["height"])
    s.append("id %s\n" % b["id"])
    s.append("prev_id %s\n" % b["prev_id"])
    s.append("timestamp %d\n" % b["timestamp"])
    s.append("major_version %d\n" % b["major_version"])
    s.append("cumulative_difficulty %s\n" % u128_text(b["cumulative_difficulty"]))
    s.append("already_generated_coins %d\n" % b["already_generated_coins"])
    # Format-2 committed set: emitted ONLY when a set is present, so a format-1
    # bundle produces exactly the bytes above and nothing here (byte-identical).
    if anchor_inc_format_of(b) == 2:
        s.append("rct_output_count %d\n" % b["rct_output_count"])
        s.append("output_set_base_height %d\n" % b["output_set_base_height"])
        s.append("output_set_leaves %d\n" % b["output_set_leaves"])
        s.append("output_set_root %s\n" % b["output_set_root"])
        s.append("spent_set_leaves %d\n" % b["spent_set_leaves"])
        s.append("spent_set_root %s\n" % b["spent_set_root"])
    for h, i in b["seed_ids"]:
        s.append("seed %d %s\n" % (h, i))
    for ts, cd in b["difficulty_window"]:
        s.append("diff %d %s\n" % (ts, u128_text(cd)))
    stw = b["short_term_weights"]
    line = []
    for i, v in enumerate(stw):
        if i % 10 == 0:
            line.append("\nstw" if i else "stw")
        line.append(" %d" % v)
    if stw:
        line.append("\n")
    s.append("".join(line))
    s.append(run_encode_ltw(b["long_term_weights"], 20))
    for h, i in b["monerod_checkpoints"]:
        s.append("checkpoint %d %s\n" % (h, i))
    return "".join(s)


def write_anchor_inc(b, header_comment):
    body = anchor_body_text(b)
    out = [FRAME_OPEN, "\n"]
    for line in header_comment.split("\n"):
        out.append("# %s\n" % line.rstrip())
    out.append(body)
    out.append("digest %s\n" % hashlib.sha256(body.encode()).hexdigest())
    out.append(FRAME_CLOSE)
    out.append("\n")
    return "".join(out)


# --- self-check (contracts/anchor.hpp anchor_self_check, the parts we can) ----
def self_check(b):
    need_d, need_s, need_l = anchor_expected_rows(b["height"])
    if len(b["difficulty_window"]) != need_d:
        raise RuntimeError("difficulty window is %d, need %d"
                           % (len(b["difficulty_window"]), need_d))
    if len(b["short_term_weights"]) != need_s:
        raise RuntimeError("short-term window is %d, need %d"
                           % (len(b["short_term_weights"]), need_s))
    if len(b["long_term_weights"]) != need_l:
        raise RuntimeError("long-term window is %d, need %d"
                           % (len(b["long_term_weights"]), need_l))
    if not (1 <= len(b["seed_ids"]) <= ANCHOR_MAX_SEED_IDS):
        raise RuntimeError("%d seed ids" % len(b["seed_ids"]))
    for h, _ in b["seed_ids"]:
        if h % SEEDHASH_EPOCH_BLOCKS or h > b["height"]:
            raise RuntimeError("seed height %d is not aligned at or below H_a" % h)
    prev = -1
    for _, cd in b["difficulty_window"]:
        if cd < prev:
            raise RuntimeError("difficulty window not monotone")
        prev = cd
    for h, _ in b["monerod_checkpoints"]:
        if h < b["height"]:
            raise RuntimeError("checkpoint %d below H_a" % h)
    # Format-2 committed-set shape (mirrors contracts/anchor.hpp).
    if b.get("output_set_leaves"):
        base = b["output_set_base_height"]
        if base > b["height"]:
            raise RuntimeError("output-set base %d above H_a" % base)
        if b["output_set_leaves"] != b["height"] + 1 - base:
            raise RuntimeError("output-set leaves %d != one-per-block %d"
                               % (b["output_set_leaves"], b["height"] + 1 - base))
        if b["spent_set_leaves"] != b["output_set_leaves"]:
            raise RuntimeError("spent leaves != output leaves")
        if b["rct_output_count"] == 0:
            raise RuntimeError("committed set with rct_output_count 0")


# --- the output-set / spent-set walk (genesis..H_a) --------------------------
# Walks blocks 1..H_a (leaf 0 is block 1; genesis is seeded, not connected, and
# its v1 coinbase creates no amount-0 output -- exactly what a from-genesis node
# holds). Per block it assembles the amount-0 output records in monerod's own
# global order (miner_tx outputs first, then each tx in block order), taking the
# (pubkey, commitment) pairs straight from get_outs -- so no ed25519 curve code
# lives here and the coinbase zeroCommit is the daemon's own value -- and the
# spent key images from the tx bodies. It builds the SAME leaves and MMR the C++
# ChainOutputSet does and the SAME serialize() snapshot the node re-derives.
def _tx_json(rpc, tx_hashes):
    if not tx_hashes:
        return []
    out = rpc.plain("/get_transactions", {"txs_hashes": list(tx_hashes),
                                          "decode_as_json": True})
    txs = out.get("txs", [])
    res = []
    for t in txs:
        j = t.get("as_json") or t.get("as_hex")
        res.append(json.loads(j) if j else {})
    return res


def _target_key(vout):
    tgt = vout.get("target", {})
    if "key" in tgt:
        return tgt["key"]
    if "tagged_key" in tgt:
        return tgt["tagged_key"]["key"]
    raise RuntimeError("vout target has neither key nor tagged_key")


def build_output_set(rpc, h_a):
    out_mmr = Mmr()
    ki_mmr = Mmr()
    outputs = []            # (pubkey, commitment, unlock_time, height)
    out_leaves = []
    out_leaves_first = []
    ki_leaves = []
    spent = []              # key images, in first-seen order
    seen_ki = set()
    frontier = 0            # base is 0 on a from-genesis walk

    for h in range(1, h_a + 1):
        blk = rpc.json_rpc("get_block", {"height": h})
        block_id = bytes.fromhex(blk["block_header"]["hash"])
        bj = json.loads(blk["json"])
        miner = bj["miner_tx"]
        miner_v = int(miner.get("version", 1))
        cb_unlock = int(miner.get("unlock_time", 0))
        n_cb = len(miner["vout"]) if miner_v >= 2 else 0
        tx_hashes = bj.get("tx_hashes", []) or []
        txj = _tx_json(rpc, tx_hashes)

        # count the block's amount-0 outputs and gather per-output unlock times
        unlocks = [cb_unlock] * n_cb
        block_kis = []
        for t in txj:
            tv = int(t.get("version", 1))
            tu = int(t.get("unlock_time", 0))
            n_to = len(t.get("vout", [])) if tv >= 2 else 0
            unlocks += [tu] * n_to
            for vin in t.get("vin", []):
                k = vin.get("key")
                if k and "k_image" in k:
                    block_kis.append(bytes.fromhex(k["k_image"]))
        n = len(unlocks)

        # (pubkey, commitment) straight from get_outs, in global-index order
        recs = []
        if n:
            req = [{"amount": 0, "index": frontier + i} for i in range(n)]
            og = rpc.plain("/get_outs", {"outputs": req, "get_txid": False})
            outs = og.get("outs", [])
            if len(outs) != n:
                raise RuntimeError("get_outs returned %d of %d at block %d"
                                   % (len(outs), n, h))
            for i in range(n):
                pk = bytes.fromhex(outs[i]["key"])
                cm = bytes.fromhex(outs[i]["mask"])
                recs.append((pk, cm, unlocks[i]))
                outputs.append((pk, cm, unlocks[i], h))

        out_leaves.append(output_leaf(h, block_id, frontier, recs))
        out_leaves_first.append(frontier)
        out_mmr.append(out_leaves[-1])

        ki_leaves.append(spent_leaf(h, block_id, block_kis))
        ki_mmr.append(ki_leaves[-1])
        for ki in block_kis:
            if ki not in seen_ki:
                seen_ki.add(ki)
                spent.append(ki)

        frontier += n
        if h % 500 == 0 or h == h_a:
            print("  output-set walk %d/%d (rct_output_count=%d)"
                  % (h, h_a, frontier), file=sys.stderr)

    # tip id is the anchor block's own id
    tip_id = bytes.fromhex(rpc.json_rpc("get_block", {"height": h_a})["block_header"]["hash"])
    snapshot = serialize_output_set(0, h_a, tip_id, outputs, out_leaves_first,
                                    out_leaves, ki_leaves, spent)
    return {
        "rct_output_count": frontier,
        "leaves": h_a,                       # one per block 1..H_a
        "output_root": out_mmr.bag(),
        "spent_root": ki_mmr.bag(),
        "snapshot": snapshot,
    }


# --- self-test: pin the MMR + leaf encoding against the C++ producer ----------
# The C++ xmr_native_output_set_kat PART E builds the SAME synthetic block with
# ChainOutputSet and prints its roots; these must match. The expected hex is the
# C++ ChainOutputSet's own output; a drift here or there is a RED test.
SELFTEST_OUTPUT_ROOT = "4f8d4835a2788d17bdb6c06048a9fa12395f9b0945993553703db8a4e929d293"
SELFTEST_SPENT_ROOT = "0fd7d87a83a87e7ccae7bb5bc8a6418f4dbf3f187c2bf29d3f1156426ce2af33"


def _selftest_scenario():
    # Two blocks, NO coinbase (so every commitment is explicit and neither side
    # needs ed25519), matching xmr_native_output_set_kat PART E exactly.
    # Block 1 (first_idx 0): outputs (0x33,0x44,unlock 0) and (0x35,0x46,unlock 5);
    # key image 0xAA. Block 2 (first_idx 2): output (0x55,0x66,unlock 62); key
    # images 0xBB and 0x0C (unsorted on input -- the leaf sorts them).
    def b(x):
        return bytes([x]) + b"\x00" * 31
    out = Mmr()
    ki = Mmr()
    out.append(output_leaf(1, b(0x91), 0, [(b(0x33), b(0x44), 0), (b(0x35), b(0x46), 5)]))
    ki.append(spent_leaf(1, b(0x91), [b(0xAA)]))
    out.append(output_leaf(2, b(0x92), 2, [(b(0x55), b(0x66), 62)]))
    ki.append(spent_leaf(2, b(0x92), [b(0xBB), b(0x0C)]))
    return out.bag(), ki.bag()


def run_selftest():
    out_root, spent_root = _selftest_scenario()
    print("SELFTEST output_root %s" % out_root.hex())
    print("SELFTEST spent_root  %s" % spent_root.hex())
    # Raw-leaf MMR vector (pins mmr_append/mmr_bag independent of leaf payloads).
    m = Mmr()
    for i in range(5):
        m.append(bytes([i]) + b"\x00" * 31)
    print("SELFTEST raw5_root   %s" % m.bag().hex())
    if SELFTEST_OUTPUT_ROOT.startswith("PLACEHOLDER"):
        print("SELFTEST (expected roots not yet pinned; compare with the C++ KAT)",
              file=sys.stderr)
        return 0
    ok = (out_root.hex() == SELFTEST_OUTPUT_ROOT
          and spent_root.hex() == SELFTEST_SPENT_ROOT)
    print("SELFTEST %s" % ("OK" if ok else "MISMATCH vs pinned C++ roots"),
          file=sys.stderr)
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rpc", default="http://127.0.0.1:38081")
    ap.add_argument("--net", required=True,
                    choices=["mainnet", "testnet", "stagenet", "regtest"])
    ap.add_argument("--height", type=int, default=0)
    ap.add_argument("--bury", type=int, default=720)
    ap.add_argument("--out", required=True)
    ap.add_argument("--checkpoints", default="",
                    help="optional 'height:hash,height:hash' copied from "
                         "monerod checkpoints.cpp, all at or above H_a")
    ap.add_argument("--output-set", action="store_true",
                    help="format 2: also commit the output-set / spent-set roots "
                         "computed over the genesis..H_a walk (needs an unrestricted "
                         "monerod). Without this the bundle is byte-identical format 1.")
    ap.add_argument("--output-set-out", default="",
                    help="write the ChainOutputSet snapshot (serialize() form) here, "
                         "so a node booting the format-2 anchor seeds the historical set")
    ap.add_argument("--selftest", action="store_true",
                    help="run the MMR / leaf-encoding self-test vector (no daemon) and exit")
    args = ap.parse_args()

    if args.selftest:
        return run_selftest()

    rpc = Rpc(args.rpc)
    info = rpc.plain("/get_info")
    if info.get("nettype") != args.net:
        raise SystemExit("daemon is %s, --net says %s"
                         % (info.get("nettype"), args.net))
    if not info.get("synchronized"):
        print("WARNING: daemon reports synchronized=false", file=sys.stderr)
    tip = int(info["height"]) - 1
    h_a = args.height if args.height else tip - args.bury
    print("tip=%d  H_a=%d  (buried %d)" % (tip, h_a, tip - h_a), file=sys.stderr)

    if tip - h_a < 60:
        raise SystemExit("H_a is only %d deep; refuse (reorg risk)" % (tip - h_a))
    # A mature anchor (mainnet/stagenet) must sit past the full long-term window;
    # a YOUNG chain (regtest, or an early testnet) carries the shorter windows a
    # genesis-booted node holds -- anchor_expected_rows. A young anchor is only
    # meaningful with --output-set (the whole point below the full windows).
    if h_a < ANCHOR_LONG_TERM_WEIGHTS - 1 and not args.output_set and args.net != "regtest":
        raise SystemExit("H_a=%d is below the %d-block long-term window; a young "
                         "anchor is only minted for regtest or with --output-set"
                         % (h_a, ANCHOR_LONG_TERM_WEIGHTS))

    lo = max(0, h_a - (ANCHOR_LONG_TERM_WEIGHTS - 1))
    print("fetching headers %d..%d" % (lo, h_a), file=sys.stderr)
    win = fetch_headers(rpc, lo, h_a, note="headers")
    at = win[-1]
    assert at["height"] == h_a

    # already_generated_coins at H_a: the tip value from get_miner_data, minus
    # the BASE EMISSION of every block above H_a.
    #
    # NOT the header `reward`, which is the coinbase amount -- base emission
    # PLUS the fees the miner swept. monerod does not add that. It does
    #
    #     already_generated_coins = base_reward + already_generated_coins;
    #
    # (Blockchain::handle_block_to_main_chain), because a fee is existing
    # supply changing hands, not supply being created; counting it as emission
    # would inflate the number the tail-emission curve and the template's own
    # reward calculation are both read off.
    #
    # Backing the tip value out with `reward` therefore removes base+fee per
    # block where only base was ever added, and leaves the anchor SHORT BY THE
    # FEE TOTAL over the range. That is what shipped in the stagenet bundle,
    # and the M4 parity soak caught it on its first template sample: every
    # P-TPL compare differed on already_generated_coins by exactly the daemon's
    # own fee_amount for those blocks, which -- the field being a sentinel --
    # revoked the graduation key outright.
    md = rpc.json_rpc("get_miner_data")
    md_tip = int(md["height"]) - 1
    coins_at_md_tip = int(md["already_generated_coins"])
    above = fetch_headers(rpc, h_a + 1, md_tip) if md_tip > h_a else []

    emission_above = 0
    if above:
        cs = rpc.json_rpc("get_coinbase_tx_sum",
                          {"height": h_a + 1, "count": md_tip - h_a})
        emission_above = wide_to_int(cs, "wide_emission_amount", "emission_amount",
                                     "emission_amount_top64")
        fees_above = wide_to_int(cs, "wide_fee_amount", "fee_amount",
                                 "fee_amount_top64")

        # THE CROSS-CHECK THAT CATCHES THIS CLASS, rather than the one that
        # missed it. The old check asserted emission+fee == sum(reward), which
        # is a true identity about the two RPCs and says nothing about which of
        # them belongs in the subtraction -- so it confirmed the wrong quantity
        # and printed OK. What is actually claimed here is that the headers'
        # rewards decompose into the daemon's emission and fee totals, and the
        # quantity used is the emission half, named as such.
        reward_above = sum(x["reward"] for x in above)
        if emission_above + fees_above != reward_above:
            raise SystemExit("coinbase decomposition disagrees: emission %d + fee %d "
                             "!= sum(reward) %d"
                             % (emission_above, fees_above, reward_above))
        print("coinbase decomposition OK over %d blocks: emission=%d fee=%d "
              "(fee is NOT emitted and is NOT subtracted)"
              % (len(above), emission_above, fees_above), file=sys.stderr)

    coins = coins_at_md_tip - emission_above
    if coins <= 0:
        raise SystemExit("already_generated_coins came out non-positive")

    by_height = {x["height"]: x for x in win}
    seeds = []
    for h in sorted({rx_seedheight(h_a + 1),
                     rx_seedheight(h_a + 1 + SEEDHASH_EPOCH_LAG)}):
        if h not in by_height:
            raise SystemExit("seed height %d is outside the fetched window" % h)
        seeds.append((h, by_height[h]["hash"]))

    checkpoints = []
    if args.checkpoints:
        for tok in args.checkpoints.split(","):
            hh, _, ident = tok.partition(":")
            checkpoints.append((int(hh), ident))

    need_d, need_s, need_l = anchor_expected_rows(h_a)
    bundle = {
        "network": args.net,
        "height": h_a,
        "id": at["hash"],
        "prev_id": at["prev_hash"],
        "timestamp": at["timestamp"],
        "major_version": at["major_version"],
        "cumulative_difficulty": at["cumdiff"],
        "already_generated_coins": coins,
        "seed_ids": seeds,
        "difficulty_window": [(x["timestamp"], x["cumdiff"])
                              for x in win[-need_d:]],
        "short_term_weights": [x["block_weight"] for x in win[-need_s:]],
        "long_term_weights": [x["long_term_weight"] for x in win[-need_l:]],
        "monerod_checkpoints": checkpoints,
        # format-1 defaults; --output-set fills these in below.
        "rct_output_count": 0,
        "output_set_base_height": 0,
        "output_set_leaves": 0,
        "output_set_root": "",
        "spent_set_leaves": 0,
        "spent_set_root": "",
    }

    set_provenance = ""
    if args.output_set:
        oset = build_output_set(rpc, h_a)
        bundle["rct_output_count"]       = oset["rct_output_count"]
        bundle["output_set_base_height"] = 1
        bundle["output_set_leaves"]      = oset["leaves"]
        bundle["output_set_root"]        = oset["output_root"].hex()
        bundle["spent_set_leaves"]       = oset["leaves"]
        bundle["spent_set_root"]         = oset["spent_root"].hex()
        set_provenance = ("set       output/spent roots over blocks 1..%d, "
                          "rct_output_count=%d, %d leaves each"
                          % (h_a, oset["rct_output_count"], oset["leaves"]))
        if args.output_set_out:
            with open(args.output_set_out, "wb") as f:
                f.write(oset["snapshot"])
            print("wrote %s (%d bytes) -- ChainOutputSet snapshot"
                  % (args.output_set_out, len(oset["snapshot"])), file=sys.stderr)

    self_check(bundle)

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%MZ")
    comment = "\n".join([
        "c2pool native-XMR trust anchor -- generated, do not hand-edit.",
        "tool      tools/xmr-anchor-gen/xmr_anchor_gen.py (read-only RPC)",
        "daemon    monerod %s, nettype %s" % (info.get("version", "?"), args.net),
        "captured  %s, daemon tip %d, anchor buried %d"
        % (stamp, tip, tip - h_a),
        "windows   %d difficulty / %d short-term / %d long-term"
        % (ANCHOR_DIFFICULTY_WINDOW, ANCHOR_SHORT_TERM_WEIGHTS,
           ANCHOR_LONG_TERM_WEIGHTS),
        "coins     already_generated_coins from get_miner_data at %d minus the"
        % md_tip,
        "          BASE EMISSION of every block above H_a -- get_coinbase_tx_sum's",
        "          emission_amount, NOT the header `reward`. monerod accumulates",
        "          base_reward into already_generated_coins; fees are recycled from",
        "          the existing supply and are never added to it.",
        "note      monerod publishes no RPC for its compiled-in checkpoints;",
        "          `checkpoint` rows are copied by hand at release time and",
        "          this capture carries %d of them." % len(checkpoints),
    ] + ([set_provenance] if set_provenance else []))
    text = write_anchor_inc(bundle, comment)
    with open(args.out, "w") as f:
        f.write(text)
    print("wrote %s (%d bytes), H_a=%d id=%s"
          % (args.out, len(text), h_a, bundle["id"]), file=sys.stderr)


if __name__ == "__main__":
    main()
