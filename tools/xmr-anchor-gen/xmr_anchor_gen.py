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
# READ-ONLY. Every method used here is a query: get_info, get_block_headers_
# range, get_miner_data, get_coinbase_tx_sum and, for --output-set, get_block,
# get_transactions, get_outs. The tool never submits, never mines, never
# touches the daemon's wallet or peers.
#
# USAGE
#   xmr_anchor_gen.py --rpc http://127.0.0.1:38081 --net stagenet \
#                     [--height H | --bury N] --out xmr_chain_anchor_stagenet.inc
#
#   --bury N   pick height = tip - N (default 720, about a day on Monero), so
#              the anchor is far below any plausible reorg. --height overrides.
#
#   Format 2 (--output-set [--output-set-out SNAPSHOT.bin]) walks genesis..H_a.
#   On mainnet that is ~3.8M blocks, ~165M RingCT outputs and ~150M key images,
#   so the walk is built to run for hours on a machine that also hosts monerod:
#
#   * STATE ON DISK, NOT IN RAM. Outputs, per-block leaves and spent key images
#     go to append-only fixed-size record files in --state-dir (default
#     <snapshot or out>.walkstate). Resident memory is the key-image dedupe
#     table (8+4 bytes per slot, ~3 GB at mainnet scale) plus a few in-flight
#     RPC batches -- it no longer grows with the output count.
#   * CHECKPOINT + --resume. Every --checkpoint-blocks / --checkpoint-secs a
#     small JSON checkpoint (height, frontier, file sizes, both MMR peak sets,
#     a sha256 per record file and a digest over itself) is written atomically
#     (temp + fsync + rename). --resume truncates the record files back to the
#     checkpoint, re-hashes them against it, re-derives the peaks from the leaf
#     files and continues; H_a is pinned by the checkpoint, so a resumed run
#     commits to the same anchor block. Anything that does not add up is
#     refused -- a damaged state never becomes a different anchor.
#   * STREAMED SNAPSHOT. The ChainOutputSet snapshot is the header followed by
#     the four record files, each prefixed with its count, so it is copied to
#     disk in fixed-size chunks rather than assembled in memory.
#   * BATCHED, PARALLEL, RETRIED RPC. Batches of --batch-blocks blocks are
#     fetched by --threads workers over persistent HTTP connections: one
#     headers call, get_block only for blocks that carry transactions, batched
#     get_transactions (pruned) and one get_outs per contiguous global-index
#     range. Transport errors and "busy" answers are retried with backoff (a
#     monerod relaunch is ridden out); logic errors ("Failed", missed tx) are
#     not.
#
#   The bytes written -- the .inc (format 1 and 2) and the snapshot -- are the
#   same as the previous in-memory walk produced for the same chain and flags.
# ---------------------------------------------------------------------------
"""Mint a c2pool native-XMR trust-anchor bundle from a synced monerod."""

import argparse
import collections
import concurrent.futures
import datetime
import gc
import hashlib
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import urllib.parse
from array import array

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


def log(msg):
    """Timestamped progress / diagnostics line on stderr (flushed, so a stall is
    visible in a nohup log)."""
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    sys.stderr.write("[%s] %s\n" % (ts, msg))
    sys.stderr.flush()


class RpcError(RuntimeError):
    """A daemon answer that is WRONG, not late ("Failed", a JSON-RPC error other
    than busy, a non-5xx HTTP status). Never retried."""


class RpcTransient(RuntimeError):
    """Transport failure, timeout, truncated body, HTTP 5xx, or a "busy" answer.
    Retried with backoff; raised to the caller only when the budget runs out."""


class RpcStopped(RuntimeError):
    """The walk is shutting down; a worker's retry loop gives up at once."""


class Rpc:
    """monerod JSON-RPC client, queries only. One persistent HTTP/1.1
    connection per calling thread (monerod keeps connections alive), and every
    call retried on transient failure: first retry immediately on a fresh
    connection, then 1, 2, 4 .. 60 s, until `retry_budget` seconds have passed
    (0 = forever). A monerod that is being relaunched is therefore waited out
    instead of killing a multi-hour walk."""

    def __init__(self, base, timeout=300, retry_budget=3600):
        u = urllib.parse.urlsplit(base if "://" in base else "http://" + base)
        if u.scheme != "http":
            raise SystemExit("--rpc must be a plain http:// URL")
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or 80
        self.prefix = u.path.rstrip("/")
        self.timeout = timeout
        self.retry_budget = retry_budget
        self.stop = threading.Event()
        self._local = threading.local()
        self._id_lock = threading.Lock()
        self._id = 0

    def _conn(self, timeout):
        c = getattr(self._local, "conn", None)
        if c is None:
            c = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
            self._local.conn = c
        c.timeout = timeout
        if c.sock is not None:
            c.sock.settimeout(timeout)
        return c

    def _drop(self):
        c = getattr(self._local, "conn", None)
        self._local.conn = None
        if c is not None:
            try:
                c.close()
            except Exception:
                pass

    def _post_once(self, path, payload, timeout):
        body = json.dumps(payload).encode()
        try:
            c = self._conn(timeout)
            c.request("POST", self.prefix + path, body,
                      {"Content-Type": "application/json",
                       "Connection": "keep-alive"})
            r = c.getresponse()
            raw = r.read()
        except (OSError, http.client.HTTPException) as e:
            self._drop()
            raise RpcTransient("%s: %s: %s" % (path, type(e).__name__, e))
        if r.status >= 500:
            self._drop()
            raise RpcTransient("%s: HTTP %d" % (path, r.status))
        if r.status != 200:
            raise RpcError("%s: HTTP %d" % (path, r.status))
        if r.getheader("Connection", "").lower() == "close":
            self._drop()
        try:
            return json.loads(raw)
        except ValueError as e:
            self._drop()
            raise RpcTransient("%s: unparseable body (%d bytes): %s"
                               % (path, len(raw), e))

    def _retry(self, what, fn, max_attempts=0, budget=None):
        budget = self.retry_budget if budget is None else budget
        t0 = time.time()
        attempt = 0
        while True:
            if self.stop.is_set():
                raise RpcStopped(what)
            try:
                return fn()
            except RpcTransient as e:
                attempt += 1
                waited = time.time() - t0
                if (max_attempts and attempt >= max_attempts) or \
                        (budget and waited >= budget):
                    raise
                delay = 0 if attempt == 1 else min(60, 1 << min(attempt - 2, 6))
                if attempt > 1:
                    log("RPC %s transient failure #%d (%s); retry in %ds "
                        "(waited %ds so far)" % (what, attempt, e, delay, waited))
                if delay:
                    self.stop.wait(delay)

    def json_rpc(self, method, params=None, max_attempts=0, timeout=None,
                 budget=None):
        with self._id_lock:
            self._id += 1
            rid = str(self._id)
        payload = {"jsonrpc": "2.0", "id": rid, "method": method,
                   "params": params or {}}
        to = timeout or self.timeout

        def once():
            out = self._post_once("/json_rpc", payload, to)
            err = out.get("error")
            if err:
                code = err.get("code") if isinstance(err, dict) else None
                msg = str(err.get("message", "")) if isinstance(err, dict) else str(err)
                # -9 CORE_RPC_ERROR_CODE_CORE_BUSY ("Core is busy")
                if code == -9 or "busy" in msg.lower():
                    raise RpcTransient("%s: %s" % (method, err))
                raise RpcError("%s: %s" % (method, err))
            res = out.get("result")
            if res is None:
                raise RpcError("%s: no result" % method)
            if res.get("status") == "BUSY":
                raise RpcTransient("%s: BUSY" % method)
            return res
        return self._retry(method, once, max_attempts, budget)

    def plain(self, path, params=None, max_attempts=0, timeout=None):
        to = timeout or self.timeout
        payload = params or {}

        def once():
            out = self._post_once(path, payload, to)
            st = out.get("status")
            if st == "BUSY":
                raise RpcTransient("%s: BUSY" % path)
            if st not in (None, "OK"):
                raise RpcError("%s: %s" % (path, st))
            return out
        return self._retry(path, once, max_attempts)


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
            log("%s %d/%d" % (note, len(out), hi - lo + 1))
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
#
# The per-block RULES are unchanged from the in-memory walk this replaces:
#   amount-0 outputs of a block = len(miner_tx.vout) if miner_tx.version >= 2,
#     then len(tx.vout) for every tx with version >= 2, in block order;
#   unlock_time of an output = its transaction's unlock_time;
#   (pubkey, commitment) of the i-th = get_outs(amount 0, frontier + i);
#   key images = every vin.key.k_image of every non-coinbase tx, all versions;
#   spent set = key images in first-seen order, duplicates dropped.
# What changed is where the data lives (disk, see WalkState) and how it is
# fetched (fetch_batch, below), plus cross-checks the old walk could not make:
# each tx's own output_indices must be exactly frontier + i, get_outs must
# report the block's height and the tx's own output key, no tx may be missed,
# and prev_id must chain block to block from genesis to H_a.

WALK_STATE_VERSION = 2   # 2: checkpoint carries per-file sha256 + its own digest
REC_OUTPUT = 80        # pubkey32 | commitment32 | u64 unlock_time | u64 height
REC_OUT_LEAF = 40      # leaf32 | u64 first_output_index
REC_KI_LEAF = 32
REC_KEY_IMAGE = 32


def _target_key(vout):
    tgt = vout.get("target", {})
    if "key" in tgt:
        return tgt["key"]
    if "tagged_key" in tgt:
        return tgt["tagged_key"]["key"]
    return None     # not a key output: no cross-check for it (count rule unchanged)


def _chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def fetch_batch(rpc, a, b, tx_chunk=1000, out_chunk=5000):
    """Fetch and pre-digest blocks a..b (inclusive). Returns one tuple per block:
        (height, block_id, prev_id, first_global_index or -1, n_outputs,
         rows80, compose, ki_leaf, key_images)
    where rows80 is the n snapshot rows (pk|cm|u64 unlock|u64 height), compose
    = sha256d(pk|cm|u64 unlock ...) of the output leaf, and ki_leaf the block's
    finished spent leaf. Everything here is independent of the running frontier;
    the caller checks first_global_index against it."""
    hdrs = rpc.json_rpc("get_block_headers_range",
                        {"start_height": a, "end_height": b})["headers"]
    if len(hdrs) != b - a + 1:
        raise RpcError("headers_range %d..%d returned %d rows" % (a, b, len(hdrs)))
    blocks = []
    for k, hd in enumerate(hdrs):
        h = int(hd["height"])
        if h != a + k:
            raise RpcError("headers_range out of order at %d" % h)
        mth = hd.get("miner_tx_hash") or ""
        ntx = int(hd.get("num_txes", -1))
        if mth and ntx == 0:
            txh = []
        else:
            blk = rpc.json_rpc("get_block", {"height": h})
            if blk["block_header"]["hash"] != hd["hash"]:
                raise RpcError("get_block(%d) id %s != header id %s"
                               % (h, blk["block_header"]["hash"], hd["hash"]))
            txh = blk.get("tx_hashes")
            if txh is None:
                txh = json.loads(blk["json"]).get("tx_hashes") or []
            m2 = blk.get("miner_tx_hash") or ""
            if not m2:
                raise RpcError("get_block(%d) carries no miner_tx_hash; monerod "
                               ">= 0.17 is required" % h)
            if mth and m2 != mth:
                raise RpcError("miner_tx_hash mismatch at %d" % h)
            mth = m2
            if ntx >= 0 and len(txh) != ntx:
                raise RpcError("block %d: %d tx hashes, header says %d"
                               % (h, len(txh), ntx))
        blocks.append((h, hd["hash"], hd["prev_hash"], mth, txh))

    want = []
    for (_, _, _, mth, txh) in blocks:
        want.append(mth)
        want.extend(txh)
    txmap = {}
    for chunk in _chunks(want, tx_chunk):
        res = rpc.plain("/get_transactions", {"txs_hashes": chunk,
                                              "decode_as_json": True,
                                              "prune": True})
        if res.get("missed_tx"):
            raise RpcError("get_transactions missed %d tx(s), e.g. %s"
                           % (len(res["missed_tx"]), res["missed_tx"][0]))
        txs = res.get("txs") or []
        if len(txs) != len(chunk):
            raise RpcError("get_transactions returned %d of %d"
                           % (len(txs), len(chunk)))
        for t in txs:
            txmap[t["tx_hash"]] = t

    pre = []            # per block: (h, bid, prev, first, n, unlocks, vkeys, kis)
    run_end = None      # global index one past the batch's last output so far
    lo = None
    for (h, bid_hex, prev_hex, mth, txh) in blocks:
        unlocks = []
        vkeys = []
        idx = []
        kis = []
        for j, th in enumerate([mth] + txh):
            t = txmap.get(th)
            if t is None:
                raise RpcError("tx %s of block %d not returned" % (th, h))
            if t.get("in_pool") or int(t.get("block_height", -1)) != h:
                raise RpcError("tx %s: block_height %s, expected %d"
                               % (th, t.get("block_height"), h))
            aj = t.get("as_json")
            if not aj:
                raise RpcError("tx %s: no as_json (decode_as_json unsupported?)" % th)
            tj = json.loads(aj)
            tv = int(tj.get("version", 1))
            tu = int(tj.get("unlock_time", 0))
            vout = tj.get("vout", [])
            n_to = len(vout) if tv >= 2 else 0
            if n_to:
                oi = t.get("output_indices") or []
                if len(oi) != n_to:
                    raise RpcError("tx %s: %d output_indices for %d outputs"
                                   % (th, len(oi), n_to))
                idx.extend(int(x) for x in oi)
                vkeys.extend(_target_key(v) for v in vout)
                unlocks.extend([tu] * n_to)
            if j:       # the coinbase spends nothing
                for vin in tj.get("vin", []):
                    kk = vin.get("key")
                    if kk and "k_image" in kk:
                        kis.append(bytes.fromhex(kk["k_image"]))
        n = len(unlocks)
        first = idx[0] if n else -1
        if n:
            if idx != list(range(first, first + n)):
                raise RpcError("block %d: amount-0 global indices not contiguous" % h)
            if run_end is not None and first != run_end:
                raise RpcError("block %d: first global index %d, expected %d"
                               % (h, first, run_end))
            if lo is None:
                lo = first
            run_end = first + n
        pre.append((h, bytes.fromhex(bid_hex), bytes.fromhex(prev_hex), first, n,
                    unlocks, vkeys, kis))

    outs = []
    if lo is not None:
        for s in range(lo, run_end, out_chunk):
            e = min(s + out_chunk, run_end)
            og = rpc.plain("/get_outs", {"outputs": [{"amount": 0, "index": i}
                                                     for i in range(s, e)],
                                         "get_txid": False})
            got = og.get("outs") or []
            if len(got) != e - s:
                raise RpcError("get_outs returned %d of %d at %d" % (len(got), e - s, s))
            outs.extend(got)

    res = []
    at = 0
    for (h, bid, prev, first, n, unlocks, vkeys, kis) in pre:
        rows72 = []
        rows80 = []
        hb = _u64le(h)
        for i in range(n):
            o = outs[at + i]
            if int(o["height"]) != h:
                raise RpcError("get_outs(%d) reports height %s, expected %d"
                               % (first + i, o["height"], h))
            if vkeys[i] is not None and o["key"] != vkeys[i]:
                raise RpcError("get_outs(%d) key != tx output key at block %d"
                               % (first + i, h))
            r = bytes.fromhex(o["key"]) + bytes.fromhex(o["mask"]) + _u64le(unlocks[i])
            rows72.append(r)
            rows80.append(r + hb)
        at += n
        compose = sha256d(b"".join(rows72))
        res.append((h, bid, prev, first, n, b"".join(rows80), compose,
                    spent_leaf(h, bid, kis), kis))
    return res


class RecFile:
    """Append-only file of fixed-size records with its own write buffer, so a
    record can be read back (read_at) whether or not it has reached the disk.
    A running sha256 over everything appended (digest()) goes into each
    checkpoint; --resume re-hashes the truncated file against it, and the
    snapshot writer re-hashes what it streams, so a record file that changed
    under the walk (bit rot, a hand edit, a wrong truncation) is refused
    instead of becoming a different snapshot."""

    FLUSH_AT = 8 << 20

    def __init__(self, path, rec):
        self.path = path
        self.rec = rec
        self.fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        size = os.fstat(self.fd).st_size
        if size % rec:
            raise RuntimeError("%s: size %d is not a multiple of %d" % (path, size, rec))
        self.flushed = size
        self.buf = bytearray()
        self.hasher = hashlib.sha256()      # valid only after truncate()/rehash()

    @property
    def nbytes(self):
        return self.flushed + len(self.buf)

    @property
    def count(self):
        return self.nbytes // self.rec

    def truncate(self, count):
        self.flush()
        want = count * self.rec
        if self.flushed < want:
            raise RuntimeError("%s holds %d bytes, checkpoint needs %d -- state is "
                               "damaged, cannot resume" % (self.path, self.flushed, want))
        os.ftruncate(self.fd, want)
        self.flushed = want
        self.rehash()

    def rehash(self):
        """Recompute the running sha256 from the file's current bytes."""
        h = hashlib.sha256()
        for blob in self.iter_chunks(self.flushed):
            h.update(blob)
        self.hasher = h
        return h.hexdigest()

    def digest(self):
        return self.hasher.hexdigest()

    def append(self, b):
        self.buf += b
        self.hasher.update(b)
        if len(self.buf) >= self.FLUSH_AT:
            self.flush()

    def flush(self):
        mv = memoryview(self.buf)
        off = 0
        while off < len(mv):
            off += os.pwrite(self.fd, mv[off:], self.flushed + off)
        mv.release()
        self.flushed += off
        self.buf = bytearray()

    def sync(self):
        self.flush()
        os.fsync(self.fd)

    def read_at(self, i):
        off = i * self.rec
        if off >= self.flushed:
            o = off - self.flushed
            return bytes(self.buf[o:o + self.rec])
        return os.pread(self.fd, self.rec, off)

    def iter_chunks(self, nbytes, chunk=0):
        """Yield the first `nbytes` bytes of the file (flush first), in chunks
        that hold whole records (default ~16 MB)."""
        if chunk <= 0:
            chunk = max(self.rec, (16 << 20) // self.rec * self.rec)
        off = 0
        while off < nbytes:
            b = os.pread(self.fd, min(chunk, nbytes - off), off)
            if not b:
                raise RuntimeError("%s: short read at %d" % (self.path, off))
            off += len(b)
            yield b

    def close(self):
        self.flush()
        os.close(self.fd)


class KiSet:
    """Exact key-image dedupe in ~12 bytes per slot: open addressing over an
    array of 64-bit key-image prefixes plus an array of 32-bit ordinals into the
    spent-key-image file. A prefix hit is confirmed against the full 32 bytes
    read back from that file, so a 64-bit prefix collision can never drop a key
    image. Grows (doubling) at 75% load. A plain set of 32-byte keys would cost
    ~100+ bytes per key image -- tens of GB at mainnet scale."""

    LOAD = 0.75

    def __init__(self, store, bits=20):
        self.store = store
        self.n = 0
        self._alloc(bits)

    def _alloc(self, bits):
        self.bits = bits
        self.size = 1 << bits
        self.mask = self.size - 1
        self.keys = array("Q", [0]) * self.size
        self.ords = array("I", [0]) * self.size
        if self.keys.itemsize != 8 or self.ords.itemsize != 4:
            raise RuntimeError("unexpected array item sizes")
        self.limit = int(self.size * self.LOAD)

    def _grow(self):
        ok, oo = self.keys, self.ords
        self.keys = self.ords = None
        self._alloc(self.bits + 1)
        keys, ords, m = self.keys, self.ords, self.mask
        for j in range(len(ok)):
            k = ok[j]
            if k:
                i = k & m
                while keys[i]:
                    i = (i + 1) & m
                keys[i] = k
                ords[i] = oo[j]

    def add(self, ki):
        """True (and the caller appends ki to the store as ordinal n) if new."""
        if self.n >= self.limit:
            self._grow()
        p = int.from_bytes(ki[:8], "little") or 1
        keys, m = self.keys, self.mask
        i = p & m
        while True:
            k = keys[i]
            if k == 0:
                keys[i] = p
                self.ords[i] = self.n
                self.n += 1
                return True
            if k == p and self.store.read_at(self.ords[i]) == ki:
                return False
            i = (i + 1) & m

    def nbytes(self):
        return self.size * 12


def _mmr_to_json(m):
    return {"leaf_count": m.leaf_count, "peaks": [p.hex() for p in m.peaks]}


def _checkpoint_digest(cp):
    """sha256 over the checkpoint's other fields, canonically encoded, so a
    checkpoint whose bytes changed after it was written is refused rather than
    resumed (a wrong peak or count would otherwise walk on into a different
    anchor or snapshot)."""
    body = {k: v for k, v in cp.items() if k != "digest"}
    return hashlib.sha256(json.dumps(body, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _mmr_from_leaf_file(rf):
    """Re-derive the MMR peaks from a leaf record file (leaf = first 32 bytes
    of each record); the resume check that the checkpoint's peaks are the
    peaks of the leaves that will be streamed into the snapshot."""
    m = Mmr()
    rec = rf.rec
    for blob in rf.iter_chunks(rf.count * rec):
        for o in range(0, len(blob), rec):
            m.append(blob[o:o + 32])
    return m


def _mmr_from_json(j):
    m = Mmr()
    m.leaf_count = int(j["leaf_count"])
    m.peaks = [bytes.fromhex(p) for p in j["peaks"]]
    if len(m.peaks) != bin(m.leaf_count).count("1"):
        raise RuntimeError("checkpoint MMR has %d peaks for %d leaves"
                           % (len(m.peaks), m.leaf_count))
    return m


def _max_rss_bytes():
    try:
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return r if sys.platform == "darwin" else r * 1024
    except Exception:
        return 0


def _cur_rss_bytes():
    try:
        with open("/proc/self/statm") as f:
            return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except Exception:
        return 0


def _gb(x):
    return "%.2fG" % (x / float(1 << 30))


def _fsync_dir(d):
    # Make a preceding os.replace() durable across a crash. Some filesystems
    # (and platforms) cannot open or fsync a directory; that is not fatal for
    # the walk, but it weakens crash durability, so say so instead of hiding it.
    try:
        fd = os.open(d, os.O_RDONLY)
    except OSError as e:
        print("  warning: cannot open %s to fsync it (%s); a crash right now may "
              "lose the last checkpoint rename" % (d, e), file=sys.stderr)
        return
    try:
        os.fsync(fd)
    except OSError as e:
        print("  warning: fsync of directory %s failed (%s); a crash right now may "
              "lose the last checkpoint rename" % (d, e), file=sys.stderr)
    finally:
        os.close(fd)


def _atomic_write(path, data):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(d)


def archive_existing(path):
    """Never overwrite a previous anchor / snapshot: move it aside first."""
    if os.path.lexists(path):
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dst = "%s.prev-%s" % (path, stamp)
        k = 1
        while os.path.lexists(dst):
            dst = "%s.prev-%s.%d" % (path, stamp, k)
            k += 1
        os.replace(path, dst)
        log("archived existing %s -> %s" % (path, dst))


class WalkState:
    """The walk's durable state: four record files + checkpoint.json in a
    directory. Invariant at every checkpoint: the files hold exactly blocks
    1..height, and the checkpoint records their sizes and both MMR peak sets."""

    FILES = (("outputs", "outputs.dat", REC_OUTPUT),
             ("out_leaves", "out_leaves.dat", REC_OUT_LEAF),
             ("ki_leaves", "ki_leaves.dat", REC_KI_LEAF),
             ("spent", "spent.dat", REC_KEY_IMAGE))

    def __init__(self, d, net, h_a, h_a_id_hex, genesis_id_hex):
        self.dir = d
        self.cp_path = os.path.join(d, "checkpoint.json")
        self.net = net
        self.h_a = h_a
        self.h_a_id = h_a_id_hex
        self.genesis_id = genesis_id_hex
        self.files = {}
        self.height = 0
        self.last_id = bytes.fromhex(genesis_id_hex)
        self.frontier = 0
        self.out_mmr = Mmr()
        self.ki_mmr = Mmr()
        self.kiset = None
        self.complete = False

    @staticmethod
    def read_checkpoint(d):
        p = os.path.join(d, "checkpoint.json")
        if not os.path.exists(p):
            return None
        with open(p) as f:
            return json.load(f)

    def open(self, resume):
        os.makedirs(self.dir, exist_ok=True)
        cp = self.read_checkpoint(self.dir) if resume else None
        for key, name, rec in self.FILES:
            self.files[key] = RecFile(os.path.join(self.dir, name), rec)
        if cp is None:
            if resume:
                log("--resume: no checkpoint in %s, starting the walk from genesis"
                    % self.dir)
            for rf in self.files.values():
                rf.truncate(0)
            self.kiset = KiSet(self.files["spent"])
            return
        if int(cp.get("version", 0)) != WALK_STATE_VERSION:
            raise SystemExit("checkpoint version %s != %d" % (cp.get("version"),
                                                               WALK_STATE_VERSION))
        if cp.get("digest") != _checkpoint_digest(cp):
            raise SystemExit("%s: digest mismatch -- the checkpoint was altered "
                             "after it was written; cannot resume" % self.cp_path)
        for k, want in (("net", self.net), ("h_a", self.h_a),
                        ("h_a_id", self.h_a_id), ("genesis_id", self.genesis_id)):
            if cp.get(k) != want:
                raise SystemExit("checkpoint %s=%s does not match this run (%s); "
                                 "refusing to resume a different anchor"
                                 % (k, cp.get(k), want))
        self.height = int(cp["height"])
        self.last_id = bytes.fromhex(cp["last_id"])
        self.frontier = int(cp["frontier"])
        self.out_mmr = _mmr_from_json(cp["out_mmr"])
        self.ki_mmr = _mmr_from_json(cp["ki_mmr"])
        self.complete = bool(cp.get("complete"))
        counts = cp["counts"]
        hashes = cp["hashes"]
        t0 = time.time()
        for key, name, _ in self.FILES:
            rf = self.files[key]
            rf.truncate(int(counts[key]))       # re-hashes the kept bytes
            if rf.digest() != hashes[key]:
                raise SystemExit("%s: sha256 of the %d checkpointed bytes does not "
                                 "match the checkpoint -- the record file changed "
                                 "after the checkpoint was written; cannot resume"
                                 % (rf.path, rf.nbytes))
        log("resume: %d record files re-hashed against the checkpoint in %.1fs"
            % (len(self.FILES), time.time() - t0))
        if (self.files["outputs"].count != self.frontier
                or self.files["out_leaves"].count != self.height
                or self.files["ki_leaves"].count != self.height
                or self.out_mmr.leaf_count != self.height
                or self.ki_mmr.leaf_count != self.height):
            raise SystemExit("checkpoint is internally inconsistent; cannot resume")
        # the checkpoint's peaks must be the peaks of the leaf files themselves
        t0 = time.time()
        for key, mmr in (("out_leaves", self.out_mmr), ("ki_leaves", self.ki_mmr)):
            got = _mmr_from_leaf_file(self.files[key])
            if got.leaf_count != mmr.leaf_count or got.peaks != mmr.peaks:
                raise SystemExit("checkpoint %s MMR peaks are not the peaks of %s; "
                                 "cannot resume" % (key, self.files[key].path))
        log("resume: MMR peaks re-derived from %d leaves per tree in %.1fs"
            % (self.height, time.time() - t0))
        # rebuild the key-image dedupe from the spent file (sized up front)
        s = self.files["spent"].count
        bits = 20
        while (1 << bits) * KiSet.LOAD * 0.9 < s:
            bits += 1
        self.kiset = KiSet(self.files["spent"], bits)
        t0 = time.time()
        log("resume: checkpoint height %d/%d, frontier %d, rebuilding key-image "
            "dedupe from %d spent records (table 2^%d, %s)"
            % (self.height, self.h_a, self.frontier, s, bits,
               _gb(self.kiset.nbytes())))
        sp = self.files["spent"]
        done = 0
        for blob in sp.iter_chunks(s * REC_KEY_IMAGE, chunk=REC_KEY_IMAGE << 16):
            for o in range(0, len(blob), REC_KEY_IMAGE):
                if not self.kiset.add(blob[o:o + REC_KEY_IMAGE]):
                    raise SystemExit("spent.dat holds a duplicate key image at "
                                     "record %d; state is damaged" % done)
                done += 1
        log("resume: dedupe rebuilt in %.1fs" % (time.time() - t0))

    def connect(self, blk):
        (h, bid, prev, first, n, rows80, compose, ki_leaf, kis) = blk
        if h != self.height + 1:
            raise RuntimeError("walk out of order: got %d after %d" % (h, self.height))
        if prev != self.last_id:
            raise RuntimeError("prev_id break at %d: %s != %s"
                               % (h, prev.hex(), self.last_id.hex()))
        if n and first != self.frontier:
            raise RuntimeError("block %d: first global index %d != frontier %d "
                               "(an output was skipped or duplicated)"
                               % (h, first, self.frontier))
        # output leaf: exactly output_leaf(h, bid, frontier, records)
        leaf = mmr_leaf_hash(b"XMRO" + b"\x01" + _u64le(h) + bid
                             + _u64le(self.frontier) + _u32le(n) + compose)
        f = self.files
        if n:
            f["outputs"].append(rows80)
        f["out_leaves"].append(leaf + _u64le(self.frontier))
        self.out_mmr.append(leaf)
        f["ki_leaves"].append(ki_leaf)
        self.ki_mmr.append(ki_leaf)
        sp = f["spent"]
        for ki in kis:
            if self.kiset.add(ki):
                sp.append(ki)
        self.frontier += n
        self.height = h
        self.last_id = bid

    def checkpoint(self, complete=False):
        for rf in self.files.values():
            rf.sync()
        self.complete = complete
        cp = {
            "version": WALK_STATE_VERSION,
            "net": self.net,
            "h_a": self.h_a,
            "h_a_id": self.h_a_id,
            "genesis_id": self.genesis_id,
            "height": self.height,
            "last_id": self.last_id.hex(),
            "frontier": self.frontier,
            "counts": {k: self.files[k].count for k, _, _ in self.FILES},
            "hashes": {k: self.files[k].digest() for k, _, _ in self.FILES},
            "out_mmr": _mmr_to_json(self.out_mmr),
            "ki_mmr": _mmr_to_json(self.ki_mmr),
            "complete": complete,
            "written": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        cp["digest"] = _checkpoint_digest(cp)
        _atomic_write(self.cp_path, (json.dumps(cp, indent=1) + "\n").encode())

    def write_snapshot(self, path, tip_id):
        """Stream ChainOutputSet::serialize() to `path`: identical bytes to
        serialize_output_set(0, h_a, tip_id, ...), never more than one chunk in
        memory. Written to a temp name and renamed into place."""
        for rf in self.files.values():
            rf.flush()
        d = os.path.dirname(os.path.abspath(path))
        tmp = os.path.join(d, ".%s.partial" % os.path.basename(path))
        need = 1 + 8 + 8 + 32 + sum(8 + rf.nbytes for rf in self.files.values())
        if os.path.exists(tmp):
            os.unlink(tmp)          # our own half-written temp from a killed run
        free = shutil.disk_usage(d).free
        if free < need + (256 << 20):
            raise SystemExit("snapshot needs %s, only %s free in %s; the walk is "
                             "checkpointed complete -- free space and rerun with "
                             "--resume" % (_gb(need), _gb(free), d))
        total = 0
        t0 = time.time()
        with open(tmp, "wb") as out:
            hdr = bytes([OUTPUT_SET_SER_VER]) + _u64le(0) + _u64le(self.h_a) + tip_id
            out.write(hdr)
            total += len(hdr)
            for key, _, rec in self.FILES:
                rf = self.files[key]
                cnt = rf.count
                out.write(_u64le(cnt))
                total += 8
                h = hashlib.sha256()
                for blob in rf.iter_chunks(cnt * rec):
                    h.update(blob)
                    out.write(blob)
                    total += len(blob)
                if h.hexdigest() != rf.digest():
                    out.close()
                    os.unlink(tmp)
                    raise RuntimeError("%s: bytes read back for the snapshot do not "
                                       "hash to what was appended; snapshot not "
                                       "written" % rf.path)
            out.flush()
            os.fsync(out.fileno())
        if os.path.getsize(tmp) != total:
            raise RuntimeError("snapshot size mismatch")
        archive_existing(path)
        os.replace(tmp, path)
        _fsync_dir(d)
        log("wrote %s (%d bytes) -- ChainOutputSet snapshot, streamed in %.1fs"
            % (path, total, time.time() - t0))
        return total

    def close(self):
        for rf in self.files.values():
            rf.close()


def build_output_set(rpc, h_a, h_a_id_hex, genesis_id_hex, opts):
    """Walk 1..H_a into WalkState (resumable) and return the committed roots.
    `opts` carries state_dir, resume, threads, batch_blocks, checkpoint_blocks,
    checkpoint_secs, progress_secs, tx_chunk, out_chunk, debug_block_delay."""
    st = WalkState(opts.state_dir, opts.net, h_a, h_a_id_hex, genesis_id_hex)
    st.open(opts.resume)

    # No cyclic GC during the walk: nothing it allocates is cyclic, and a gen-2
    # pass over a large heap is what used to freeze the walk for minutes.
    gc.collect()
    if hasattr(gc, "freeze"):
        gc.freeze()
    gc.disable()

    threads = max(1, opts.threads)
    bb = max(1, opts.batch_blocks)
    window = threads * 2
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
    pending = collections.deque()
    next_submit = st.height + 1

    def refill():
        nonlocal next_submit
        while len(pending) < window and next_submit <= h_a:
            a = next_submit
            b = min(h_a, a + bb - 1)
            pending.append((a, b, pool.submit(fetch_batch, rpc, a, b,
                                              opts.tx_chunk, opts.out_chunk)))
            next_submit = b + 1

    t_start = time.time()
    h_start = st.height
    last_cp_t = time.time()
    last_cp_h = st.height
    last_pr_t = 0.0
    rate_hist = collections.deque()      # (t, height) for a 10-minute rate window
    if st.height < h_a:
        log("output-set walk: blocks %d..%d, %d threads x %d-block batches, "
            "state %s" % (st.height + 1, h_a, threads, bb, st.dir))
    try:
        refill()
        while pending:
            a, b, fut = pending.popleft()
            try:
                blocks = fut.result()
            except BaseException:
                # state holds whole blocks 1..st.height: record that before leaving
                rpc.stop.set()
                st.checkpoint()
                log("walk stopped at height %d; checkpoint written, rerun with "
                    "--resume" % st.height)
                raise
            refill()
            for blk in blocks:
                st.connect(blk)
                if opts.debug_block_delay:
                    time.sleep(opts.debug_block_delay)
            now = time.time()
            if (st.height - last_cp_h >= opts.checkpoint_blocks
                    or now - last_cp_t >= opts.checkpoint_secs) and st.height < h_a:
                st.checkpoint()
                last_cp_t, last_cp_h = now, st.height
            if now - last_pr_t >= opts.progress_secs or st.height == h_a:
                last_pr_t = now
                rate_hist.append((now, st.height))
                while len(rate_hist) > 2 and now - rate_hist[0][0] > 600:
                    rate_hist.popleft()
                t0, h0 = rate_hist[0]
                rate = (st.height - h0) / (now - t0) if now > t0 else 0.0
                avg = (st.height - h_start) / (now - t_start) if now > t_start else 0.0
                r = rate or avg
                eta = (h_a - st.height) / r if r > 0 else 0
                cur = _cur_rss_bytes()
                log("output-set walk %d/%d (%.2f%%) rct_output_count=%d spent=%d "
                    "rate=%.1f blk/s (avg %.1f) eta=%dh%02dm dedupe=%s %smaxrss=%s"
                    % (st.height, h_a, 100.0 * st.height / max(1, h_a), st.frontier,
                       st.files["spent"].count, rate, avg, eta // 3600,
                       (eta % 3600) // 60, _gb(st.kiset.nbytes()),
                       ("rss=%s " % _gb(cur)) if cur else "", _gb(_max_rss_bytes())))
    finally:
        rpc.stop.set()
        pool.shutdown(wait=True, cancel_futures=True)
        rpc.stop.clear()
        gc.enable()

    if st.height != h_a:
        raise RuntimeError("walk ended at %d, not H_a=%d" % (st.height, h_a))
    tip_id = st.last_id
    if tip_id.hex() != h_a_id_hex:
        raise RuntimeError("walk tip id %s != anchor id %s" % (tip_id.hex(), h_a_id_hex))
    st.checkpoint(complete=True)

    # completeness probe: the first amount-0 output past the frontier (if any)
    # must belong to a block above H_a, i.e. the walk missed none at the end.
    try:
        og = rpc.plain("/get_outs", {"outputs": [{"amount": 0, "index": st.frontier}],
                                     "get_txid": False})
        nxt = (og.get("outs") or [{}])[0]
        if "height" in nxt and int(nxt["height"]) <= h_a:
            raise RuntimeError("output %d is at height %s <= H_a: the walk missed "
                               "outputs" % (st.frontier, nxt["height"]))
        log("completeness probe: output %d is at height %s (> H_a)"
            % (st.frontier, nxt.get("height")))
    except RpcError:
        log("completeness probe: no amount-0 output at index %d (chain tip)"
            % st.frontier)

    log("output-set walk done: %d blocks, rct_output_count=%d, %d spent key "
        "images, %.1f min this run, maxrss=%s"
        % (h_a, st.frontier, st.files["spent"].count, (time.time() - t_start) / 60,
           _gb(_max_rss_bytes())))
    return st, {
        "rct_output_count": st.frontier,
        "leaves": h_a,                       # one per block 1..H_a
        "output_root": st.out_mmr.bag(),
        "spent_root": st.ki_mmr.bag(),
        "tip_id": tip_id,
    }


def bench_walk(rpc, start, count, opts):
    """Fetch-only throughput probe over [start, start+count): the same batched
    pipeline as the walk, nothing written. Prints blocks/s, tx/s, outputs/s."""
    threads = max(1, opts.threads)
    bb = max(1, opts.batch_blocks)
    end = start + count - 1
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
    pending = collections.deque()
    nxt = start
    t0 = time.time()
    nblk = nout = nki = 0
    while nxt <= end or pending:
        while len(pending) < threads * 2 and nxt <= end:
            b = min(end, nxt + bb - 1)
            pending.append(pool.submit(fetch_batch, rpc, nxt, b,
                                       opts.tx_chunk, opts.out_chunk))
            nxt = b + 1
        for blk in pending.popleft().result():
            nblk += 1
            nout += blk[4]
            nki += len(blk[8])
    dt = time.time() - t0
    pool.shutdown()
    log("bench %d..%d: %d blocks, %d outputs, %d key images in %.1fs = %.1f blk/s, "
        "%.0f out/s, %.0f ki/s (threads=%d batch=%d) maxrss=%s"
        % (start, end, nblk, nout, nki, dt, nblk / dt, nout / dt, nki / dt,
           threads, bb, _gb(_max_rss_bytes())))
    return 0


def _selftest_streaming():
    """The streamed snapshot must equal serialize_output_set() byte for byte, and
    the dedupe must be exact under forced 64-bit-prefix collisions."""
    import random
    rnd = random.Random(1234)
    d = tempfile.mkdtemp(prefix="xmr-anchor-selftest-")
    try:
        gid = bytes(32)
        st = WalkState(d, "regtest", 0, "", gid.hex())
        st.open(False)
        st.kiset = KiSet(st.files["spent"], bits=4)     # force growth + probing
        outputs, lf, lv, kl, spent, seen = [], [], [], [], [], set()
        frontier = 0
        prev = gid
        # key images sharing an 8-byte prefix (collide in the table) + repeats
        pool = [b"\x07" * 8 + bytes([i]) * 24 for i in range(6)]
        for h in range(1, 60):
            bid = hashlib.sha256(b"b%d" % h).digest()
            n = rnd.randrange(0, 4)
            recs = []
            for i in range(n):
                pk = bytes(rnd.randrange(256) for _ in range(32))
                cm = bytes(rnd.randrange(256) for _ in range(32))
                ut = rnd.choice([0, 0, 10, 2 ** 40])
                recs.append((pk, cm, ut))
                outputs.append((pk, cm, ut, h))
            kis = [rnd.choice(pool) if rnd.random() < 0.3 else
                   bytes(rnd.randrange(256) for _ in range(32))
                   for _ in range(rnd.randrange(0, 4))]
            ol = output_leaf(h, bid, frontier, recs)
            lf.append(frontier)
            lv.append(ol)
            kl.append(spent_leaf(h, bid, kis))
            for ki in kis:
                if ki not in seen:
                    seen.add(ki)
                    spent.append(ki)
            rows72 = b"".join(pk + cm + _u64le(ut) for (pk, cm, ut) in recs)
            rows80 = b"".join(pk + cm + _u64le(ut) + _u64le(h) for (pk, cm, ut) in recs)
            st.connect((h, bid, prev, frontier if n else -1, n, rows80,
                        sha256d(rows72), spent_leaf(h, bid, kis), kis))
            frontier += n
            prev = bid
        st.h_a = 59
        tip = prev
        ref = serialize_output_set(0, 59, tip, outputs, lf, lv, kl, spent)
        p = os.path.join(d, "snap.bin")
        st.write_snapshot(p, tip)
        with open(p, "rb") as f:
            got = f.read()
        st.close()
        ok = (got == ref)
        print("SELFTEST streamed snapshot %s (%d bytes, %d spent incl. forced "
              "prefix collisions)" % ("OK" if ok else "MISMATCH", len(ref), len(spent)))
        return ok
    finally:
        shutil.rmtree(d, ignore_errors=True)

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
    stream_ok = _selftest_streaming()
    print("SELFTEST %s" % ("OK" if ok and stream_ok else
                           "MISMATCH vs pinned C++ roots" if not ok else
                           "MISMATCH streamed snapshot vs serialize_output_set"),
          file=sys.stderr)
    return 0 if ok and stream_ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rpc", default="http://127.0.0.1:38081")
    ap.add_argument("--net", choices=["mainnet", "testnet", "stagenet", "regtest"],
                    help="required unless --selftest")
    ap.add_argument("--height", type=int, default=0)
    ap.add_argument("--bury", type=int, default=720)
    ap.add_argument("--out", help="the .inc to write (required unless --selftest "
                                  "or --bench-walk); an existing file is archived "
                                  "as <out>.prev-<UTC>, never overwritten")
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
    # --- walk engine (format 2) ---
    ap.add_argument("--state-dir", default="",
                    help="walk state directory (record files + checkpoint.json); "
                         "default <output-set-out or out>.walkstate")
    ap.add_argument("--resume", action="store_true",
                    help="continue the walk from the checkpoint in --state-dir "
                         "(H_a is taken from the checkpoint; --height must match "
                         "if given)")
    ap.add_argument("--threads", type=int, default=8,
                    help="parallel RPC fetch workers (default 8)")
    ap.add_argument("--batch-blocks", type=int, default=100,
                    help="blocks per fetch batch (default 100)")
    ap.add_argument("--checkpoint-blocks", type=int, default=20000,
                    help="checkpoint at least every N blocks (default 20000)")
    ap.add_argument("--checkpoint-secs", type=float, default=300,
                    help="checkpoint at least every N seconds (default 300)")
    ap.add_argument("--progress-secs", type=float, default=60,
                    help="progress line every N seconds (default 60)")
    ap.add_argument("--tx-chunk", type=int, default=1000,
                    help="tx hashes per get_transactions call (default 1000)")
    ap.add_argument("--out-chunk", type=int, default=5000,
                    help="global indices per get_outs call (default 5000)")
    ap.add_argument("--rpc-timeout", type=float, default=300,
                    help="per-call socket timeout, seconds (default 300)")
    ap.add_argument("--rpc-retry-budget", type=float, default=3600,
                    help="give up on an RPC after retrying this long, seconds; "
                         "0 = never (default 3600). The walk checkpoints before "
                         "exiting, so --resume picks it up.")
    ap.add_argument("--stamp", default="",
                    help="fixed 'captured' time for the .inc comment header "
                         "(reproducible test output); default: now, UTC")
    ap.add_argument("--bench-walk", default="",
                    help="FROM:COUNT -- fetch-only throughput probe over that "
                         "block range, nothing written; then exit")
    ap.add_argument("--debug-block-delay", type=float, default=0.0,
                    help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.selftest:
        return run_selftest()

    rpc = Rpc(args.rpc, timeout=args.rpc_timeout, retry_budget=args.rpc_retry_budget)

    if args.bench_walk:
        a, _, n = args.bench_walk.partition(":")
        return bench_walk(rpc, int(a), int(n or 1000), args)

    if not args.net or not args.out:
        ap.error("--net and --out are required")

    info = rpc.plain("/get_info")
    # monerod reports its regtest network as "fakechain"; treat it as regtest.
    daemon_net = info.get("nettype")
    if not (daemon_net == args.net
            or (args.net == "regtest" and daemon_net == "fakechain")):
        raise SystemExit("daemon is %s, --net says %s" % (daemon_net, args.net))
    if not info.get("synchronized"):
        print("WARNING: daemon reports synchronized=false", file=sys.stderr)
    tip = int(info["height"]) - 1

    # Walk state: pin H_a from a checkpoint on --resume; never clobber one.
    if args.output_set:
        if not args.state_dir:
            args.state_dir = (args.output_set_out or args.out) + ".walkstate"
        cp = WalkState.read_checkpoint(args.state_dir)
        if cp is not None and not args.resume:
            raise SystemExit("%s holds a walk checkpoint (height %s/%s); pass "
                             "--resume to continue it, or choose another "
                             "--state-dir" % (args.state_dir, cp.get("height"),
                                              cp.get("h_a")))
        if cp is None and not args.resume and os.path.isdir(args.state_dir) and any(
                os.path.getsize(os.path.join(args.state_dir, nm)) > 0
                for _, nm, _ in WalkState.FILES
                if os.path.exists(os.path.join(args.state_dir, nm))):
            raise SystemExit("%s holds walk data but no checkpoint; pass --resume "
                             "(restarts that walk from genesis) or choose another "
                             "--state-dir" % args.state_dir)
        if cp is not None:
            cp_h_a = int(cp["h_a"])
            if args.height and args.height != cp_h_a:
                raise SystemExit("--height %d != checkpoint H_a %d"
                                 % (args.height, cp_h_a))
            args.height = cp_h_a
    elif args.resume:
        raise SystemExit("--resume only applies with --output-set")

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
    #
    # get_miner_data answers "Core is busy" on a daemon that does not consider
    # itself synchronized (a peerless, non --offline regtest node). Then the
    # SAME quantity is read directly: get_coinbase_tx_sum over blocks 0..H_a,
    # whose emission_amount is the sum monerod accumulates into
    # already_generated_coins (genesis included, fees excluded).
    md = None
    try:
        md = rpc.json_rpc("get_miner_data", max_attempts=5)
    except RpcTransient as e:
        if "busy" not in str(e).lower():
            raise
        log("get_miner_data: daemon busy (%s); falling back to "
            "get_coinbase_tx_sum over 0..H_a" % e)

    if md is not None:
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
        coins_comment = [
            "coins     already_generated_coins from get_miner_data at %d minus the"
            % md_tip,
            "          BASE EMISSION of every block above H_a -- get_coinbase_tx_sum's",
            "          emission_amount, NOT the header `reward`. monerod accumulates",
            "          base_reward into already_generated_coins; fees are recycled from",
            "          the existing supply and are never added to it.",
        ]
    else:
        cs = rpc.json_rpc("get_coinbase_tx_sum", {"height": 0, "count": h_a + 1},
                          timeout=max(args.rpc_timeout, 7200))
        coins = wide_to_int(cs, "wide_emission_amount", "emission_amount",
                            "emission_amount_top64")
        coins_comment = [
            "coins     already_generated_coins = get_coinbase_tx_sum(0..H_a)",
            "          emission_amount (get_miner_data was busy on this daemon).",
            "          monerod accumulates base_reward into already_generated_coins;",
            "          fees are recycled from the existing supply and never added.",
        ]
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
    # win holds only the last 100000 headers; release them before a long walk
    del win, by_height

    set_provenance = ""
    if args.output_set:
        genesis_id = fetch_headers(rpc, 0, 0)[0]["hash"]
        st, oset = build_output_set(rpc, h_a, bundle["id"], genesis_id, args)
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
            st.write_snapshot(args.output_set_out, oset["tip_id"])
        st.close()

    self_check(bundle)

    stamp = args.stamp or datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y-%m-%d %H:%MZ")
    comment = "\n".join([
        "c2pool native-XMR trust anchor -- generated, do not hand-edit.",
        "tool      tools/xmr-anchor-gen/xmr_anchor_gen.py (read-only RPC)",
        "daemon    monerod %s, nettype %s" % (info.get("version", "?"), args.net),
        "captured  %s, daemon tip %d, anchor buried %d"
        % (stamp, tip, tip - h_a),
        "windows   %d difficulty / %d short-term / %d long-term"
        % (ANCHOR_DIFFICULTY_WINDOW, ANCHOR_SHORT_TERM_WEIGHTS,
           ANCHOR_LONG_TERM_WEIGHTS),
    ] + coins_comment + [
        "note      monerod publishes no RPC for its compiled-in checkpoints;",
        "          `checkpoint` rows are copied by hand at release time and",
        "          this capture carries %d of them." % len(checkpoints),
    ] + ([set_provenance] if set_provenance else []))
    text = write_anchor_inc(bundle, comment)
    archive_existing(args.out)
    with open(args.out, "w") as f:
        f.write(text)
    print("wrote %s (%d bytes), H_a=%d id=%s"
          % (args.out, len(text), h_a, bundle["id"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
