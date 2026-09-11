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
ANCHOR_INC_FORMAT_VERSION = 1

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
    s.append("format %d\n" % ANCHOR_INC_FORMAT_VERSION)
    s.append("network %s\n" % b["network"])
    s.append("height %d\n" % b["height"])
    s.append("id %s\n" % b["id"])
    s.append("prev_id %s\n" % b["prev_id"])
    s.append("timestamp %d\n" % b["timestamp"])
    s.append("major_version %d\n" % b["major_version"])
    s.append("cumulative_difficulty %s\n" % u128_text(b["cumulative_difficulty"]))
    s.append("already_generated_coins %d\n" % b["already_generated_coins"])
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
    if len(b["difficulty_window"]) != ANCHOR_DIFFICULTY_WINDOW:
        raise RuntimeError("difficulty window is %d" % len(b["difficulty_window"]))
    if len(b["short_term_weights"]) != ANCHOR_SHORT_TERM_WEIGHTS:
        raise RuntimeError("short-term window is %d" % len(b["short_term_weights"]))
    if len(b["long_term_weights"]) != ANCHOR_LONG_TERM_WEIGHTS:
        raise RuntimeError("long-term window is %d" % len(b["long_term_weights"]))
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
    args = ap.parse_args()

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

    if h_a < ANCHOR_LONG_TERM_WEIGHTS - 1:
        raise SystemExit("H_a=%d is below the %d-block long-term window"
                         % (h_a, ANCHOR_LONG_TERM_WEIGHTS))
    if tip - h_a < 60:
        raise SystemExit("H_a is only %d deep; refuse (reorg risk)" % (tip - h_a))

    lo = h_a - (ANCHOR_LONG_TERM_WEIGHTS - 1)
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
                              for x in win[-ANCHOR_DIFFICULTY_WINDOW:]],
        "short_term_weights": [x["block_weight"]
                               for x in win[-ANCHOR_SHORT_TERM_WEIGHTS:]],
        "long_term_weights": [x["long_term_weight"] for x in win],
        "monerod_checkpoints": checkpoints,
    }
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
    ])
    text = write_anchor_inc(bundle, comment)
    with open(args.out, "w") as f:
        f.write(text)
    print("wrote %s (%d bytes), H_a=%d id=%s"
          % (args.out, len(text), h_a, bundle["id"]), file=sys.stderr)


if __name__ == "__main__":
    main()
