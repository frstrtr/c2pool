#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
#
# Regenerates src/impl/xmr/native/test/xmr_c6_parity_golden.hpp -- the C6
# monerod-parity capture.
#
# The capture is READ-ONLY against a synced stagenet daemon. Nothing here mines,
# submits or writes: the four calls are get_info, get_last_block_header,
# get_miner_data and get_block_headers_range, plus two get_block_header_by_height
# for the RandomX seed blocks.
#
# Two windows are captured on purpose:
#   STEADY -- the 60 heights below the tip at capture time, the ordinary case;
#   EPOCH  -- 193 heights straddling a RandomX epoch boundary (a multiple of
#             2048) so the graduation ledger has real EpochEdge coverage rather
#             than a synthetic one. A comparator that only ever saw steady
#             heights has not been shown to work where the seed changes.
#
# Usage:
#   gen_c6_parity_golden.py --rpc http://127.0.0.1:38081/json_rpc [--out FILE]
#   gen_c6_parity_golden.py --from-capture capture.json [--out FILE]
#
# The second form replays a saved capture so the header can be regenerated
# without a daemon (the capture itself is what carries the provenance).

import argparse
import json
import sys
import urllib.request

EPOCH = 2048          # RandomX seed epoch, in blocks
SEED_LAG = 64         # rx_seedheight lag
STEADY_ROWS = 60
# The epoch window is boundary +/- 96, not +/- 64: the outer 32 heights on each
# side are NOT epoch edges, so the classifier is checked against real chain data
# on BOTH sides of the line. A window that is entirely inside the lag would only
# ever prove that the classifier says yes.
EPOCH_HALF_SPAN = 96


def rpc(url, method, params=None):
    body = {"jsonrpc": "2.0", "id": "0", "method": method}
    if params is not None:
        body["params"] = params
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode()


def capture(url):
    out = {}
    out["INFO"] = json.loads(rpc(url, "get_info"))
    info = out["INFO"]["result"]
    tip = info["height"] - 1
    out["LASTHDR"] = json.loads(rpc(url, "get_last_block_header"))
    out["MINERDATA"] = json.loads(rpc(url, "get_miner_data"))
    out["RANGE_STEADY"] = json.loads(rpc(url, "get_block_headers_range", {
        "start_height": tip - (STEADY_ROWS - 1), "end_height": tip}))
    boundary = ((tip - SEED_LAG) // EPOCH) * EPOCH
    out["RANGE_EPOCH"] = json.loads(rpc(url, "get_block_headers_range", {
        "start_height": boundary - EPOCH_HALF_SPAN,
        "end_height": boundary + EPOCH_HALF_SPAN}))
    seed_h = ((info["height"] - SEED_LAG - 1) // EPOCH) * EPOCH
    out["SEED1"] = json.loads(rpc(url, "get_block_header_by_height", {"height": seed_h}))
    out["SEED0"] = json.loads(rpc(url, "get_block_header_by_height", {"height": seed_h - EPOCH}))
    return out


def c_string(s, width=96):
    """Emit a JSON body as a run of adjacent C string literals."""
    esc = s.replace("\\", "\\\\").replace('"', '\\"')
    lines = []
    i = 0
    while i < len(esc):
        chunk = esc[i:i + width]
        # never split an escape sequence across two literals
        while chunk.endswith("\\"):
            chunk = chunk[:-1]
        i += len(chunk)
        lines.append('    "%s"' % chunk)
    return "\n".join(lines)


def compact(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


def rows_block(name, headers):
    out = ["inline constexpr GoldenHeader %s[] = {" % name]
    for h in headers:
        out.append(
            '    {%dull, "%s", "%s", %dull, %dull, %dull, %dull, %dull, %dull, %dull, %dull, %d, %d, %dull},'
            % (h["height"], h["hash"], h["prev_hash"], h["timestamp"],
               h["difficulty"], h.get("difficulty_top64", 0),
               h["cumulative_difficulty"], h.get("cumulative_difficulty_top64", 0),
               h["reward"], h["block_weight"], h["long_term_weight"],
               h["major_version"], h["minor_version"], h["num_txes"]))
    out.append("};")
    out.append("inline constexpr std::size_t %s_COUNT = sizeof(%s) / sizeof(%s[0]);"
               % (name, name, name))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc")
    ap.add_argument("--from-capture")
    ap.add_argument("--out", default="xmr_c6_parity_golden.hpp")
    a = ap.parse_args()

    if a.from_capture:
        d = json.load(open(a.from_capture))
    elif a.rpc:
        d = capture(a.rpc)
    else:
        ap.error("one of --rpc / --from-capture is required")

    info = d["INFO"]["result"]
    last = d["LASTHDR"]["result"]["block_header"]
    md = d["MINERDATA"]["result"]
    steady = d["RANGE_STEADY"]["result"]["headers"]
    epoch = d["RANGE_EPOCH"]["result"]["headers"]
    seed1 = d["SEED1"]["result"]["block_header"]
    seed0 = d["SEED0"]["result"]["block_header"]

    # Coherence gates: a capture that is not internally consistent is not a
    # golden, it is noise. Refuse rather than emit it.
    assert info["height"] == last["height"] + 1, "get_info tip disagrees with get_last_block_header"
    assert info["top_block_hash"] == last["hash"], "get_info top hash disagrees with the header"
    assert md["height"] == info["height"], "get_miner_data height disagrees with get_info"
    assert md["prev_id"] == info["top_block_hash"], "get_miner_data prev_id is not the tip"
    assert md["seed_hash"] == seed1["hash"], "get_miner_data seed_hash is not the seed block id"
    assert steady[-1]["height"] == last["height"], "steady window does not end at the tip"
    for w in (steady, epoch):
        for i in range(1, len(w)):
            assert w[i]["prev_hash"] == w[i - 1]["hash"], "window is not a chain"

    body = []
    body.append('''// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_c6_parity_golden.hpp  -- GENERATED, DO NOT EDIT
//
// The C6 monerod-parity capture: what a real, synced monerod said about its own
// tip, its own template inputs and %d of its own blocks, at one instant.
//
//   source daemon : monerod %s (%s)
//   captured tip  : %d
//   regenerate    : src/impl/xmr/native/test/gen_c6_parity_golden.py
//
// The three RAW bodies are VERBATIM. They are replayed through the production
// decode path, so the oracle under test parses what a daemon actually sends --
// hex-string difficulty, wide_cumulative_difficulty and all -- rather than a
// re-typed struct that would agree with itself by construction.
//
// Two windows: STEADY (the 60 heights below the tip) and EPOCH (193 heights
// straddling the RandomX epoch boundary at %d, so EpochEdge coverage is
// real chain data and not a synthetic class label).
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>

namespace c2pool::xmr::native::golden_c6 {

inline constexpr const char* MONEROD_VERSION = "%s";
inline constexpr const char* NETWORK         = "%s";

// --- the tip, as three independent monerod answers -------------------------
inline constexpr std::uint64_t INFO_HEIGHT        = %dull;   // tip + 1
inline constexpr const char*   INFO_TOP_BLOCK_HASH = "%s";
inline constexpr std::uint64_t INFO_CUMULATIVE_DIFFICULTY_LO = %dull;
inline constexpr std::uint64_t INFO_CUMULATIVE_DIFFICULTY_HI = %dull;
inline constexpr std::uint64_t INFO_DIFFICULTY_LO = %dull;
inline constexpr std::uint64_t INFO_DIFFICULTY_HI = %dull;
inline constexpr bool          INFO_SYNCHRONIZED  = %s;

inline constexpr std::uint64_t TIP_HEIGHT     = %dull;
inline constexpr const char*   TIP_ID         = "%s";
inline constexpr const char*   TIP_PREV_ID    = "%s";
inline constexpr std::uint64_t TIP_TIMESTAMP  = %dull;
inline constexpr std::uint64_t TIP_REWARD     = %dull;
inline constexpr std::uint64_t TIP_BLOCK_WEIGHT     = %dull;
inline constexpr std::uint64_t TIP_LONG_TERM_WEIGHT = %dull;
inline constexpr std::uint8_t  TIP_MAJOR_VERSION    = %d;

// --- the template inputs at that tip ---------------------------------------
inline constexpr std::uint64_t MD_HEIGHT        = %dull;
inline constexpr const char*   MD_PREV_ID       = "%s";
inline constexpr const char*   MD_SEED_HASH     = "%s";
inline constexpr std::uint64_t MD_DIFFICULTY_LO = %dull;
inline constexpr std::uint64_t MD_DIFFICULTY_HI = %dull;
inline constexpr std::uint64_t MD_MEDIAN_WEIGHT = %dull;
inline constexpr std::uint64_t MD_ALREADY_GENERATED_COINS = %dull;
inline constexpr std::uint8_t  MD_MAJOR_VERSION = %d;

// --- RandomX seed blocks ----------------------------------------------------
inline constexpr std::uint64_t SEED_HEIGHT       = %dull;
inline constexpr const char*   SEED_ID           = "%s";
inline constexpr std::uint64_t PREV_SEED_HEIGHT  = %dull;
inline constexpr const char*   PREV_SEED_ID      = "%s";
inline constexpr std::uint64_t EPOCH_BOUNDARY    = %dull;

// --- verbatim RPC bodies ----------------------------------------------------
inline constexpr const char* INFO_RAW_JSON =
%s
    ;

inline constexpr const char* LAST_BLOCK_HEADER_RAW_JSON =
%s
    ;

inline constexpr const char* MINER_DATA_RAW_JSON =
%s
    ;

// --- chain rows -------------------------------------------------------------
struct GoldenHeader {
    std::uint64_t height;
    const char*   hash;
    const char*   prev_hash;
    std::uint64_t timestamp;
    std::uint64_t difficulty_lo;
    std::uint64_t difficulty_hi;
    std::uint64_t cumulative_difficulty_lo;
    std::uint64_t cumulative_difficulty_hi;
    std::uint64_t reward;
    std::uint64_t block_weight;
    std::uint64_t long_term_weight;
    std::uint8_t  major_version;
    std::uint8_t  minor_version;
    std::uint64_t num_txes;
};
''' % (len(steady) + len(epoch), info["version"], info["nettype"], last["height"],
       ((last["height"] - SEED_LAG) // EPOCH) * EPOCH,
       info["version"], info["nettype"],
       info["height"], info["top_block_hash"],
       info["cumulative_difficulty"], info.get("cumulative_difficulty_top64", 0),
       info["difficulty"], info.get("difficulty_top64", 0),
       "true" if info.get("synchronized") else "false",
       last["height"], last["hash"], last["prev_hash"], last["timestamp"],
       last["reward"], last["block_weight"], last["long_term_weight"],
       last["major_version"],
       md["height"], md["prev_id"], md["seed_hash"],
       int(md["difficulty"], 16) & ((1 << 64) - 1), int(md["difficulty"], 16) >> 64,
       md["median_weight"], md["already_generated_coins"], md["major_version"],
       seed1["height"], seed1["hash"], seed0["height"], seed0["hash"],
       ((last["height"] - SEED_LAG) // EPOCH) * EPOCH,
       c_string(compact(d["INFO"])),
       c_string(compact(d["LASTHDR"])),
       c_string(compact(d["MINERDATA"]))))

    body.append(rows_block("STEADY", steady))
    body.append("")
    body.append(rows_block("EPOCH_WINDOW", epoch))
    body.append("")
    body.append("} // namespace c2pool::xmr::native::golden_c6")
    body.append("")

    text = "\n".join(body)
    with open(a.out, "w") as f:
        f.write(text)
    print("wrote %s (%d bytes, %d steady rows, %d epoch rows)"
          % (a.out, len(text), len(steady), len(epoch)), file=sys.stderr)


if __name__ == "__main__":
    main()
