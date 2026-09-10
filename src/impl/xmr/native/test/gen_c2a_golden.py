#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
#
# Regenerates src/impl/xmr/native/test/xmr_c2a_golden.hpp from captures taken
# off a SYNCED, READ-ONLY monerod (stagenet). Nothing here talks to a daemon:
# the capture step is separate and paced (see CAPTURE below), so regenerating
# the golden never touches the network.
#
# CAPTURE (what the three inputs are, and the RPC that produced them):
#
#   headers.json    get_block_headers_range over [TEST_FIRST - 735, ...], in
#                   200-header pages: height, major/minor version, timestamp,
#                   difficulty(+top64), cumulative_difficulty(+top64),
#                   block_weight, long_term_weight, reward, num_txes.
#   lt_prefix.json  the same call over the 1500 heights immediately BELOW the
#                   100 000-block long-term window, so the window can be rolled
#                   forward with the exact values that leave it.
#   blocks.json     get_block(height) for a handful of heights inside the test
#                   range: the raw block blob, monerod's block id, its
#                   miner_tx_hash and its tx_hashes.
#   sums.json       get_coinbase_tx_sum(0, TEST_FIRST) and (0, TEST_LAST + 1):
#                   already_generated_coins at both ends of the replay.
#
# WHAT IS INDEPENDENT ABOUT THIS GOLDEN. Every number the KAT compares against
# is one monerod computed and this repository did not: the per-height
# difficulty, the per-height long_term_weight, the per-height reward, the block
# ids, and the emission totals at both ends of the run. A formula error here
# cannot pass by agreeing with itself.
import json, sys


def rle(values):
    runs = []
    for v in values:
        if runs and runs[-1][0] == v:
            runs[-1][1] += 1
        else:
            runs.append([v, 1])
    return runs


def main():
    cap = json.load(open(sys.argv[1]))       # headers + long_term + miner_data
    pre = json.load(open(sys.argv[2]))       # long-term prefix rows
    blocks = json.load(open(sys.argv[3]))    # full block blobs
    sums = json.load(open(sys.argv[4]))      # coinbase sums
    out_path = sys.argv[5]

    TEST_FIRST = int(sys.argv[6])
    TEST_COUNT = int(sys.argv[7])
    TEST_LAST = TEST_FIRST + TEST_COUNT - 1

    H = {r[0]: r for r in cap["headers"]}
    LT = {r[0]: r[2] for r in pre}
    for r in cap["long_term"]:
        LT[r[0]] = r[2]

    hdr_first = TEST_FIRST - 735
    headers = [H[h] for h in range(hdr_first, TEST_LAST + 1)]

    lt_window = [LT[h] for h in range(TEST_FIRST - 100000, TEST_FIRST)]
    head = lt_window[:TEST_COUNT]            # these leave during the replay
    tail_runs = rle(lt_window[TEST_COUNT:])  # these never leave; order is free

    md = cap["miner_data"]
    agc_first = int(sums[str(TEST_FIRST)]["emission"])
    agc_last = int(sums[str(TEST_LAST + 1)]["emission"])

    L = []
    w = L.append
    w("// SPDX-License-Identifier: AGPL-3.0-or-later")
    w("// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)")
    w("//")
    w("// ---------------------------------------------------------------------------")
    w("// src/impl/xmr/native/test/xmr_c2a_golden.hpp   -- GENERATED, DO NOT EDIT")
    w("//")
    w("// Consensus-state goldens for the C2a KAT, captured from a synced stagenet")
    w("// daemon. Every value below is monerod's own, not this repository's:")
    w("// difficulty, long_term_weight and reward per height, the block ids, and")
    w("// already_generated_coins at both ends of the replay.")
    w("//")
    w("//   source daemon : monerod %s (%s)" % (cap["monerod_version"], cap["nettype"]))
    w("//   captured tip  : %d" % cap["captured_tip"])
    w("//   regenerate    : src/impl/xmr/native/test/gen_c2a_golden.py")
    w("// ---------------------------------------------------------------------------")
    w("#pragma once")
    w("")
    w("#include <cstdint>")
    w("")
    w("namespace c2pool::xmr::native::golden_c2a {")
    w("")
    w('inline constexpr const char* MONEROD_VERSION = "%s";' % cap["monerod_version"])
    w('inline constexpr const char* NETWORK        = "%s";' % cap["nettype"])
    w("inline constexpr std::uint64_t CAPTURE_TIP  = %d;" % cap["captured_tip"])
    w("")
    w("// The replay range: TEST_COUNT consecutive heights, each re-derived from the")
    w("// windows that end at its parent.")
    w("inline constexpr std::uint64_t TEST_FIRST = %d;" % TEST_FIRST)
    w("inline constexpr std::uint64_t TEST_COUNT = %d;" % TEST_COUNT)
    w("inline constexpr std::uint64_t TEST_LAST  = %d;" % TEST_LAST)
    w("")
    w("// already_generated_coins from get_coinbase_tx_sum: before TEST_FIRST and")
    w("// after TEST_LAST. The replay must walk exactly from one to the other.")
    w("inline constexpr std::uint64_t AGC_BEFORE_FIRST = %dull;" % agc_first)
    w("inline constexpr std::uint64_t AGC_AFTER_LAST   = %dull;" % agc_last)
    w("")
    w("// get_miner_data at the captured tip, for the template-input pins.")
    w("inline constexpr std::uint64_t MINER_DATA_HEIGHT        = %d;" % md["height"])
    w("inline constexpr std::uint64_t MINER_DATA_MEDIAN_WEIGHT = %d;" % md["median_weight"])
    w("inline constexpr std::uint64_t MINER_DATA_AGC           = %dull;" % md["already_generated_coins"])
    w('inline constexpr const char*   MINER_DATA_SEED_HASH     = "%s";' % md["seed_hash"])
    w("inline constexpr std::uint8_t  MINER_DATA_MAJOR_VERSION = %d;" % md["major_version"])
    w("")
    w("// One row per height, oldest first, starting 735 heights below TEST_FIRST so")
    w("// the first replayed height has a full difficulty window.")
    w("struct GoldenHeader {")
    w("    std::uint64_t height;")
    w("    std::uint8_t  major_version;")
    w("    std::uint8_t  minor_version;")
    w("    std::uint64_t timestamp;")
    w("    std::uint64_t difficulty_lo;")
    w("    std::uint64_t difficulty_hi;")
    w("    std::uint64_t cumulative_difficulty_lo;")
    w("    std::uint64_t cumulative_difficulty_hi;")
    w("    std::uint64_t block_weight;")
    w("    std::uint64_t long_term_weight;")
    w("    std::uint64_t reward;")
    w("    std::uint32_t num_txes;")
    w("};")
    w("")
    w("inline constexpr std::uint64_t HEADERS_FIRST_HEIGHT = %d;" % hdr_first)
    w("inline constexpr GoldenHeader HEADERS[] = {")
    for r in headers:
        w("    { %d, %d, %d, %d, %dull, %dull, %dull, %dull, %d, %d, %dull, %d },"
          % (r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11]))
    w("};")
    w("inline constexpr std::size_t HEADERS_COUNT = sizeof(HEADERS) / sizeof(HEADERS[0]);")
    w("")
    w("// The 100 000-entry long-term weight window as it stands just before")
    w("// TEST_FIRST, in two pieces. LT_SEED_HEAD is the OLDEST TEST_COUNT values in")
    w("// chronological order -- exactly the ones the replay pushes out of the window,")
    w("// so their order is load-bearing. LT_SEED_TAIL_RUNS is the rest, run-length")
    w("// encoded: none of them leaves during the replay, and a median does not care")
    w("// in what order a multiset was inserted.")
    w("inline constexpr std::uint64_t LT_WINDOW_SIZE = 100000;")
    w("inline constexpr std::uint64_t LT_SEED_HEAD[] = {")
    for i in range(0, len(head), 12):
        w("    " + " ".join("%d," % v for v in head[i:i + 12]))
    w("};")
    w("inline constexpr std::size_t LT_SEED_HEAD_COUNT = sizeof(LT_SEED_HEAD) / sizeof(LT_SEED_HEAD[0]);")
    w("")
    w("struct GoldenRun { std::uint64_t value; std::uint64_t count; };")
    w("inline constexpr GoldenRun LT_SEED_TAIL_RUNS[] = {")
    for v, c in tail_runs:
        w("    { %d, %d }," % (v, c))
    w("};")
    w("inline constexpr std::size_t LT_SEED_TAIL_RUNS_COUNT ="
      " sizeof(LT_SEED_TAIL_RUNS) / sizeof(LT_SEED_TAIL_RUNS[0]);")
    w("")
    w("// Whole blocks from inside the replay range: the raw blob a peer would send,")
    w("// with the identity monerod reports for it.")
    w("struct GoldenBlock {")
    w("    std::uint64_t height;")
    w("    const char*   blob_hex;")
    w("    const char*   id_hex;")
    w("    const char*   miner_tx_hash_hex;")
    w("    std::uint32_t num_txes;")
    w("    std::uint64_t block_weight;")
    w("    std::uint64_t reward;")
    w("    std::uint64_t timestamp;")
    w("};")
    w("")
    w("inline constexpr GoldenBlock BLOCKS[] = {")
    for b in sorted(blocks, key=lambda x: x["height"]):
        w('    { %d, "%s",\n      "%s",\n      "%s", %d, %d, %dull, %d },'
          % (b["height"], b["blob"], b["hash"], b["miner_tx_hash"],
             b["num_txes"], b["block_weight"], b["reward"], b["timestamp"]))
    w("};")
    w("inline constexpr std::size_t BLOCKS_COUNT = sizeof(BLOCKS) / sizeof(BLOCKS[0]);")
    w("")
    w("} // namespace c2pool::xmr::native::golden_c2a")
    w("")

    open(out_path, "w").write("\n".join(L))
    print("wrote", out_path, "headers", len(headers), "lt_head", len(head),
          "lt_runs", len(tail_runs), "blocks", len(blocks))


main()
