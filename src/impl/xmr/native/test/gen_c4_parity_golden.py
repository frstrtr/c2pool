#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
#
# Regenerates src/impl/xmr/native/test/xmr_c4_parity_golden.hpp from ONE capture
# taken off a synced, READ-ONLY monerod (stagenet). This script never talks to a
# daemon; the capture step is separate (tools/xmr-c4-parity/capture_miner_data.py)
# so regenerating the golden never touches the network.
#
# WHAT THE CAPTURE CONTAINS, and why each part is there:
#
#   miner_data_raw   the WHOLE get_miner_data JSON-RPC response, verbatim. It is
#                    embedded as a string so the KAT can replay it through the
#                    real MoneroDaemonRpc::parse_miner_data over a fake
#                    transport -- that is the monerod arm under test, not a
#                    re-typed struct that could quietly disagree with the parser.
#                    (Note the daemon returns `difficulty` as the HEX STRING
#                    "0x...", which is exactly the shape PR #1529 fixed.)
#   headers          get_block_headers_range over [FIRST .. tip], the rows the
#                    native chain state is rolled forward with. FIRST is the
#                    C2a golden's TEST_FIRST, so the 100 000-entry long-term
#                    weight window can be seeded from that golden's captured
#                    window and rolled to this capture's tip. Every number in a
#                    row is monerod's own.
#   tip id / seed id the block ids the native arm must reproduce as prev_id and
#                    seed_hash. The seed id is the block at rx_seedheight(H).
#
# The parity claim this golden supports: given the same chain rows, the native
# template source derives the SAME seven get_miner_data fields the daemon
# reported at the same height. A formula error cannot pass by agreeing with
# itself, because no field below was computed by this repository.
import json, sys


def main():
    cap = json.load(open(sys.argv[1]))
    out_path = sys.argv[2]

    md = cap["miner_data_raw"]
    res = md["result"]
    hdrs = cap["headers"]
    info = cap["info"]

    height = int(res["height"])                 # the block being mined = tip + 1
    tip_h = height - 1
    assert hdrs[-1]["height"] == tip_h, "capture tip moved during the header walk"

    # rx_seedheight(H): SEEDHASH_EPOCH_BLOCKS = 2048, SEEDHASH_EPOCH_LAG = 64.
    def rx_seedheight(h):
        if h <= 2048 + 64:
            return 0
        return (h - 64 - 1) & ~(2048 - 1)

    seed_h = rx_seedheight(height)
    seed_row = next((r for r in hdrs if r["height"] == seed_h), None)
    assert seed_row is not None, "seed height %d not in the captured header range" % seed_h
    assert seed_row["hash"] == res["seed_hash"], "captured seed id != get_miner_data.seed_hash"

    diff = res["difficulty"]
    diff_lo = int(diff, 16) if isinstance(diff, str) else int(diff)
    diff_hi = int(res.get("difficulty_top64", 0))

    raw = json.dumps(md, separators=(",", ":"), sort_keys=True)

    L = []
    a = L.append
    a("// SPDX-License-Identifier: AGPL-3.0-or-later")
    a("// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)")
    a("//")
    a("// ---------------------------------------------------------------------------")
    a("// src/impl/xmr/native/test/xmr_c4_parity_golden.hpp   -- GENERATED, DO NOT EDIT")
    a("//")
    a("// C4 template-parity golden: one real get_miner_data captured from a synced")
    a("// stagenet daemon, together with the chain rows below it that the native")
    a("// template source must reproduce it from.")
    a("//")
    a("//   source daemon : monerod %s (%s)" % (info.get("version", "?"), info.get("nettype", "?")))
    a("//   captured tip  : %d   (get_miner_data.height = %d)" % (tip_h, height))
    a("//   regenerate    : src/impl/xmr/native/test/gen_c4_parity_golden.py")
    a("//")
    a("// The long-term weight window is NOT re-captured here: it is seeded from")
    a("// xmr_c2a_golden.hpp (whose window ends at that golden's TEST_FIRST - 1) and")
    a("// rolled forward with the long_term_weight column below, which is why the")
    a("// header range starts exactly at the C2a golden's TEST_FIRST.")
    a("// ---------------------------------------------------------------------------")
    a("#pragma once")
    a("")
    a("#include <cstdint>")
    a("")
    a("namespace c2pool::xmr::native::golden_c4 {")
    a("")
    a('inline constexpr const char* MONEROD_VERSION = "%s";' % info.get("version", "?"))
    a('inline constexpr const char* NETWORK         = "%s";' % info.get("nettype", "?"))
    a("")
    a("// --- the get_miner_data the native arm is judged against ------------------")
    a("inline constexpr std::uint64_t MD_HEIGHT        = %dull;   // tip + 1" % height)
    a('inline constexpr const char*   MD_PREV_ID       = "%s";' % res["prev_id"])
    a('inline constexpr const char*   MD_SEED_HASH     = "%s";' % res["seed_hash"])
    a("inline constexpr std::uint64_t MD_DIFFICULTY_LO = %dull;" % diff_lo)
    a("inline constexpr std::uint64_t MD_DIFFICULTY_HI = %dull;" % diff_hi)
    a("inline constexpr std::uint64_t MD_MEDIAN_WEIGHT = %dull;" % int(res["median_weight"]))
    a("inline constexpr std::uint64_t MD_ALREADY_GENERATED_COINS = %dull;" % int(res["already_generated_coins"]))
    a("inline constexpr std::uint8_t  MD_MAJOR_VERSION = %d;" % int(res["major_version"]))
    a("inline constexpr std::size_t   MD_TX_BACKLOG_COUNT = %d;" % len(res.get("tx_backlog", []) or []))
    a("")
    a("// The RandomX seed block: rx_seedheight(MD_HEIGHT) and the id monerod")
    a("// reported for it. Equality with MD_SEED_HASH is checked by the generator.")
    a("inline constexpr std::uint64_t SEED_HEIGHT = %dull;" % seed_h)
    a("")
    a("// The VERBATIM JSON-RPC response body, replayed through the real parser so")
    a("// the monerod arm under test is the production decode path, hex difficulty")
    a("// string and all.")
    a("inline constexpr const char* MD_RAW_JSON =")
    for i in range(0, len(raw), 90):
        chunk = raw[i:i + 90].replace("\\", "\\\\").replace('"', '\\"')
        a('    "%s"' % chunk)
    a("    ;")
    a("")
    a("// --- chain rows: [FIRST .. tip], monerod's own numbers ---------------------")
    a("struct GoldenRow {")
    a("    std::uint64_t height;")
    a("    std::uint8_t  major_version;")
    a("    std::uint8_t  minor_version;")
    a("    std::uint64_t timestamp;")
    a("    std::uint64_t difficulty_lo;")
    a("    std::uint64_t difficulty_hi;")
    a("    std::uint64_t cumulative_difficulty_lo;")
    a("    std::uint64_t cumulative_difficulty_hi;")
    a("    std::uint64_t block_weight;")
    a("    std::uint64_t long_term_weight;")
    a("    std::uint64_t reward;")
    a("};")
    a("")
    a("inline constexpr std::uint64_t ROWS_FIRST_HEIGHT = %dull;" % hdrs[0]["height"])
    a("inline constexpr std::uint64_t ROWS_LAST_HEIGHT  = %dull;" % hdrs[-1]["height"])
    a("inline constexpr GoldenRow ROWS[] = {")
    for r in hdrs:
        a("    { %d, %d, %d, %d, %dull, %dull, %dull, %dull, %d, %d, %dull }," % (
            r["height"], r["major_version"], r["minor_version"], r["timestamp"],
            int(r["difficulty"]), int(r.get("difficulty_top64", 0)),
            int(r["cumulative_difficulty"]), int(r.get("cumulative_difficulty_top64", 0)),
            r["block_weight"], r["long_term_weight"], int(r["reward"])))
    a("};")
    a("inline constexpr std::size_t ROWS_COUNT = sizeof(ROWS) / sizeof(ROWS[0]);")
    a("")
    a("// The two block ids the native arm has to answer with: the tip (prev_id of")
    a("// the block being mined) and the RandomX seed block.")
    a('inline constexpr const char* TIP_ID  = "%s";' % hdrs[-1]["hash"])
    a('inline constexpr const char* SEED_ID = "%s";' % seed_row["hash"])
    a("")
    a("} // namespace c2pool::xmr::native::golden_c4")
    a("")
    open(out_path, "w").write("\n".join(L))
    print("wrote %s: %d rows, height %d" % (out_path, len(hdrs), height), file=sys.stderr)


if __name__ == "__main__":
    main()
