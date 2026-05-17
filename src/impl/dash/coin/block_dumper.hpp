#pragma once

/// Block-replay regression test harness — Phase 1 dumper.
///
/// Connects to a trusted dashd via JSON-RPC and dumps N blocks as
/// JSON fixtures to disk. Each fixture file captures everything the
/// replay test needs to assert bit-exact formula correctness:
///   - block hex (verbosity=0 raw)
///   - getblock verbosity=2 JSON (decoded coinbase outputs, tx details,
///     cb_tx extraPayload fields)
///   - height + block hash
///
/// One file per block: `<out_dir>/h<HEIGHT>.json`. Pre-existing files
/// are skipped (idempotent — safe to re-run after RPC outage).
///
/// Design doc: frstrtr/the/docs/c2pool-dash-block-replay-test-harness.md
///
/// Usage from main_dash:
///   dash::coin::BlockDumper dumper{rpc, out_dir, heights};
///   dumper.run();   // walks heights, writes files, logs progress

#include <impl/dash/coin/rpc.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace dash {
namespace coin {

struct BlockDumper {
    NodeRPC&             rpc;
    std::string          out_dir;
    std::vector<int>     heights;   // explicit list — caller picks coverage

    // Returns number of blocks successfully written. Skips heights that
    // already have a file on disk (re-runnable after failure).
    int run()
    {
        std::filesystem::create_directories(out_dir);

        int written = 0;
        int skipped = 0;
        int failed  = 0;
        for (size_t i = 0; i < heights.size(); ++i) {
            int h = heights[i];
            std::string path = out_dir + "/h" + std::to_string(h) + ".json";

            if (std::filesystem::exists(path)) {
                ++skipped;
                continue;
            }

            try {
                nlohmann::json hash_resp = rpc.getblockhash(h);
                if (!hash_resp.is_string()) {
                    LOG_WARNING << "[BLOCK-DUMP] h=" << h
                                << " getblockhash returned non-string";
                    ++failed;
                    continue;
                }
                std::string hash_hex = hash_resp.get<std::string>();
                uint256 hash;
                hash.SetHex(hash_hex);

                // Two RPC calls: verbosity=0 gives raw hex (for c2pool's
                // parser), verbosity=2 gives the decoded JSON (for ground
                // truth: coinbase vouts, cb_tx fields, payee addresses).
                nlohmann::json block_hex     = rpc.getblock(hash, 0);
                nlohmann::json block_verbose = rpc.getblock(hash, 2);

                nlohmann::json fixture = {
                    {"height",        h},
                    {"block_hash",    hash_hex},
                    {"block_hex",     block_hex},
                    {"block_verbose", block_verbose},
                };

                std::ofstream out(path);
                out << fixture.dump(2);
                ++written;

                if ((written + skipped) % 10 == 0 || i + 1 == heights.size()) {
                    LOG_INFO << "[BLOCK-DUMP] progress: "
                             << (i + 1) << "/" << heights.size()
                             << " (written=" << written
                             << " skipped=" << skipped
                             << " failed=" << failed << ")";
                }
            } catch (const std::exception& e) {
                LOG_WARNING << "[BLOCK-DUMP] h=" << h
                            << " failed: " << e.what();
                ++failed;
            }
        }

        LOG_INFO << "[BLOCK-DUMP] complete: written=" << written
                 << " skipped=" << skipped
                 << " failed=" << failed
                 << " out_dir=" << out_dir;
        return written;
    }
};

/// Produce the canonical 100-block fixture selection from the design doc.
/// Heights chosen to span: V20 boundary, MN_RR boundary, superblocks,
/// halvings, broad recent regression coverage, recent tip.
///
/// `tip_height` should be the current chain tip (from getblockchaininfo)
/// — the "recent tip" portion is anchored to it. Pass `recent_tip=true`
/// to include tip-relative heights; `false` if tip blocks aren't desired
/// (e.g. for offline replay against an older snapshot).
inline std::vector<int> canonical_fixture_heights(int tip_height)
{
    std::vector<int> hs;

    // 5 blocks straddling V20 activation (h=1,987,776 mainnet)
    for (int delta : {-1, 0, 1, 24, 224}) hs.push_back(1'987'776 + delta);

    // 5 blocks straddling MN_RR activation (h=2,128,896 — Bug 15 boundary)
    for (int delta : {-1, 0, 1, 4, 104}) hs.push_back(2'128'896 + delta);

    // 5 superblock heights post-MN_RR (cycle=16,616)
    for (int n : {129, 130, 131, 140, 145}) hs.push_back(n * 16'616);

    // 5 halving-boundary blocks near recent tip
    for (int n : {10, 11, 12}) {
        int h = n * 210'240;
        if (h < tip_height) {
            hs.push_back(h - 1);
            hs.push_back(h);
        }
    }

    // 20 random-spread blocks across post-MN_RR mainnet
    for (int i = 0; i < 20; ++i) {
        hs.push_back(2'200'000 + i * 11'000);  // every ~11k blocks
    }

    // 20 recent-tip blocks (last 20 if tip is set)
    if (tip_height > 0) {
        for (int i = 20; i > 0; --i) hs.push_back(tip_height - i);
    }

    // 20 blocks at known interesting heights — Bug discovery anchors
    // (Bug 15 caught here, plus padding for future-Bug anchors)
    for (int h : {
        2'460'249,   // first DMN snapshot block (mn_snapshot.hpp pin)
        2'463'018,   // Bug 12 PoSe-ban height
        2'462'994,   // Bug 13 CProUpServTx parse failure block
        2'465'346,   // Bug 14 implicit-revive height
        2'465'862,   // Bug 14 snapshot pin
        2'470'904,   // Bug 15 platform-reward verification block
        2'470'890,   // Bug-15 recovery snapshot block
    }) {
        hs.push_back(h);
    }

    // De-dup + sort + drop out-of-range
    std::sort(hs.begin(), hs.end());
    hs.erase(std::unique(hs.begin(), hs.end()), hs.end());
    if (tip_height > 0) {
        hs.erase(std::remove_if(hs.begin(), hs.end(),
                                [tip_height](int h) { return h > tip_height; }),
                 hs.end());
    }

    return hs;
}

} // namespace coin
} // namespace dash
