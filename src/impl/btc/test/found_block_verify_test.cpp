// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// BTC found-block wiring + verdict KAT (#995/#1155 BTC arm).
//
// Two halves, both pinned here, folded into the EXISTING allowlisted
// btc_share_test GTest target (a NEW add_executable would silently report
// "Not Run" -- see merged PR #868 / the sibling CMake note):
//
//   A) WIRING (the #1155 defect). On master, main_btc.cpp's live won-block
//      dispatch (btc::coin::make_on_block_found, installed as
//      ShareTracker::m_on_block_found) reconstructs + broadcasts a won block but
//      NEVER fires a found-block reporter -- so record_found_block /
//      schedule_block_verification are never reached and the submit path records
//      NOTHING. This KAT drives make_on_block_found with a recording sink (the
//      exact seam main_btc binds to record_found_block) and asserts the sink
//      fires once with the reconstructed block bytes, STRICTLY AFTER the
//      broadcast arms. RED on master (0 records), GREEN after (1 record).
//
//   B) VERDICT. btc::coin::block_confirm::resolve_status -- the confirm/orphan
//      logic wired into MiningInterface::set_block_verify_fn -- pinned across all
//      branches (confirmed / shallow-pending / exact-depth / orphaned /
//      not-indexed / tip-behind), matching the core verify_found_block contract
//      (>0 confirmed / <0 orphaned / 0 pending).
// ---------------------------------------------------------------------------
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <core/uint256.hpp>
#include "../coin/block_confirm.hpp"
#include "../coin/won_block_dispatch.hpp"

namespace {

uint256 mk(const char* hex) { uint256 h; h.SetHex(hex); return h; }

// A best-chain oracle: height -> winning block hash. Absent height => nullopt
// (we have not yet reached/indexed it), matching HeaderChain::get_header_by_height.
struct BestChain {
    std::map<uint32_t, uint256> by_height;
    std::optional<uint256> operator()(uint32_t h) const {
        auto it = by_height.find(h);
        if (it == by_height.end()) return std::nullopt;
        return it->second;
    }
};

} // namespace

// === A) WIRING: the live won-block dispatch fires the found-block reporter ===
//
// This is the #1155 defect made testable. main_btc.cpp binds a found-block
// reporter (record_found_block + schedule_block_verification) to
// make_on_block_found's on_found sink. If that sink is not wired/fired, a won
// BTC block broadcasts but the submit path records NOTHING.

TEST(BtcFoundBlockWire, OnFoundFiresOnceWithReconstructedBlock)
{
    // A reconstructable won block: >= 80 bytes so it carries an 80-byte header
    // (the block-identity key on BTC == SHA256d(header)).
    const std::vector<unsigned char> block(90, 0x11);
    const std::string                hex = "1100";
    const uint256                    share = mk(
        "00000000000000000000000000000000000000000000000000000000000000aa");

    auto reconstruct = [&](const uint256&)
        -> std::optional<std::pair<std::vector<unsigned char>, std::string>> {
        return std::make_pair(block, hex);
    };

    // Recording sink -- the exact seam main_btc binds to record_found_block.
    int                        records = 0;
    uint256                    got_share;
    std::vector<unsigned char> got_bytes;
    bool                       broadcast_ran_before_record = false;
    bool                       relay_fired = false;

    auto on_found = [&](const uint256& sh,
                        const std::vector<unsigned char>& b,
                        const std::string& /*h*/) {
        ++records;
        got_share = sh;
        got_bytes = b;
        broadcast_ran_before_record = relay_fired;  // record must be downstream
    };

    auto handler = btc::coin::make_on_block_found(
        /*reconstruct=*/reconstruct,
        /*relay_p2p=*/[&](const std::vector<unsigned char>&) { relay_fired = true; return true; },
        /*submit_rpc=*/btc::coin::SubmitRpcSink{},
        /*on_found=*/on_found);

    handler(share);

    // RED on master (make_on_block_found never fires a reporter) => records == 0.
    EXPECT_EQ(records, 1) << "won-block submit path recorded nothing";
    EXPECT_EQ(got_share, share);
    EXPECT_EQ(got_bytes, block);
    // Telemetry-only contract: the reporter runs strictly AFTER the broadcast.
    EXPECT_TRUE(broadcast_ran_before_record);
}

TEST(BtcFoundBlockWire, UnreconstructableShareRecordsNothing)
{
    // A share that cannot be reconstructed must NOT be recorded (no fabricated
    // block reaches the dashboard) -- and must not crash the dispatch.
    int records = 0;
    auto handler = btc::coin::make_on_block_found(
        /*reconstruct=*/[](const uint256&)
            -> std::optional<std::pair<std::vector<unsigned char>, std::string>> {
            return std::nullopt;  // unknown / unassemblable share
        },
        /*relay_p2p=*/btc::coin::P2pRelaySink{},
        /*submit_rpc=*/btc::coin::SubmitRpcSink{},
        /*on_found=*/[&](const uint256&, const std::vector<unsigned char>&,
                         const std::string&) { ++records; });
    handler(mk("00000000000000000000000000000000000000000000000000000000000000bb"));
    EXPECT_EQ(records, 0);
}

TEST(BtcFoundBlockWire, EmptyReporterIsAHarmlessNoOp)
{
    // No dashboard bound (--http absent): a won block still broadcasts, it is
    // simply not recorded. An unset on_found must not crash.
    const std::vector<unsigned char> block(90, 0x22);
    bool reached_neither_crash = false;
    auto handler = btc::coin::make_on_block_found(
        [&](const uint256&)
            -> std::optional<std::pair<std::vector<unsigned char>, std::string>> {
            return std::make_pair(block, std::string("2200"));
        },
        /*relay_p2p=*/[](const std::vector<unsigned char>&) { return true; },
        /*submit_rpc=*/btc::coin::SubmitRpcSink{},
        /*on_found=*/btc::coin::FoundBlockReporter{});  // empty
    handler(mk("00000000000000000000000000000000000000000000000000000000000000cc"));
    (void)reached_neither_crash;
    SUCCEED();
}

// === B) VERDICT: resolve_status confirm/orphan/pending contract ===

TEST(BtcFoundBlockVerdict, DepthConstantIsSix)
{
    EXPECT_EQ(btc::coin::block_confirm::kDefaultConfirmDepth, 6u);
}

TEST(BtcFoundBlockVerdict, ConfirmedWhenBuriedAtOrPastDepth)
{
    using btc::coin::block_confirm::resolve_status;
    using btc::coin::block_confirm::kDefaultConfirmDepth;
    const uint256  WON = mk("00000000000000000000000000000000000000000000000000000000000000aa");
    const uint32_t H   = 800000;

    BestChain chain; chain.by_height[H] = WON;
    // tip = H+5 -> confs = 6 == depth -> confirmed (returns the conf count)
    int v = resolve_status(chain, /*tip=*/H + 5, WON, /*found=*/H);
    EXPECT_GT(v, 0);
    EXPECT_EQ(v, static_cast<int>(kDefaultConfirmDepth));

    // tip = H+6 -> confs = 7 > depth -> still confirmed
    EXPECT_EQ(resolve_status(chain, H + 6, WON, H), 7);
}

TEST(BtcFoundBlockVerdict, ShallowInChainIsPending)
{
    using btc::coin::block_confirm::resolve_status;
    const uint256  WON = mk("00000000000000000000000000000000000000000000000000000000000000aa");
    const uint32_t H   = 800000;
    BestChain chain; chain.by_height[H] = WON;
    // tip = H+2 -> confs = 3 < 6 -> pending
    EXPECT_EQ(resolve_status(chain, H + 2, WON, H), 0);
}

TEST(BtcFoundBlockVerdict, DifferentBlockAtHeightIsOrphaned)
{
    using btc::coin::block_confirm::resolve_status;
    const uint256  WON   = mk("00000000000000000000000000000000000000000000000000000000000000aa");
    const uint256  OTHER = mk("00000000000000000000000000000000000000000000000000000000000000bb");
    const uint32_t H     = 800000;
    BestChain chain; chain.by_height[H] = OTHER;
    EXPECT_EQ(resolve_status(chain, H + 100, WON, H), -1);
}

TEST(BtcFoundBlockVerdict, NotYetIndexedOrTipBehindIsPending)
{
    using btc::coin::block_confirm::resolve_status;
    const uint256  WON = mk("00000000000000000000000000000000000000000000000000000000000000aa");
    const uint32_t H   = 800000;

    // 5a) height not yet indexed (oracle nullopt) -> pending
    BestChain empty;
    EXPECT_EQ(resolve_status(empty, H - 5, WON, H), 0);

    // 5b) in chain but tip behind found_height (reorg) -> pending
    BestChain chain; chain.by_height[H] = WON;
    EXPECT_EQ(resolve_status(chain, H - 1, WON, H), 0);
}

TEST(BtcFoundBlockVerdict, ThreeSignClassesAreDistinct)
{
    using btc::coin::block_confirm::resolve_status;
    const uint256  WON   = mk("00000000000000000000000000000000000000000000000000000000000000aa");
    const uint256  OTHER = mk("00000000000000000000000000000000000000000000000000000000000000bb");
    const uint32_t H     = 800000;
    BestChain confirmed; confirmed.by_height[H] = WON;
    BestChain orphaned;  orphaned.by_height[H]  = OTHER;
    BestChain pending;   // empty
    EXPECT_GT(resolve_status(confirmed, H + 10, WON, H), 0);
    EXPECT_LT(resolve_status(orphaned,  H + 10, WON, H), 0);
    EXPECT_EQ(resolve_status(pending,   H + 10, WON, H), 0);
}
