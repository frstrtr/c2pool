// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DASH post-broadcast found-block confirmation / orphan lane.
//
// THE GAP (on master). DASH wired NONE of the confirmation seam —
// main_dash.cpp calls neither set_block_verify_fn nor
// schedule_block_verification (LTC wires both). So a DASH found block sat
// "pending" on the dashboard forever and orphans (e.g. hotel block 2508008)
// were discovered by humans, not the board. NoVerifierLeavesPending below is
// the master baseline: with no verifier armed, a recorded block never leaves
// pending no matter how many verification passes run.
//
// THE FIX. main_dash arms set_block_verify_fn with the daemonless verdict
// dash::coin::block_confirm::resolve_status (embedded X11+DGW header chain:
// "which hash won height h?" vs our recorded block), plus a dashd
// getblockheader fallback, and calls schedule_block_verification on both
// found-block record paths. These tests exercise:
//   1. resolve_status — the pure daemonless verdict (confirmed / orphaned /
//      pending), including a reorg that flips a competitor back to our block.
//   2. The MiningInterface status flip driven by that exact resolver through
//      the REAL verify_found_block transition code (via the synchronous
//      run_block_verification_now seam) — pending→confirmed, pending→orphaned.
//
// TELEMETRY ONLY. Nothing here touches submit / mint / target / payout.

#include <gtest/gtest.h>

#include <impl/dash/coin/block_confirm.hpp>
#include <core/web_server.hpp>
#include <core/uint256.hpp>
#include <core/address_validator.hpp>   // Blockchain

#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <string>

namespace {

// Distinct, deterministic block identities (SetHex like the sibling TU).
uint256 blk_hash(unsigned char b)
{
    static const char* digits = "0123456789abcdef";
    std::string s = "22";
    s += digits[b >> 4];
    s += digits[b & 0x0f];
    s += std::string(64 - s.size(), '0');
    uint256 h;
    h.SetHex(s);
    return h;
}

constexpr uint32_t kHeight   = 2508008;      // the real hotel orphan height
constexpr uint32_t kTime     = 1753000000;
constexpr uint64_t kSubsidy  = 155000000;

// A fake best-chain view: hash on the best chain at each height, plus a tip.
struct FakeChain {
    std::map<uint32_t, uint256> best;   // height -> winning hash
    uint32_t tip_height{0};

    std::optional<uint256> winner_at(uint32_t h) const {
        auto it = best.find(h);
        if (it == best.end()) return std::nullopt;
        return it->second;
    }
};

// ── 1. Pure daemonless verdict ──────────────────────────────────────────────

TEST(DashBlockConfirmLane, PendingWhenChainHasNotReachedHeight)
{
    FakeChain c;                         // empty — chain has not reached kHeight
    c.tip_height = kHeight - 3;
    const uint256 ours = blk_hash(0x01);
    EXPECT_EQ(0, dash::coin::block_confirm::resolve_status(
                     [&](uint32_t h){ return c.winner_at(h); },
                     c.tip_height, ours, kHeight));
}

TEST(DashBlockConfirmLane, ConfirmedWhenOnBestChainAtDepth)
{
    FakeChain c;
    const uint256 ours = blk_hash(0x01);
    c.best[kHeight] = ours;              // our block won its height
    c.tip_height    = kHeight + 4;       // 5 blocks deep
    int v = dash::coin::block_confirm::resolve_status(
                [&](uint32_t h){ return c.winner_at(h); },
                c.tip_height, ours, kHeight);
    EXPECT_GT(v, 0);
    EXPECT_EQ(5, v);                     // tip - height + 1
}

TEST(DashBlockConfirmLane, OrphanedWhenCompetitorWonHeight)
{
    FakeChain c;
    const uint256 ours       = blk_hash(0x01);
    const uint256 competitor = blk_hash(0x02);
    c.best[kHeight] = competitor;        // a DIFFERENT block occupies our height
    c.tip_height    = kHeight + 2;
    EXPECT_EQ(-1, dash::coin::block_confirm::resolve_status(
                      [&](uint32_t h){ return c.winner_at(h); },
                      c.tip_height, ours, kHeight));
}

TEST(DashBlockConfirmLane, HigherConfirmDepthHoldsPendingUntilBuried)
{
    FakeChain c;
    const uint256 ours = blk_hash(0x01);
    c.best[kHeight] = ours;
    c.tip_height    = kHeight;           // only 1 confirmation
    // depth 3 required → still pending at 1 conf
    EXPECT_EQ(0, dash::coin::block_confirm::resolve_status(
                     [&](uint32_t h){ return c.winner_at(h); },
                     c.tip_height, ours, kHeight, /*confirm_depth=*/3));
    c.tip_height = kHeight + 2;          // now 3 confirmations
    EXPECT_EQ(3, dash::coin::block_confirm::resolve_status(
                     [&](uint32_t h){ return c.winner_at(h); },
                     c.tip_height, ours, kHeight, /*confirm_depth=*/3));
}

TEST(DashBlockConfirmLane, ReorgRestoresOurBlockToConfirmed)
{
    FakeChain c;
    const uint256 ours       = blk_hash(0x01);
    const uint256 competitor = blk_hash(0x02);
    // First a competitor is seen at our height → orphaned verdict.
    c.best[kHeight] = competitor;
    c.tip_height    = kHeight;
    EXPECT_EQ(-1, dash::coin::block_confirm::resolve_status(
                      [&](uint32_t h){ return c.winner_at(h); },
                      c.tip_height, ours, kHeight));
    // A deeper reorg puts OUR block back on the best chain.
    c.best[kHeight] = ours;
    c.tip_height    = kHeight + 1;
    EXPECT_GT(dash::coin::block_confirm::resolve_status(
                  [&](uint32_t h){ return c.winner_at(h); },
                  c.tip_height, ours, kHeight), 0);
}

// ── 2. MiningInterface status flip through the REAL transition code ─────────

// Wire a verify fn that resolves against a FakeChain using the SAME resolver
// main_dash arms, then flip status synchronously via run_block_verification_now.
static void arm_verifier(core::MiningInterface& mi, const FakeChain& c)
{
    mi.set_block_verify_fn([&mi, &c](const std::string& hash_hex) -> int {
        uint256 h; h.SetHex(hash_hex);
        uint32_t found_height = 0; bool have = false;
        for (const auto& b : mi.get_found_blocks()) {
            if (b.hash == hash_hex) {
                found_height = static_cast<uint32_t>(b.height);
                have = true; break;
            }
        }
        if (!have) return 0;
        return dash::coin::block_confirm::resolve_status(
            [&c](uint32_t hh){ return c.winner_at(hh); },
            c.tip_height, h, found_height);
    });
}

TEST(DashBlockConfirmLane, NoVerifierLeavesPending)
{
    // MASTER BASELINE: DASH main never armed a verifier, so a recorded found
    // block stays pending across every verification pass.
    core::MiningInterface mi(/*testnet=*/false, nullptr, Blockchain::DASH);
    const uint256 ours = blk_hash(0x01);
    mi.record_found_block(kHeight, ours, kTime, "DASH", "Xminer",
                          ours.GetHex(), 1.0, 0.0, 3.0, kSubsidy);

    EXPECT_EQ(0, mi.run_block_verification_now(ours.GetHex()));
    ASSERT_EQ(mi.get_found_blocks().size(), 1u);
    EXPECT_EQ(mi.get_found_blocks()[0].status,
              core::MiningInterface::BlockStatus::pending)
        << "with no verifier a DASH found block must stay pending (the defect)";
}

TEST(DashBlockConfirmLane, FoundBlockFlipsPendingToConfirmed)
{
    core::MiningInterface mi(/*testnet=*/false, nullptr, Blockchain::DASH);
    const uint256 ours = blk_hash(0x01);
    mi.record_found_block(kHeight, ours, kTime, "DASH", "Xminer",
                          ours.GetHex(), 1.0, 0.0, 3.0, kSubsidy);
    ASSERT_EQ(mi.get_found_blocks()[0].status,
              core::MiningInterface::BlockStatus::pending);

    FakeChain c;
    c.best[kHeight] = ours;              // our block is on the best chain
    c.tip_height    = kHeight + 5;
    arm_verifier(mi, c);

    int v = mi.run_block_verification_now(ours.GetHex());
    EXPECT_GT(v, 0);
    EXPECT_EQ(mi.get_found_blocks()[0].status,
              core::MiningInterface::BlockStatus::confirmed);
    EXPECT_EQ(mi.get_found_blocks()[0].confirmations, 6u);   // tip - h + 1
}

TEST(DashBlockConfirmLane, FoundBlockFlipsPendingToOrphaned)
{
    core::MiningInterface mi(/*testnet=*/false, nullptr, Blockchain::DASH);
    const uint256 ours       = blk_hash(0x01);
    const uint256 competitor = blk_hash(0x02);
    mi.record_found_block(kHeight, ours, kTime, "DASH", "Xminer",
                          ours.GetHex(), 1.0, 0.0, 3.0, kSubsidy);
    ASSERT_EQ(mi.get_found_blocks()[0].status,
              core::MiningInterface::BlockStatus::pending);

    FakeChain c;
    c.best[kHeight] = competitor;        // a different block won our height
    c.tip_height    = kHeight + 2;
    arm_verifier(mi, c);

    int v = mi.run_block_verification_now(ours.GetHex());
    EXPECT_LT(v, 0);
    EXPECT_EQ(mi.get_found_blocks()[0].status,
              core::MiningInterface::BlockStatus::orphaned)
        << "a DASH block replaced at its height must flip to orphaned, not "
           "linger pending as on master";
}

TEST(DashBlockConfirmLane, UnknownHashReportsSentinel)
{
    core::MiningInterface mi(/*testnet=*/false, nullptr, Blockchain::DASH);
    EXPECT_EQ(std::numeric_limits<int>::min(),
              mi.run_block_verification_now(blk_hash(0x09).GetHex()));
}

}  // namespace
