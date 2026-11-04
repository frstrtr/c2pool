// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The dashboard's verdict on a found block (rides share_test): the embedded
// LTC node's parent blocks and its merged DOGE blocks
// (ltc::coin::found_block, wired by main_ltc.cpp into
// MiningInterface::set_block_verify_fn / add_chain_verify_fn: > 0 confirmed,
// < 0 orphaned, 0 pending).
//
// A lost block must read as lost within minutes; a python pool hid two lost
// blocks for months behind "pending" / "confirmed". The verdict is taken at
// the height the found-block record holds, against the best chain:
//   - our block is the best chain's block there: confirmed once 6 deep
//     (tip - height + 1 >= 6), pending before (it can still be reorged out,
//     and a confirmed row is never checked again);
//   - another block is there (or none, while the tip is past it): orphaned
//     once the best chain is 6 blocks deep from that height, pending before
//     (a sibling race can still go our way);
//   - the chain has not reached the height: pending.
// A ChainView over maps stands in for the header chain (best chain by
// height, every known header's height).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include <core/uint256.hpp>
#include <impl/ltc/coin/found_block_verify.hpp>

namespace {

using ltc::coin::found_block::ChainView;
using ltc::coin::found_block::aux_verdict;
using ltc::coin::found_block::parent_verdict;

uint256 h_of(const std::string& tag)
{
    uint256 h;
    h.SetHex(tag);
    return h;
}

/// Best chain at heights [from, to], hashes 0xb<height>; `known` adds side
/// branch headers (hash -> height).
struct Chain {
    std::map<uint32_t, uint256> best;
    std::map<uint256, uint32_t> known;

    void grow(uint32_t from, uint32_t to)
    {
        for (uint32_t h = from; h <= to; ++h) {
            best[h] = h_of("b" + std::to_string(h));
            known[best[h]] = h;
        }
    }
    ChainView view() const
    {
        ChainView v;
        v.height_of = [this](const uint256& hh) -> std::optional<uint32_t> {
            auto it = known.find(hh);
            if (it == known.end())
                return std::nullopt;
            return it->second;
        };
        v.hash_at = [this](uint32_t h) -> std::optional<uint256> {
            auto it = best.find(h);
            if (it == best.end())
                return std::nullopt;
            return it->second;
        };
        v.tip_height = [this]() { return best.empty() ? 0u : best.rbegin()->first; };
        v.has_tip = [this]() { return !best.empty(); };
        return v;
    }
};

} // namespace

// Our LTC block X lost a race at 105: its header reached us (a side branch)
// but the best chain holds another block there. It is never "confirmed";
// once the best chain is 6 deep from 105 it is orphaned.
TEST(LtcFoundBlockVerify, SideBranchHeaderIsNotConfirmed)
{
    Chain c;
    c.grow(100, 106);
    const uint256 x = h_of("a105");
    c.known[x] = 105;
    EXPECT_EQ(parent_verdict(c.view(), x, 105), 0) << "2 deep: a sibling race can still go our way";
    c.grow(107, 110);
    const int v = parent_verdict(c.view(), x, 105);
    EXPECT_LT(v, 0) << "6 deep with another block at 105: orphaned (was " << v << ")";
    EXPECT_LT(parent_verdict(c.view(), x, std::nullopt), 0) << "height from the header when the record has none";
}

// Our block never reached us back (peers never relayed it): the header
// chain does not know it at all. Pending only until the best chain is 6 deep
// from the height it was mined at; then orphaned, not pending forever.
TEST(LtcFoundBlockVerify, UnseenBlockBecomesOrphanedAfterSixBlocks)
{
    Chain c;
    c.grow(100, 107);
    const uint256 x = h_of("c105");
    EXPECT_EQ(parent_verdict(c.view(), x, 105), 0) << "3 deep: pending";
    c.grow(108, 110);
    EXPECT_LT(parent_verdict(c.view(), x, 105), 0) << "6 deep, never seen: orphaned";
    EXPECT_EQ(parent_verdict(c.view(), x, std::nullopt), 0)
        << "no height anywhere: cannot judge, pending";
}

// Controls: our block on the best chain confirms once 6 deep (pending while
// shallow), and a height the chain has not reached is pending.
TEST(LtcFoundBlockVerify, BestChainBlockConfirmsOnceBuried)
{
    Chain c;
    c.grow(100, 106);
    const uint256 x = c.best[105];
    EXPECT_EQ(parent_verdict(c.view(), x, 105), 0) << "2 deep: can still be reorged out";
    c.grow(107, 110);
    EXPECT_EQ(parent_verdict(c.view(), x, 105), 6);
    c.grow(111, 115);
    EXPECT_EQ(parent_verdict(c.view(), x, 105), 11);
    EXPECT_EQ(parent_verdict(c.view(), h_of("d120"), 120), 0) << "height not reached";
}

// The DOGE verifier said "confirmed" whenever the backend had a tip. A DOGE
// block that is not on the DOGE best chain is not confirmed because the
// chain is alive; it is orphaned once the chain is 6 deep from its height.
TEST(DogeFoundBlockVerify, TipAliveIsNotConfirmed)
{
    Chain c;
    c.grow(500, 501);
    const uint256 x = h_of("e500");
    ASSERT_TRUE(c.view().has_tip());
    EXPECT_EQ(aux_verdict(c.view(), x, 500), 0) << "tip alive is not confirmation";
    c.grow(502, 505);
    EXPECT_LT(aux_verdict(c.view(), x, 500), 0) << "another block won 500: orphaned";

    Chain ok;
    ok.grow(500, 503);
    const uint256 y = ok.best[501];
    EXPECT_EQ(aux_verdict(ok.view(), y, 501), 0) << "3 deep: pending";
    ok.grow(504, 506);
    EXPECT_EQ(aux_verdict(ok.view(), y, 501), 6) << "on the DOGE best chain, 6 deep: confirmed";
}
