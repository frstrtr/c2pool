// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH think() Phase 4 head score: the p2pool block-solution credit.
//
// p2pool (p2pool-merged-v36 data.py:1690-1696) punishes a block-solution
// share with -1 ("block solution"), checked before the naughty checks, and
// sorts the heads ascending as ((work - min(punish,1)*ata(target), -punish,
// -time_seen), h), the last one best (data.py:2933-2940). So a head that
// solved a block gets one share of work ahead of an equal-work sibling, and
// a full tie goes to the numerically larger hash h.
//
// c2pool punished naughty heads only, and its time_seen is whole seconds, so
// a block-solving share and a same-parent sibling minted in the same second
// tied, and the sibling could win. On 11-13/14 two blocks found by the hotel
// (2571721, 2571868) ended with their solving shares as orphaned heads off
// the best sharechain. The block reward was not affected (it is fixed in
// the coinbase), but the finder lost one share of PPLNS weight and the
// dashboard counts disagreed.
//
// Expectations are hand-derived from the p2pool tuple, not from the helpers
// under test. FOLDED into the allowlisted test_dash_share_tracker target.

#include <gtest/gtest.h>

#include <impl/dash/share_tracker.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

using dash::DecoratedData;
using dash::HeadScore;
using dash::TraditionalScore;
using dash::block_solution_credit;
using dash::head_punish_reason;
using dash::make_head_score;
using dash::make_traditional_score;

namespace {

constexpr uint32_t NET_BITS = 0x1923269b;   // the network target for the parent (11-14)

struct Head {
    std::string hex;        // share hash, big-endian hex as logged
    uint64_t work;          // verified work up to the 5th parent
    uint64_t attempts;      // ata(target) of the head itself
    int64_t time_seen;      // whole seconds, as the index keeps it
    bool block = false;     // is_block_solution (PoW meets the header's bits)
    int32_t naughty = 0;
    uint32_t header_bits = NET_BITS;                    // the share header's block bits
    std::optional<uint32_t> expected = NET_BITS;        // header chain's target for the parent
};

uint256 h(const std::string& hex)
{
    uint256 r;
    r.SetHex(hex);
    return r;
}

// p2pool: sorted(decorated_heads)[-1]
std::string best_of(const std::vector<Head>& heads)
{
    std::vector<DecoratedData<HeadScore>> d;
    for (const auto& x : heads) {
        const uint256 hash = h(x.hex);
        const bool credit = block_solution_credit(x.block, x.header_bits, x.expected);
        d.push_back({make_head_score(uint288(x.work), uint288(x.attempts),
                                     head_punish_reason(credit, x.naughty), x.time_seen, hash),
                     hash});
    }
    std::sort(d.begin(), d.end());
    return d.back().hash.GetHex();
}

std::string pad(const std::string& tail)
{
    return std::string(64 - tail.size(), '0') + tail;
}

// A share known only by its logged 16-hex short hash: the prefix, zero tail.
std::string prefix16(const std::string& short_hash)
{
    return short_hash + std::string(48, '0');
}

constexpr uint64_t W = 1'000'000;   // work at the 5th parent
constexpr uint64_t A = 1'000;       // one share's attempts

} // namespace

TEST(DashHeadScoreBlockSolution, PunishReasonIsBlockSolutionFirstThenNaughty)
{
    EXPECT_EQ(head_punish_reason(false, 0), 0);
    EXPECT_EQ(head_punish_reason(true, 0), -1);
    EXPECT_EQ(head_punish_reason(false, 1), 1);
    EXPECT_EQ(head_punish_reason(false, 3), 3) << "a descendant of a naughty share keeps its depth";
    EXPECT_EQ(head_punish_reason(true, 1), -1) << "p2pool checks the block solution before naughty";
}

// The 11-14 case at h 2571868: block share 0000000000000022a769.. (full
// hash) and its sibling, logged as 0000000000003bfe (short hash only: the
// tail here is zero). Same parent 0266.., same second; the sibling arrived
// 187 ms later and has the larger hash. p2pool keeps the block share.
TEST(DashHeadScoreBlockSolution, BlockShareBeatsSameSecondSiblingWithLargerHash)
{
    const std::string blk = pad("22a7698e043c411c28df049209b695f97aef28ea22fc70ac9e");
    const std::string sib = prefix16("0000000000003bfe");
    ASSERT_TRUE(h(blk) < h(sib)) << "the sibling has the larger hash: a hash tie-break alone would pick it";
    const Head b{blk, W, A, 1794616206, true};
    const Head s{sib, W, A, 1794616206};
    EXPECT_EQ(best_of({b, s}), h(blk).GetHex());
    EXPECT_EQ(best_of({s, b}), h(blk).GetHex()) << "independent of arrival order";
}

// The 11-13 case at h 2571721: block share 00000000000000023dd4.. (full
// hash) against its sibling logged as 00000000000053f3 (short hash only),
// minted 121 ms EARLIER in the same second on the same parent.
TEST(DashHeadScoreBlockSolution, BlockShareBeatsEarlierSiblingInTheSameSecond)
{
    const std::string blk = pad("023dd4b4dd4fbaaa226d74fe4410e64f0fb71be92b722503c5");
    const std::string sib = prefix16("00000000000053f3");
    ASSERT_TRUE(h(blk) < h(sib));
    EXPECT_EQ(best_of({{sib, W, A, 1794593964}, {blk, W, A, 1794593964, true}}), h(blk).GetHex());
}

// Even a sibling SEEN a second earlier loses: the -1 punish adds one share
// of work, which outranks time_seen.
TEST(DashHeadScoreBlockSolution, BlockShareBeatsSiblingSeenEarlier)
{
    const std::string blk = pad("aa");
    const std::string sib = pad("bb");
    EXPECT_EQ(best_of({{sib, W, A, 100}, {blk, W, A, 101, true}}), h(blk).GetHex());
}

// +1 share of work: a block head ties a one-share-longer branch on work and
// wins on -punish; a two-share-longer branch still wins.
TEST(DashHeadScoreBlockSolution, BlockShareCreditIsExactlyOneShare)
{
    const std::string blk = pad("aa");
    const std::string lng = pad("ff");
    EXPECT_EQ(best_of({{blk, W, A, 100, true}, {lng, W + A, A, 100}}), h(blk).GetHex());
    EXPECT_EQ(best_of({{blk, W, A, 100, true}, {lng, W + 2 * A, A, 100}}), h(lng).GetHex());
}

// No block, no punish: equal work goes to the head seen first, a full tie
// to the numerically larger hash (p2pool's trailing h).
TEST(DashHeadScoreBlockSolution, TieBreaksAreTimeSeenThenLargerHash)
{
    const std::string lo = pad("10");
    const std::string hi = pad("20");
    EXPECT_EQ(best_of({{hi, W, A, 101}, {lo, W, A, 100}}), h(lo).GetHex()) << "seen first wins";
    EXPECT_EQ(best_of({{lo, W, A, 100}, {hi, W, A, 100}}), h(hi).GetHex()) << "full tie: larger hash";
    EXPECT_EQ(best_of({{hi, W, A, 100}, {lo, W, A, 100}}), h(hi).GetHex()) << "in either order";
}

// A naughty head is one share behind: against a clean head with one share
// less work it ties on work and loses on -punish.
TEST(DashHeadScoreBlockSolution, NaughtyHeadIsOneShareBehind)
{
    const std::string bad = pad("ff");
    const std::string ok = pad("01");
    EXPECT_EQ(best_of({{bad, W + A, A, 100, false, 1}, {ok, W, A, 100}}), h(ok).GetHex());
    EXPECT_EQ(best_of({{bad, W + 2 * A, A, 100, false, 1}, {ok, W, A, 100}}), h(bad).GetHex());
}

// p2pool punish_aggressively = traditional_sort[-1][0][2] (= -punish): true
// when the traditional best is punished either way, a block solution included.
TEST(DashHeadScoreBlockSolution, TraditionalSortCarriesTheBlockSolutionPunish)
{
    std::vector<DecoratedData<TraditionalScore>> t;
    const uint256 blk = h(pad("aa")), sib = h(pad("bb"));
    t.push_back({make_traditional_score(uint288(W), head_punish_reason(true, 0), 100, blk), blk});
    t.push_back({make_traditional_score(uint288(W), head_punish_reason(false, 0), 101, sib), sib});
    std::sort(t.begin(), t.end());
    EXPECT_EQ(t.back().hash, blk) << "traditional: equal work, seen first";
    EXPECT_NE(t.back().score.neg_reason, 0) << "punish_aggressively is set";
}

// The credit needs the network target. p2pool trusts the share's own header
// bits; here a share whose header claims an easier target than the one our
// coin header chain computes for its parent (or whose parent is unknown or
// off our best chain: no expected bits) gets no credit and scores as a plain
// share. Otherwise any peer could mark every share a "block solution".
TEST(DashHeadScoreBlockSolution, CreditNeedsTheNetworkTargetForTheParent)
{
    EXPECT_TRUE(block_solution_credit(true, NET_BITS, NET_BITS));
    EXPECT_FALSE(block_solution_credit(true, 0x1f00ffff, NET_BITS)) << "fake easy bits";
    EXPECT_FALSE(block_solution_credit(true, NET_BITS, std::nullopt)) << "parent unknown / off chain";
    EXPECT_FALSE(block_solution_credit(false, NET_BITS, NET_BITS)) << "not a block solution";
}

TEST(DashHeadScoreBlockSolution, FakeEasyBitsWinNoRace)
{
    const std::string fake = pad("aa");
    const std::string sib = pad("bb");
    Head f{fake, W, A, 100, true};
    f.header_bits = 0x1f00ffff;     // meets its own (easy) bits: is_block_solution
    EXPECT_EQ(best_of({f, {sib, W, A, 100}}), h(sib).GetHex())
        << "no credit: the full tie goes to the larger hash";
    EXPECT_EQ(best_of({f, {pad("01"), W + A, A, 100}}), h(pad("01")).GetHex())
        << "no credit: a one-share-longer branch wins";
    Head u{fake, W, A, 100, true};
    u.expected = std::nullopt;      // parent unknown to our header chain
    EXPECT_EQ(best_of({u, {sib, W, A, 100}}), h(sib).GetHex());
}
