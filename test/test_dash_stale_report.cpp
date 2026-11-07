// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH own orphan/DOA report (stale_report.hpp) — pure KATs against the
// p2pool-dash oracle (work.py):
//   * next_stale_info == work.py:345-349 over a hand table of get_stale_counts
//     inputs (work.py:151-161), DOA shares excluded from the orphan count;
//   * solve_on_time == work.py:479-480 (<= 3 work events of grace);
//   * LocalStaleLedger: a mint that loses the head race is reported as orphan
//     until an on-chain share of ours announces it; an off-chain DOA mint is
//     reported as doa; a reorg back flips the verdict; a share pruned before
//     it settled stays "not in chain"; settled verdicts are permanent.
// Folded into test_dash_share_hash_link (no new CI target).

#include <gtest/gtest.h>

#include <impl/dash/stale_report.hpp>

#include <core/uint256.hpp>

#include <cstdint>
#include <map>
#include <utility>
#include <vector>

namespace {

using dash::StaleInfo;
using dash::mint::LocalStaleLedger;
using dash::mint::StaleTally;
using dash::mint::next_stale_info;
using dash::mint::solve_on_time;
using dash::mint::stale_counts;

StaleTally tally(uint64_t mine, uint64_t mine_doa, uint64_t in_chain, uint64_t doa_in_chain,
                 uint64_t orphans_recorded, uint64_t doas_recorded)
{
    StaleTally t;
    t.my_shares = mine;
    t.my_doa_shares = mine_doa;
    t.my_shares_in_chain = in_chain;
    t.my_doa_shares_in_chain = doa_in_chain;
    t.orphans_recorded_in_chain = orphans_recorded;
    t.doas_recorded_in_chain = doas_recorded;
    return t;
}

// The three sharechain primitives the ledger uses, over an explicit parent
// map (heights given), plus removal (a pruned share).
class FakeChain {
public:
    void add(const uint256& h, const uint256& parent, int32_t height)
    {
        m_parent[h] = parent;
        m_height[h] = height;
    }
    void remove(const uint256& h) { m_parent.erase(h); m_height.erase(h); }
    bool contains(const uint256& h) const { return m_height.count(h) != 0; }
    int32_t get_acc_height(const uint256& h)
    {
        auto it = m_height.find(h);
        return it == m_height.end() ? 0 : it->second;
    }
    uint256 get_nth_parent_via_skip(const uint256& h, int32_t n) const
    {
        uint256 cur = h;
        for (int32_t i = 0; i < n; ++i) {
            auto it = m_parent.find(cur);
            if (it == m_parent.end()) return uint256();
            cur = it->second;
        }
        return cur;
    }
private:
    std::map<uint256, uint256> m_parent;
    std::map<uint256, int32_t> m_height;
};

uint256 H(uint32_t n)
{
    uint256 h;
    h.SetHex("5a1e" + std::to_string(1000000 + n));
    return h;
}

} // namespace

TEST(DashStaleReport, NextStaleInfoMatchesOracleTable)
{
    // (orphans, doas) = (not_in_chain - doa_not_in_chain, doa_not_in_chain)
    using Counts = std::pair<uint64_t, uint64_t>;
    EXPECT_EQ(stale_counts(tally(0, 0, 0, 0, 0, 0)), Counts(0, 0));
    EXPECT_EQ(stale_counts(tally(5, 2, 3, 1, 0, 0)), Counts(1, 1));

    struct Row { StaleTally t; StaleInfo want; const char* what; };
    const Row rows[] = {
        {tally(0, 0, 0, 0, 0, 0), StaleInfo::none,   "nothing minted"},
        {tally(3, 0, 3, 0, 0, 0), StaleInfo::none,   "every share on the chain"},
        {tally(3, 0, 2, 0, 0, 0), StaleInfo::orphan, "one orphan, unannounced"},
        {tally(4, 0, 3, 0, 1, 0), StaleInfo::none,   "the orphan is announced by an on-chain share"},
        {tally(5, 0, 3, 0, 1, 0), StaleInfo::orphan, "two orphans, one announced"},
        {tally(3, 1, 2, 0, 0, 0), StaleInfo::doa,    "the off-chain share is DOA: doa, not orphan"},
        {tally(3, 1, 3, 1, 0, 0), StaleInfo::none,   "a DOA share that is on the chain is not stale"},
        {tally(4, 1, 2, 0, 0, 0), StaleInfo::orphan, "orphan + doa: orphan first"},
        {tally(5, 1, 3, 0, 1, 0), StaleInfo::doa,    "orphan announced, doa pending"},
        {tally(5, 1, 3, 0, 1, 1), StaleInfo::none,   "both announced"},
        {tally(2, 0, 3, 0, 0, 0), StaleInfo::none,   "saturating (never underflows)"},
    };
    for (const auto& r : rows)
        EXPECT_EQ(next_stale_info(r.t), r.want) << r.what;

    // The wire values of the oracle EnumType (data.py:91).
    EXPECT_EQ(static_cast<uint8_t>(StaleInfo::orphan), 253);
    EXPECT_EQ(static_cast<uint8_t>(StaleInfo::doa), 254);
}

TEST(DashStaleReport, SolveOnTimeGraceIsThreeWorkEvents)
{
    for (uint64_t d = 0; d <= 3; ++d)
        EXPECT_TRUE(solve_on_time(100, 100 + d)) << "diff " << d;
    EXPECT_FALSE(solve_on_time(100, 104));
    EXPECT_FALSE(solve_on_time(100, 1000));
    EXPECT_TRUE(solve_on_time(100, 99)) << "a generation that went backwards is on time";
}

TEST(DashStaleReport, LedgerTallyFollowsBestChainAndSettles)
{
    // g <- a1 (ours)
    //   <- b1 <- b2 <- a3 (ours, announces orphan) <- a4 (ours, DOA)
    //                                               <- c4 <- ...
    FakeChain c;
    c.add(H(0), uint256(), 1);
    c.add(H(1), H(0), 2);   // a1
    c.add(H(11), H(0), 2);  // b1
    c.add(H(12), H(11), 3); // b2
    LocalStaleLedger L;

    // Genesis-time job: no best share yet, nothing to report.
    EXPECT_EQ(next_stale_info(L.tally(c, uint256())), StaleInfo::none);

    L.record_mint(H(1), /*doa=*/false, StaleInfo::none);
    EXPECT_EQ(next_stale_info(L.tally(c, H(1))), StaleInfo::none) << "a1 is the best share";
    EXPECT_EQ(next_stale_info(L.tally(c, H(0))), StaleInfo::none)
        << "a1 minted on top of the best share, election pending: not an orphan";
    EXPECT_EQ(next_stale_info(L.tally(c, H(12))), StaleInfo::orphan) << "b2 won: a1 is an orphan";

    // Our next share on b2 carries the orphan byte; once it is on the chain the
    // debt is paid.
    c.add(H(3), H(12), 4);
    L.record_mint(H(3), false, StaleInfo::orphan);
    auto t = L.tally(c, H(3));
    EXPECT_EQ(t.my_shares, 2u);
    EXPECT_EQ(t.my_shares_in_chain, 1u);
    EXPECT_EQ(t.orphans_recorded_in_chain, 1u);
    EXPECT_EQ(next_stale_info(t), StaleInfo::none);

    // A DOA mint that also loses: reported as doa (not a second orphan).
    c.add(H(4), H(3), 5);   // a4 (ours, DOA)
    c.add(H(24), H(3), 5);  // c4
    c.add(H(25), H(24), 6); // c5
    L.record_mint(H(4), /*doa=*/true, StaleInfo::none);
    EXPECT_EQ(next_stale_info(L.tally(c, H(4))), StaleInfo::none) << "a DOA share on the chain";
    EXPECT_EQ(next_stale_info(L.tally(c, H(25))), StaleInfo::doa);

    // Reorg back onto a4 (within the settle depth): the verdict flips back.
    c.add(H(5), H(4), 6);
    c.add(H(6), H(5), 7);
    EXPECT_EQ(next_stale_info(L.tally(c, H(6))), StaleInfo::none);

    // A share of ours pruned before it settled stays "not in chain".
    c.add(H(7), H(6), 8);
    L.record_mint(H(7), false, StaleInfo::none);
    c.add(H(37), H(6), 8);
    c.remove(H(7));
    EXPECT_EQ(next_stale_info(L.tally(c, H(37))), StaleInfo::orphan);
    L.settle(c, H(37));   // gone -> folded as not in chain
    EXPECT_EQ(L.pending_count(), 3u) << "only the pruned entry settled";
    EXPECT_EQ(next_stale_info(L.tally(c, H(37))), StaleInfo::orphan);

    // Bury everything kSettleDepth deep on top of H(37): the verdicts fold into
    // the permanent counters and the tally is unchanged.
    uint256 tip = H(37);
    int32_t height = 8;
    for (int i = 0; i < LocalStaleLedger::kSettleDepth + 2; ++i) {
        const uint256 n = H(100 + i);
        c.add(n, tip, ++height);
        tip = n;
    }
    const auto before = L.tally(c, tip);
    L.settle(c, tip);
    EXPECT_EQ(L.pending_count(), 0u) << "every verdict is final";
    const auto after = L.tally(c, tip);
    EXPECT_EQ(after.my_shares, before.my_shares);
    EXPECT_EQ(after.my_shares_in_chain, before.my_shares_in_chain);
    EXPECT_EQ(after.my_doa_shares_in_chain, before.my_doa_shares_in_chain);
    EXPECT_EQ(after.orphans_recorded_in_chain, before.orphans_recorded_in_chain);
    EXPECT_EQ(after.my_shares, 4u);
    EXPECT_EQ(after.my_shares_in_chain, 2u) << "a3 and a4 are on the chain; a1 and the pruned one are not";
    EXPECT_EQ(after.my_doa_shares_in_chain, 1u);
    EXPECT_EQ(after.orphans_recorded_in_chain, 1u);
    EXPECT_EQ(next_stale_info(after), StaleInfo::orphan) << "one orphan still unannounced";

    // A later share announcing it pays that debt too.
    const uint256 a_next = H(200);
    c.add(a_next, tip, ++height);
    L.record_mint(a_next, false, StaleInfo::orphan);
    EXPECT_EQ(next_stale_info(L.tally(c, a_next)), StaleInfo::none);
}

TEST(DashStaleReport, LedgerIsBoundedAndForgetsTheOldest)
{
    FakeChain c;
    c.add(H(0), uint256(), 1);
    LocalStaleLedger L;
    for (uint32_t i = 0; i < LocalStaleLedger::kMaxPending + 5; ++i)
        L.record_mint(H(1000 + i), (i % 2) == 0, StaleInfo::none);
    EXPECT_EQ(L.pending_count(), LocalStaleLedger::kMaxPending);
    EXPECT_EQ(L.my_shares(), LocalStaleLedger::kMaxPending) << "a forgotten share counts neither way";
    EXPECT_EQ(L.my_doa_shares(), LocalStaleLedger::kMaxPending / 2);
}
