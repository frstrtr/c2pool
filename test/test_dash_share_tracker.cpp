// DASH S8 pool-node leaf 4 — share_tracker.hpp KAT.
//
// Exercises the consensus-bearing, PoW-independent core of the DASH ShareTracker
// port: DensePPLNSWindow's decayed-weight ring buffer (compute_v36_weights),
// the precomputed decay table, the donation weight split, and window slides.
//
// These are namespace-ported byte-for-byte from btc::ShareTracker (DASH is X11
// but the tracker is consensus-agnostic — share weighting/decay is PoW-independent),
// so the KAT pins the arithmetic invariants that v36 standardization relies on.
//
// Socket-free, chain-free: drives PPLNSEntry/DensePPLNSWindow directly.

#include <gtest/gtest.h>

#include <impl/dash/share_tracker.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <vector>

using dash::DensePPLNSWindow;
using dash::PPLNSEntry;
using dash::CumulativeWeights;

namespace {

constexpr uint64_t DECAY_PRECISION = DensePPLNSWindow::DECAY_PRECISION; // 40
constexpr uint64_t DECAY_SCALE     = DensePPLNSWindow::DECAY_SCALE;     // 1<<40

std::vector<unsigned char> script_a() { return {0x76, 0xa9, 0x14, 0xaa, 0x88, 0xac}; }
std::vector<unsigned char> script_b() { return {0x76, 0xa9, 0x14, 0xbb, 0x88, 0xac}; }

PPLNSEntry entry(uint64_t att, uint32_t donation, std::vector<unsigned char> s)
{
    PPLNSEntry e;
    e.att = uint288(att);
    e.donation = donation;
    e.script = std::move(s);
    return e;
}

// Mirror of the decayed_att computation inside compute_v36_weights() so the
// expected values are derived the same way the code derives them (bit-exact).
uint288 decayed(uint64_t att, int depth)
{
    return (uint288(att) * uint288(DensePPLNSWindow::s_decay_table[depth])) >> DECAY_PRECISION;
}

} // namespace

// 1. The decay table head is unity (depth 0 = no decay) and the table is
//    monotonically non-increasing — the foundational invariant for PPLNS.
TEST(DashShareTracker, DecayTableHeadUnityAndMonotonic)
{
    DensePPLNSWindow::init_decay_table(32);
    ASSERT_GE(DensePPLNSWindow::s_decay_table.size(), 32u);
    EXPECT_EQ(DensePPLNSWindow::s_decay_table[0], DECAY_SCALE);
    for (size_t d = 1; d < 32; ++d)
        EXPECT_LE(DensePPLNSWindow::s_decay_table[d], DensePPLNSWindow::s_decay_table[d - 1]);
    // half_life = chain_len/4 = 8; decay_per strictly below scale.
    EXPECT_LT(DensePPLNSWindow::s_decay_per, DECAY_SCALE);
}

// 2. A single share at depth 0 with no donation: full attempt weight to its
//    script, donation pool empty, no decay applied.
TEST(DashShareTracker, SingleEntryDepth0NoDonation)
{
    DensePPLNSWindow::init_decay_table(32);
    DensePPLNSWindow win;
    win.m_entries.push_back(entry(1000, 0, script_a()));

    auto w = win.compute_v36_weights();
    const uint64_t expect = 1000ull * 65535ull;
    EXPECT_EQ(w.weights.at(script_a()).GetLow64(), expect);
    EXPECT_EQ(w.total_weight.GetLow64(), expect);
    EXPECT_EQ(w.total_donation_weight.GetLow64(), 0u);
}

// 3. Donation split conserves total weight: addr_w + don_w == att*65535, and
//    the donation pool gets exactly att*donation.
TEST(DashShareTracker, DonationSplitConserved)
{
    DensePPLNSWindow::init_decay_table(32);
    DensePPLNSWindow win;
    const uint32_t don = 6553; // ~10%
    win.m_entries.push_back(entry(1000, don, script_a()));

    auto w = win.compute_v36_weights();
    EXPECT_EQ(w.weights.at(script_a()).GetLow64(), 1000ull * (65535ull - don));
    EXPECT_EQ(w.total_donation_weight.GetLow64(), 1000ull * don);
    EXPECT_EQ(w.total_weight.GetLow64(), 1000ull * 65535ull); // addr_w + don_w
}

// 4. Decay is applied by depth: an identical share one step deeper contributes
//    strictly less, and exactly decayed_att*65535 (bit-exact vs the table).
TEST(DashShareTracker, DepthDecayApplied)
{
    DensePPLNSWindow::init_decay_table(32);
    DensePPLNSWindow win;
    win.m_entries.push_back(entry(1000, 0, script_a())); // depth 0
    win.m_entries.push_back(entry(1000, 0, script_b())); // depth 1

    auto w = win.compute_v36_weights();
    const uint288 d0 = decayed(1000, 0) * uint288(65535u);
    const uint288 d1 = decayed(1000, 1) * uint288(65535u);
    EXPECT_EQ(w.weights.at(script_a()), d0);
    EXPECT_EQ(w.weights.at(script_b()), d1);
    EXPECT_LT(w.weights.at(script_b()), w.weights.at(script_a())); // decay shrinks deeper
}

// 5. Two shares paying the same script accumulate into one map entry.
TEST(DashShareTracker, SameScriptAccumulates)
{
    DensePPLNSWindow::init_decay_table(32);
    DensePPLNSWindow win;
    win.m_entries.push_back(entry(1000, 0, script_a())); // depth 0
    win.m_entries.push_back(entry(2000, 0, script_a())); // depth 1

    auto w = win.compute_v36_weights();
    ASSERT_EQ(w.weights.size(), 1u);
    const uint288 expect = decayed(1000, 0) * uint288(65535u)
                         + decayed(2000, 1) * uint288(65535u);
    EXPECT_EQ(w.weights.at(script_a()), expect);
    EXPECT_EQ(w.total_weight, expect);
}

// 6. Empty window yields no weights and zero totals.
TEST(DashShareTracker, EmptyWindowZero)
{
    DensePPLNSWindow win;
    EXPECT_TRUE(win.empty());
    auto w = win.compute_v36_weights();
    EXPECT_TRUE(w.weights.empty());
    EXPECT_EQ(w.total_weight.GetLow64(), 0u);
    EXPECT_EQ(w.total_donation_weight.GetLow64(), 0u);
}

// 7. slide_forward enters at depth 0 and evicts the oldest once chain_len full.
TEST(DashShareTracker, SlideForwardCapsAtChainLen)
{
    DensePPLNSWindow::init_decay_table(32);
    DensePPLNSWindow win;
    win.m_chain_len = 2;
    win.m_entries.push_back(entry(10, 0, script_a())); // depth 0
    win.m_entries.push_back(entry(20, 0, script_b())); // depth 1
    win.slide_forward(entry(30, 0, script_a()));       // new depth 0, evict att=20

    EXPECT_EQ(win.size(), 2);
    EXPECT_EQ(win.m_entries.front().att.GetLow64(), 30u); // newest at front
    EXPECT_EQ(win.m_entries.back().att.GetLow64(), 10u);  // att=20 evicted
}

// 8. slide_backward drops the shallowest and appends a deeper share.
TEST(DashShareTracker, SlideBackwardShiftsDeeper)
{
    DensePPLNSWindow win;
    win.m_chain_len = 3;
    win.m_entries.push_back(entry(10, 0, script_a())); // depth 0
    win.m_entries.push_back(entry(20, 0, script_b())); // depth 1
    win.slide_backward(entry(30, 0, script_a()));      // drop depth 0, add deeper

    EXPECT_EQ(win.size(), 2);
    EXPECT_EQ(win.m_entries.front().att.GetLow64(), 20u); // old depth1 now shallowest
    EXPECT_EQ(win.m_entries.back().att.GetLow64(), 30u);  // new deepest
}

// 9. Distinct scripts remain separate keys; totals sum both.
TEST(DashShareTracker, DistinctScriptsSeparate)
{
    DensePPLNSWindow::init_decay_table(32);
    DensePPLNSWindow win;
    win.m_entries.push_back(entry(1000, 0, script_a())); // depth 0
    win.m_entries.push_back(entry(1000, 0, script_b())); // depth 1

    auto w = win.compute_v36_weights();
    EXPECT_EQ(w.weights.size(), 2u);
    const uint288 sum = w.weights.at(script_a()) + w.weights.at(script_b());
    EXPECT_EQ(w.total_weight, sum);
}
