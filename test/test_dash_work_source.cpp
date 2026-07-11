// SPDX-License-Identifier: AGPL-3.0-or-later
///
/// KAT for dash::coin::select_dash_work — the embedded-vs-dashd work-source
/// selector (S8 embedded_gbt live-wire capstone). Proves the routing contract
/// and the RETAINED dashd fallback, without a live daemon or a populated
/// MN/mempool harness (the embedded builder is injected as a stub; its
/// oracle-parity output is already pinned by test_dash_embedded_gbt).
///
/// Contract under test:
///   1. viable() bundle          -> WorkSource::Embedded, embedded builder run,
///                                  fallback NEVER touched.
///   2. has_state=false          -> WorkSource::DashdFallback, fallback run.
///   3. viable but null mnstates -> fallback (defensive null-guard).
///   4. viable but null mempool  -> fallback (defensive null-guard).

#include <impl/dash/coin/work_source.hpp>

#include <gtest/gtest.h>

using dash::coin::EmbeddedWorkInputs;
using dash::coin::WorkSource;
using dash::coin::WorkSelection;
using dash::coin::select_dash_work;
using dash::coin::DashWorkData;
using dash::coin::MnStateMachine;
using dash::coin::Mempool;

namespace {

// Distinguishable sentinels so we can prove WHICH closure produced the result.
constexpr uint32_t EMB_SENTINEL_HEIGHT  = 0xE3BEDDEDu & 0xffffffu;  // "embedded"
constexpr uint32_t DASHD_SENTINEL_HEIGHT = 999'999u;

DashWorkData embedded_stub(bool& ran) {
    ran = true;
    DashWorkData w;
    w.m_height = EMB_SENTINEL_HEIGHT;
    return w;
}

DashWorkData dashd_stub(bool& ran) {
    ran = true;
    DashWorkData w;
    w.m_height = DASHD_SENTINEL_HEIGHT;
    return w;
}

} // namespace

// 1) Viable bundle routes to the EMBEDDED builder; fallback is not invoked.
TEST(DashWorkSource, ViableRoutesEmbedded)
{
    MnStateMachine mn;
    Mempool mp;
    EmbeddedWorkInputs emb;
    emb.has_state = true;
    emb.mnstates  = &mn;
    emb.mempool   = &mp;
    ASSERT_TRUE(emb.viable());

    bool emb_ran = false, fb_ran = false;
    WorkSelection sel = select_dash_work(
        emb,
        [&] { return embedded_stub(emb_ran); },
        [&] { return dashd_stub(fb_ran); });

    EXPECT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_TRUE(emb_ran);
    EXPECT_FALSE(fb_ran);
    EXPECT_EQ(sel.work.m_height, EMB_SENTINEL_HEIGHT);
}

// 2) No embedded state -> the RETAINED dashd getblocktemplate fallback runs.
TEST(DashWorkSource, NoStateRoutesDashdFallback)
{
    EmbeddedWorkInputs emb;        // has_state defaults false
    ASSERT_FALSE(emb.viable());

    bool emb_ran = false, fb_ran = false;
    WorkSelection sel = select_dash_work(
        emb,
        [&] { return embedded_stub(emb_ran); },
        [&] { return dashd_stub(fb_ran); });

    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_FALSE(emb_ran);
    EXPECT_TRUE(fb_ran);
    EXPECT_EQ(sel.work.m_height, DASHD_SENTINEL_HEIGHT);
}

// 3) has_state true but mnstates null -> not viable -> fallback (null-guard).
TEST(DashWorkSource, NullMnStatesRoutesFallback)
{
    Mempool mp;
    EmbeddedWorkInputs emb;
    emb.has_state = true;
    emb.mnstates  = nullptr;
    emb.mempool   = &mp;
    EXPECT_FALSE(emb.viable());

    bool emb_ran = false, fb_ran = false;
    WorkSelection sel = select_dash_work(
        emb,
        [&] { return embedded_stub(emb_ran); },
        [&] { return dashd_stub(fb_ran); });

    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_FALSE(emb_ran);
    EXPECT_TRUE(fb_ran);
}

// 4) has_state true but mempool null -> not viable -> fallback (null-guard).
TEST(DashWorkSource, NullMempoolRoutesFallback)
{
    MnStateMachine mn;
    EmbeddedWorkInputs emb;
    emb.has_state = true;
    emb.mnstates  = &mn;
    emb.mempool   = nullptr;
    EXPECT_FALSE(emb.viable());

    bool emb_ran = false, fb_ran = false;
    WorkSelection sel = select_dash_work(
        emb,
        [&] { return embedded_stub(emb_ran); },
        [&] { return dashd_stub(fb_ran); });

    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_FALSE(emb_ran);
    EXPECT_TRUE(fb_ran);
}
