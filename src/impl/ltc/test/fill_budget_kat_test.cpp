// SPDX-License-Identifier: AGPL-3.0-or-later
// G2 fill-budget KATs (c2pool LTC + DOGE aux).
// Faithful port of p2pool-merged-v36 p2pool/test/test_g2_fillbudget.py.
// Offline, deterministic: injected clock, integer ramp arithmetic, refill
// deltas exact in IEEE doubles (6666*15 == 99990.0). Header-only unit under
// test (no core deps); folded into the existing allowlisted share_test
// target (the #769 trap -- no new executable).

#include <gtest/gtest.h>

#include "../coin/fill_budget.hpp"

#include <cstdint>
#include <vector>

using ltc::coin::FillBudget;
using ltc::coin::FillBudgetBook;
using ltc::coin::LEGACY_NEWTX_CAP;

namespace {

struct FakeClock {
    double t = 0.0;
    double operator()() const { return t; }
    void advance(double dt) { t += dt; }
};

// The derived LTC defaults: rate=1MB/150s=6666 B/s, burst=250 kB,
// floor=legacy 50 kB, ramp=4 shares.
FillBudget ltc_bucket(FakeClock& c) {
    return FillBudget("ltc", /*rate=*/6666, /*burst=*/250000,
                      /*floor=*/50000, /*ramp_shares=*/4,
                      [&c] { return c(); });
}

constexpr double SATURATED = 1e9;

} // namespace

// KAT-1: one saturated 150 s LTC window, 15 s shares. Bucket admits
// 1,099,920 new bytes vs the legacy 500,000 -- 2.2x, first share pinned
// to exactly legacy 50 kB.
TEST(FillBudgetKat, FillRatioRisesVsLegacy) {
    FakeClock c; auto b = ltc_bucket(c);
    b.on_block_reset();
    std::vector<int64_t> grants;
    for (int i = 0; i < 10; ++i) { c.advance(15); int64_t g = b.grant(); b.settle(g); grants.push_back(g); }
    const std::vector<int64_t> want = {50000,100000,150000,199980,99990,99990,99990,99990,99990,99990};
    EXPECT_EQ(grants, want);
    int64_t sum = 0; for (auto g : grants) sum += g;
    EXPECT_EQ(sum, 1099920);
    EXPECT_GT(sum, 10 * LEGACY_NEWTX_CAP);
}

// KAT-2: floor invariant -- grant() >= 50000 in ANY state (exhaustion,
// mid-ramp, fast shares).
TEST(FillBudgetKat, FloorNeverViolated) {
    FakeClock c; auto b = ltc_bucket(c);
    for (double dt : {0.0,1.0,3.0,15.0,0.0,200.0,1.0,1.0,1.0,1.0,300.0,3.0}) {
        c.advance(dt);
        EXPECT_GE(b.grant(), 50000) << "dt=" << dt;
        b.settle(SATURATED);           // worst case: massive over-spend
        if (dt == 200.0) b.on_block_reset();
    }
}

// KAT-3: get_work polling must not drain -- grant() is a pure read.
TEST(FillBudgetKat, PollingDoesNotDrain) {
    FakeClock c; auto b = ltc_bucket(c);
    b.on_block_reset();
    c.advance(15);
    const int64_t g0 = b.grant();
    for (int i = 0; i < 1000; ++i) ASSERT_EQ(b.grant(), g0);
    EXPECT_EQ(static_cast<int64_t>(b.tokens()), 250000);
}

// KAT-4: parent-block boundary -- first grant after reset is EXACTLY legacy.
TEST(FillBudgetKat, ResetRestartsRampAtLegacy) {
    FakeClock c; auto b = ltc_bucket(c);
    for (int i = 0; i < 5; ++i) { c.advance(15); b.settle(b.grant()); }
    b.on_block_reset();
    c.advance(1);
    EXPECT_EQ(b.grant(), LEGACY_NEWTX_CAP);
}

// KAT-5: rate binds above the floor -- fast 3 s run from a full bucket:
// one burst share, then floor (v35-equivalent).
TEST(FillBudgetKat, FastShareRunBounded) {
    FakeClock c; auto b = ltc_bucket(c);      // boot: full, ramp complete
    std::vector<int64_t> grants;
    for (int i = 0; i < 5; ++i) { c.advance(3); int64_t g = b.grant(); b.settle(g); grants.push_back(g); }
    EXPECT_EQ(grants[0], 250000);
    for (int i = 1; i < 5; ++i) EXPECT_EQ(grants[i], 50000) << "share " << i;
}

// KAT-6: rider wiring -- aux (DOGE) bucket resets on the parent's event,
// no timer of its own.
TEST(FillBudgetKat, RiderResetsWithParent) {
    FakeClock c; FillBudgetBook book;
    auto& ltc = book.register_bucket("ltc", ltc_bucket(c));
    auto& doge = book.register_bucket("doge",
        FillBudget("doge", 16666, 250000, 50000, 4, [&c]{ return c(); }), "ltc");
    for (int i = 0; i < 3; ++i) { c.advance(15); ltc.settle(ltc.grant()); doge.settle(doge.grant()); }
    book.on_block_reset("ltc", c());
    EXPECT_EQ(doge.shares_since_reset(), 0);
    EXPECT_EQ(doge.tokens(), 250000.0);
}
