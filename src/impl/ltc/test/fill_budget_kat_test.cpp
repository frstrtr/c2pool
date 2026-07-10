// G2 fill-budget KATs (c2pool LTC + DOGE aux).
// Faithful port of p2pool-merged-v36 p2pool/test/test_g2_fillbudget.py.
// Offline, deterministic: injected clock, integer ramp arithmetic, refill
// deltas exact in IEEE doubles (6666*15 == 99990.0). Self-contained: no
// c2pool deps, compiles with `g++ -std=c++17` for standalone verification
// and links unchanged into the project ctest target.

#include "../coin/fill_budget.hpp"

#include <cstdint>
#include <cstdio>
#include <vector>

using ltc::coin::FillBudget;
using ltc::coin::FillBudgetBook;
using ltc::coin::LEGACY_NEWTX_CAP;

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("  FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); ++g_fail; } } while (0)

struct FakeClock {
    double t = 0.0;
    double operator()() const { return t; }
    void advance(double dt) { t += dt; }
};

// The derived LTC defaults: rate=1MB/150s=6666 B/s, burst=250 kB,
// floor=legacy 50 kB, ramp=4 shares.
static FillBudget ltc_bucket(FakeClock& c) {
    return FillBudget("ltc", /*rate=*/6666, /*burst=*/250000,
                      /*floor=*/50000, /*ramp_shares=*/4,
                      [&c] { return c(); });
}

static const double SATURATED = 1e9;

// KAT-1: one saturated 150 s LTC window, 15 s shares. Bucket admits
// 1,099,920 new bytes vs the legacy 500,000 -- 2.2x, first share pinned
// to exactly legacy 50 kB.
static void kat1_fill_ratio_rises_vs_legacy() {
    FakeClock c; auto b = ltc_bucket(c);
    b.on_block_reset();
    std::vector<int64_t> grants;
    for (int i = 0; i < 10; ++i) { c.advance(15); int64_t g = b.grant(); b.settle(g); grants.push_back(g); }
    std::vector<int64_t> want = {50000,100000,150000,199980,99990,99990,99990,99990,99990,99990};
    CHECK(grants == want, "KAT-1 grant sequence");
    int64_t sum = 0; for (auto g : grants) sum += g;
    CHECK(sum == 1099920, "KAT-1 total == 1099920");
    CHECK(sum > 10 * LEGACY_NEWTX_CAP, "KAT-1 beats legacy envelope");
}

// KAT-2: floor invariant -- grant() >= 50000 in ANY state (exhaustion,
// mid-ramp, fast shares).
static void kat2_floor_never_violated() {
    FakeClock c; auto b = ltc_bucket(c);
    for (double dt : {0.0,1.0,3.0,15.0,0.0,200.0,1.0,1.0,1.0,1.0,300.0,3.0}) {
        c.advance(dt);
        CHECK(b.grant() >= 50000, "KAT-2 grant below legacy floor");
        b.settle(SATURATED);           // worst case: massive over-spend
        if (dt == 200.0) b.on_block_reset();
    }
}

// KAT-3: get_work polling must not drain -- grant() is a pure read.
static void kat3_polling_does_not_drain() {
    FakeClock c; auto b = ltc_bucket(c);
    b.on_block_reset();
    c.advance(15);
    int64_t g0 = b.grant();
    for (int i = 0; i < 1000; ++i) CHECK(b.grant() == g0, "KAT-3 poll drained budget");
    CHECK(static_cast<int64_t>(b.tokens()) == 250000, "KAT-3 tokens intact");
}

// KAT-4: parent-block boundary -- first grant after reset is EXACTLY legacy.
static void kat4_reset_restarts_ramp_at_legacy() {
    FakeClock c; auto b = ltc_bucket(c);
    for (int i = 0; i < 5; ++i) { c.advance(15); b.settle(b.grant()); }
    b.on_block_reset();
    c.advance(1);
    CHECK(b.grant() == LEGACY_NEWTX_CAP, "KAT-4 first post-reset grant != legacy");
}

// KAT-5: rate binds above the floor -- fast 3 s run from a full bucket:
// one burst share, then floor (v35-equivalent).
static void kat5_fast_share_run_bounded() {
    FakeClock c; auto b = ltc_bucket(c);      // boot: full, ramp complete
    std::vector<int64_t> grants;
    for (int i = 0; i < 5; ++i) { c.advance(3); int64_t g = b.grant(); b.settle(g); grants.push_back(g); }
    CHECK(grants[0] == 250000, "KAT-5 first fast share == burst");
    for (int i = 1; i < 5; ++i) CHECK(grants[i] == 50000, "KAT-5 subsequent fast shares == floor");
}

// KAT-6: rider wiring -- aux (DOGE) bucket resets on the parent's event,
// no timer of its own.
static void kat6_rider_resets_with_parent() {
    FakeClock c; FillBudgetBook book;
    auto& ltc = book.register_bucket("ltc", ltc_bucket(c));
    auto& doge = book.register_bucket("doge",
        FillBudget("doge", 16666, 250000, 50000, 4, [&c]{ return c(); }), "ltc");
    for (int i = 0; i < 3; ++i) { c.advance(15); ltc.settle(ltc.grant()); doge.settle(doge.grant()); }
    book.on_block_reset("ltc", c());
    CHECK(doge.shares_since_reset() == 0, "KAT-6 rider ramp not reset");
    CHECK(doge.tokens() == 250000.0, "KAT-6 rider not refilled to burst");
}

int main() {
    std::printf("G2 fill-budget KATs (LTC + DOGE aux)\n");
    kat1_fill_ratio_rises_vs_legacy();
    kat2_floor_never_violated();
    kat3_polling_does_not_drain();
    kat4_reset_restarts_ramp_at_legacy();
    kat5_fast_share_run_bounded();
    kat6_rider_resets_with_parent();
    if (g_fail == 0) { std::printf("ALL 6 KATs PASS\n"); return 0; }
    std::printf("%d CHECK(s) FAILED\n", g_fail);
    return 1;
}
