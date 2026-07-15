// ---------------------------------------------------------------------------
// dash::payout 128-bit payout muldiv KAT -- the guard for the MSVC-portability
// rework of coinbase_builder.hpp (v0.2.1 c2pool-dash Windows build fix).
//
// coinbase_builder evaluates the PPLNS per-script coinbase amount in a 128-bit
// intermediate:
//     v36     : amount = worker_payout * weight / total_weight
//     pre-v36 : amount = worker_payout * 49 * weight / (total_weight * 50)
// GCC/Clang use native unsigned __int128; MSVC (no __int128, error C2065 on
// '__uint128_t') falls back to boost::multiprecision::uint128_t. This is
// CONSENSUS PAYOUT math -- a one-satoshi divergence forks payouts -- so the two
// paths MUST be BIT-IDENTICAL.
//
// Two layers (mirrors bch abla muldiv_kat / dgb arith256_muldiv_kat):
//   A. cross-platform known answers: payout_share() / payout_share_portable()
//      produce exact fixed results on EVERY compiler incl. MSVC (all MSVC can
//      run -- there is no native to diff against there). Several exercise a
//      product > 2^64, which a 64-bit multiply would wrap and fail.
//   B. Linux-only equivalence sweep (guarded by __SIZEOF_INT128__): the
//      portable path must equal the native path across the DASH payout operand
//      space plus a deterministic wide fuzz, over BOTH the v36 and pre-v36
//      branches. Proving portable == native on the trusted platform certifies
//      the MSVC path this CI cannot run.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <limits>

#include <impl/dash/payout_muldiv.hpp>

namespace {

using dash::payout::payout_share;
using dash::payout::payout_share_portable;

constexpr uint64_t U64MAX = std::numeric_limits<uint64_t>::max();

// Deterministic 64-bit LCG (no <random>, no Date/rand) -- reproducible vectors.
struct Lcg {
    uint64_t s;
    explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; }
};

} // namespace

// ---- A. cross-platform known answers (run on ALL compilers incl. MSVC) ------
TEST(DashCoinbaseMuldiv, KnownAnswersV36) {
    // v36: amount = worker_payout * weight / total_weight
    EXPECT_EQ(payout_share(1, 100, 4, true), 25ULL);
    EXPECT_EQ(payout_share(3, 100, 4, true), 75ULL);
    EXPECT_EQ(payout_share(4, 100, 4, true), 100ULL);   // whole weight -> full payout
    EXPECT_EQ(payout_share(0, 100, 4, true), 0ULL);
    // product > 2^64 (weight*worker_payout = 2^80): a 64-bit multiply would wrap.
    EXPECT_EQ(payout_share(1099511627776ULL, 1099511627776ULL,
                           1099511627776ULL, true), 1099511627776ULL);
}

TEST(DashCoinbaseMuldiv, KnownAnswersPreV36) {
    // pre-v36: amount = worker_payout * 49 * weight / (total_weight * 50)
    EXPECT_EQ(payout_share(50, 100, 50, false), 98ULL);  // whole share = 98% (2% finder fee added separately)
    EXPECT_EQ(payout_share(1, 100, 2, false), 49ULL);
    EXPECT_EQ(payout_share(0, 100, 50, false), 0ULL);
    // numerator worker_payout*49*weight ~ 2^75 (> 2^64) and den = total*50 > 2^64.
    EXPECT_EQ(payout_share(1099511627776ULL, 1000000ULL,
                           1099511627776ULL, false), 980000ULL);
}

TEST(DashCoinbaseMuldiv, PortablePathSatisfiesKnownAnswers) {
    // the MSVC fallback must independently produce the same answers.
    EXPECT_EQ(payout_share_portable(1, 100, 4, true), 25ULL);
    EXPECT_EQ(payout_share_portable(4, 100, 4, true), 100ULL);
    EXPECT_EQ(payout_share_portable(1099511627776ULL, 1099511627776ULL,
                                    1099511627776ULL, true), 1099511627776ULL);
    EXPECT_EQ(payout_share_portable(50, 100, 50, false), 98ULL);
    EXPECT_EQ(payout_share_portable(1099511627776ULL, 1000000ULL,
                                    1099511627776ULL, false), 980000ULL);
}

#if defined(__SIZEOF_INT128__)
// ---- B. native == portable across the DASH payout domain (trusted platform) -
TEST(DashCoinbaseMuldiv, NativeEqualsPortableGrid) {
    using dash::payout::payout_share_native;
    // operand shapes from the coinbase_builder call site: weights are subsets of
    // total_weight (so quotient <= worker_payout), worker_payout < 2^50.
    const uint64_t totals[] = {
        1, 2, 50, 100, 37938, 1000000ULL,
        (1ULL << 30), (1ULL << 40), (1ULL << 62), U64MAX
    };
    const uint64_t payouts[] = {
        0, 1, 100, 5000000000ULL, (1ULL << 40), (1ULL << 50) - 1
    };
    for (uint64_t total : totals) {
        // weight sampled across [0, total]: 0, 1, total/2, total-1, total.
        const uint64_t weights[] = {
            0, 1, total / 2, total > 0 ? total - 1 : 0, total
        };
        for (uint64_t w : weights)
            for (uint64_t wp : payouts)
                for (bool v36 : {false, true}) {
                    EXPECT_EQ(payout_share_native(w, wp, total, v36),
                              payout_share_portable(w, wp, total, v36))
                        << "w=" << w << " wp=" << wp
                        << " total=" << total << " v36=" << v36;
                }
    }
}

TEST(DashCoinbaseMuldiv, NativeEqualsPortableFuzz) {
    using dash::payout::payout_share_native;
    Lcg rng(0x9E3779B97F4A7C15ULL);
    int compared = 0;
    for (int i = 0; i < 200000; ++i) {
        uint64_t total = rng.next();
        if (total == 0) total = 1;
        const uint64_t w  = rng.next() % total;                 // weight in [0, total)
        const uint64_t wp = rng.next() & ((1ULL << 50) - 1);    // worker_payout < 2^50
        const bool v36 = (rng.next() & 1) != 0;
        ++compared;
        ASSERT_EQ(payout_share_native(w, wp, total, v36),
                  payout_share_portable(w, wp, total, v36))
            << "fuzz i=" << i << " w=" << w << " wp=" << wp
            << " total=" << total << " v36=" << v36;
    }
    EXPECT_GT(compared, 1000);
    std::cerr << "dash coinbase muldiv KAT: native==portable over "
              << compared << " fuzz vectors\n";
}
#else
TEST(DashCoinbaseMuldiv, NoInt128KnownAnswerLayerOnly) {
    std::cerr << "dash coinbase muldiv KAT: no __int128 (MSVC) -- "
                 "known-answer layer only\n";
    SUCCEED();
}
#endif
