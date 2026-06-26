// dgb::coin::weight_decay -- V36 PPLNS exponential weight-decay KAT.
//
// FENCED conformance test (no production code touched). Pins the decay-rate
// arithmetic lifted into coin/share_weight_decay.hpp against the
// frstrtr/p2pool-merged-v36 oracle p2pool/data.py get_decayed_cumulative_weights:
//       half_life = max(net.CHAIN_LENGTH // 4, 1)
//       decay_per = SCALE - (SCALE * 693147) // (1_000_000 * half_life)
//       decayed_att = (att * decay_fp) >> 40
//   SCALE = 1 << 40, 693147 = ln(2) * 1e6 truncated.
//
// All expected values are HAND-DERIVED by independently evaluating the oracle
// Python expression above (run as a separate reference, not by calling the
// helper under test), so the test is NON-CIRCULAR. The CL goldens cover the
// V36 DGB chain length (CHAIN_LENGTH = 24*60*60//10 = 8640), the older
// p2pool-dgb-scrypt baseline (12*60*60//15 = 2880), and the tiny-chain
// half_life=1 guard.
//
// MUST appear in BOTH the ctest registration (this dir CMakeLists.txt) AND the
// build.yml --target allowlist, or it becomes a #143-style NOT_BUILT sentinel
// that reds master.

#include <impl/dgb/coin/share_weight_decay.hpp>

#include <gtest/gtest.h>

namespace wd = dgb::coin::weight_decay;

// ---- fixed-point constants match the oracle exactly ---------------------

TEST(DgbWeightDecay, FixedPointConstants) {
    EXPECT_EQ(wd::DECAY_PRECISION, 40u);
    EXPECT_EQ(wd::DECAY_SCALE, uint64_t(1) << 40);
    EXPECT_EQ(wd::DECAY_SCALE, uint64_t(1099511627776));
    EXPECT_EQ(wd::LN2_MICRO, 693147u);
}

// ---- half_life = max(CHAIN_LENGTH // 4, 1) ------------------------------

TEST(DgbWeightDecay, HalfLifeMatchesOracle) {
    EXPECT_EQ(wd::half_life(8640), 2160u); // V36 DGB:  8640 // 4
    EXPECT_EQ(wd::half_life(2880), 720u);  // baseline: 2880 // 4
    EXPECT_EQ(wd::half_life(3600), 900u);
    EXPECT_EQ(wd::half_life(720),  180u);
}

TEST(DgbWeightDecay, HalfLifeTinyChainGuard) {
    // chain_length // 4 == 0 must clamp to 1 (oracle max(.., 1)).
    EXPECT_EQ(wd::half_life(4), 1u);
    EXPECT_EQ(wd::half_life(3), 1u);
    EXPECT_EQ(wd::half_life(1), 1u);
    EXPECT_EQ(wd::half_life(0), 1u);
}

// ---- decay_per = SCALE - SCALE*693147 // (1e6 * half_life) ---------------
// Goldens computed independently from the oracle expression.

TEST(DgbWeightDecay, DecayPerShareMatchesOracle) {
    EXPECT_EQ(wd::decay_per_share(8640), uint64_t(1099158792968)); // hl=2160 (V36 DGB)
    EXPECT_EQ(wd::decay_per_share(2880), uint64_t(1098453123351)); // hl=720  (baseline)
    EXPECT_EQ(wd::decay_per_share(3600), uint64_t(1098664824236)); // hl=900
    EXPECT_EQ(wd::decay_per_share(720),  uint64_t(1095277610075)); // hl=180
    EXPECT_EQ(wd::decay_per_share(4),    uint64_t(337388441518));  // hl=1 (guard)
}

// ---- decayed_att = (att * decay_fp) >> 40 -------------------------------
// The per-depth decay_fp accumulation (decay_fp_{n+1} = decay_fp_n * decay_per)
// is a 80-bit product done with mul128_shift in the caller's walk -- that
// 128-bit step lives in share_tracker.hpp, NOT in this SSOT (which exposes only
// the rate constants + the final attempts shift). So the decay_fp values below
// are supplied as DIRECT oracle literals (computed in Python bignums from
// decay_fp_{n+1} = (decay_fp_n * decay_per) >> 40 with CL=8640,
// decay_per=1099158792968), and decayed_attempts is checked against each. The
// att*decay_fp product fits uint64 here because att (65535) is small.

TEST(DgbWeightDecay, DecayedAttemptsAtOracleDepthFactors) {
    const uint64_t att = 65535; // target_to_average_attempts placeholder
    // depth 0..3 decay_fp factors for the V36 DGB chain (CL=8640):
    EXPECT_EQ(wd::decayed_attempts(att, uint64_t(1099511627776)), uint64_t(65535)); // depth 0: 1.0
    EXPECT_EQ(wd::decayed_attempts(att, uint64_t(1099158792968)), uint64_t(65513)); // depth 1
    EXPECT_EQ(wd::decayed_attempts(att, uint64_t(1098806071385)), uint64_t(65492)); // depth 2
    EXPECT_EQ(wd::decayed_attempts(att, uint64_t(1098453462991)), uint64_t(65471)); // depth 3
}

TEST(DgbWeightDecay, DecayedAttemptsZeroAndIdentity) {
    EXPECT_EQ(wd::decayed_attempts(0, wd::DECAY_SCALE), uint64_t(0));
    EXPECT_EQ(wd::decayed_attempts(12345, wd::DECAY_SCALE), uint64_t(12345)); // x1.0
}

// ---- #450 consumer-rewire byte-identity invariance ----------------------
//
// Pins the share_tracker.hpp rewire (init_decay_table /
// get_v36_decayed_cumulative_weights / dump_v36_pplns_walk) onto this SSOT.
// The OLD path below recomputes decay_per and the iterative decay table with
// the open-coded literals (1<<40, 693147, 1e6, max(CL/4,1)) exactly as the
// three sites did before #450; the SSOT path sources the rate from
// wd::decay_per_share / wd::DECAY_SCALE / wd::DECAY_PRECISION. Both run the
// SAME unsigned __int128 mul-shift used by the production mul128_shift /
// uint288 hot path, so this proves the rewire is value-invariant
// (byte-for-byte) across the full decayed-cumulative-weight vector. The OLD
// path is independent of the helper under test -> NON-CIRCULAR.

TEST(DgbWeightDecay, DecayedCumulativeWeightVectorInvariance) {
    using uint128 = unsigned __int128;
    const uint32_t CL = 8640; // V36 DGB chain length

    // --- OLD open-coded decay_per (literals, pre-#450) ---
    const uint64_t old_half_life = std::max(CL / 4u, 1u);
    const uint64_t old_decay_per =
        (uint64_t(1) << 40)
      - ((uint64_t(1) << 40) * 693147ull) / (1000000ull * old_half_life);

    // --- SSOT decay_per ---
    const uint64_t ssot_decay_per = wd::decay_per_share(CL);

    ASSERT_EQ(ssot_decay_per, old_decay_per);

    // Synthetic share window: distinct attempts + donation per depth.
    const std::vector<uint64_t> att = {
        1000ull, 999983ull, 2500000ull, 65535ull,
        1ull, 123456789ull, 42ull, 7777777ull,
    };
    const std::vector<uint64_t> don = { 0, 100, 32767, 65535, 1, 12345, 200, 65534 };
    const size_t N = att.size();

    // --- OLD path: iterative decay table via uint128 mul-shift ---
    std::vector<uint64_t> old_table(N);
    old_table[0] = (uint64_t(1) << 40); // DECAY_SCALE
    for (size_t d = 1; d < N; ++d)
        old_table[d] =
            (uint64_t)((uint128(old_table[d-1]) * old_decay_per) >> 40);

    // --- SSOT path: same uint128 mul-shift, SSOT-sourced constants/rate ---
    std::vector<uint64_t> ssot_table(N);
    ssot_table[0] = wd::DECAY_SCALE;
    for (size_t d = 1; d < N; ++d)
        ssot_table[d] = (uint64_t)(
            (uint128(ssot_table[d-1]) * ssot_decay_per) >> wd::DECAY_PRECISION);

    // Decay-table vectors must be element-by-element identical.
    ASSERT_EQ(old_table.size(), ssot_table.size());
    for (size_t d = 0; d < N; ++d)
        EXPECT_EQ(old_table[d], ssot_table[d]) << "decay_table depth " << d;

    // Per-depth decayed attempts + addr/donation split + running cumulative
    // totals, mirroring the consumer's uint288 hot path (replicated with
    // uint128 here; the SSOT scalar decayed_attempts is uint64-only so it is
    // intentionally NOT used for the att*table widening).
    uint128 old_cum_total = 0, old_cum_don = 0;
    uint128 ssot_cum_total = 0, ssot_cum_don = 0;
    for (size_t d = 0; d < N; ++d) {
        const uint128 old_dec = (uint128(att[d]) * old_table[d]) >> 40;
        const uint128 ssot_dec =
            (uint128(att[d]) * ssot_table[d]) >> wd::DECAY_PRECISION;
        EXPECT_EQ((uint64_t)old_dec, (uint64_t)ssot_dec) << "decayed_att depth " << d;

        const uint128 old_addr = old_dec * uint128(65535 - don[d]);
        const uint128 old_donw = old_dec * uint128(don[d]);
        const uint128 ssot_addr = ssot_dec * uint128(65535 - don[d]);
        const uint128 ssot_donw = ssot_dec * uint128(don[d]);
        EXPECT_EQ((uint64_t)old_addr, (uint64_t)ssot_addr) << "addr_w depth " << d;
        EXPECT_EQ((uint64_t)old_donw, (uint64_t)ssot_donw) << "don_w depth " << d;

        old_cum_total  += old_addr + old_donw;
        old_cum_don    += old_donw;
        ssot_cum_total += ssot_addr + ssot_donw;
        ssot_cum_don   += ssot_donw;
        EXPECT_EQ((uint64_t)old_cum_total, (uint64_t)ssot_cum_total)
            << "cum_total depth " << d;
        EXPECT_EQ((uint64_t)old_cum_don, (uint64_t)ssot_cum_don)
            << "cum_don depth " << d;
    }
}

// ---- compounding decayed-cumulative walk over a chain --------------------
//
// Pins the actual V36-native PPLNS shape produced by the oracle
// p2pool/data.py get_decayed_cumulative_weights: walking shares tip->back,
// each share's attempts are scaled by the running decay factor for its depth
// and the cumulative (prefix-sum) weights are what feed the PPLNS payout
// split. The per-share factor tests above pin single factors; this exercises
// the prefix-sum COMPOSITION over a chain via the SSOT decayed_attempts
// primitive.
//
// The per-depth running factors are passed in as literals rather than
// recomputed in-loop on purpose: factor[d] = decay_per^d in 40-bit fixed
// point, and a fp*fp product (~2^80) overflows uint64 -- the production hot
// path uses a precomputed decay table for exactly this reason, and the SSOT
// deliberately exposes only the single-step primitive. factor[1] is asserted
// to equal decay_per_share(cl), tying the table's first step back to the SSOT.
//
// All goldens (factors, decayed, cumulative) are HAND-DERIVED from the oracle
// expression in an independent Python reference (NON-CIRCULAR).
#include <vector>

namespace {
struct WalkResult {
    std::vector<uint64_t> decayed;
    std::vector<uint64_t> cumulative;
    uint64_t total = 0;
};
// decayed[i] = decayed_attempts(att[i], factor[i]); cumulative = prefix sum.
inline WalkResult decayed_cumulative_walk(const std::vector<uint64_t>& atts_tip_first,
                                          const std::vector<uint64_t>& depth_factors) {
    WalkResult r;
    for (size_t i = 0; i < atts_tip_first.size(); ++i) {
        const uint64_t d = wd::decayed_attempts(atts_tip_first[i], depth_factors[i]);
        r.decayed.push_back(d);
        r.total += d;
        r.cumulative.push_back(r.total);
    }
    return r;
}
} // namespace

TEST(DgbWeightDecay, DecayedCumulativeWalkV36ChainLength) {
    // V36 DGB CHAIN_LENGTH = 8640 (half_life 2160), six equal shares tip->back.
    const std::vector<uint64_t> factors{1099511627776, 1099158792968, 1098806071385,
                                        1098453462991, 1098100967749, 1097748585623};
    EXPECT_EQ(factors[0], wd::DECAY_SCALE);            // depth 0 == 1.0
    EXPECT_EQ(factors[1], wd::decay_per_share(8640));  // depth 1 == one SSOT step
    const auto r = decayed_cumulative_walk(
        {1000000, 1000000, 1000000, 1000000, 1000000, 1000000}, factors);
    EXPECT_EQ(r.decayed,
              (std::vector<uint64_t>{1000000, 999679, 999358, 999037, 998717, 998396}));
    EXPECT_EQ(r.cumulative,
              (std::vector<uint64_t>{1000000, 1999679, 2999037, 3998074, 4996791, 5995187}));
    EXPECT_EQ(r.total, uint64_t(5995187));
}

TEST(DgbWeightDecay, DecayedCumulativeWalkBaselineChainLength) {
    // Older p2pool-dgb-scrypt baseline CHAIN_LENGTH = 2880 (half_life 720).
    const std::vector<uint64_t> factors{1099511627776, 1098453123351,
                                        1097395637952, 1096339170599};
    EXPECT_EQ(factors[1], wd::decay_per_share(2880));
    const auto r = decayed_cumulative_walk({800000, 800000, 800000, 800000}, factors);
    EXPECT_EQ(r.decayed, (std::vector<uint64_t>{800000, 799229, 798460, 797691}));
    EXPECT_EQ(r.cumulative, (std::vector<uint64_t>{800000, 1599229, 2397689, 3195380}));
    EXPECT_EQ(r.total, uint64_t(3195380));
}

TEST(DgbWeightDecay, DecayedCumulativeWalkVisibleDecayTinyHalfLife) {
    // half_life=2 (CL=8) makes the compounding visible (~0.653 retained per hop).
    const std::vector<uint64_t> factors{1099511627776, 718450034647,
                                        469454291564, 306753874646};
    EXPECT_EQ(factors[1], wd::decay_per_share(8));
    const auto r = decayed_cumulative_walk({1000, 1000, 1000, 1000}, factors);
    EXPECT_EQ(r.decayed, (std::vector<uint64_t>{1000, 653, 426, 278}));
    EXPECT_EQ(r.cumulative, (std::vector<uint64_t>{1000, 1653, 2079, 2357}));
    EXPECT_EQ(r.total, uint64_t(2357));
}
