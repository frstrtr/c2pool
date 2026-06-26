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

// ===================================================================
// #450 VALUE-INVARIANCE KAT -- proves the share_tracker.hpp rewire onto
// the SSOT is byte-identical to the prior open-coded arithmetic.
//
// Each of the three rewired sites (init_decay_table, get_v36_decayed_
// cumulative_weights, dump_v36_pplns_walk) previously computed:
//     half_life = max(chain_length / 4, 1)
//     decay_per = SCALE - (SCALE * 693147) / (1e6 * half_life)
//     decay_fp_{d+1} = mul128_shift(decay_fp_d, decay_per, 40)
//     decayed_att   = (att * decay_fp) >> 40
// inline. The rewire routes half_life/decay_per/constants through the SSOT
// while leaving the mul128_shift decay_fp walk + the uint288 hot-path
// widening open-coded (the consensus/wire bytes). This KAT re-evaluates
// the FULL decayed-cumulative-weight vector via the OLD literal expressions
// and via the SSOT helpers over a depth + chain-length sweep and asserts
// equality -- the proof the merge needs.
//
// mul128_shift is reproduced verbatim from share_tracker.hpp; it is the
// SAME function on both arms (unchanged by the rewire), so it cancels and
// the comparison isolates exactly what moved into the SSOT.
namespace {
inline uint64_t mul128_shift_ref(uint64_t a, uint64_t b, unsigned shift) {
    return static_cast<uint64_t>((static_cast<__uint128_t>(a) * b) >> shift);
}

// OLD open-coded constants (pre-rewire literals).
constexpr uint64_t OLD_SCALE = uint64_t(1) << 40;
constexpr uint64_t OLD_LN2   = 693147;
inline uint32_t old_half_life(uint32_t cl) { return std::max(cl / 4, uint32_t(1)); }
inline uint64_t old_decay_per(uint32_t cl) {
    return OLD_SCALE - (OLD_SCALE * OLD_LN2) / (uint64_t(1000000) * old_half_life(cl));
}
} // namespace

TEST(DgbWeightDecay, RewireConstantsValueInvariant) {
    for (uint32_t cl : {8640u, 2880u, 3600u, 720u, 100u, 8u, 4u, 3u, 1u, 0u}) {
        EXPECT_EQ(old_half_life(cl), wd::half_life(cl)) << "half_life cl=" << cl;
        EXPECT_EQ(old_decay_per(cl), wd::decay_per_share(cl)) << "decay_per cl=" << cl;
        EXPECT_EQ(wd::DECAY_SCALE, OLD_SCALE);
        EXPECT_EQ(wd::DECAY_PRECISION, 40u);
    }
}

// Full decayed-cumulative-weight vector: old expressions vs SSOT helpers.
TEST(DgbWeightDecay, DecayedCumulativeWeightVectorInvariant) {
    for (uint32_t cl : {8640u, 2880u, 720u, 4u}) {
        const uint64_t old_per = old_decay_per(cl);
        const uint64_t new_per = wd::decay_per_share(cl);
        ASSERT_EQ(old_per, new_per);

        uint64_t old_fp = OLD_SCALE;
        uint64_t new_fp = wd::DECAY_SCALE;
        uint64_t old_cum_addr = 0, new_cum_addr = 0;
        uint64_t old_cum_total = 0, new_cum_total = 0;

        const int depths = 64;
        for (int d = 0; d < depths; ++d) {
            for (uint64_t att : {uint64_t(65535), uint64_t(1000), uint64_t(7), uint64_t(0)}) {
                for (uint32_t don : {0u, 1u, 100u, 65535u}) {
                    uint64_t old_dec = (att * old_fp) >> 40;
                    uint64_t old_addr = old_dec * (65535 - don);
                    uint64_t old_don  = old_dec * don;
                    uint64_t new_dec = wd::decayed_attempts(att, new_fp);
                    uint64_t new_addr = new_dec * (65535 - don);
                    uint64_t new_don  = new_dec * don;

                    EXPECT_EQ(old_dec, new_dec) << "cl=" << cl << " d=" << d << " att=" << att;
                    EXPECT_EQ(old_addr, new_addr);
                    EXPECT_EQ(old_don, new_don);

                    old_cum_addr += old_addr; new_cum_addr += new_addr;
                    old_cum_total += old_addr + old_don;
                    new_cum_total += new_addr + new_don;
                }
            }
            old_fp = mul128_shift_ref(old_fp, old_per, 40);
            new_fp = mul128_shift_ref(new_fp, new_per, 40);
            ASSERT_EQ(old_fp, new_fp) << "decay_fp drift cl=" << cl << " d=" << d;
        }
        EXPECT_EQ(old_cum_addr, new_cum_addr)   << "cumulative addr weight cl=" << cl;
        EXPECT_EQ(old_cum_total, new_cum_total) << "cumulative total weight cl=" << cl;
    }
}
