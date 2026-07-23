// ---------------------------------------------------------------------------
// DGB dgb_arith256 128-bit primitives KAT -- the guard for #690 (MSVC
// portability rework of the DigiShield 256-bit retarget arithmetic).
//
// dgb_arith256.hpp evaluates the DigiShield damped multiply avg*mul/div at true
// 256-bit width via three 128-bit primitives (mul_add_u128 / div_u128 /
// add_u128). GCC/Clang express them with unsigned __int128; MSVC (no __int128,
// error C4235) uses the x64 intrinsics _umul128 / _udiv128 that lower to the
// SAME mul/div/add-with-carry. The claim "both branches bit-identical" is
// CONSENSUS-critical (a divergent limb would compute a different next target and
// fork from DigiByte Core / p2pool-merged-v36), so it is PROVEN here, not
// asserted -- mirroring the bch #688 muldiv_kat precedent.
//
// The MSVC intrinsics cannot be compiled/run on the Linux/macOS CI, so the
// header exposes a third, fully SOFTWARE implementation (detail::*_portable /
// u256_portable, pure 32-bit-limb, no __int128, no intrinsic) as an independent
// oracle. This test proves software == native across the DigiShield operand
// domain plus a deterministic wide fuzz; since the x64 _umul128/_udiv128 are by
// ISA definition the exact 64x64->128 product and 128/64 quotient the software
// reproduces, native == portable on Linux certifies the MSVC path too.
//
// Pure header math: depends only on <cstdint>. No node / RPC / consensus link.
// p2pool-merged-v36 surface: NONE (local DigiShield retarget compute only).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <gtest/gtest.h>

#include <impl/dgb/coin/dgb_arith256.hpp>

using dgb::coin::u256;
using dgb::coin::u256_portable;
using dgb::coin::mul_div_u256;
using dgb::coin::mul_div_u256_portable;
namespace detail = dgb::coin::detail;

namespace {

constexpr uint64_t U64MAX = ~uint64_t(0);

// Deterministic 64-bit LCG (no <random>, no Date/rand) -- reproducible vectors.
struct Lcg {
    uint64_t s;
    explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; }
};

u256 make(uint64_t l3, uint64_t l2, uint64_t l1, uint64_t l0) {
    u256 r; r.limb[3] = l3; r.limb[2] = l2; r.limb[1] = l1; r.limb[0] = l0; return r;
}

// The DigiShield operand domain: avg_target shapes near pow_limit (~2^224) and
// across the 256-bit truncation boundary, plus small/identity values.
const u256 kTargets[] = {
    make(0, 0, 0, 0),
    make(0, 0, 0, 1),
    make(0, 0, 0, 4096),
    make(0, 0, 0, U64MAX),
    make(0, 0, 1, 0),                                   // 2^64
    make(0x00000000ffffffffULL, U64MAX, U64MAX, U64MAX),// pow_limit-ish (~2^224)
    make(0x8000000000000000ULL, 0, 0, 0),               // 2^255 (mul-by-2 truncates)
    make(U64MAX, U64MAX, U64MAX, U64MAX),               // 2^256 - 1
    make(0x0123456789abcdefULL, 0xfedcba9876543210ULL,
         0x0f1e2d3c4b5a6978ULL, 0x8796a5b4c3d2e1f0ULL), // dense mixed limbs
};

// Scalars the damped multiply / divide actually apply: DigiShield timespans
// (60s block, MultiShield windows) plus wide stressors up to 2^64-1.
const uint64_t kScalars[] = {
    1, 2, 3, 60, 75, 90, 150, 3600, 37938,
    (1ULL << 32), (1ULL << 40) + 1, (1ULL << 62),
    0x8000000000000001ULL, U64MAX - 1, U64MAX,
};

} // namespace

// ---- primitive layer: native vs portable, exact ---------------------------

TEST(Arith256Muldiv, MulAddPrimitiveNativeEqualsPortable) {
    for (uint64_t a : kScalars)
        for (uint64_t b : kScalars)
            for (uint64_t add : {uint64_t(0), uint64_t(1), U64MAX, uint64_t(0x1234567800000000ULL)}) {
                uint64_t hn, hp;
                uint64_t ln = detail::mul_add_u128(a, b, add, hn);
                uint64_t lp = detail::mul_add_u128_portable(a, b, add, hp);
                EXPECT_EQ(ln, lp) << "lo a=" << a << " b=" << b << " add=" << add;
                EXPECT_EQ(hn, hp) << "hi a=" << a << " b=" << b << " add=" << add;
            }
}

TEST(Arith256Muldiv, AddPrimitiveNativeEqualsPortable) {
    for (uint64_t a : kScalars)
        for (uint64_t b : kScalars)
            for (uint64_t cin : {uint64_t(0), uint64_t(1)}) {
                uint64_t cn, cp;
                uint64_t sn = detail::add_u128(a, b, cin, cn);
                uint64_t sp = detail::add_u128_portable(a, b, cin, cp);
                EXPECT_EQ(sn, sp);
                EXPECT_EQ(cn, cp);
            }
}

// Direct stress of the _udiv128 precondition (hi < d): feed hi at the MAXIMAL
// running-remainder boundary (hi = d-1) so any mishandling of the top-bit /
// running-remainder in the software long division surfaces as a diff vs native
// rather than as MSVC UB in the field.
TEST(Arith256Muldiv, DivPrimitiveRunningRemainderBoundary) {
    const uint64_t ds[] = {2, 3, 7, 60, 90, 4096, (1ULL << 40),
                           0x8000000000000000ULL, 0x8000000000000001ULL,
                           U64MAX - 1, U64MAX};
    const uint64_t los[] = {0, 1, 2, U64MAX, 0x0f0f0f0f0f0f0f0fULL,
                            0x8000000000000000ULL, 0xdeadbeefcafef00dULL};
    for (uint64_t d : ds) {
        for (uint64_t hi : {uint64_t(0), uint64_t(1), d / 2, d - 1}) { // all < d
            for (uint64_t lo : los) {
                uint64_t rn, rp;
                uint64_t qn = detail::div_u128(hi, lo, d, rn);
                uint64_t qp = detail::div_u128_portable(hi, lo, d, rp);
                EXPECT_EQ(qn, qp) << "q hi=" << hi << " lo=" << lo << " d=" << d;
                EXPECT_EQ(rn, rp) << "r hi=" << hi << " lo=" << lo << " d=" << d;
                EXPECT_LT(rp, d)  << "remainder must be < divisor";
            }
        }
    }
}

// ---- u256 layer: mul_u64 / div_u64 / operator+= native vs portable --------

TEST(Arith256Muldiv, U256OpsNativeEqualsPortable) {
    for (const u256& t : kTargets) {
        u256_portable tp(t);
        for (uint64_t m : kScalars) {
            EXPECT_TRUE(tp.mul_u64(m).equals(t.mul_u64(m)))
                << "mul_u64 m=" << m;
            EXPECT_TRUE(tp.div_u64(m).equals(t.div_u64(m)))  // m != 0 for all kScalars
                << "div_u64 d=" << m;
        }
        for (const u256& o : kTargets) {
            u256 sn = t;  sn += o;
            u256_portable sp = tp; sp += u256_portable(o);
            EXPECT_TRUE(sp.equals(sn)) << "operator+=";
        }
    }
}

// Full damped-multiply pipeline avg*mul/div at 256 bits, native vs portable.
TEST(Arith256Muldiv, MulDivPipelineNativeEqualsPortable) {
    for (const u256& t : kTargets)
        for (uint64_t mul : kScalars)
            for (uint64_t div : kScalars) {          // div != 0
                u256 n = mul_div_u256(t, mul, div);
                u256_portable p = mul_div_u256_portable(u256_portable(t), mul, div);
                EXPECT_TRUE(p.equals(n))
                    << "avg*mul/div mul=" << mul << " div=" << div;
            }
}

// ---- hand-verified cross-platform known answers (hold on MSVC too) ---------

TEST(Arith256Muldiv, HandVerifiedKnownAnswers) {
    // u64-range proxy identities (the pre-256-bit slices relied on these).
    EXPECT_EQ(mul_div_u256(u256::from_u64(1000000), 90, 60).low64(), 1500000ULL);
    EXPECT_EQ(mul_div_u256(u256::from_u64(4096), 1, 1).low64(), 4096ULL);

    // 256-bit truncation: 2^255 * 2 == 2^256 == 0 (mod 2^256). The DIVERGENCE
    // point vs a 128/wider proxy -- carry past limb[3] is dropped.
    EXPECT_TRUE(make(0x8000000000000000ULL,0,0,0).mul_u64(2).is_zero());
    // (2^256 - 1) * 2 == 2^256 - 2 (low 256 bits).
    {
        u256 r = make(U64MAX,U64MAX,U64MAX,U64MAX).mul_u64(2);
        EXPECT_EQ(r.limb[0], U64MAX - 1);
        EXPECT_EQ(r.limb[1], U64MAX);
        EXPECT_EQ(r.limb[2], U64MAX);
        EXPECT_EQ(r.limb[3], U64MAX);
    }
    // (2^256 - 1) / 2 == 2^255 - 1.
    {
        u256 r = make(U64MAX,U64MAX,U64MAX,U64MAX).div_u64(2);
        EXPECT_EQ(r.limb[3], 0x7fffffffffffffffULL);
        EXPECT_EQ(r.limb[2], U64MAX);
        EXPECT_EQ(r.limb[1], U64MAX);
        EXPECT_EQ(r.limb[0], U64MAX);
    }
    // portable oracle independently satisfies the same truncation KATs.
    EXPECT_TRUE(u256_portable(make(0x8000000000000000ULL,0,0,0)).mul_u64(2)
                    .equals(make(0,0,0,0)));
}

// ---- deterministic wide fuzz: native == portable over full-width operands --

TEST(Arith256Muldiv, WideDeterministicFuzz) {
    Lcg rng(0x9E3779B97F4A7C15ULL);
    int checked = 0;
    for (int i = 0; i < 100000; ++i) {
        u256 t = make(rng.next(), rng.next(), rng.next(), rng.next());
        u256_portable tp(t);
        uint64_t m = rng.next();
        uint64_t d = rng.next(); if (d == 0) d = 1;

        ASSERT_TRUE(tp.mul_u64(m).equals(t.mul_u64(m)))  << "mul fuzz i=" << i;
        ASSERT_TRUE(tp.div_u64(d).equals(t.div_u64(d)))  << "div fuzz i=" << i;
        u256 sn = t; sn += t;
        u256_portable sp = tp; sp += tp;
        ASSERT_TRUE(sp.equals(sn)) << "add fuzz i=" << i;
        ASSERT_TRUE(mul_div_u256_portable(tp, m, d).equals(mul_div_u256(t, m, d)))
            << "pipeline fuzz i=" << i;
        ++checked;
    }
    EXPECT_GT(checked, 1000);
}
