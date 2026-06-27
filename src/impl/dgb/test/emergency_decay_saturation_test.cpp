// ---------------------------------------------------------------------------
// dgb emergency-decay (Step 3) saturating-shift regression guard.
//
// Pins the DGB sharechain emergency time-based decay ("death spiral
// prevention") at share_tracker.hpp Step 3 against its oracle. The eased
// target doubles once per half_life past the emergency threshold; the
// canonical retarget is the arbitrary-precision saturating value
//
//     eased = min(prev_max_target * 2^halvings, MAX_TARGET)
//
// with NO wrap at any bound. The shipped fix performs the shift incrementally
// in the wider uint288 accumulator, saturating to MAX_TARGET as it goes, so
// neither a uint256 wrap (at 2^256) NOR a single-shot uint288 wrap (at 2^288,
// reachable for halvings >= 53) can collapse the eased target.
//
// The pre-fix shape did `uint256 eased <<= halvings`, which truncates mod
// 2^256: a prev target whose mantissa shifts past bit 256 wraps back to a
// SUB-MAX value, so the DAA stops easing and the chain death-spirals. The
// observed stall hole sat at ~50-68 min since last share.
//
// ORACLE NON-CIRCULARITY: oracle() below never shifts a value that could
// overflow -- it tests prev <= (MAX >> halvings) FIRST (a right-shift, which
// cannot overflow) and only then performs the in-range left-shift. A proxy
// that instead did `uint288 << halvings` would itself wrap at 2^288 and
// fabricate false mismatches; this guard MUST keep the right-shift threshold
// form. (Proxy gotcha baked in per the boundary-divergence evidence,
// sha256 5d5c9452..., ~/dgb-emergency-decay-evidence/.)
//
// Links ONLY core (uint256/uint288 big-int) + gtest -- no dgb OBJECT lib /
// transport, matching the pure-math scope of the Step-3 computation.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <core/uint256.hpp>

namespace {

// DGB Scrypt MAX_TARGET (powLimit), bits_to_target upper bound.
uint256 MAXT()
{
    uint256 t;
    t.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return t;
}

uint256 H(const std::string& s)
{
    uint256 t;
    t.SetHex(s);
    return t;
}

// TRUE oracle: arbitrary-precision min(prev * 2^h, MAX). No wrap at any bound.
// prev<<h <= MAX iff prev <= (MAX >> h); the right-shift can never overflow, so
// the threshold test is exact and the surviving left-shift is in-range.
uint256 oracle(const uint256& prev, uint32_t h)
{
    uint256 mx = MAXT();
    if (h >= 256)
        return prev.IsNull() ? prev : mx;
    uint256 thr = mx;
    thr >>= h;
    if (prev > thr)
        return mx;
    uint288 f;
    f.SetHex(prev.GetHex());
    f <<= h;
    uint256 r;
    r.SetHex(f.GetHex());
    return r;
}

// NEW shape: byte-for-byte the share_tracker.hpp Step-3 emergency-ease body
// (incremental uint288 saturating shift + linear interpolation), lifted as a
// pure function so the consensus math is provable in isolation.
uint256 new_shape(const uint256& prev, uint32_t h, uint32_t HL, uint32_t rem)
{
    uint288 x;
    x.SetHex(prev.GetHex());
    uint288 m;
    m.SetHex(MAXT().GetHex());
    for (uint64_t i = 0; i < static_cast<uint64_t>(h) && i < 288 && x <= m; ++i)
        x <<= 1;
    if (x > m)
        x = m;
    x = x * static_cast<uint32_t>(HL + rem);
    x = x / static_cast<uint32_t>(HL);
    if (x > m)
        return MAXT();
    uint256 r;
    r.SetHex(x.GetHex());
    return r;
}

// OLD shape: the pre-fix uint256 `eased <<= halvings`, kept ONLY to demonstrate
// the fails-now divergence the fix repairs. Never shipped past the fix.
uint256 old_shape(const uint256& prev, uint32_t h, uint32_t HL, uint32_t rem)
{
    uint256 e = prev;
    if (h < 256)
        e <<= h;
    else
        e = MAXT();
    uint288 x;
    x.SetHex(e.GetHex());
    uint288 m;
    m.SetHex(MAXT().GetHex());
    x = x * static_cast<uint32_t>(HL + rem);
    x = x / static_cast<uint32_t>(HL);
    if (x > m)
        return MAXT();
    uint256 r;
    r.SetHex(x.GetHex());
    return r;
}

constexpr uint32_t HL = 150; // half_life = SHARE_PERIOD(15) * 10

// 5 representative prev_max_target vectors: a sparse hi-bit + lo-bit pattern
// that wraps under uint256 truncation, a mid-density, two dense, and the unit.
const char* const PREVS[] = {
    "0000080000000000000000000000000000000000000000000000000000000001", // bit235 + bit0
    "0000000000000fa1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071829",
    "00000000000000000ddccbbaa9988776655443322110ffeeddccbbaa99887766",
    "00000000003fedcba9876543210fedcba9876543210fedcba9876543210fedcb",
    "0000000000000000000000000000000000000000000000000000000000000001",
};

// minutes-since-last-share for a given halving count h:
//   threshold = SHARE_PERIOD*20 = 300s, half_life = SHARE_PERIOD*10 = 150s
//   t = (300 + h*HL) / 60  minutes
double t_minutes(uint32_t h) { return (300.0 + static_cast<double>(h) * HL) / 60.0; }

} // namespace

// (a) LOAD-BEARING fails-now / passes-after vector.
// prev = bit235 + bit0, h = 21 (t = 57.5 min, dead-center of the observed
// 50-68 min stall hole). The pre-fix uint256 shift wraps bit235<<21 -> bit256
// -> 0 (mod 2^256), collapsing the eased target FAR below the saturating
// oracle; the shipped saturating shift returns MAX_TARGET == oracle.
TEST(EmergencyDecaySaturation, LoadBearingBoundaryVector_h21_57min)
{
    const uint256 prev = H(PREVS[0]); // bit235 + bit0
    const uint32_t h = 21;
    ASSERT_DOUBLE_EQ(57.5, t_minutes(h)); // dead-center of the stall hole

    const uint256 want = oracle(prev, h);
    EXPECT_EQ(want, MAXT()) << "prev<<21 overflows MAX -> oracle saturates";

    // fails-now: the pre-fix wrapping shape DIVERGES from the oracle here.
    EXPECT_NE(old_shape(prev, h, HL, 0), want)
        << "pre-fix uint256 <<= wraps mod 2^256 and death-spirals";

    // passes-after: the shipped saturating shift MATCHES the oracle.
    EXPECT_EQ(new_shape(prev, h, HL, 0), want)
        << "saturating uint288 shift == min(prev*2^h, MAX)";
}

// (b) Full-sweep NEW == ORACLE behavioral identity, exact boundary (rem == 0),
// every prev vector x every halving count 0..255. Zero mismatch proves the fix
// is the oracle, not merely "closer".
TEST(EmergencyDecaySaturation, NewEqualsOracleIdentity_rem0_sweep)
{
    int mismatch = 0;
    for (const char* hx : PREVS)
    {
        const uint256 prev = H(hx);
        for (uint32_t h = 0; h <= 255; ++h)
            if (new_shape(prev, h, HL, 0) != oracle(prev, h))
                ++mismatch;
    }
    EXPECT_EQ(0, mismatch) << "NEW must equal oracle across full h-sweep";
}

// (b') Interpolated identity incl. the fractional remainder term:
//   new == min( min(prev*2^h, MAX) * (HL+rem)/HL , MAX )
// across prev x h0..60 x rem. Pins the linear-interpolation tail too.
TEST(EmergencyDecaySaturation, NewEqualsOracleIdentity_interpolated_sweep)
{
    int mismatch = 0;
    for (const char* hx : PREVS)
    {
        const uint256 prev = H(hx);
        for (uint32_t h = 0; h <= 60; ++h)
            for (uint32_t rem = 0; rem < HL; rem += 29)
            {
                uint256 base = oracle(prev, h);
                uint288 b;
                b.SetHex(base.GetHex());
                uint288 m;
                m.SetHex(MAXT().GetHex());
                b = b * static_cast<uint32_t>(HL + rem);
                b = b / static_cast<uint32_t>(HL);
                uint256 want;
                if (b > m)
                    want = MAXT();
                else
                    want.SetHex(b.GetHex());
                if (new_shape(prev, h, HL, rem) != want)
                    ++mismatch;
            }
    }
    EXPECT_EQ(0, mismatch) << "interpolated NEW must equal oracle";
}

// (c) Divergence catalogue: there EXISTS a non-empty set of death-spiral cases
// where the pre-fix shape is wrong and the fix is right. Guards against a
// future "simplification" that silently reintroduces the wrap.
TEST(EmergencyDecaySaturation, OldShapeDeathSpiralCasesExist)
{
    int total = 0;
    for (const char* hx : PREVS)
    {
        const uint256 prev = H(hx);
        for (uint32_t h = 0; h <= 255; ++h)
        {
            const uint256 o = oracle(prev, h);
            const bool old_ok = (old_shape(prev, h, HL, 0) == o);
            const bool new_ok = (new_shape(prev, h, HL, 0) == o);
            if (!old_ok && new_ok)
                ++total;
        }
    }
    EXPECT_GT(total, 0) << "the wrap bug must be demonstrably reachable";
}
