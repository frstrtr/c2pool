// ---------------------------------------------------------------------------
// dgb M3 §7b HeaderChain Scrypt-only validate() + retarget-body guard.
//
// Pins the THIRD INVARIANT (coin/header_chain.hpp) at the validate() level:
//   1. Work-neutrality SSOT — only a Scrypt header credits cumulative work; a
//      continuity (known non-Scrypt) header appends but is work-neutral; an
//      unknown-algo or malformed header is rejected. The work-credit decision
//      and the retarget-window inclusion go through ONE predicate
//      (header_credits_work == is_scrypt_header) so they cannot drift.
//   2. Retarget continuity-skip — a continuity header sitting INSIDE the
//      nominal window is excluded from the Scrypt target computation: it never
//      reaches avg_target nor widens actual_timespan. A naive all-headers
//      window would corrupt both; this proves it can't.
//
// Links the header-only chain helpers + gtest, plus the btclibs Scrypt PoW TU
// set (scrypt.cpp + the SHA256 family) so the M3 7b digest conversion runs
// against the REAL scrypt_1024_1_1_256 hash -- NOT the full btclibs archive,
// NOT the dgb OBJECT lib / transport. MUST appear in BOTH the test/CMakeLists
// dedicated target block AND both build.yml --target allowlists, or it becomes
// a #143 NOT_BUILT sentinel.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstring>
#include <limits>

#include <gtest/gtest.h>

#include <impl/dgb/coin/header_chain.hpp>
#include <btclibs/crypto/scrypt.h>

using namespace c2pool::dgb;
using dgb::coin::DGB_BLOCK_VERSION_SCRYPT;
using dgb::coin::DGB_BLOCK_VERSION_SHA256D;
using dgb::coin::DGB_BLOCK_VERSION_SKEIN;

static constexpr int32_t PRIMARY = 2; // BLOCK_VERSION_DEFAULT
static constexpr int32_t SCRYPT  = PRIMARY | DGB_BLOCK_VERSION_SCRYPT;
static constexpr int32_t SHA256D = PRIMARY | DGB_BLOCK_VERSION_SHA256D;
static constexpr int32_t SKEIN   = PRIMARY | DGB_BLOCK_VERSION_SKEIN;
static constexpr int32_t UNKNOWN_ALGO = PRIMARY | (10 << 8); // not a known codepoint

TEST(HeaderChainValidate, ScryptCreditsWorkContinuityIsNeutral)
{
    HeaderChain hc;
    EXPECT_EQ(hc.validate_and_append({SCRYPT, 1000, 100}),
              IngestResult::VALIDATED_SCRYPT);
    const uint64_t after_one = hc.cumulative_work();
    EXPECT_GT(after_one, 0u);

    // Continuity header: appended, but ZERO work credited.
    EXPECT_EQ(hc.validate_and_append({SHA256D, 1075, 999999}),
              IngestResult::ACCEPTED_CONTINUITY);
    EXPECT_EQ(hc.cumulative_work(), after_one);   // work-neutral
    EXPECT_EQ(hc.size(), 2u);                     // but chain extended
}

TEST(HeaderChainValidate, RejectsUnknownAlgoAndMalformedScrypt)
{
    HeaderChain hc;
    EXPECT_EQ(hc.validate_and_append({UNKNOWN_ALGO, 1000, 100}),
              IngestResult::REJECTED);
    EXPECT_EQ(hc.validate_and_append({SCRYPT, 1000, 0}),   // zero target
              IngestResult::REJECTED);
    EXPECT_EQ(hc.size(), 0u);                  // neither appended
    EXPECT_EQ(hc.cumulative_work(), 0u);       // no work credited
}

TEST(HeaderChainValidate, ContinuityHeaderInsideWindowSkippedFromTarget)
{
    // oldest..newest: S(100) , sha(cheap) , S(100) , S(100)
    // The continuity header sits between two Scrypt samples, INSIDE a window=3.
    HeaderChain hc;
    ASSERT_EQ(hc.validate_and_append({SCRYPT,  1000, 100}),    IngestResult::VALIDATED_SCRYPT);
    ASSERT_EQ(hc.validate_and_append({SHA256D, 1075, 999999}), IngestResult::ACCEPTED_CONTINUITY);
    ASSERT_EQ(hc.validate_and_append({SCRYPT,  1150, 100}),    IngestResult::VALIDATED_SCRYPT);
    ASSERT_EQ(hc.validate_and_append({SCRYPT,  1225, 100}),    IngestResult::VALIDATED_SCRYPT);

    const RetargetWindow rw = hc.next_retarget_window(3);

    EXPECT_TRUE(rw.sufficient);
    EXPECT_EQ(rw.scrypt_samples, 3u);
    // Scrypt-only average: (100+100+100)/3 == 100. A naive all-headers window
    // would fold the cheap 999999 target in and blow this up.
    EXPECT_EQ(rw.avg_target, 100u);
    // Timespan spans the newest..oldest SCRYPT samples (1225 - 1000 == 225),
    // NOT the naive newest..3rd-back-header span (1225 - 1075 == 150).
    EXPECT_EQ(rw.actual_timespan, 225);
    EXPECT_NE(rw.actual_timespan, 150);

    // The continuity header was work-neutral: only the 3 Scrypt headers count.
    EXPECT_EQ(hc.size(), 4u);
    EXPECT_EQ(hc.cumulative_work(), 3u * (UINT64_MAX / 100));
}

TEST(HeaderChainValidate, AllScryptWindowIsContiguous)
{
    HeaderChain hc;
    hc.validate_and_append({SCRYPT, 1000, 200});
    hc.validate_and_append({SCRYPT, 1100, 100});
    hc.validate_and_append({SCRYPT, 1200, 300});
    const RetargetWindow rw = hc.next_retarget_window(3);
    EXPECT_TRUE(rw.sufficient);
    EXPECT_EQ(rw.scrypt_samples, 3u);
    EXPECT_EQ(rw.avg_target, (200u + 100u + 300u) / 3u);
    EXPECT_EQ(rw.actual_timespan, 200);   // 1200 - 1000
}

TEST(HeaderChainValidate, InsufficientWindowFlaggedNotSufficient)
{
    // Only 2 Scrypt samples exist; a window of 4 is under-filled (early chain).
    HeaderChain hc;
    hc.validate_and_append({SCRYPT,  1000, 100});
    hc.validate_and_append({SKEIN,   1050, 555});   // continuity
    hc.validate_and_append({SCRYPT,  1100, 100});
    const RetargetWindow rw = hc.next_retarget_window(4);
    EXPECT_FALSE(rw.sufficient);
    EXPECT_EQ(rw.scrypt_samples, 2u);
    EXPECT_EQ(rw.avg_target, 100u);
    EXPECT_EQ(rw.actual_timespan, 100);   // 1100 - 1000, Scrypt-only
}

TEST(HeaderChainValidate, EmptyChainAndZeroWindowAreSafe)
{
    HeaderChain hc;
    EXPECT_FALSE(hc.next_retarget_window(3).sufficient);   // empty chain
    hc.validate_and_append({SCRYPT, 1000, 100});
    const RetargetWindow rw = hc.next_retarget_window(0);  // zero window
    EXPECT_FALSE(rw.sufficient);
    EXPECT_EQ(rw.scrypt_samples, 0u);
}


// ---------------------------------------------------------------------------
// DigiShield/MultiShield damped retarget multiply (digishield_next_target).
// Exercises the amplitude filter + clamp at BOTH rails plus the nominal case,
// and the pow_limit difficulty floor. Inputs are hand-built RetargetWindows so
// the multiply is pinned independently of the (already-tested) Scrypt-only
// window assembly above.
//
//   nominal target_timespan = 60  ->  floor = 60 - 60/4 = 45,
//                                      ceil  = 60 + 60/2 = 90.
// ---------------------------------------------------------------------------
static RetargetWindow make_window(uint64_t avg_target, int64_t actual_timespan)
{
    RetargetWindow rw;
    rw.scrypt_samples  = 3;
    rw.avg_target      = avg_target;
    rw.actual_timespan = actual_timespan;
    rw.sufficient      = true;
    return rw;
}

TEST(DigiShieldRetarget, NominalTimespanLeavesTargetUnchanged)
{
    // actual == nominal -> damped == nominal -> bnNew == avg_target.
    const DigiShieldParams p{60, 0};
    EXPECT_EQ(digishield_next_target(make_window(1000, 60), p), 1000u);
}

TEST(DigiShieldRetarget, CeilingRailCapsTheEasing)
{
    // actual far above nominal: damped = 60 + (1000-60)/8 = 177 -> clamps to 90.
    // bnNew = 1000 * 90 / 60 = 1500 (target relaxes by exactly the 3/2 rail).
    const DigiShieldParams p{60, 0};
    EXPECT_EQ(digishield_next_target(make_window(1000, 1000), p), 1500u);
}

TEST(DigiShieldRetarget, FloorRailCapsTheTightening)
{
    // Sharply negative timespan (out-of-order block times): damped goes well
    // below floor -> clamps to 45. bnNew = 1000 * 45 / 60 = 750 (3/4 rail).
    const DigiShieldParams p{60, 0};
    EXPECT_EQ(digishield_next_target(make_window(1000, -1000), p), 750u);
}

TEST(DigiShieldRetarget, PowLimitFloorsTheTarget)
{
    // Ceiling rail would yield 1500, but pow_limit (easiest target) caps it.
    const DigiShieldParams p{60, 1200};
    EXPECT_EQ(digishield_next_target(make_window(1000, 1000), p), 1200u);
}

TEST(DigiShieldRetarget, EmptyWindowKeepsPriorTarget)
{
    // No Scrypt samples -> 0 sentinel: caller keeps the prior target.
    RetargetWindow rw;            // scrypt_samples == 0
    const DigiShieldParams p{60, 0};
    EXPECT_EQ(digishield_next_target(rw, p), 0u);
    // Degenerate nominal is also rejected (no divide-by-zero).
    EXPECT_EQ(digishield_next_target(make_window(1000, 60), DigiShieldParams{0, 0}), 0u);
}

TEST(DigiShieldRetarget, ConsumesLiveScryptOnlyWindow)
{
    // End-to-end: the same continuity-skipped window the validate() path builds
    // (avg 100, timespan 225 over 3 Scrypt samples) feeds the multiply. With
    // nominal 225 the damped value is exactly nominal -> target unchanged at 100.
    HeaderChain hc;
    hc.validate_and_append({SCRYPT,  1000, 100});
    hc.validate_and_append({SHA256D, 1075, 999999});   // continuity, skipped
    hc.validate_and_append({SCRYPT,  1150, 100});
    hc.validate_and_append({SCRYPT,  1225, 100});
    const RetargetWindow rw = hc.next_retarget_window(3);
    ASSERT_TRUE(rw.sufficient);
    EXPECT_EQ(digishield_next_target(rw, DigiShieldParams{225, 0}), 100u);
}

// ---------------------------------------------------------------------------
// Parent-difficulty retarget gate DEMOTED to a no-op for V36 (integrator
// decision 2026-06-18, operator FYI'd). p2pool-merged-v36 never re-derives
// parent difficulty -- it trusts the declared nBits and checks PoW against it.
// DGB's live retarget is MultiShield V4 (a GLOBAL cross-algo averaging window),
// which a Scrypt-only walk cannot reproduce -> full recompute is V37 5-algo
// scope. So a declared Scrypt target that does NOT equal the single-algo
// DigiShield next-target is NO LONGER rejected by the ingest path; it is
// accepted on the daemon-independent CheckProofOfWork halves alone (pow_limit
// floor + scrypt(header) <= target). digishield_next_target() survives as test
// scaffolding / a reference for the V37 embedded-daemon port.
//
//   window depth 1, nominal 80. Window(1) over a lone Scrypt tip has
//   actual_timespan 0 (front == back) -> damped = 80 + (0-80)/8 = 70, above the
//   floor rail 60 -> reference next target = avg * 70/80 = avg * 7/8.
// ---------------------------------------------------------------------------
TEST(HeaderChainValidate, IngestRetargetGateDemotedToNoOpForV36)
{
    HeaderChain hc(DigiShieldParams{80, 0}, /*retarget_window=*/1);

    // Seed a lone Scrypt tip.
    ASSERT_EQ(hc.validate_and_append({SCRYPT, 1000, 4096}),
              IngestResult::VALIDATED_SCRYPT);

    // The single-algo DigiShield reference next-target over window(1) is
    // 4096 * 7/8 = 3584 -- still computable as V37 embedded-port scaffolding,
    // even though the ingest path no longer enforces it.
    const RetargetWindow rw = hc.next_retarget_window(1);
    EXPECT_EQ(digishield_next_target(rw, DigiShieldParams{80, 0}), 3584u);

    // A header whose declared target does NOT equal that reference (4096 != 3584)
    // is ACCEPTED and credits work: V36 trusts the declared nBits rather than
    // re-deriving and demanding an exact match.
    const uint64_t work_before = hc.cumulative_work();
    EXPECT_EQ(hc.validate_and_append({SCRYPT, 1080, 4096}),
              IngestResult::VALIDATED_SCRYPT);
    EXPECT_GT(hc.cumulative_work(), work_before);

    // The PoW satisfaction half still fires independent of the demoted gate: a
    // header whose scrypt(header) digest exceeds its declared target is rejected
    // without mutating the chain.
    HeaderSample weak{SCRYPT, 1090, 4096};
    weak.pow_hash = 4097;
    const std::size_t size_before = hc.size();
    EXPECT_EQ(hc.validate_and_append(weak), IngestResult::REJECTED);
    EXPECT_EQ(hc.size(), size_before);

    // Continuity headers remain work-neutral and bypass every PoW gate.
    EXPECT_EQ(hc.validate_and_append({SHA256D, 1100, 1}),
              IngestResult::ACCEPTED_CONTINUITY);
}


// Ingest-path minimum-difficulty ceiling: a Scrypt header declaring a target
// EASIER than pow_limit (numerically larger) is consensus-invalid REGARDLESS of
// the retarget window -- it must be rejected even on the bootstrap/empty-window
// path where the nBits-style equality gate is a no-op (expected == 0). Mirrors
// DigiByte Core CheckProofOfWork rejecting when bnTarget > bnPowLimit.
TEST(HeaderChainValidate, IngestGateRejectsTargetAbovePowLimit)
{
    // pow_limit configured, retarget_window 1. Seed empty -> equality gate is a
    // no-op, so only the ceiling can reject this first header.
    HeaderChain hc(DigiShieldParams{80, /*pow_limit=*/4096}, /*window=*/1);

    // target == pow_limit is the easiest ADMISSIBLE target (strict > reject):
    // accepted and credits work, seeding the chain.
    ASSERT_EQ(hc.validate_and_append({SCRYPT, 1000, 4096}),
              IngestResult::VALIDATED_SCRYPT);

    // A target ABOVE pow_limit (easier than the network minimum) must REJECT
    // without mutating the chain -- the ceiling is the sole rejecter here (the
    // single-algo retarget-equality gate is demoted to a no-op in V36).
    const std::size_t size_before = hc.size();
    const uint64_t    work_before = hc.cumulative_work();
    EXPECT_EQ(hc.validate_and_append({SCRYPT, 1080, 4097}),
              IngestResult::REJECTED);
    EXPECT_EQ(hc.size(),            size_before);
    EXPECT_EQ(hc.cumulative_work(), work_before);

    // pow_limit == 0 leaves the ceiling unconfigured: an enormous target is not
    // rejected by THIS gate (legacy default-ctor behaviour preserved).
    HeaderChain unconfigured;  // target_timespan 0, pow_limit 0
    EXPECT_EQ(unconfigured.validate_and_append({SCRYPT, 1000, UINT64_MAX}),
              IngestResult::VALIDATED_SCRYPT);
}

// Ingest-path PoW satisfaction (DigiByte Core CheckProofOfWork second half):
// a Scrypt header whose scrypt(header) digest is NUMERICALLY GREATER than its
// declared target does not meet the work it claims and is consensus-invalid --
// rejected without mutating the chain, independent of the retarget/ceiling
// gates. Mirrors `if (UintToArith256(hash) > bnTarget) return false`. The
// pow_hash field defaults to 0 (every brace-init vector above), which trivially
// satisfies any target, so all chain-helper tests run unchanged; here we set it
// explicitly to drive the gate. A default-ctor chain leaves the retarget gate
// and pow_limit ceiling unconfigured, so ONLY this PoW check can fire.
TEST(HeaderChainValidate, IngestGateRejectsInsufficientScryptPoW)
{
    HeaderChain hc;   // gate + ceiling unconfigured: only the PoW check can fire

    // pow_hash strictly ABOVE the declared target: the header does not satisfy
    // its own difficulty. REJECT, no work credited, chain not extended.
    HeaderSample weak{SCRYPT, 1000, 100};
    weak.pow_hash = 101;
    EXPECT_EQ(hc.validate_and_append(weak), IngestResult::REJECTED);
    EXPECT_EQ(hc.size(), 0u);
    EXPECT_EQ(hc.cumulative_work(), 0u);

    // pow_hash == target is the boundary: hash <= target satisfies the work.
    HeaderSample exact{SCRYPT, 1000, 100};
    exact.pow_hash = 100;
    EXPECT_EQ(hc.validate_and_append(exact), IngestResult::VALIDATED_SCRYPT);

    // pow_hash strictly below target also satisfies (more work than required).
    HeaderSample strong{SCRYPT, 1075, 100};
    strong.pow_hash = 1;
    EXPECT_EQ(hc.validate_and_append(strong), IngestResult::VALIDATED_SCRYPT);
    EXPECT_EQ(hc.size(), 2u);

    // A continuity (non-Scrypt) header never reaches the PoW check: its
    // disposition short-circuits to ACCEPT_BY_CONTINUITY even with a huge
    // pow_hash, confirming the gate is Scrypt-path only.
    HeaderSample cont{SHA256D, 1090, 100};
    cont.pow_hash = UINT64_MAX;
    EXPECT_EQ(hc.validate_and_append(cont), IngestResult::ACCEPTED_CONTINUITY);
}

// ---------------------------------------------------------------------------
// 256-BIT BOUNDARY (M3 §7b — arith_uint256 swap). Proves, not assumes, that
// the DigiShield damped multiply runs at TRUE 256-bit width: a uint64/__int128
// proxy and the full-width path DIVERGE once avg_target leaves the 64-bit range
// or the product overflows 256 bits near pow_limit. mul_div_u256 reproduces
// arith_uint256 multiply-then-divide with 256-bit overflow truncation, which is
// CONSENSUS behaviour in DigiByte Core CalculateNextWorkRequired.
// ---------------------------------------------------------------------------
#include <impl/dgb/coin/dgb_arith256.hpp>
using dgb::coin::u256;
using dgb::coin::mul_div_u256;

static constexpr uint64_t BIT63 = 0x8000000000000000ull; // 2^63

TEST(DigiShield256, Uint64RangeIsBitIdenticalToProxy)
{
    // For every avg in 64-bit range the 256-bit path equals the old __int128
    // proxy (a*m)/d exactly — this is the no-regression guard for the swap.
    const uint64_t cases[][3] = {
        {1000, 60,  60},   // nominal     -> 1000
        {1000, 90,  60},   // ceiling rail-> 1500
        {1000, 45,  60},   // floor rail  -> 750
        {4096, 70,  80},   // window-1 7/8-> 3584
        {999999999ull, 90, 60},
    };
    for (auto& c : cases) {
        const u256 r = mul_div_u256(u256::from_u64(c[0]), c[1], c[2]);
        ASSERT_TRUE(r.fits_u64());
        const unsigned __int128 proxy =
            ((unsigned __int128)c[0] * c[1]) / c[2];
        EXPECT_EQ(r.low64(), (uint64_t)proxy);
    }
}

TEST(DigiShield256, FullWidthAvgDivergesFromUint64Proxy)
{
    // avg_target = 2^64 (limb[1]=1, limb[0]=0): a value the uint64 proxy CANNOT
    // hold — it sees only low64()==0. Full width: 2^64 * 3/2 = 3*2^63.
    u256 avg; avg.limb[1] = 1; avg.limb[0] = 0;        // == 2^64
    const u256 full = mul_div_u256(avg, 3, 2);

    // Full-width result carries the high limb: 3*2^63 = 2^64 + 2^63.
    EXPECT_EQ(full.limb[1], 1u);
    EXPECT_EQ(full.limb[0], BIT63);
    EXPECT_FALSE(full.fits_u64());

    // The proxy, fed the truncated low64()==0, would compute 0 -> divergence.
    const u256 proxy = mul_div_u256(u256::from_u64(avg.low64()), 3, 2);
    EXPECT_TRUE(proxy.is_zero());
    EXPECT_FALSE(full == proxy);
}

TEST(DigiShield256, MultiplyTruncatesAt256BitsLikeArithUint256)
{
    // avg = 2^255 (top bit of the top limb). *4 = 2^257 -> wraps to 0 mod 2^256.
    // A wider/overflow-safe intermediate would yield 2^257 (non-zero); the
    // 256-bit consensus path MUST truncate to 0.
    u256 avg; avg.limb[3] = BIT63;                      // == 2^255
    EXPECT_TRUE(mul_div_u256(avg, 4, 1).is_zero());

    // *3 = 2^256 + 2^255 -> truncates back to 2^255.
    const u256 wrap = mul_div_u256(avg, 3, 1);
    EXPECT_EQ(wrap.limb[3], BIT63);
    EXPECT_EQ(wrap.limb[0], 0u);
    EXPECT_EQ(wrap.limb[1], 0u);
    EXPECT_EQ(wrap.limb[2], 0u);
}

TEST(DigiShield256, NearPowLimitCeilingRailRetargetsAtFullWidth)
{
    // A near-pow_limit avg at the ceiling rail (damped 90, nominal 60 -> *3/2).
    // avg = 2^224 (representative DGB Scrypt pow_limit magnitude); *3/2 stays in
    // range here (no wrap) but lives ENTIRELY in the high limbs the proxy drops.
    u256 avg; avg.limb[3] = 0x0000000100000000ull;     // 2^224
    const u256 full = mul_div_u256(avg, 90, 60);        // *3/2
    // 2^224 * 3/2 = 3 * 2^223 = 2^224 + 2^223; high limb 0x0000000180000000.
    EXPECT_EQ(full.limb[3], 0x0000000180000000ull);
    EXPECT_FALSE(full.fits_u64());
    // Proxy on low64()==0 collapses to 0 — the rail would be computed wrong.
    EXPECT_TRUE(mul_div_u256(u256::from_u64(avg.low64()), 90, 60).is_zero());
}

TEST(DigiShield256, ComparePicksTheLargerFullWidthValue)
{
    // pow_limit cap uses u256 compare; verify ordering across the limb boundary.
    u256 big;   big.limb[3] = 1;                         // 2^192
    u256 small = u256::from_u64(UINT64_MAX);             // 2^64 - 1
    EXPECT_TRUE(small < big);
    EXPECT_TRUE(big > small);
    EXPECT_FALSE(big < small);
}

// ---------------------------------------------------------------------------
// 256-BIT INGEST PATH (M3 7b -- field-shape swap). The swap widened
// HeaderSample::target/pow_hash (and the retarget fields) to u256, so the
// ingest PoW-satisfaction check (h.pow_hash <= h.target) now runs at TRUE
// 256-bit width through validate_and_append -- not only inside
// digishield_next_target. This PROVES it: targets/digests living in the HIGH
// limbs decide acceptance the SAME way arith_uint256 would and DIVERGE from a
// uint64 (low64-only) proxy in BOTH directions. Gate + ceiling stay
// unconfigured (default ctor) so only the PoW satisfaction check can fire.
// ---------------------------------------------------------------------------
TEST(HeaderChainValidate, IngestPoWSatisfactionRunsAtFullWidth)
{
    HeaderChain hc;   // unconfigured: only the PoW satisfaction gate can fire

    // target = 2^192 + 5 (lives in the top limb; low64 == 5).
    u256 target; target.limb[3] = 1; target.limb[0] = 5;

    // pow_hash = 10 (fits u64). Full width: 10 <= 2^192+5 -> PoW SATISFIED, the
    // header is valid. A low64-only proxy would compare 10 > 5 and WRONGLY
    // reject -- so acceptance here proves the check is full-width.
    HeaderSample ok{SCRYPT, 1000};
    ok.target   = target;
    ok.pow_hash = u256::from_u64(10);
    EXPECT_EQ(hc.validate_and_append(ok), IngestResult::VALIDATED_SCRYPT);
    EXPECT_EQ(hc.size(), 1u);

    // pow_hash = 2^193 (top limb 2, low64 == 0) vs the same 2^192+5 target.
    // Full width: 2^193 > 2^192+5 -> does NOT satisfy -> REJECT. A low64-only
    // proxy would compare 0 > 5 (false) and WRONGLY accept -- divergence the
    // other direction. No mutation on reject.
    HeaderSample weak{SCRYPT, 1075};
    weak.target = target;
    weak.pow_hash.limb[3] = 2;            // 2^193, low64 == 0
    EXPECT_EQ(hc.validate_and_append(weak), IngestResult::REJECTED);
    EXPECT_EQ(hc.size(), 1u);             // unchanged
}

// ---------------------------------------------------------------------------
// 256-BIT DIGEST INGEST (M3 7b) -- bytes -> field conversion. The embedded
// DigiByte Core port produces the Scrypt PoW hash as a 32-byte little-endian
// digest (scrypt_1024_1_1_256 output). u256::from_le_bytes is the bytes->field
// half of dropping that digest into HeaderSample::pow_hash; the scrypt CALL
// itself (btclibs) lands at the ingest boundary in a following slice. Pins the
// little-endian limb mapping (limb[0] = least-significant 8 bytes, matching
// bitcoin UintToArith256) and proves a converted digest feeds the existing
// full-width satisfaction gate with the SAME ordering -- no low64 proxy.
// ---------------------------------------------------------------------------
TEST(HeaderChainValidate, ScryptDigestLittleEndianConversion)
{
    // Byte i = i+1, so each limb is a distinct, easily-checked LE word.
    unsigned char d[32];
    for (int i = 0; i < 32; ++i) d[i] = (unsigned char)(i + 1);
    u256 h = u256::from_le_bytes(d);
    EXPECT_EQ(h.limb[0], 0x0807060504030201ULL);
    EXPECT_EQ(h.limb[1], 0x100f0e0d0c0b0a09ULL);
    EXPECT_EQ(h.limb[2], 0x1817161514131211ULL);
    EXPECT_EQ(h.limb[3], 0x201f1e1d1c1b1a19ULL);

    // All-zero digest -> 0 (trivially satisfies any non-zero target).
    unsigned char zero[32] = {0};
    EXPECT_TRUE(u256::from_le_bytes(zero).is_zero());

    // All-0xff digest -> MAX 256-bit value (every limb saturated), exceeding
    // any real Scrypt target -> would NOT satisfy PoW.
    unsigned char ones[32];
    for (int i = 0; i < 32; ++i) ones[i] = 0xff;
    u256 maxv = u256::from_le_bytes(ones);
    for (int i = 0; i < 4; ++i) EXPECT_EQ(maxv.limb[i], 0xffffffffffffffffULL);

    // Feed a converted digest through the live satisfaction gate: digest 9
    // (low byte) vs target 2^192 + 5 -> 9 <= 2^192+5 at full width -> VALIDATED.
    // Proves the converted value flows the SAME full-width path the field-shape
    // swap widened, not a low64 proxy.
    HeaderChain hc;
    u256 target; target.limb[3] = 1; target.limb[0] = 5;
    unsigned char nine[32] = {0}; nine[0] = 9;
    HeaderSample s{SCRYPT, 1000};
    s.target   = target;
    s.pow_hash = u256::from_le_bytes(nine);
    EXPECT_EQ(hc.validate_and_append(s), IngestResult::VALIDATED_SCRYPT);
    EXPECT_EQ(hc.size(), 1u);
}


// ---------------------------------------------------------------------------
// REAL SCRYPT DIGEST -> pow_hash, END-TO-END (M3 7b, slice (a)). The prior test
// pins the from_le_bytes limb mapping against SYNTHETIC bytes; this one closes
// the loop by running the ACTUAL btclibs scrypt_1024_1_1_256 PoW hash over an
// 80-byte header, converting the 32-byte little-endian digest via from_le_bytes,
// and feeding it through the live full-width satisfaction gate. Proves the
// conversion primitive is correct against a GENUINE Scrypt digest. It does NOT
// prove scrypt is wired into the production node.cpp ingest path -- that
// (b)-shaped call lands in embedded-daemon Phase A, scoped with an exe-smoke.
// ---------------------------------------------------------------------------
TEST(HeaderChainValidate, RealScryptDigestFeedsSatisfactionGate)
{
    // Deterministic 80-byte header (content arbitrary for the conversion proof;
    // fixed so the digest is a stable self-derived KAT).
    char header[80];
    for (int i = 0; i < 80; ++i) header[i] = (char)(i + 1);

    unsigned char digest[32];
    scrypt_1024_1_1_256(header, reinterpret_cast<char*>(digest));

    // Deterministic: a second run yields the identical digest.
    unsigned char digest2[32];
    scrypt_1024_1_1_256(header, reinterpret_cast<char*>(digest2));
    EXPECT_EQ(0, std::memcmp(digest, digest2, 32));

    // Self-derived KAT: pin the actual scrypt PoW hash for this fixed header so
    // any drift in scrypt OR the LE conversion is caught. limb[0] is the least-
    // significant 8 bytes (from_le_bytes / UintToArith256 ordering).
    u256 h = u256::from_le_bytes(digest);
    EXPECT_EQ(h.limb[0], 0x3863b84a2bd8d4c7ULL);
    EXPECT_EQ(h.limb[1], 0xdbc48fcba50b456bULL);
    EXPECT_EQ(h.limb[2], 0x22185f7f7b983293ULL);
    EXPECT_EQ(h.limb[3], 0x64d9ed52d29c3fbdULL);

    // The real digest, converted, satisfies a max (pow_limit) target -> VALID.
    HeaderChain hc;
    u256 max_target; for (int i = 0; i < 4; ++i) max_target.limb[i] = 0xffffffffffffffffULL;
    HeaderSample ok{SCRYPT, 1000};
    ok.target   = max_target;
    ok.pow_hash = h;
    EXPECT_EQ(hc.validate_and_append(ok), IngestResult::VALIDATED_SCRYPT);
    EXPECT_EQ(hc.size(), 1u);

    // Same real digest vs a tiny target (value 1): the high limbs are nonzero
    // (0x64d9...) so hash > 1 at full width -> REJECT. A low64-only proxy could
    // not see the high limbs -- this proves the converted digest flows the
    // full-width satisfaction path, not a truncated comparison. No mutation.
    HeaderSample weak{SCRYPT, 1075};
    weak.target.limb[0] = 1;        // value == 1, all high limbs zero
    weak.pow_hash = h;
    EXPECT_EQ(hc.validate_and_append(weak), IngestResult::REJECTED);
    EXPECT_EQ(hc.size(), 1u);        // unchanged
}

// ---------------------------------------------------------------------------
// MTP MONOTONICITY INGEST GUARD (M3 7b -- ContextualCheckBlockHeader
// "time-too-old"). A Scrypt header's nTime must be STRICTLY GREATER than the
// median timestamp of the tip and its (up to) 10 nearest ancestors. This is the
// daemon-independent, Scrypt-only-walk-safe half of header time validation: it
// reads only timestamps already in the local header chain, no difficulty
// re-derivation (the demoted V4-MultiShield recompute). Every appended header of
// EVERY algo contributes to the median exactly as DGB Core's block index does,
// but only the Scrypt-validated path is rejected on it -- continuity headers are
// accept-by-continuity and bypass the gate.
// ---------------------------------------------------------------------------
TEST(HeaderChainMtp, GenesisIsUnconstrained)
{
    // Empty chain -> median_time_past() == INT64_MIN -> any nTime accepted.
    HeaderChain hc;
    EXPECT_EQ(hc.median_time_past(), std::numeric_limits<int64_t>::min());
    EXPECT_EQ(hc.validate_and_append({SCRYPT, 1, 100}),
              IngestResult::VALIDATED_SCRYPT);
    EXPECT_EQ(hc.size(), 1u);
}

TEST(HeaderChainMtp, RejectsTimeNotStrictlyAboveMedian)
{
    // Seed 5 monotone Scrypt headers; MTP over the last 5 is sorted[2] == 1200.
    HeaderChain hc;
    for (int64_t t : {1000, 1100, 1200, 1300, 1400})
        ASSERT_EQ(hc.validate_and_append({SCRYPT, t, 100}),
                  IngestResult::VALIDATED_SCRYPT);
    EXPECT_EQ(hc.median_time_past(), 1200);

    const std::size_t size_before = hc.size();
    const uint64_t    work_before = hc.cumulative_work();

    // nTime == median: NOT strictly greater -> reject, no mutation.
    EXPECT_EQ(hc.validate_and_append({SCRYPT, 1200, 100}),
              IngestResult::REJECTED);
    // nTime below median -> reject.
    EXPECT_EQ(hc.validate_and_append({SCRYPT, 1150, 100}),
              IngestResult::REJECTED);
    EXPECT_EQ(hc.size(),            size_before);
    EXPECT_EQ(hc.cumulative_work(), work_before);

    // nTime strictly above median -> accepted.
    EXPECT_EQ(hc.validate_and_append({SCRYPT, 1500, 100}),
              IngestResult::VALIDATED_SCRYPT);
    EXPECT_EQ(hc.size(), size_before + 1);
}

TEST(HeaderChainMtp, ContinuityTimestampsContributeToMedian)
{
    // A continuity header is NOT MTP-checked (accept-by-continuity), but its
    // timestamp DOES enter the median window -- DGB Core's GetMedianTimePast
    // walks every block of every algo.
    HeaderChain hc;
    ASSERT_EQ(hc.validate_and_append({SCRYPT,  1000, 100}),
              IngestResult::VALIDATED_SCRYPT);
    // Continuity header far in the future: accepted, bypasses MTP.
    ASSERT_EQ(hc.validate_and_append({SHA256D, 5000, 100}),
              IngestResult::ACCEPTED_CONTINUITY);

    // Median over the last 2 headers (1000, 5000) is sorted[1] == 5000. A Scrypt
    // header at 4000 is ABOVE the prior Scrypt time yet <= the continuity-lifted
    // median, so it is rejected -- proving the continuity timestamp feeds it.
    EXPECT_EQ(hc.median_time_past(), 5000);
    EXPECT_EQ(hc.validate_and_append({SCRYPT, 4000, 100}),
              IngestResult::REJECTED);
    // Strictly above the continuity-lifted median -> accepted.
    EXPECT_EQ(hc.validate_and_append({SCRYPT, 6000, 100}),
              IngestResult::VALIDATED_SCRYPT);
}

TEST(HeaderChainMtp, ContinuityHeaderItselfBypassesMtp)
{
    // A continuity header with a time AT or BELOW the median is still accepted:
    // the gate is Scrypt-path only.
    HeaderChain hc;
    ASSERT_EQ(hc.validate_and_append({SCRYPT, 2000, 100}),
              IngestResult::VALIDATED_SCRYPT);
    EXPECT_EQ(hc.median_time_past(), 2000);
    // A continuity header at 1500 (below the median) is NOT rejected.
    EXPECT_EQ(hc.validate_and_append({SKEIN, 1500, 100}),
              IngestResult::ACCEPTED_CONTINUITY);
    EXPECT_EQ(hc.size(), 2u);
}


// ---------------------------------------------------------------------------
// Absolute block-height tracking (M3 §4c prerequisite). Height is the
// embedded TemplateBuilder's next_h source (subsidy_func(height) + BIP34
// push). DGB counts every block of every algo, so BOTH Scrypt-validated and
// continuity appends advance height; a rejected header never does.
// ---------------------------------------------------------------------------

TEST(HeaderChainBlockHeight, EmptyChainHasNoTipHeight)
{
    HeaderChain hc;
    EXPECT_FALSE(hc.tip_height().has_value());
    EXPECT_EQ(hc.base_height(), 0u);
    EXPECT_EQ(hc.next_block_height(), 0u);  // genesis is the next block
}

TEST(HeaderChainBlockHeight, EveryAlgoAdvancesHeight)
{
    HeaderChain hc;
    // Scrypt block at height 0.
    ASSERT_EQ(hc.validate_and_append({SCRYPT, 1000, 100}),
              IngestResult::VALIDATED_SCRYPT);
    EXPECT_EQ(hc.tip_height().value(), 0u);
    EXPECT_EQ(hc.next_block_height(), 1u);

    // A continuity (non-Scrypt) block STILL occupies a height -- DGB height
    // counts all five algos, not just the Scrypt-validated subset.
    ASSERT_EQ(hc.validate_and_append({SHA256D, 1500, 100}),
              IngestResult::ACCEPTED_CONTINUITY);
    EXPECT_EQ(hc.tip_height().value(), 1u);
    EXPECT_EQ(hc.next_block_height(), 2u);

    ASSERT_EQ(hc.validate_and_append({SKEIN, 1200, 100}),
              IngestResult::ACCEPTED_CONTINUITY);
    EXPECT_EQ(hc.tip_height().value(), 2u);

    // Another Scrypt block (time strictly above the MTP of {1000,1500,1200}).
    ASSERT_EQ(hc.validate_and_append({SCRYPT, 2000, 100}),
              IngestResult::VALIDATED_SCRYPT);
    EXPECT_EQ(hc.tip_height().value(), 3u);
    EXPECT_EQ(hc.next_block_height(), 4u);
    EXPECT_EQ(hc.size(), 4u);
}

TEST(HeaderChainBlockHeight, RejectedHeaderNeverAdvancesHeight)
{
    HeaderChain hc;
    ASSERT_EQ(hc.validate_and_append({SCRYPT, 1000, 100}),
              IngestResult::VALIDATED_SCRYPT);
    EXPECT_EQ(hc.tip_height().value(), 0u);

    // Malformed Scrypt header (zero target) is rejected -- it must not occupy
    // a height. tip/next stay pinned exactly where the last accepted block left
    // them, so the embedded coinbasevalue can never be computed for a phantom
    // block the chain never accepted.
    EXPECT_EQ(hc.validate_and_append({SCRYPT, 1100, 0}),
              IngestResult::REJECTED);
    EXPECT_EQ(hc.tip_height().value(), 0u);
    EXPECT_EQ(hc.next_block_height(), 1u);
    EXPECT_EQ(hc.size(), 1u);

    // The next genuinely-valid block takes the height the reject did NOT.
    ASSERT_EQ(hc.validate_and_append({SCRYPT, 2000, 100}),
              IngestResult::VALIDATED_SCRYPT);
    EXPECT_EQ(hc.tip_height().value(), 1u);
}

TEST(HeaderChainBlockHeight, CheckpointSeedNumbersFirstHeader)
{
    // Fast-start: seed the absolute height of m_chain[0] before any append.
    HeaderChain hc;
    hc.set_base_height(12345);
    EXPECT_FALSE(hc.tip_height().has_value());
    EXPECT_EQ(hc.next_block_height(), 12345u);  // the seed block itself

    ASSERT_EQ(hc.validate_and_append({SCRYPT, 1000, 100}),
              IngestResult::VALIDATED_SCRYPT);
    EXPECT_EQ(hc.tip_height().value(), 12345u);
    EXPECT_EQ(hc.next_block_height(), 12346u);
}
