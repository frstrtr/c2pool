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
// Header-only guard: links the header-only chain helpers + gtest, no dgb
// OBJECT lib / transport. MUST appear in BOTH the test/CMakeLists foreach AND
// both build.yml --target allowlists, or it becomes a #143 NOT_BUILT sentinel.
// ---------------------------------------------------------------------------

#include <cstdint>

#include <gtest/gtest.h>

#include <impl/dgb/coin/header_chain.hpp>

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
// Ingest-path retarget gate: validate_and_append must demand the declared
// Scrypt target EQUAL the DigiShield next-target computed over the Scrypt-only
// window ending at the current tip (nBits-style exact consensus match). A
// default-constructed chain leaves the gate unconfigured (target_timespan 0 ->
// expected 0), so every test above runs unconstrained; this one configures it.
//
//   window depth 1, nominal 80. Window(1) over a lone Scrypt tip has
//   actual_timespan 0 (front == back) -> damped = 80 + (0-80)/8 = 70, above the
//   floor rail 60 -> next target = avg * 70/80 = avg * 7/8, deterministically.
// ---------------------------------------------------------------------------
TEST(HeaderChainValidate, IngestGateEnforcesDigiShieldNextTarget)
{
    HeaderChain hc(DigiShieldParams{80, 0}, /*retarget_window=*/1);

    // Seed: empty window -> gate no-op, any non-zero target seeds the chain.
    ASSERT_EQ(hc.validate_and_append({SCRYPT, 1000, 4096}),
              IngestResult::VALIDATED_SCRYPT);

    // Required next target = 4096 * 7/8 = 3584. A mismatch is consensus-invalid
    // and must REJECT without mutating the chain (size + work unchanged).
    const std::size_t size_before = hc.size();
    const uint64_t    work_before = hc.cumulative_work();
    EXPECT_EQ(hc.validate_and_append({SCRYPT, 1080, 4096}),
              IngestResult::REJECTED);
    EXPECT_EQ(hc.size(),            size_before);
    EXPECT_EQ(hc.cumulative_work(), work_before);

    // The exact DigiShield target is accepted and credits work.
    EXPECT_EQ(hc.validate_and_append({SCRYPT, 1080, 3584}),
              IngestResult::VALIDATED_SCRYPT);
    EXPECT_GT(hc.cumulative_work(), work_before);

    // Continuity headers bypass the retarget gate (work-neutral, no nBits).
    EXPECT_EQ(hc.validate_and_append({SHA256D, 1090, 1}),
              IngestResult::ACCEPTED_CONTINUITY);
}
