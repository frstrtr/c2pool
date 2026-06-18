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
