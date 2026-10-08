// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <map>
#include <string>
#include <cstdint>
#include <stdexcept>

#include <core/version_gate.hpp>
#include <core/uint256.hpp>

using core::version_gate::verify_version_transition;

// KAT for the cross-coin v36-native share-version-transition rule SSOT.
// Weight type is uint288, matching get_desired_version_weights' tally type.

namespace {

// Build a weighted desired-version tally: { version -> weight }.
std::map<uint64_t, uint288> tally(std::initializer_list<std::pair<uint64_t, uint64_t>> entries)
{
    std::map<uint64_t, uint288> m;
    for (const auto& [ver, w] : entries)
        m[ver] = uint288(w);
    return m;
}

} // namespace

TEST(VersionGateTransition, SameVersionAdmitted)
{
    // parent=36, share=36: never throws (correct when minted), with or w/o history.
    auto w = tally({{36, 100}});
    EXPECT_NO_THROW(verify_version_transition<uint288>(36, 36, w, /*have_history=*/true));
    EXPECT_NO_THROW(verify_version_transition<uint288>(36, 36, w, /*have_history=*/false));
}

TEST(VersionGateTransition, UpgradeWithMajoritySupportAdmitted)
{
    // +1 upgrade, new version holds 70% of weighted support, history present -> ok.
    auto w = tally({{36, 70}, {35, 30}});
    EXPECT_NO_THROW(verify_version_transition<uint288>(35, 36, w, /*have_history=*/true));
}

TEST(VersionGateTransition, UpgradeWithoutMajoritySupportRejected)
{
    // +1 upgrade, new version only 50% of weighted support -> reject.
    auto w = tally({{36, 50}, {35, 50}});
    try
    {
        verify_version_transition<uint288>(35, 36, w, /*have_history=*/true);
        FAIL() << "expected throw";
    }
    catch (const std::invalid_argument& e)
    {
        EXPECT_STREQ(e.what(), "switch without enough hash power upgraded");
    }
}

TEST(VersionGateTransition, UpgradeWithoutHistoryRejected)
{
    // +1 upgrade, no CHAIN_LENGTH history -> reject with the history message.
    auto w = tally({{36, 100}});
    try
    {
        verify_version_transition<uint288>(35, 36, w, /*have_history=*/false);
        FAIL() << "expected throw";
    }
    catch (const std::invalid_argument& e)
    {
        EXPECT_STREQ(e.what(), "switch without enough history");
    }
}

TEST(VersionGateTransition, DowngradeByOneAdmitted)
{
    // -1 downgrade (parent=36, share=35: AutoRatchet deactivation) with history -> ok.
    auto w = tally({{36, 100}});
    EXPECT_NO_THROW(verify_version_transition<uint288>(36, 35, w, /*have_history=*/true));
}

TEST(VersionGateTransition, MultiVersionJumpWithHistoryRejected)
{
    // parent=34, share=36 (jump of 2) with history -> invalid version jump.
    auto w = tally({{36, 100}});
    try
    {
        verify_version_transition<uint288>(34, 36, w, /*have_history=*/true);
        FAIL() << "expected throw";
    }
    catch (const std::invalid_argument& e)
    {
        EXPECT_STREQ(e.what(), "invalid version jump from 34 to 36");
    }
}

TEST(VersionGateTransition, MultiVersionJumpWithoutHistoryAdmitted)
{
    // parent=34, share=36 with no history: only +1 upgrades are gated -> admitted.
    auto w = tally({{36, 100}});
    EXPECT_NO_THROW(verify_version_transition<uint288>(34, 36, w, /*have_history=*/false));
}

TEST(VersionGateTransition, ExactSixtyPercentBoundaryAdmitted)
{
    // new version == exactly 60% of total. Rule is new < floor(total*60/100):
    // 60 < 60 is false -> 60% PASSES (no throw).
    auto w = tally({{36, 60}, {35, 40}});  // total 100, new=60 -> exactly 60%
    EXPECT_NO_THROW(verify_version_transition<uint288>(35, 36, w, /*have_history=*/true));
}

// Rounding boundary of the 60% gate (#1739). The oracle (p2pool data.py)
// rejects when counts.get(VERSION, 0) < sum(counts)*60//100, a FLOOR
// threshold. When 60*total is not a multiple of 100, new == floor(0.6*total)
// must be admitted; the previous cross-multiplied form rejected it.
TEST(VersionGateTransition, FloorThresholdAdmitsFloorOfSixtyPercent)
{
    // total 7: floor(4.2) = 4. new = 4 -> 4 < 4 is false -> admitted.
    // RED on the cross-multiplied form: 4*100 = 400 < 7*60 = 420.
    auto w = tally({{36, 4}, {35, 3}});
    EXPECT_NO_THROW(verify_version_transition<uint288>(35, 36, w, /*have_history=*/true));
}

TEST(VersionGateTransition, FloorThresholdRejectsBelowFloor)
{
    // total 7: new = 3 < floor(4.2) = 4 -> rejected.
    auto w = tally({{36, 3}, {35, 4}});
    EXPECT_THROW(verify_version_transition<uint288>(35, 36, w, /*have_history=*/true),
                 std::invalid_argument);
}

TEST(VersionGateTransition, FloorThresholdRejectsJustBelowExactSixty)
{
    // total 100 (60*total is a multiple of 100): new = 59 < 60 -> rejected.
    auto w = tally({{36, 59}, {35, 41}});
    EXPECT_THROW(verify_version_transition<uint288>(35, 36, w, /*have_history=*/true),
                 std::invalid_argument);
}

TEST(VersionGateTransition, EmptyWindowWithHistoryAdmitted)
{
    // Oracle: 0 < 0*60//100 is false -> admitted. Pinned so that tightening
    // it is a deliberate rule change, not a side effect.
    std::map<uint64_t, uint288> w;
    EXPECT_NO_THROW(verify_version_transition<uint288>(35, 36, w, /*have_history=*/true));
}

TEST(VersionGateTransition, FloorThresholdAt288BitMagnitude)
{
    // Weights are 2^256/(target+1)-sized; exercise the base_uint division.
    // total = 2^250 + 7, new = floor(total*60/100) -> admitted; new - 1 -> rejected.
    const uint288 total = (uint288(1) << 250) + uint288(7);
    const uint288 floor_new = (total * uint32_t(60)) / uint288(100);
    {
        std::map<uint64_t, uint288> w{{36, floor_new}, {35, total - floor_new}};
        EXPECT_NO_THROW(verify_version_transition<uint288>(35, 36, w, /*have_history=*/true));
    }
    {
        const uint288 below = floor_new - uint288(1);
        std::map<uint64_t, uint288> w{{36, below}, {35, total - below}};
        EXPECT_THROW(verify_version_transition<uint288>(35, 36, w, /*have_history=*/true),
                     std::invalid_argument);
    }
}
