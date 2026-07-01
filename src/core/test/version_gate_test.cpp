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
    // new version == exactly 60% of total. Rule is `new*100 < total*60`:
    // 60*100 == 100*60, NOT strictly less -> 60% PASSES (no throw).
    auto w = tally({{36, 60}, {35, 40}});  // total 100, new=60 -> exactly 60%
    EXPECT_NO_THROW(verify_version_transition<uint288>(35, 36, w, /*have_history=*/true));
}
