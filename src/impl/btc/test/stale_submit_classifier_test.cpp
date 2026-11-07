// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::coin::classify_pending_submit KATs — the B5 stale-submit timer must
// warn only on a genuinely unconfirmed submit, not on a same-height sibling
// that lost the race to another of our blocks (see stale_submit_classifier.hpp).
// Rides the already-allowlisted btc_share_test executable.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <chrono>
#include <optional>

#include "../coin/stale_submit_classifier.hpp"

using btc::coin::classify_pending_submit;
using btc::coin::kStaleSubmitAfter;
using btc::coin::PendingSubmitVerdict;

namespace {

uint256 h(const char* hex) { uint256 v; v.SetHex(hex); return v; }

const uint256 kOurs    = h("00000000d1b4073d076373eb2e9d0bc0ef4a2b08e68cbda816e03620462e95bb");
const uint256 kSibling = h("0000000080d85bfad07b89406088f0f0fecebf49e3470a8f9f244d869568104b");

} // namespace

// Case 1 (the regression): same-height sibling already holds the height.
// Must NOT be classified Stale (no "bitcoind likely rejected" warning).
TEST(BtcStaleSubmitClassifier, SameHeightSiblingFilledDoesNotWarn)
{
    auto v = classify_pending_submit(kStaleSubmitAfter, kOurs, kSibling);
    EXPECT_EQ(v, PendingSubmitVerdict::SiblingFilled);
    EXPECT_NE(v, PendingSubmitVerdict::Stale);
}

// Case 2: genuinely stale. HeaderChain never reached the height, so we still warn.
TEST(BtcStaleSubmitClassifier, GenuinelyStaleSubmitWarns)
{
    EXPECT_EQ(classify_pending_submit(kStaleSubmitAfter, kOurs, std::nullopt),
              PendingSubmitVerdict::Stale);
    EXPECT_EQ(classify_pending_submit(std::chrono::seconds{3600}, kOurs, std::nullopt),
              PendingSubmitVerdict::Stale);
}

// Our own block at the height (roundtrip confirmed late, e.g. via a resync
// batch that new_headers matched before the entry was recorded) is not stale.
TEST(BtcStaleSubmitClassifier, OwnBlockAtHeightIsConfirmed)
{
    EXPECT_EQ(classify_pending_submit(kStaleSubmitAfter, kOurs, kOurs),
              PendingSubmitVerdict::Confirmed);
}

// Below the threshold nothing is decided yet, whatever HeaderChain says.
TEST(BtcStaleSubmitClassifier, YoungSubmitStaysPending)
{
    const auto young = kStaleSubmitAfter - std::chrono::seconds{1};
    EXPECT_EQ(classify_pending_submit(young, kOurs, std::nullopt), PendingSubmitVerdict::Pending);
    EXPECT_EQ(classify_pending_submit(young, kOurs, kSibling),     PendingSubmitVerdict::Pending);
    EXPECT_EQ(classify_pending_submit(young, kOurs, kOurs),        PendingSubmitVerdict::Pending);
}
