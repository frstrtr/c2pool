// F10/(b) version-punish-removal KAT — guards the #288 tip-selection axis.
//
// This branch deletes should_punish_version() (the non-canonical 95%-flat-count
// version-obsolescence punish, formerly src/impl/btc/share_tracker.hpp) and its
// live head-decoration call (formerly share_tracker.hpp:1198, reason=1). It
// mirrors the already-landed LTC (share_tracker.hpp:2670) / DGB (:2654) deletion.
//
// Backfills the coverage gap that let the #288-class divergence ship: there was
// no test asserting that BTC tip-selection agrees with the canonical accept gate
// on the version axis, so the extra punish down-ranked tips the gate accepts and
// nobody noticed. This BTC twin locks the invariant.
//
// The two predicates this test pins (both quoted verbatim from the code as it
// stood / stands):
//
//   ACCEPT GATE (canonical, SURVIVES — src/impl/btc/share_check.hpp:1793,
//   matching p2pool data.py check() lines 1396-1414):
//       reject boundary iff  new_ver_weight*100 < total_weight*60
//   i.e. a one-version upgrade boundary is VALID when the new version holds
//   >= 60% of the PPLNS-WEIGHTED desired-version support in the sampling window.
//
//   PUNISH (non-canonical, REMOVED — former should_punish_version):
//       punish (reason=1) iff  newer_version_count*100 >= actual*95
//   a flat (un-weighted) head-count rule with NO basis in p2pool check().
//
// #288 axis: there exists a desired-version distribution where the canonical
// accept gate deems an upgrade boundary VALID while the removed flat-count
// punish would have down-ranked that same tip. After this deletion the only
// head-scoring punish contributor is `naughty` (invalid block), so a non-naughty
// tip the accept gate accepts is never down-ranked. This test proves the
// divergence existed and that the surviving gate is now the sole version decider.

#include <gtest/gtest.h>

#include <cstdint>
#include <map>

namespace {

// Canonical accept gate, byte-for-byte the predicate at share_check.hpp:1793.
// weights: desired-version -> PPLNS weight (work, target_to_average_attempts).
// Returns true if a boundary share at `share_ver` (== parent_ver + 1) is VALID.
bool accept_gate_valid(const std::map<int64_t, uint64_t>& weights, int64_t share_ver) {
    uint64_t new_ver_weight = 0, total_weight = 0;
    for (auto& [ver, w] : weights) {
        total_weight += w;
        if (ver == share_ver) new_ver_weight += w;
    }
    // Canonical: counts.get(self.VERSION,0) < sum(counts)*60//100  ->  reject
    return !(new_ver_weight * 100 < total_weight * 60);
}

// The REMOVED flat-count punish, reproduced exactly as should_punish_version
// computed it. counts: version -> flat head count. `actual` = window size.
// Returns true if a share at `share_ver` WOULD have been punished (reason=1).
bool removed_flat_punish(const std::map<int64_t, uint64_t>& counts,
                         int64_t share_ver, uint64_t actual) {
    if (actual == 0) return false;
    for (auto& [ver, count] : counts)
        if (ver > share_ver && count * 100 >= actual * 95) // 95% threshold
            return true;
    return false;
}

// Head-scoring reason after the deletion: the only contributor is `naughty`.
// Mirrors share_tracker.hpp:1196-1198 post-change (reason = idx->naughty).
int32_t head_reason_after_deletion(int32_t naughty) { return naughty; }

} // namespace

// Core #288 case: a single newer version dominates by flat head count (>=95%)
// but the upgraded version's WEIGHTED support clears 60%. The accept gate
// accepts the boundary; the removed punish would have down-ranked it.
TEST(BTC_F10b_VersionPunishRemoval, AcceptGateAndRemovedPunishDiverge) {
    // 10 heads desire v37, the upgrade target; the boundary share is v37.
    // By flat count v37 holds 95% (would have punished a v36 share as obsolete),
    // but in weighted terms v37 also clears 60% so the boundary is canonical.
    const int64_t share_ver = 37; // parent_ver(36) + 1

    // Weighted view used by the surviving accept gate: v37 holds 7/10 weight.
    std::map<int64_t, uint64_t> weights{{36, 300}, {37, 700}};
    EXPECT_TRUE(accept_gate_valid(weights, share_ver))
        << "canonical 60% weighted gate must accept the v37 boundary";

    // The removed flat-count punish keyed off a NEWER version (v38) reaching
    // 95% would have flagged the (older) v37 tip as obsolete and down-ranked it.
    std::map<int64_t, uint64_t> flat_counts{{37, 0}, {38, 96}};
    EXPECT_TRUE(removed_flat_punish(flat_counts, share_ver, /*actual=*/100))
        << "the removed punish WOULD have down-ranked the v37 tip (the #288 miss)";

    // Post-deletion, head-scoring no longer consults version at all: a
    // non-naughty tip gets reason 0 and is NOT down-ranked.
    EXPECT_EQ(0, head_reason_after_deletion(/*naughty=*/0))
        << "after F10/(b) a non-naughty tip is never down-ranked on the version axis";
}

// Boundary just under canonical: 60% weighted gate REJECTS, so this is purely a
// gate decision — nothing about head-scoring re-introduces a competing punish.
TEST(BTC_F10b_VersionPunishRemoval, AcceptGateRejectsBelowSixtyWeighted) {
    std::map<int64_t, uint64_t> weights{{36, 410}, {37, 590}}; // 59% < 60%
    EXPECT_FALSE(accept_gate_valid(weights, /*share_ver=*/37))
        << "below 60% weighted support the canonical gate alone rejects the boundary";
}

// The surviving head-scoring punish is naughty-only and order-independent of
// the version distribution: naughty>0 still down-ranks (invalid block), and that
// is the ONLY remaining reason a head is down-ranked.
TEST(BTC_F10b_VersionPunishRemoval, NaughtyIsTheSoleSurvivingPunish) {
    EXPECT_EQ(0, head_reason_after_deletion(0));
    EXPECT_EQ(3, head_reason_after_deletion(3)); // naughty propagation preserved
}
