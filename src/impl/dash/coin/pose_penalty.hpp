// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// dashd's PoSe penalty arithmetic as pure functions — ONE transcription,
/// shared by the full-history list fold (replay_fold_engine.hpp DmlFoldEngine)
/// and the serve-time PoSe pass over a template's own quorum commitments
/// (sml_pose_fold.hpp). The two must agree with dashd v23.1.7 to the unit: a
/// disagreement at the ban threshold flips one SML leaf (isValid) and with it
/// the committed merkleRootMNList (bad-cbtx-mnmerkleroot, a lost block).
///
/// Values are dashd's `int`. The arithmetic runs in int64 so that an UPPER
/// BOUND supplied by a penalty oracle (sml_pose_fold.hpp) can never overflow
/// before PoSePunish's clamp brings it back into range; for every value dashd
/// itself can hold the result is identical to the int32 computation.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace dash {
namespace coin {
namespace pose {

/// CDeterministicMNList::CalcMaxPoSePenalty (evo/deterministicmns.cpp:292-298):
/// max(100, GetCounts().total()) — every registered MN, banned included
/// (deterministicmns.h:268-293 counts the whole mnMap).
inline int32_t calc_max_pose_penalty(size_t total_mn_count)
{
    const size_t cap = static_cast<size_t>(std::numeric_limits<int32_t>::max());
    const int32_t n = static_cast<int32_t>(std::min(total_mn_count, cap));
    return std::max<int32_t>(100, n);
}

/// CDeterministicMNList::CalcPenalty (deterministicmns.cpp:300-304):
/// (CalcMaxPoSePenalty() * percent) / 100, integer division.
inline int32_t calc_penalty(int32_t max_penalty, int32_t percent)
{
    return static_cast<int32_t>(
        (static_cast<int64_t>(max_penalty) * percent) / 100);
}

/// HandleQuorumCommitment's per-member punishment (evo/specialtxman.cpp:170):
/// PoSePunish(proTxHash, CalcPenalty(66)).
inline constexpr int32_t kQcPunishPercent = 66;

/// One block of DecreaseScores (deterministicmns.cpp:334-359 -> PoSeDecrease
/// :353-359): a NON-banned MN with a positive penalty loses 1. dashd runs it
/// once per block BEFORE the block's transactions (specialtxman.cpp:229).
/// The caller owns the "not banned" condition.
inline int64_t decayed(int64_t penalty)
{
    return penalty > 0 ? penalty - 1 : penalty;
}

/// PoSePunish's penalty update (deterministicmns.cpp:315-317):
/// nPoSePenalty = min(maxPenalty, nPoSePenalty + penalty).
inline int64_t punished(int64_t penalty, int32_t add, int32_t max_penalty)
{
    return std::min<int64_t>(max_penalty, penalty + add);
}

/// PoSePunish's ban rule (deterministicmns.cpp:319-321): an MN that was NOT
/// banned before this punishment and whose new penalty reached the maximum is
/// banned (BanIfNotBanned). A banned MN is never re-banned.
inline bool punish_bans(bool was_banned, int64_t new_penalty, int32_t max_penalty)
{
    return !was_banned && new_penalty >= max_penalty;
}

} // namespace pose
} // namespace coin
} // namespace dash
