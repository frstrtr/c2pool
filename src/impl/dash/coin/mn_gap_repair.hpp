// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The GAP-REPAIR seam shared by the two payee-queue gap handlers
/// (CoinStateMaintainer::on_block_connected and
/// MnCheckpointLane::on_block_connected).
///
/// dashd never needs this seam because its diff store is written
/// consensus-atomically with block connect (evo/deterministicmns.cpp:689
/// writes DB_LIST_DIFF inside ProcessBlock) and any list for any block is
/// reconstructable on demand via GetListForBlockInternal
/// (evo/deterministicmns.cpp:778-870). Our payee queue is fed by a P2P fold,
/// so a gap (blocks mined while the machine was not folding) historically
/// had exactly one remedy: wipe + demote + authoritative re-seed. This seam
/// lets the caller ASK for the list at a specific height, reconstructed from
/// the MnDiffStore (mn_diff_store.hpp) — the ported analogue of dashd's
/// snapshot+diff walk — before paying the wipe.
///
/// The function is injected (main_dash wires it to
/// MnDiffStore::reconstruct + the PoW-validated header chain); when absent
/// or refusing, callers execute their pre-existing fail-closed path
/// UNCHANGED. Repair only ever ADDS a lane in front of the wipe.

#include <impl/dash/coin/mn_state_db.hpp>   // dash::coin::MNState
#include <core/uint256.hpp>

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

/// The `source` token a diff-store gap repair publishes under. The source is
/// the classification of PROVENANCE (the queue was reconstructed from stored
/// root-checked fold outputs), never inferred from flags — same rule as the
/// kPayeeSource* tokens in replay_payee_publish.hpp.
inline constexpr const char* kPayeeSourceMnDiffRepair = "mn-diff-repair";

/// Result of a gap-repair ask. `ok` is true ONLY when `entries` is the
/// reconstructed, root-verified masternode list AS OF `as_of` (the height the
/// caller asked for). Any refusal carries the blocking condition in `error`
/// and the caller falls through to its unchanged wipe/fail_closed path.
struct MnGapRepairResult
{
    bool        ok{false};
    uint32_t    as_of{0};
    std::vector<std::pair<uint256, MNState>> entries;
    std::string error;
};

/// want_height -> the list AT want_height (i.e. after folding block
/// want_height), or a refusal. Callers ask for H-1 when a gap fires at
/// incoming block H.
using MnGapRepairFn = std::function<MnGapRepairResult(uint32_t want_height)>;

} // namespace coin
} // namespace dash
