// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// auto_ratchet_wire.hpp — DGB production wire-in for the AutoRatchet mint-side
// share-version ratchet.
//
// This is the run-loop seam that turns the (otherwise compile-default)
// AutoRatchet into a node that mints the CORRECT DGB baseline share version
// while voting for the V36 target. It exists as a separate translation unit
// from auto_ratchet.hpp so the consensus-bearing baseline constant lives in
// exactly one production location and can be tap-reviewed on its own.
//
// BASELINE RESOLVED (was a [decision-needed]; closed 2026-06-21):
//   Oracle = frstrtr/p2pool-dgb-scrypt @ 22761e7 (2026-06-17).
//     data.py:636                  Share.VERSION = 35, VOTING_VERSION = 35,
//                                  SUCCESSOR = None, share_versions = {35: Share}
//     networks/digibyte.py:26      SEGWIT_ACTIVATION_VERSION = 35
//   SUCCESSOR=None => 35 is the format the live node currently mints, so the
//   VOTING-state output (base_version) is unambiguously 35. DGB's "older than
//   LTC" axis is the P2P PROTOCOL version (p2p.py VERSION = 3501 vs LTC 3503),
//   NOT the share version — both share versions are 35. base_version=35
//   therefore coincides with LTC's target-1, but stays an explicit constant
//   here because the v37 unified shape wants it explicit and the protocol-gap
//   is real elsewhere.
//
// Bucket-2 (v36-native shared structure): the ratchet SHAPE is standardized
// cross-coin toward the v37 unified form; only the per-coin baseline constant
// below is DGB-specific. The work-weighted tail guard inside
// AutoRatchet::get_share_version keeps mint activation subordinate to the
// 60%-by-work accept gate (#249/#289) — this seam adds no new policy, it only
// pins the constants and hands callers the {mint, vote} version pair.

#include "auto_ratchet.hpp"
#include <utility>
#include <system_error>
#include <string>
#include <mutex>
#include <memory>
#include <filesystem>

namespace dgb
{

// DGB live-baseline share version minted while VOTING (oracle 22761e7).
inline constexpr int64_t DGB_BASE_VERSION   = 35;
// V36 crossing target.
inline constexpr int64_t DGB_TARGET_VERSION = 36;

// Production factory: construct the DGB AutoRatchet with the oracle-confirmed
// baseline. state_file_path persists VOTING/ACTIVATED/CONFIRMED across restarts
// so a crossed node never regresses. This is THE place base_version=35 enters
// production code.
inline AutoRatchet make_dgb_ratchet(const std::string& state_file_path = "")
{
    return AutoRatchet(state_file_path, DGB_TARGET_VERSION, DGB_BASE_VERSION);
}

// Run-loop selector: given the live tracker + current best share, return the
// {share_version_to_mint, desired_version_to_vote} pair the node should stamp
// onto the share it is about to create. Thin pass-through over the state
// machine so the run-loop never re-implements the gate; centralizes the call
// the eventual create_local_share() caller binds to.
inline std::pair<int64_t, int64_t> dgb_select_mint_versions(
    AutoRatchet& ratchet, ShareTracker& tracker, const uint256& best_share_hash)
{
    return ratchet.get_share_version(tracker, best_share_hash);
}

// The share version policy of c2pool-dgb. Operator decision (2026-11-27):
// hold DGB at V35 until a flag day. The live DGB network is python V35 only
// (SUCCESSOR None): a V36 share there "can't follow" a V35 one
// (PeerMisbehavingError, data.py), so the ratchet must never switch by itself
// once c2pool shares reach its 95% window.
//   Held (the default): mint V35 and vote 35, as python does (VOTING_VERSION
//     35, so its peers log no "unsupported share implementation" majority);
//     no AutoRatchet, so no v36_ratchet.json is read or written. A file left
//     by an earlier build is logged and ignored.
//   Opt-in (--v36-ratchet / sharechain.v36_ratchet): the AutoRatchet, as
//     before (mint the baseline, vote 36, switch at the activation window).
class DgbVersionPolicy
{
public:
    DgbVersionPolicy(bool v36_ratchet, const std::string& state_file_path)
        : state_file_(state_file_path)
    {
        if (v36_ratchet) {
            ratchet_ = std::make_unique<AutoRatchet>(state_file_path, DGB_TARGET_VERSION, DGB_BASE_VERSION);
            return;
        }
        std::error_code ec;
        stale_state_file_ = !state_file_path.empty() && std::filesystem::exists(state_file_path, ec);
    }

    bool ratchet_enabled() const { return ratchet_ != nullptr; }
    /// Held, and a persisted ratchet state file exists (ignored).
    bool stale_state_file_ignored() const { return stale_state_file_; }
    const std::string& state_file() const { return state_file_; }
    AutoRatchet* ratchet() { return ratchet_.get(); }

    /// The {mint, vote} pair for the next job.
    std::pair<int64_t, int64_t> select(ShareTracker& tracker, const uint256& best_share_hash)
    {
        if (!ratchet_)
            return {DGB_BASE_VERSION, DGB_BASE_VERSION};
        std::lock_guard<std::mutex> l(mu_);
        return dgb_select_mint_versions(*ratchet_, tracker, best_share_hash);
    }

private:
    std::string state_file_;
    std::unique_ptr<AutoRatchet> ratchet_;
    std::mutex mu_;
    bool stale_state_file_ = false;
};

} // namespace dgb