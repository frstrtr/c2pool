// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/anchor.hpp
//
// The trust-anchor bundle: the release-pinned block plus the five state windows
// that let C2 start verifying at a recent height instead of at height 1, so the
// cost of a cold start is O(anchor age) and not O(chain age).
//
// WHY IT IS PINNED HERE, IN WAVE 0. The wave-1 table hands the anchor GENERATOR
// to WF-C6a and anchor BOOT to WF-C2a/C2b, and the plan's own shared-ownership
// list names the bundle as cross-owned. Cross-owned and undeclared is exactly
// the collision this family exists to prevent, and this is the worst artefact
// to collide on: it is the node's trust root, so two independently invented
// layouts would not merely fail to compile, they would disagree about what is
// trusted. The struct, the window sizes and the load-time invariants therefore
// live here, where both waves consume one definition.
//
// WHAT IS NOT HERE, AND WHY. Plan section 4.10 writes the generator as
// generate_anchor(MoneroDaemonRpc&, height, AnchorBundle&). MoneroDaemonRpc sits
// behind a live HTTP transport, and pulling it in would end the property that
// makes contracts/ safe to include anywhere -- the same argument as the
// CONTRACT NOTE in relay.hpp. So contracts/ pins the RESULT and the CHECK; the
// transport-bound generator keeps the plan's signature and is declared by the
// tool that owns it. Likewise the digest is a FIELD here but is verified by the
// loader: it is a SHA-256 and this family has no crypto dependency.
//
// FAIL-CLOSED, ITEM BY ITEM. Every pinned datum except the anchor id itself
// feeds a computation whose result is checked against real blocks (PoW meets
// difficulty, weight within 2x the median, coinbase exact-sum). A corrupted
// window therefore makes the node REJECT the true chain -- a loud halt -- and
// never accept a cheaper false one. The id is the one datum whose wrongness is
// a release-compromise scenario, which is why load refuses to start until the
// anchor block fetched from the network hashes to it.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "types.hpp"
#include "impl/xmr/native/consensus/xmr_epoch.hpp"
#include "impl/xmr/native/consensus/xmr_hf_table.hpp"

namespace c2pool::xmr::native {

// --- window sizes ------------------------------------------------------------
// Exact, not maxima: a short window means the first post-anchor block computes
// the wrong difficulty or the wrong median, so load refuses a bundle that is
// off by one rather than starting and failing later at a confusing height.

// [H_a - 734, H_a] -- monerod's DIFFICULTY_BLOCKS_COUNT for the next-difficulty
// computation.
inline constexpr std::size_t ANCHOR_DIFFICULTY_WINDOW = 735;
// [H_a - 99, H_a] -- the short-term weight median.
inline constexpr std::size_t ANCHOR_SHORT_TERM_WEIGHTS = 100;
// [H_a - 99999, H_a] -- the long-term weight median.
inline constexpr std::size_t ANCHOR_LONG_TERM_WEIGHTS = 100000;
// The RandomX seed ids for the at most two epoch heights inside
// [H_a - (SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG), H_a].
inline constexpr std::size_t ANCHOR_MAX_SEED_IDS = 2;

// --- the bundle --------------------------------------------------------------
// Parsed from xmr_chain_anchor_<net>.inc (generated, digest-committed). Field
// order is the file's order, so a reader can follow one against the other.
struct AnchorBundle {
    // The anchor block itself.
    std::string   network;          // "mainnet" / "testnet" / "stagenet" / "regtest"
    std::uint64_t height = 0;       // H_a
    Hash          id{};
    Hash          prev_id{};
    std::uint64_t timestamp = 0;
    std::uint8_t  major_version = 0;

    // Fork-choice base and reward base.
    U128          cumulative_difficulty{};
    std::uint64_t already_generated_coins = 0;

    // RandomX seeds for the first post-anchor epoch(s): (epoch height, key block
    // id), at most ANCHOR_MAX_SEED_IDS, each height a multiple of
    // SEEDHASH_EPOCH_BLOCKS.
    std::vector<std::pair<std::uint64_t, Hash>> seed_ids;

    // The five state windows, oldest first, ending at H_a inclusive.
    std::vector<std::pair<std::uint64_t, U128>> difficulty_window;  // (timestamp, cumdiff)
    std::vector<std::uint64_t>                  short_term_weights;
    std::vector<std::uint64_t>                  long_term_weights;

    // monerod's own hardcoded checkpoints at or above H_a, copied at release
    // time. A second, independent source for the heights it covers, and the
    // floor below which an alt chain is refused outright.
    std::vector<std::pair<std::uint64_t, Hash>> monerod_checkpoints;

    // SHA-256 over every other line of the .inc. Integrity against accidents,
    // not against malice -- the anchor's real defence is that its id is checked
    // against the block the network serves. Verified by the LOADER, which has
    // the hash function; this family does not.
    std::array<std::uint8_t, 32> digest{};
};

// --- load-time invariants ----------------------------------------------------
enum class AnchorStatus : std::uint8_t {
    Ok = 0,
    NetworkMismatch,     // bundle is for a different network than we are running
    WindowSize,          // a window is not exactly the required length
    SeedMisaligned,      // a seed height is not on an epoch boundary, or is above H_a
    NonMonotone,         // the difficulty window's cumulative difficulties go backwards
    VersionMismatch,     // major_version disagrees with the hard-fork table at H_a
    Fenced,              // the anchor sits at a fork this build does not implement
    CheckpointBelow,     // a copied checkpoint sits below H_a
};

inline const char* to_string(AnchorStatus s) noexcept {
    switch (s) {
        case AnchorStatus::Ok:              return "Ok";
        case AnchorStatus::NetworkMismatch: return "NetworkMismatch";
        case AnchorStatus::WindowSize:      return "WindowSize";
        case AnchorStatus::SeedMisaligned:  return "SeedMisaligned";
        case AnchorStatus::NonMonotone:     return "NonMonotone";
        case AnchorStatus::VersionMismatch: return "VersionMismatch";
        case AnchorStatus::Fenced:          return "Fenced";
        case AnchorStatus::CheckpointBelow: return "CheckpointBelow";
    }
    return "?";
}

// Everything about a bundle that can be judged WITHOUT the network and WITHOUT
// a hash function. Shared so C2b's loader and C6a's generator agree on what a
// well-formed bundle is; the generator runs it on what it just built, which is
// how a generator bug is caught at the tool rather than at someone's boot.
//
// Two checks are deliberately NOT here because they need something this family
// does not have: the digest (needs SHA-256, the loader does it) and "the anchor
// block fetched from peers hashes to id" (needs the network, C2's boot does it,
// and it is the one that must refuse to start).
inline AnchorStatus anchor_self_check(const AnchorBundle& b, XmrNet net, std::string& why) {
    if (b.network != to_string(net)) {
        why = "anchor bundle is for network '" + b.network + "', this node runs '"
            + to_string(net) + "'";
        return AnchorStatus::NetworkMismatch;
    }
    if (b.difficulty_window.size() != ANCHOR_DIFFICULTY_WINDOW
        || b.short_term_weights.size() != ANCHOR_SHORT_TERM_WEIGHTS
        || b.long_term_weights.size() != ANCHOR_LONG_TERM_WEIGHTS) {
        why = "anchor window lengths are "
            + std::to_string(b.difficulty_window.size()) + "/"
            + std::to_string(b.short_term_weights.size()) + "/"
            + std::to_string(b.long_term_weights.size()) + ", required "
            + std::to_string(ANCHOR_DIFFICULTY_WINDOW) + "/"
            + std::to_string(ANCHOR_SHORT_TERM_WEIGHTS) + "/"
            + std::to_string(ANCHOR_LONG_TERM_WEIGHTS);
        return AnchorStatus::WindowSize;
    }
    if (b.seed_ids.empty() || b.seed_ids.size() > ANCHOR_MAX_SEED_IDS) {
        why = "anchor carries " + std::to_string(b.seed_ids.size())
            + " seed ids, expected 1.." + std::to_string(ANCHOR_MAX_SEED_IDS);
        return AnchorStatus::SeedMisaligned;
    }
    for (const auto& s : b.seed_ids) {
        if (s.first % SEEDHASH_EPOCH_BLOCKS != 0 || s.first > b.height) {
            why = "anchor seed height " + std::to_string(s.first)
                + " is not an epoch boundary at or below " + std::to_string(b.height);
            return AnchorStatus::SeedMisaligned;
        }
    }
    for (std::size_t i = 1; i < b.difficulty_window.size(); ++i) {
        if (u128_less(b.difficulty_window[i].second, b.difficulty_window[i - 1].second)) {
            why = "anchor difficulty window is not monotone at index " + std::to_string(i);
            return AnchorStatus::NonMonotone;
        }
    }
    for (const auto& c : b.monerod_checkpoints) {
        if (c.first < b.height) {
            why = "anchor carries a monerod checkpoint at " + std::to_string(c.first)
                + ", below the anchor height " + std::to_string(b.height);
            return AnchorStatus::CheckpointBelow;
        }
    }
    if (hf_is_fenced(b.major_version)) {
        why = "anchor is at fork version " + std::to_string(b.major_version)
            + " which this build does not implement";
        return AnchorStatus::Fenced;
    }
    const std::uint8_t required = hf_version_for_height(net, b.height);
    if (b.major_version < required) {
        why = "anchor major_version " + std::to_string(b.major_version)
            + " is below the " + std::to_string(required) + " the hard-fork table "
            + "requires at height " + std::to_string(b.height);
        return AnchorStatus::VersionMismatch;
    }
    why.clear();
    return AnchorStatus::Ok;
}

// --- the two entry points ----------------------------------------------------
// Both keep the plan's names. Neither is DEFINED here: contracts/ pins what the
// two waves must agree on and nothing else.

// Parse a bundle from a path, or from the release-embedded text when the path is
// empty. FAIL-CLOSED: verifies the digest, runs anchor_self_check(), and returns
// false with a reason on anything at all. Defined by WF-C2b.
bool load_anchor(const std::string& path_or_embedded, XmrNet net,
                 AnchorBundle& out, std::string& why);

// Build a bundle at `height` from a synced monerod. Declared by the C6a/C2b tool
// that owns it, together with the MoneroDaemonRpc parameter the plan pins --
// see WHAT IS NOT HERE above for why that declaration cannot live in this file.

} // namespace c2pool::xmr::native
