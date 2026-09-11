// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/consensus/xmr_hf_policy.hpp
//
// R-HFFUSE: the unknown-hard-fork POLICY, which Wave 0 deliberately left open.
//
// consensus/xmr_hf_table.hpp decides the VALUES (which version applies at a
// height, which transaction shapes that version admits) and reports a version
// above MAX_IMPLEMENTED_HF_VERSION as HfStatus::Fenced. It says, in its own
// words, that it "does NOT decide the unknown-fork POLICY ... That is a wave-1
// C2a ruling". This header is that ruling.
//
// THE RULING: VERSION-AGNOSTIC CODE-ROLLING, NOT FAIL-CLOSED HALT.
//
// The rejected alternative (R-HF in the plan) was: meet an unimplemented fork,
// halt the whole native path, fall back to an armed daemon. That is safe and
// useless -- it converts every Monero hard fork into a total outage of the
// native node, on a schedule Monero controls and we do not. Worse, it is safe
// only for the arm that needed protecting (block PRODUCTION) and pays for that
// safety with the arm that needed none (chain FOLLOWING).
//
// The ruling splits the two, because they fail in opposite directions:
//
//   * FOLLOWING a chain is version-agnostic in the parts we implement. A block
//     id is keccak over (header bytes || tree root || varint n_tx); the PoW
//     input is that same blob; next_difficulty is a 735-row window of
//     (timestamp, cumulative difficulty); the weight windows are medians of
//     integers; the reward is an arithmetic function of the coin supply and the
//     median. None of those has changed at ANY Monero fork in the range this
//     node targets, and none of them can be wrong in a way that costs us
//     anything: if we follow a fork we do not understand, we produce no
//     artefact anyone else consumes. We are a reader.
//
//   * PRODUCING a block is exactly version-specific. The coinbase shape, the
//     admissible rct types, the ring size and (at the next fork) the whole
//     FCMP++/CARROT transaction format are what a template must get right.
//     Building one from rules we do not have is how an invalid block gets mined
//     and a pool's identity gets banned.
//
// So the fuse DEGRADES CAPABILITIES rather than stopping the node:
//
//     capability          at a known version    at a rolled (fenced) version
//     ------------------  --------------------  ----------------------------
//     follow the chain    yes                   yes      <- fail-OPEN
//     serve/relay blocks  yes                   yes
//     admit transactions  yes                   NO       <- fail-CLOSED
//     build a template    yes                   NO       <- fail-CLOSED
//
// CODE-ROLLING is the second half of the ruling: at a fenced version the rule
// lookups do not refuse and do not guess a NEW rule -- they ROLL, i.e. they
// answer with the rules of the newest version this build actually implements
// (hf_rules_version() below clamps). Rolling forward can only ever be wrong
// about a rule that the unknown fork CHANGED; it is never wrong about a height
// below the fork, because no rule in this tree is expressed as "the value at
// the newest version" (the hf_table header is built that way on purpose).
//
// THE FUSE IS A LATCH AND IT IS LOUD. Tripping records the first height and
// version that tripped it and counts every subsequent one. It never un-trips by
// itself: the only thing that clears it is a build whose MAX_IMPLEMENTED_HF_VERSION
// covers the fork -- which is the point. "Roll the code" is the remedy, and the
// fuse is the receipt that says the code has not been rolled yet.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>

#include "xmr_hf_table.hpp"

namespace c2pool::xmr::native {

// --- what a rolled fork costs -------------------------------------------------
// One bit per capability. `Follow` and `Serve` survive a rolled fork; the two
// that can produce an artefact the network judges do not.
enum class HfCapability : std::uint8_t {
    Follow   = 0,   // parse, verify PoW against difficulty, extend/reorg the index
    Serve    = 1,   // answer a peer's chain/objects request, relay a block
    AdmitTx  = 2,   // accept a transaction into the pool as consensus-shaped
    Template = 3,   // hand a miner a block template
};

inline const char* to_string(HfCapability c) noexcept {
    switch (c) {
        case HfCapability::Follow:   return "Follow";
        case HfCapability::Serve:    return "Serve";
        case HfCapability::AdmitTx:  return "AdmitTx";
        case HfCapability::Template: return "Template";
    }
    return "?";
}

// True when the capability survives at a version we do not implement.
inline constexpr bool hf_capability_survives_roll(HfCapability c) noexcept {
    return c == HfCapability::Follow || c == HfCapability::Serve;
}

// --- the verdict on one block header -----------------------------------------
enum class HfVerdict : std::uint8_t {
    Ok = 0,           // a version this build implements
    OkRolled,         // above the implemented range: ACCEPTED, fuse tripped
    RejectTooLow,     // below what the table requires at this height -- a fork we left
    RejectMinorLow,   // minor_version below major (monerod's rule from v8)
};

inline const char* to_string(HfVerdict v) noexcept {
    switch (v) {
        case HfVerdict::Ok:              return "Ok";
        case HfVerdict::OkRolled:        return "OkRolled";
        case HfVerdict::RejectTooLow:    return "RejectTooLow";
        case HfVerdict::RejectMinorLow:  return "RejectMinorLow";
    }
    return "?";
}

inline constexpr bool hf_verdict_accepts(HfVerdict v) noexcept {
    return v == HfVerdict::Ok || v == HfVerdict::OkRolled;
}

// --- the rules version --------------------------------------------------------
// CODE-ROLLING in one function: rule lookups for a version above the implemented
// range answer with the newest version this build has rules for. Every rule
// predicate in xmr_hf_table.hpp is monotone in the sense that matters here --
// it is keyed on the version it was written against, never on "the newest one"
// -- so clamping cannot reinterpret an older height.
inline constexpr std::uint8_t hf_rules_version(std::uint8_t version) noexcept {
    return version > MAX_IMPLEMENTED_HF_VERSION ? MAX_IMPLEMENTED_HF_VERSION : version;
}

// --- the fuse ------------------------------------------------------------------
// Latching, monotone, and cheap to read. One instance per chain state; the
// telemetry surface copies it out.
class HfFuse {
public:
    // Records a rolled version. Returns true the FIRST time it trips.
    bool trip(std::uint64_t height, std::uint8_t version) noexcept {
        ++seen_;
        if (!tripped_) {
            tripped_        = true;
            first_height_   = height;
            first_version_  = version;
            highest_version_ = version;
            return true;
        }
        if (version > highest_version_) highest_version_ = version;
        return false;
    }

    bool          tripped()         const noexcept { return tripped_; }
    std::uint64_t first_height()    const noexcept { return first_height_; }
    std::uint8_t  first_version()   const noexcept { return first_version_; }
    std::uint8_t  highest_version() const noexcept { return highest_version_; }
    std::uint64_t blocks_seen()     const noexcept { return seen_; }

    // The capability gate. Fail-open for the reader arms, fail-closed for the
    // two arms that can emit something the network judges.
    bool allows(HfCapability c) const noexcept {
        return !tripped_ || hf_capability_survives_roll(c);
    }

    std::string why(HfCapability c) const {
        if (allows(c)) return {};
        return std::string("capability ") + to_string(c) + " is withdrawn: the chain is at "
             + "fork version " + std::to_string(highest_version_) + " (first seen at height "
             + std::to_string(first_height_) + "), this build implements up to "
             + std::to_string(MAX_IMPLEMENTED_HF_VERSION) + " -- roll the code forward";
    }

    // Deliberately NOT a reset(): the fuse un-trips only by being rebuilt as
    // part of a fresh chain state, which is what a restart on a rolled build
    // does. A running node cannot talk itself out of the fuse.

private:
    bool          tripped_         = false;
    std::uint64_t first_height_    = 0;
    std::uint8_t  first_version_   = 0;
    std::uint8_t  highest_version_ = 0;
    std::uint64_t seen_            = 0;
};

// --- the policy ----------------------------------------------------------------
// Wraps hf_check_block_version() with the ruling above. `fuse` is updated in
// place; pass the chain state's fuse.
//
// The order of the checks is monerod's, with one deliberate difference: a
// FENCED version is not a stop, it is an accept-and-trip. A version BELOW the
// table's requirement is still a hard reject -- that is not an unknown fork,
// it is a block from a fork we already left, and accepting it would be a
// consensus failure in the direction that actually costs something.
inline HfVerdict hf_policy_check_block(XmrNet net, std::uint64_t height,
                                       std::uint8_t major, std::uint8_t minor,
                                       HfFuse& fuse, std::string& why) {
    const std::uint8_t required = hf_version_for_height(net, height);
    if (major < required) {
        why = "block major_version " + std::to_string(major) + " below required "
            + std::to_string(required) + " at height " + std::to_string(height);
        return HfVerdict::RejectTooLow;
    }
    // monerod requires minor_version >= major_version in a block header from v8.
    // The rule is checked at the block's OWN major version, rolled or not: it is
    // structural, and a fork that changed it would have to change the header.
    if (major >= 8 && minor < major) {
        why = "block minor_version " + std::to_string(minor) + " below major "
            + std::to_string(major);
        return HfVerdict::RejectMinorLow;
    }
    if (hf_is_fenced(major)) {
        fuse.trip(height, major);
        why = "block major_version " + std::to_string(major) + " at height "
            + std::to_string(height) + " is beyond the implemented fork range (max "
            + std::to_string(MAX_IMPLEMENTED_HF_VERSION)
            + "): following it with rolled rules, template and tx admission withdrawn";
        return HfVerdict::OkRolled;
    }
    why.clear();
    return HfVerdict::Ok;
}

// The version we advertise as top_version in HANDSHAKE / TIMED_SYNC.
//
// Under the ruling this is NOT fenced: a peer drops us for advertising a
// version it disagrees with, so at a rolled fork the honest advertisement is
// the version the CHAIN is at -- which is what we are actually following -- and
// not the highest version we implement. Advertising a stale version at a fork
// is the availability failure the hf_table header warns about; advertising the
// chain's version costs nothing, because top_version is a statement about our
// tip, not a promise to validate transaction bodies.
//
// `tip_major` is the major version of our own tip (the block, not the table):
// at a fork the table is the thing that is out of date, so the block wins.
inline std::uint8_t hf_policy_top_version(XmrNet net, std::uint64_t tip_height,
                                          std::uint8_t tip_major) noexcept {
    const std::uint8_t table = hf_version_for_height(net, tip_height);
    return tip_major > table ? tip_major : table;
}

} // namespace c2pool::xmr::native
