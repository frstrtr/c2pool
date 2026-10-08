// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_ratchet_state.hpp
// Path B ratchet state S and the receipts_root fold (K30).
//
//   S (134 B, little-endian):
//     off   0  u16   epoch_cur
//     off   2  32    rules_cur
//     off  34  U256  all
//     off  66  U256  y1
//     off  98  U256  y2
//     off 130  u8[4] level of the last W_R completed grid windows, oldest first
//   S_x is the state after position x; the carrier at x commits S_{x-1}.
//   Genesis: epoch_cur 0, rules_cur = the genesis rules digest, the rest 0.
//
//   ballot (side_data_v3, u16) = own flag (bit 15) | epoch_no (bits 0..14)
//
//   rs_step(S_{x-1}, x, receipts placed at x, act, act_digest):
//     (1) act (the activation of the open deployment at its H_act,
//         pathb_ratchet_activation.hpp act()): epoch_cur += 1,
//         rules_cur = act_digest, y1 = y2, y2 = 0, every level l -> max(l - 1, 0);
//         without act S is unchanged by step (1)
//     (2) per receipt placed at x (carrier and carried; work 0 when dead):
//           all += work;  epoch_no(ballot) >= epoch_cur + 1: y1 += work;
//           epoch_no(ballot) >= epoch_cur + 2: y2 += work
//     (3) x = (k + 1) L - 1: append the window level (2 if all > 0 and
//         4 y2 >= 3 all; else 1 if all > 0 and 4 y1 >= 3 all; else 0),
//         drop the oldest; all = y1 = y2 = 0
//   With every ballot 0 only `all` moves and every level is 0.
//
//   rs_root(S)    = sha256d("c2pool-v37-rs1" || S)
//   receipts_root = sha256d("c2pool-v37-carry" || carried_root || rs_root(S at pos(tip)))
//   carried_root  = 0 when the carrier carries nothing
//   Carrier admission: receipts_root == the fold over the verifier's own S at
//   pos(tip), else STRIKE. A carried or pending receipt's fold is not
//   compared.
//
//   K30: L = 34,881 positions, GRACE = 120,960 positions, TIMEOUT = 941,760
//   positions; vote windows N_W = floor(TIMEOUT / L) = 26; kept windows
//   W_R = floor((GRACE - 1) / L) + 1 = 4; a configuration with W_R > 4 is
//   refused (ratchet_params_valid).
//
// Header-only. Not included by any running component.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <tuple>
#include <vector>

#include "sharechain/v37/v37_fixed.hpp"  // ::v37::U256 (4 x u64 limbs, little-endian)
#include "sharechain/v37/v37_hash.hpp"   // ::v37::sha256d

#include "pathb_params.hpp"

namespace c2pool::xmr::pathb {

using RsWork = ::v37::U256;

// ---------------------------------------------------------------------------
// Parameters (K30)
// ---------------------------------------------------------------------------
struct RatchetParams {
    std::uint64_t window = 0;   // K30 L (positions)
    std::uint64_t grace = 0;    // K30 GRACE (positions)
    std::uint64_t timeout = 0;  // K30 TIMEOUT (positions)
};

// K30b L, K30c GRACE, K30d TIMEOUT (positions).
inline constexpr std::uint64_t kVoteWindowPositions = 34881;
inline constexpr std::uint64_t kGracePositions = 120960;
inline constexpr std::uint64_t kTimeoutPositions = 941760;

// K30e N_W: the whole vote windows inside TIMEOUT.
inline constexpr std::uint64_t kVoteWindows = kTimeoutPositions / kVoteWindowPositions;
static_assert(kVoteWindows == 26);

inline constexpr RatchetParams kRuledRatchetParams{
    /*window=*/kVoteWindowPositions,
    /*grace=*/kGracePositions,
    /*timeout=*/kTimeoutPositions,
};

// Lock-in levels S holds.
inline constexpr std::size_t kRatchetKeptWindows = 4;

// W_R = floor((GRACE - 1) / L) + 1.
inline constexpr std::uint64_t ratchet_kept_windows(const RatchetParams& p) noexcept {
    return (p.grace - 1) / p.window + 1;
}

inline constexpr bool ratchet_params_valid(const RatchetParams& p) noexcept {
    return p.window > 0 && p.grace > 0 && ratchet_kept_windows(p) <= kRatchetKeptWindows;
}

// N_W = floor(TIMEOUT / L).
inline constexpr std::uint64_t ratchet_vote_windows(const RatchetParams& p) noexcept {
    return p.window > 0 ? p.timeout / p.window : 0;
}

static_assert(ratchet_params_valid(kRuledRatchetParams));
static_assert(ratchet_kept_windows(kRuledRatchetParams) == kRatchetKeptWindows);
static_assert(ratchet_vote_windows(kRuledRatchetParams) == kVoteWindows);

// Lock-in threshold: kLockInYes x yes >= kLockInAll x all.
inline constexpr std::uint64_t kLockInYes = 4;
inline constexpr std::uint64_t kLockInAll = 3;

// Window levels.
inline constexpr std::uint8_t kLevelNone = 0;
inline constexpr std::uint8_t kLevelNext = 1;        // ballots above epoch_cur
inline constexpr std::uint8_t kLevelNextButOne = 2;  // ballots above epoch_cur + 1

// ---------------------------------------------------------------------------
// Ballot
// ---------------------------------------------------------------------------
inline constexpr unsigned kBallotEpochBits = 15;
inline constexpr std::uint16_t kBallotOwnFlag = std::uint16_t{1} << kBallotEpochBits;
inline constexpr std::uint16_t kBallotEpochMask = kBallotOwnFlag - 1;

inline constexpr std::uint16_t ballot_epoch(std::uint16_t ballot) noexcept {
    return static_cast<std::uint16_t>(ballot & kBallotEpochMask);
}

inline constexpr bool ballot_own(std::uint16_t ballot) noexcept {
    return (ballot & kBallotOwnFlag) != 0;
}

inline constexpr std::uint16_t make_ballot(std::uint16_t epoch_no, bool own) noexcept {
    return static_cast<std::uint16_t>((epoch_no & kBallotEpochMask) | (own ? kBallotOwnFlag : 0));
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
struct RatchetState {
    std::uint16_t epoch_cur = 0;
    Hash32 rules_cur{};
    RsWork all{};
    RsWork y1{};
    RsWork y2{};
    std::array<std::uint8_t, kRatchetKeptWindows> levels{};  // oldest first

    friend bool operator==(const RatchetState& a, const RatchetState& b) {
        return a.epoch_cur == b.epoch_cur && a.rules_cur == b.rules_cur && a.all == b.all && a.y1 == b.y1
               && a.y2 == b.y2 && a.levels == b.levels;
    }
};

namespace rs_layout {
inline constexpr std::size_t kU16Bytes = sizeof(std::uint16_t);
inline constexpr std::size_t kLimbBytes = sizeof(std::uint64_t);
inline constexpr std::size_t kWorkBytes = std::tuple_size_v<decltype(RsWork::v)> * kLimbBytes;
inline constexpr std::size_t kEpochCurOff = 0;
inline constexpr std::size_t kRulesCurOff = kEpochCurOff + kU16Bytes;
inline constexpr std::size_t kAllOff = kRulesCurOff + kHashBytes;
inline constexpr std::size_t kY1Off = kAllOff + kWorkBytes;
inline constexpr std::size_t kY2Off = kY1Off + kWorkBytes;
inline constexpr std::size_t kLevelsOff = kY2Off + kWorkBytes;
inline constexpr std::size_t kSize = kLevelsOff + kRatchetKeptWindows;
}  // namespace rs_layout

using RatchetStateBytes = std::array<std::uint8_t, rs_layout::kSize>;

inline RatchetState genesis_ratchet_state(const Hash32& genesis_rules_digest) noexcept {
    RatchetState s;
    s.rules_cur = genesis_rules_digest;
    return s;
}

inline RatchetStateBytes encode_ratchet_state(const RatchetState& s) noexcept {
    RatchetStateBytes out{};
    std::size_t o = 0;
    for (std::size_t i = 0; i < rs_layout::kU16Bytes; ++i)
        out[o++] = static_cast<std::uint8_t>(s.epoch_cur >> (CHAR_BIT * i));
    for (std::uint8_t b : s.rules_cur) out[o++] = b;
    for (const RsWork* w : {&s.all, &s.y1, &s.y2})
        for (std::uint64_t limb : w->v)
            for (std::size_t i = 0; i < rs_layout::kLimbBytes; ++i)
                out[o++] = static_cast<std::uint8_t>(limb >> (CHAR_BIT * i));
    for (std::uint8_t l : s.levels) out[o++] = l;
    return out;
}

// ---------------------------------------------------------------------------
// rs_step
// ---------------------------------------------------------------------------
struct RatchetPlacement {
    std::uint64_t work = 0;    // credited work of the receipt (0 when dead)
    std::uint16_t ballot = 0;  // side_data_v3 ballot
};

inline bool lock_in_reached(const RsWork& yes, const RsWork& all) {
    return !all.is_zero() && !(yes.mul_small(kLockInYes) < all.mul_small(kLockInAll));
}

inline std::uint8_t window_level(const RatchetState& s) {
    if (lock_in_reached(s.y2, s.all)) return kLevelNextButOne;
    if (lock_in_reached(s.y1, s.all)) return kLevelNext;
    return kLevelNone;
}

// x is the last position of grid window k = floor(x / L).
inline constexpr bool ratchet_window_end(const RatchetParams& p, std::uint64_t x) noexcept {
    return x % p.window == p.window - 1;
}

// S_x from S_{x-1}. Precondition: ratchet_params_valid(p).
inline RatchetState rs_step(const RatchetParams& p, const RatchetState& prev, std::uint64_t x,
                            std::span<const RatchetPlacement> placed) {
    RatchetState s = prev;
    const std::uint32_t above = std::uint32_t{s.epoch_cur} + 1;
    for (const RatchetPlacement& r : placed) {
        const RsWork w(r.work);
        const std::uint32_t e = ballot_epoch(r.ballot);
        s.all += w;
        if (e >= above) s.y1 += w;
        if (e >= above + 1) s.y2 += w;
    }
    if (ratchet_window_end(p, x)) {
        const std::uint8_t level = window_level(s);
        for (std::size_t i = 0; i + 1 < s.levels.size(); ++i) s.levels[i] = s.levels[i + 1];
        s.levels.back() = level;
        s.all = s.y1 = s.y2 = RsWork{};
    }
    return s;
}

// S_x from S_{x-1} with step (1). act = false is the four-argument rs_step,
// byte for byte. Precondition: ratchet_params_valid(p); with act,
// prev.epoch_cur < kBallotEpochMask (the deployment table keeps epoch_no
// <= kBallotEpochMask).
inline RatchetState rs_step(const RatchetParams& p, const RatchetState& prev, std::uint64_t x,
                            std::span<const RatchetPlacement> placed, bool act, const Hash32& act_digest) {
    if (!act) return rs_step(p, prev, x, placed);
    RatchetState s = prev;
    s.epoch_cur = static_cast<std::uint16_t>(s.epoch_cur + 1);
    s.rules_cur = act_digest;
    s.y1 = s.y2;
    s.y2 = RsWork{};
    for (std::uint8_t& l : s.levels) l = l > kLevelNone ? static_cast<std::uint8_t>(l - 1) : kLevelNone;
    return rs_step(p, s, x, placed);
}

// ---------------------------------------------------------------------------
// Commitment and fold
// ---------------------------------------------------------------------------
inline constexpr std::string_view kRsRootDomain = "c2pool-v37-rs1";
inline constexpr std::string_view kCarryFoldDomain = "c2pool-v37-carry";

// carried_root of a carrier that carries nothing.
inline constexpr Hash32 kNoCarriedRoot{};

inline Hash32 rs_root(const RatchetState& s) {
    const RatchetStateBytes b = encode_ratchet_state(s);
    std::vector<std::uint8_t> pre(kRsRootDomain.begin(), kRsRootDomain.end());
    pre.insert(pre.end(), b.begin(), b.end());
    return ::v37::sha256d(pre);
}

inline Hash32 receipts_root_fold(const Hash32& carried_root, const Hash32& rs) {
    std::vector<std::uint8_t> pre(kCarryFoldDomain.begin(), kCarryFoldDomain.end());
    pre.insert(pre.end(), carried_root.begin(), carried_root.end());
    pre.insert(pre.end(), rs.begin(), rs.end());
    return ::v37::sha256d(pre);
}

// The receipts_root a carrier on a tip with state s_tip commits.
inline Hash32 carrier_receipts_root(const Hash32& carried_root, const RatchetState& s_tip) {
    return receipts_root_fold(carried_root, rs_root(s_tip));
}

enum class FoldVerdict : std::uint8_t { Match, Strike };

// Carrier admission: the carrier's receipts_root against the verifier's S at pos(tip).
inline FoldVerdict check_carrier_fold(const Hash32& receipts_root, const Hash32& carried_root,
                                      const RatchetState& s_tip) {
    return receipts_root == carrier_receipts_root(carried_root, s_tip) ? FoldVerdict::Match : FoldVerdict::Strike;
}

}  // namespace c2pool::xmr::pathb
