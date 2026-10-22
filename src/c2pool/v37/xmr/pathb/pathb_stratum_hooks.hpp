// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_stratum_hooks.hpp
// The Path B stratum hooks (the listener's wiring is the caller's):
//   login_hook          the login: the payee (an XMR_STD address of the node's
//                       network, else the refusal) and vote=n from
//                       params["pass"] (anything else: no stated vote)
//   login_reply_c2pool  the login reply's "c2pool" object: give_author_pct and
//                       node_owner_fee_pct (percent with 4 decimals, from basis
//                       points) and "vote": vote_json(ballot)
//   stratum_budget_of   the "+diff" floor and the submit refill from d_at:
//                       min_diff = max(1, d_at >> s), refill = 2 << s submits
//                       per T; s = --stratum-min-diff-shift (default 0,
//                       at most 62)
//
// Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>

#include "c2pool/v37/xmr/pathb/pathb_stratum.hpp"
#include "c2pool/v37/xmr/xmr_lane_constants.hpp"  // kXmrTargetIntervalS
#include "impl/xmr/pathb/pathb_ratchet_activation.hpp"  // BallotChoice, vote_json

namespace c2pool::xmr::pathb::stratum {

// ---------------------------------------------------------------------------
// The login
// ---------------------------------------------------------------------------
struct LoginHook {
    std::string refusal;  // "" = accepted
    XmrKeyRef payee;
    std::optional<std::uint32_t> stated_vote;
};

inline LoginHook login_hook(const std::string& login, const std::string& pass, LaneNet net) {
    LoginHook out;
    const LoginPayee p = login_payee(login, net);
    if (!p.refusal.empty()) {
        out.refusal = p.refusal;
        return out;
    }
    out.payee = p.ref;
    out.stated_vote = parse_vote_pass(pass);
    return out;
}

// bp / 100 percent, 4 decimals.
inline std::string pct4_of_bp(std::uint32_t bp) {
    char b[32];
    std::snprintf(b, sizeof b, "%u.%04u", bp / 100u, (bp % 100u) * 100u);
    return b;
}

inline std::string login_reply_c2pool(std::uint32_t give_author_bp, std::uint32_t owner_fee_bp, const BallotChoice& vote) {
    return "\"c2pool\":{\"give_author_pct\":" + pct4_of_bp(give_author_bp) +
           ",\"node_owner_fee_pct\":" + pct4_of_bp(owner_fee_bp) + "," + vote_json(vote) + "}";
}

// ---------------------------------------------------------------------------
// The stratum budget from d_at (node policy)
// ---------------------------------------------------------------------------
inline constexpr std::string_view kStratumMinDiffShiftFlag = "--stratum-min-diff-shift";
inline constexpr std::uint32_t kStratumMinDiffShiftDefault = 0;
inline constexpr std::uint32_t kStratumMinDiffShiftMax = 62;  // 2 << 62 is the largest refill in a u64
inline constexpr std::uint64_t kStratumRefillFactor = 2;

struct StratumBudget {
    std::uint64_t min_diff = 0;      // the "+diff" floor
    std::uint64_t refill_per_t = 0;  // submits per T per connection
    std::uint64_t t_s = 0;           // T
};

inline std::optional<StratumBudget> stratum_budget_of(std::uint64_t d_at,
                                                      std::uint32_t shift = kStratumMinDiffShiftDefault) {
    if (shift > kStratumMinDiffShiftMax) return std::nullopt;
    StratumBudget b;
    b.min_diff = std::max<std::uint64_t>(1, d_at >> shift);
    b.refill_per_t = kStratumRefillFactor << shift;
    b.t_s = ::c2pool::v37n::xmr::kXmrTargetIntervalS;
    return b;
}

}  // namespace c2pool::xmr::pathb::stratum
