// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_catchup.hpp
// Path B template builder: the Monero parent of a new template (K28, FR-B1).
// With t the best tip, h(t) its template height and M the node's Monero main
// tip height, gap = M + 1 - h(t):
//   gap < 0           -> parent P_t (template height h(t))
//   0 <= gap <= Fresh -> parent = the Monero tip (template height M + 1)
//   gap > Fresh       -> parent = the main-chain block at height h(t) + Fresh - 1
//                        (template height h(t) + Fresh)
// Template freshness against its tip: 0 <= h(r) - h(t) <= Fresh.
// Builder rule only; admission is unchanged.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>

#include "pathb_params.hpp"

namespace c2pool::xmr::pathb {

enum class TemplateParent : std::uint8_t {
    TipParent,     // P_t, the Monero parent of the best tip
    MoneroTip,     // the node's Monero main tip
    MainChainAt,   // the node's main-chain block at parent_height
};

struct CatchupDecision {
    TemplateParent parent = TemplateParent::MoneroTip;
    std::uint64_t parent_height = 0;
    std::uint64_t template_height = 0;  // parent_height + 1

    friend bool operator==(const CatchupDecision&, const CatchupDecision&) = default;
};

// 0 <= h_r - h_tip <= fresh_max.
inline constexpr bool template_fresh(std::uint64_t h_r, std::uint64_t h_tip, std::uint64_t fresh_max) noexcept {
    return h_r >= h_tip && h_r - h_tip <= fresh_max;
}

// Precondition: fresh_max >= 1, h_tip >= 1 (a template height is a Monero height + 1),
// heights below UINT64_MAX - fresh_max.
inline constexpr CatchupDecision catchup_template(std::uint64_t h_tip, std::uint64_t monero_tip,
                                                  std::uint64_t fresh_max) noexcept {
    const std::uint64_t p_t_height = h_tip - 1;
    if (monero_tip < p_t_height) {
        // M + 1 < h(t)
        return CatchupDecision{TemplateParent::TipParent, p_t_height, h_tip};
    }
    // gap = M + 1 - h(t) = M - height(P_t) >= 0
    const std::uint64_t gap = monero_tip - p_t_height;
    if (gap <= fresh_max) {
        return CatchupDecision{TemplateParent::MoneroTip, monero_tip, monero_tip + 1};
    }
    return CatchupDecision{TemplateParent::MainChainAt, h_tip + fresh_max - 1, h_tip + fresh_max};
}

inline constexpr CatchupDecision catchup_template(std::uint64_t h_tip, std::uint64_t monero_tip,
                                                  const LaneParams& p) noexcept {
    return catchup_template(h_tip, monero_tip, p.fresh_max);
}

}  // namespace c2pool::xmr::pathb
