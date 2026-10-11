// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_mainnet_refusal.hpp
// The mainnet refusal (pure; no flag lifts it):
//   mainnet_refusal   on mainnet: a start without --follow-only; then, in this
//                     order, every --stratum-* input, --mine and every
//                     --mine-* input, --pathb-launch, every Path B relay input
//                     (--relay-*, --no-relay-*, --relay-listen and --relay-peer
//                     as fields)
//   mode_refusal      the mode refusals in the daemon's order:
//                       1 the mainnet fence (without --follow-only)
//                       2 mainnet_refusal
//                       3 follow_only_refusal (its first clause: the fence)
//                       4 solo_refusal
//                       5 arm_order_refusal
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <string>
#include <string_view>

#include "c2pool/v37/xmr/pathb/pathb_follow_only.hpp"
#include "c2pool/v37/xmr/xmr_node_config.hpp"

namespace c2pool::v37n::xmr::pathb_mode {

inline constexpr std::string_view kMainnetFollowOnlyText = "mainnet requires --follow-only";
inline constexpr std::string_view kMainnetRefuses = "mainnet refuses ";
inline constexpr std::string_view kPathbLaunchFlag = "--pathb-launch";

namespace mr_detail {
inline std::string refused(std::string_view input) { return std::string(kMainnetRefuses) + std::string(input); }
}  // namespace mr_detail

inline std::string mainnet_refusal(const XmrNodeConfig& c) {
    using mr_detail::refused;
    if (c.network != MoneroNetwork::Mainnet) return {};
    if (!c.follow_only) return std::string(kMainnetFollowOnlyText);
    if (const auto f = stratum_input(c)) return refused(*f);
    if (const auto f = mine_input(c)) return refused(*f);
    if (flag_given(c, kPathbLaunchFlag)) return refused(kPathbLaunchFlag);
    if (const auto f = relay_input(c)) return refused(*f);
    return {};
}

inline std::string mode_refusal(const XmrNodeConfig& c) {
    if (!c.follow_only)
        if (std::string r = mainnet_fence_refusal(c); !r.empty()) return r;
    if (std::string r = mainnet_refusal(c); !r.empty()) return r;
    if (std::string r = follow_only_refusal(c); !r.empty()) return r;
    if (std::string r = solo_refusal(c); !r.empty()) return r;
    return arm_order_refusal(c);
}

}  // namespace c2pool::v37n::xmr::pathb_mode
