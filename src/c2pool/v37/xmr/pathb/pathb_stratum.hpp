// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_stratum.hpp
// The Path B stratum login inputs:
//   parse_vote_pass   the password "vote=<n>", n decimal in 0 .. 2^15 - 1
//                     (vote=0: own no); anything else: no stated vote (the
//                     field is ignored, never a refusal)
//   login_payee       the login address as an XMR_STD key reference, or the
//                     refusal (a subaddress, an integrated address, an
//                     address of another network, keys that do not decompress)
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "c2pool/v37/xmr/pathb/pathb_policy.hpp"
#include "impl/xmr/pathb/pathb_lane_rules.hpp"          // LaneNet
#include "impl/xmr/pathb/pathb_ratchet_activation.hpp"  // kEpochMax
#include "impl/xmr/pathb/pathb_wire_v3.hpp"             // XmrKeyRef

namespace c2pool::xmr::pathb::stratum {

inline constexpr std::string_view kVotePrefix = "vote=";

inline std::optional<std::uint32_t> parse_vote_pass(std::string_view pass) {
    if (pass.size() <= kVotePrefix.size() || pass.substr(0, kVotePrefix.size()) != kVotePrefix) return std::nullopt;
    std::uint32_t n = 0;
    for (const char c : pass.substr(kVotePrefix.size())) {
        if (c < '0' || c > '9') return std::nullopt;
        n = n * 10 + static_cast<std::uint32_t>(c - '0');
        if (n > kEpochMax) return std::nullopt;
    }
    return n;
}

struct LoginPayee {
    std::string refusal;  // "" = an XMR_STD payee
    XmrKeyRef ref;
};

// The standard-address prefix of a network (regtest: the mainnet bytes).
inline std::uint64_t std_prefix_of(LaneNet n) {
    return n == LaneNet::Testnet ? policy::kPrefixTestnetStd
         : n == LaneNet::Stagenet ? policy::kPrefixStagenetStd : policy::kPrefixMainnetStd;
}

inline LoginPayee login_payee(const std::string& address, LaneNet net) {
    LoginPayee out;
    const policy::DecodedAddress d = policy::decode_xmr_address(address);
    out.refusal = policy::payee_refusal(d);
    if (!out.refusal.empty()) return out;
    if (d.prefix != std_prefix_of(net)) {
        out.refusal = "payee: an address of another network (prefix " + std::to_string(d.prefix) + ")";
        return out;
    }
    const XmrKeyRef ref{d.spend, d.view};
    if (!key_ref_points_valid(ref)) {
        out.refusal = "payee: a key that does not decompress";
        return out;
    }
    out.ref = ref;
    return out;
}

}  // namespace c2pool::xmr::pathb::stratum
