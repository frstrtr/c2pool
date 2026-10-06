// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_headers_first.hpp
// Path B headers-first: the decision on a side branch announced by headers.
// Inputs: cumulative carrier work and tip id of the best chain, cumulative
// work at the fork point, the side headers in chain order (work d, the result
// of the header checks, carrier id), the fork depth below the best tip, and J.
//   first header that failed its checks -> RefuseHeader (its index); no bodies
//   the side branch wins the fork choice -> FetchBodies:
//     claimed work = fork work + work of the checked headers;
//     claimed work > best work, or claimed work == best work and the id of the
//     last side header < the best tip id (bytes compared in order)
//   otherwise, fork depth > J            -> Prune
//   otherwise                            -> KeepHeaders
// Cumulative work in 128 bits.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <vector>

#include "impl/xmr/native/contracts/types.hpp"  // U128, u128_add, u128_less, u128_greater

#include "pathb_params.hpp"                      // Hash32

namespace c2pool::xmr::pathb {

enum class HeaderCheck : std::uint8_t { Passed, Failed };

struct SideHeader {
    std::uint64_t work = 0;  // d of the carrier at its position
    HeaderCheck check = HeaderCheck::Passed;
    Hash32 id{};             // carrier id
};

enum class SideBranchAction : std::uint8_t { FetchBodies, KeepHeaders, Prune, RefuseHeader };

struct SideBranchDecision {
    SideBranchAction action = SideBranchAction::KeepHeaders;
    std::uint64_t refused_index = 0;                     // RefuseHeader only
    ::c2pool::xmr::native::U128 claimed_work{};          // fork work + checked header work
};

inline SideBranchDecision decide_side_branch(const ::c2pool::xmr::native::U128& best_work, const Hash32& best_tip,
                                             const ::c2pool::xmr::native::U128& fork_work,
                                             const std::vector<SideHeader>& headers, std::uint64_t fork_depth,
                                             std::uint64_t journal_depth) noexcept {
    using ::c2pool::xmr::native::U128;
    SideBranchDecision d;
    U128 sum = fork_work;
    for (std::uint64_t i = 0; i < headers.size(); ++i) {
        if (headers[i].check != HeaderCheck::Passed) {
            d.action = SideBranchAction::RefuseHeader;
            d.refused_index = i;
            d.claimed_work = sum;
            return d;
        }
        sum = ::c2pool::xmr::native::u128_add(sum, U128{headers[i].work, 0});
    }
    d.claimed_work = sum;
    const bool heavier = ::c2pool::xmr::native::u128_greater(sum, best_work);
    const bool equal = !heavier && !::c2pool::xmr::native::u128_less(sum, best_work);
    if (heavier || (equal && !headers.empty() && headers.back().id < best_tip)) {
        d.action = SideBranchAction::FetchBodies;
    } else if (fork_depth > journal_depth) {
        d.action = SideBranchAction::Prune;
    } else {
        d.action = SideBranchAction::KeepHeaders;
    }
    return d;
}

}  // namespace c2pool::xmr::pathb
