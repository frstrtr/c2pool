// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_pathb_headers_first_kat.cpp
// Headers-first decision on a side branch:
//   (1) checked headers claiming more work than the best chain: FetchBodies;
//   (2) the same branch with one header that failed its checks: RefuseHeader
//       at that header, no bodies;
//   (3) lighter within J: KeepHeaders; lighter with the fork deeper than J:
//       Prune;
//   (4) equal work: FetchBodies when the last side header id is below the
//       best tip id (bytes in order), otherwise KeepHeaders within J and Prune
//       deeper than J; the same id: no fetch;
//   (5) 128-bit cumulative work: sums across 2^64.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <vector>

#include "impl/xmr/pathb/pathb_caps.hpp"
#include "impl/xmr/pathb/pathb_headers_first.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;
namespace nat = ::c2pool::xmr::native;

int main() {
    std::printf("v37_xmr_pathb_headers_first_kat\n");
    const std::uint64_t J = pb::journal_depth(pb::kRuledLaneParams);
    const nat::U128 fork_work{1000000, 0};
    const nat::U128 best{1000000 + 10 * 18180, 0};
    const pb::Hash32 best_tip = seq32(0x40);

    std::vector<pb::SideHeader> heavier(11, pb::SideHeader{18180, pb::HeaderCheck::Passed});
    // (1)
    pb::SideBranchDecision d = pb::decide_side_branch(best, best_tip, fork_work, heavier, 10, J);
    check(d.action == pb::SideBranchAction::FetchBodies, "heavier checked headers: fetch bodies");
    check(d.claimed_work == nat::U128{1000000 + 11 * 18180, 0}, "claimed work = fork work + header work");

    // (2)
    std::vector<pb::SideHeader> bad = heavier;
    bad[6].check = pb::HeaderCheck::Failed;
    d = pb::decide_side_branch(best, best_tip, fork_work, bad, 10, J);
    check(d.action == pb::SideBranchAction::RefuseHeader && d.refused_index == 6,
          "one failed header: refused at that header, no bodies");
    bad[0].check = pb::HeaderCheck::Failed;
    d = pb::decide_side_branch(best, best_tip, fork_work, bad, 10, J);
    check(d.action == pb::SideBranchAction::RefuseHeader && d.refused_index == 0, "first failed header named");

    // (3)
    std::vector<pb::SideHeader> lighter(9, pb::SideHeader{18180, pb::HeaderCheck::Passed});
    d = pb::decide_side_branch(best, best_tip, fork_work, lighter, J, J);
    check(d.action == pb::SideBranchAction::KeepHeaders, "lighter, fork at depth J: keep headers");
    d = pb::decide_side_branch(best, best_tip, fork_work, lighter, J + 1, J);
    check(d.action == pb::SideBranchAction::Prune, "lighter, fork at depth J + 1: prune");
    d = pb::decide_side_branch(best, best_tip, fork_work, heavier, J + 500, J);
    check(d.action == pb::SideBranchAction::FetchBodies, "heavier with a fork deeper than J: fetch bodies");
    d = pb::decide_side_branch(best, best_tip, fork_work, {}, 3, J);
    check(d.action == pb::SideBranchAction::KeepHeaders && d.claimed_work == fork_work, "no headers: keep");

    // (4) equal work: the fork-choice order by tip id
    std::vector<pb::SideHeader> equal(10, pb::SideHeader{18180, pb::HeaderCheck::Passed});
    pb::Hash32 lower = best_tip;
    lower[31] = static_cast<std::uint8_t>(best_tip[31] - 1);
    pb::Hash32 higher = best_tip;
    higher[0] = static_cast<std::uint8_t>(best_tip[0] + 1);
    equal.back().id = lower;
    d = pb::decide_side_branch(best, best_tip, fork_work, equal, 10, J);
    check(d.action == pb::SideBranchAction::FetchBodies && d.claimed_work == best,
          "equal work, side tip id below the best tip id: fetch bodies");
    d = pb::decide_side_branch(best, best_tip, fork_work, equal, J + 1, J);
    check(d.action == pb::SideBranchAction::FetchBodies, "equal work, lower side tip id, fork deeper than J: fetch bodies");
    equal.back().id = higher;
    d = pb::decide_side_branch(best, best_tip, fork_work, equal, 10, J);
    check(d.action == pb::SideBranchAction::KeepHeaders, "equal work, side tip id above the best tip id: keep headers");
    d = pb::decide_side_branch(best, best_tip, fork_work, equal, J + 1, J);
    check(d.action == pb::SideBranchAction::Prune, "equal work, higher side tip id, fork deeper than J: prune");
    equal.back().id = best_tip;
    d = pb::decide_side_branch(best, best_tip, fork_work, equal, 10, J);
    check(d.action == pb::SideBranchAction::KeepHeaders, "equal work, the same tip id: no fetch");
    pb::Hash32 first_byte_low = best_tip;
    first_byte_low[0] = static_cast<std::uint8_t>(best_tip[0] - 1);
    first_byte_low[31] = 0xff;
    equal.back().id = first_byte_low;
    d = pb::decide_side_branch(best, best_tip, fork_work, equal, 10, J);
    check(d.action == pb::SideBranchAction::FetchBodies, "ids compared from the first byte");
    std::vector<pb::SideHeader> lighter_low(9, pb::SideHeader{18180, pb::HeaderCheck::Passed});
    lighter_low.back().id = lower;
    d = pb::decide_side_branch(best, best_tip, fork_work, lighter_low, 10, J);
    check(d.action == pb::SideBranchAction::KeepHeaders, "lighter with a lower tip id: keep headers");

    // (5)
    const nat::U128 near_top{UINT64_MAX - 5, 0};
    const nat::U128 best_hi{3, 1};
    std::vector<pb::SideHeader> big(2, pb::SideHeader{UINT64_MAX, pb::HeaderCheck::Passed});
    d = pb::decide_side_branch(best_hi, best_tip, near_top, big, 2, J);
    // (2^64 - 6) + 2 (2^64 - 1) = 3 x 2^64 - 8 = {2^64 - 8, 2}
    check(d.claimed_work == nat::U128{UINT64_MAX - 7, 2}, "128-bit sum across 2^64");
    check(d.action == pb::SideBranchAction::FetchBodies, "128-bit comparison: heavier");
    d = pb::decide_side_branch(nat::U128{0, 3}, best_tip, near_top, big, 2, J);
    check(d.action == pb::SideBranchAction::KeepHeaders, "128-bit comparison: lighter than 3 x 2^64");

    return finish("v37_xmr_pathb_headers_first_kat");
}
