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
//   (3) equal work: no fetch; lighter within J: KeepHeaders; lighter with the
//       fork deeper than J: Prune;
//   (4) 128-bit cumulative work: sums across 2^64.
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

    std::vector<pb::SideHeader> heavier(11, pb::SideHeader{18180, pb::HeaderCheck::Passed});
    // (1)
    pb::SideBranchDecision d = pb::decide_side_branch(best, fork_work, heavier, 10, J);
    check(d.action == pb::SideBranchAction::FetchBodies, "heavier checked headers: fetch bodies");
    check(d.claimed_work == nat::U128{1000000 + 11 * 18180, 0}, "claimed work = fork work + header work");

    // (2)
    std::vector<pb::SideHeader> bad = heavier;
    bad[6].check = pb::HeaderCheck::Failed;
    d = pb::decide_side_branch(best, fork_work, bad, 10, J);
    check(d.action == pb::SideBranchAction::RefuseHeader && d.refused_index == 6,
          "one failed header: refused at that header, no bodies");
    bad[0].check = pb::HeaderCheck::Failed;
    d = pb::decide_side_branch(best, fork_work, bad, 10, J);
    check(d.action == pb::SideBranchAction::RefuseHeader && d.refused_index == 0, "first failed header named");

    // (3)
    std::vector<pb::SideHeader> equal(10, pb::SideHeader{18180, pb::HeaderCheck::Passed});
    d = pb::decide_side_branch(best, fork_work, equal, 10, J);
    check(d.action == pb::SideBranchAction::KeepHeaders, "equal work within J: keep headers, no fetch");
    std::vector<pb::SideHeader> lighter(9, pb::SideHeader{18180, pb::HeaderCheck::Passed});
    d = pb::decide_side_branch(best, fork_work, lighter, J, J);
    check(d.action == pb::SideBranchAction::KeepHeaders, "lighter, fork at depth J: keep headers");
    d = pb::decide_side_branch(best, fork_work, lighter, J + 1, J);
    check(d.action == pb::SideBranchAction::Prune, "lighter, fork at depth J + 1: prune");
    d = pb::decide_side_branch(best, fork_work, heavier, J + 500, J);
    check(d.action == pb::SideBranchAction::FetchBodies, "heavier with a fork deeper than J: fetch bodies");
    d = pb::decide_side_branch(best, fork_work, {}, 3, J);
    check(d.action == pb::SideBranchAction::KeepHeaders && d.claimed_work == fork_work, "no headers: keep");

    // (4)
    const nat::U128 near_top{UINT64_MAX - 5, 0};
    const nat::U128 best_hi{3, 1};
    std::vector<pb::SideHeader> big(2, pb::SideHeader{UINT64_MAX, pb::HeaderCheck::Passed});
    d = pb::decide_side_branch(best_hi, near_top, big, 2, J);
    // (2^64 - 6) + 2 (2^64 - 1) = 3 x 2^64 - 8 = {2^64 - 8, 2}
    check(d.claimed_work == nat::U128{UINT64_MAX - 7, 2}, "128-bit sum across 2^64");
    check(d.action == pb::SideBranchAction::FetchBodies, "128-bit comparison: heavier");
    d = pb::decide_side_branch(nat::U128{0, 3}, near_top, big, 2, J);
    check(d.action == pb::SideBranchAction::KeepHeaders, "128-bit comparison: lighter than 3 x 2^64");

    return finish("v37_xmr_pathb_headers_first_kat");
}
