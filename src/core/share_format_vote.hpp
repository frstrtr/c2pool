// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// The share format a share's desired_version votes for.
//
// desired_version is the AutoRatchet vote for a share format (35, 36, ...).
// A value of 100 or more is a SUBVERSION of format desired_version / 100:
// 3601 is V36 (the V36 format with LTC's per-share merged payout rule, made by
// c2pool v0.2.12), 3602... would be later V36 subversions. A subversion is a
// vote for its format only — never for 37 or any higher format (37 is
// reserved for Work Receipts). Every reader that counts, compares or
// histograms votes (AutoRatchets, the version-switch checks, the version
// tallies, the stats and the dashboard) goes through this.

#include <cstdint>

namespace core {

inline constexpr uint64_t share_format_vote(uint64_t desired_version)
{
    return desired_version >= 100 ? desired_version / 100 : desired_version;
}

static_assert(share_format_vote(36) == 36);
static_assert(share_format_vote(3601) == 36);
static_assert(share_format_vote(3699) == 36);
static_assert(share_format_vote(35) == 35);
static_assert(share_format_vote(16) == 16);

} // namespace core
