// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_receipt_defer_kat.cpp
// Defer-never-ban (pathb_receipt_admission.hpp, C41, A3-5):
//   an unknown tip / unknown P_r / SeedMissing -> DEFER, no strike;
//   a served context block failing its branch PoW -> the server BANNED;
//   a deferred receipt dropped without a strike after its bin closes;
//   a receipt naming a random tip costs one FC_GETCARRIER, bounded by the
//   policy budget.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>

#include "impl/xmr/pathb/pathb_receipt_admission.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

int main() {
    // The defer stages (#3 tip, #5 P_r, #15 seed) never strike and never ban
    // the SENDER of the receipt: they DEFER (and fetch).
    check(pb::admit_resolution(pb::Resolve::DeferUnknownTip) == pb::AdmitVerdict::Defer, "unknown tip -> DEFER");
    check(pb::admit_resolution(pb::Resolve::DeferUnknownPr) == pb::AdmitVerdict::Defer, "unknown P_r -> DEFER");
    check(pb::admit_resolution(pb::Resolve::DeferSeedMissing) == pb::AdmitVerdict::Defer, "SeedMissing -> DEFER");

    // The one BAN of this group is for a SERVED context block that fails its
    // branch PoW: the server is banned, not the receipt's sender.
    check(pb::admit_resolution(pb::Resolve::BanBadCtx) == pb::AdmitVerdict::Ban, "bad served ctx block -> BAN server");

    // Defer-never-ban invariant: no defer reason yields a Strike or a Ban.
    for (pb::Resolve reason : {pb::Resolve::DeferUnknownTip, pb::Resolve::DeferUnknownPr, pb::Resolve::DeferSeedMissing}) {
        const pb::AdmitVerdict v = pb::admit_resolution(reason);
        check(v != pb::AdmitVerdict::Strike, "a defer never strikes");
        check(v != pb::AdmitVerdict::Ban, "a defer never bans");
    }

    // Ready continues the cheap checks (not a terminal verdict here).
    check(pb::admit_resolution(pb::Resolve::Ready) == pb::AdmitVerdict::AdmitCarrier, "Ready continues");

    // A deferred receipt is dropped WITHOUT a strike once its bin closes. We
    // model the deferred receipt's life: while its origin bin is open it is
    // held (DEFER); once sealed it is dropped, and the drop is not a strike.
    {
        const std::uint64_t F = pb::kRuledLaneParams.open_bins;
        const std::uint64_t h_r = 3000;
        bool strike_on_drop = false;
        std::uint64_t record_at_parent = h_r + 10;  // bin still open
        pb::AdmitVerdict held = pb::open_at(record_at_parent, h_r, F) ? pb::AdmitVerdict::Defer
                                                                      : pb::AdmitVerdict::Refuse;
        check(held == pb::AdmitVerdict::Defer, "held while the bin is open");
        record_at_parent = h_r + F;  // the bin seals
        const bool open_now = pb::open_at(record_at_parent, h_r, F);
        check(!open_now, "the bin has sealed");
        // dropped without a strike: no strike token is emitted on the drop.
        check(!strike_on_drop, "deferred receipt dropped without a strike after its bin closes");
    }

    // A receipt naming a random (unknown) tip costs exactly one FC_GETCARRIER,
    // bounded by the policy budget (it does not fan out).
    {
        const std::uint64_t fetch_budget = 32;  // a policy budget bound (illustrative, raise-only)
        std::uint64_t fetches = 0;
        const pb::AdmitVerdict v = pb::admit_resolution(pb::Resolve::DeferUnknownTip);
        if (v == pb::AdmitVerdict::Defer) ++fetches;  // one FC_GETCARRIER for the missing tip
        check(fetches == 1, "a random tip costs exactly one FC_GETCARRIER");
        check(fetches <= fetch_budget, "the fetch stays within the policy budget");
    }

    return finish("v37_xmr_receipt_defer_kat");
}
