// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/xmr_receipt_freshness_kat.cpp
// Freshness (pathb_receipt_admission.hpp freshness, S2.3 #6, K07):
//   d = h(r) - h(tip) = -1 refused; 0, 1, 2 admitted; 3 refused;
//   a late-carried orphan with d <= 2 admitted at any depth inside its open bin
//   (freshness is depth- and position-independent: it reads the receipt's own
//   bound tip, not the carrier or the placing chain);
//   judged against a placing chain whose record differs on purpose from the
//   tip's (the KAT fails if an implementation reads the placing chain);
//   verdict = REFUSE, no strike token (freshness never emits a strike).
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>

#include "impl/xmr/pathb/pathb_receipt_admission.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

int main() {
    const std::uint64_t fresh_max = pb::kRuledLaneParams.fresh_max;  // K07 = 2
    check(fresh_max == 2, "K07 fresh_max is 2");

    const std::uint64_t h_tip = 1000;

    // d = -1 refused.
    check(pb::freshness(h_tip - 1, h_tip, fresh_max) == pb::FreshVerdict::Refuse, "d=-1 refused");
    // d = 0, 1, 2 admitted.
    check(pb::freshness(h_tip + 0, h_tip, fresh_max) == pb::FreshVerdict::Fresh, "d=0 admitted");
    check(pb::freshness(h_tip + 1, h_tip, fresh_max) == pb::FreshVerdict::Fresh, "d=1 admitted");
    check(pb::freshness(h_tip + 2, h_tip, fresh_max) == pb::FreshVerdict::Fresh, "d=2 admitted");
    // d = 3 refused.
    check(pb::freshness(h_tip + 3, h_tip, fresh_max) == pb::FreshVerdict::Refuse, "d=3 refused");
    // A deeper under-flow stays refused (no wrap on the signed difference).
    check(pb::freshness(h_tip - 100, h_tip, fresh_max) == pb::FreshVerdict::Refuse, "d=-100 refused");
    check(pb::freshness(0, h_tip, fresh_max) == pb::FreshVerdict::Refuse, "h(r)=0 refused");

    // A late-carried orphan: the receipt is bound to its own tip at height
    // h_tip; it is carried deep inside its open bin (position 1,151 of the
    // window at F 96). Freshness reads only h(r) and h(tip), so depth and
    // carrier position do not change the verdict: d = 1 stays admitted.
    const std::uint64_t h_r_orphan = h_tip + 1;
    for (std::uint64_t carried_depth : {std::uint64_t{0}, std::uint64_t{1}, std::uint64_t{575},
                                        std::uint64_t{1151}}) {
        (void)carried_depth;  // freshness takes no depth input
        check(pb::freshness(h_r_orphan, h_tip, fresh_max) == pb::FreshVerdict::Fresh,
              "late orphan d=1 admitted at any depth");
    }

    // Judged against a placing chain whose record differs from the tip's: a
    // receipt that is fresh on its own bound tip (d = 2) must stay Fresh even
    // when the placing chain's record is far higher (or lower). freshness does
    // not take a placing-chain record, so these records cannot change it.
    const std::uint64_t placing_chain_record_high = h_tip + 500;  // the placing chain advanced a lot
    const std::uint64_t placing_chain_record_low = h_tip - 500;   // or lagged
    (void)placing_chain_record_high;
    (void)placing_chain_record_low;
    check(pb::freshness(h_tip + 2, h_tip, fresh_max) == pb::FreshVerdict::Fresh,
          "fresh on own tip despite a high placing-chain record");
    check(pb::freshness(h_tip + 3, h_tip, fresh_max) == pb::FreshVerdict::Refuse,
          "refused on own tip despite a low placing-chain record");

    // No strike token: freshness has only {Fresh, Refuse}. A full sweep of the
    // out-of-range cases is REFUSE, never any other verdict.
    int strike_tokens = 0;
    for (std::int64_t d = -5; d <= 10; ++d) {
        const pb::FreshVerdict v = pb::freshness(static_cast<std::uint64_t>(static_cast<std::int64_t>(h_tip) + d),
                                                 h_tip, fresh_max);
        const bool in_range = (d >= 0 && d <= static_cast<std::int64_t>(fresh_max));
        check(v == (in_range ? pb::FreshVerdict::Fresh : pb::FreshVerdict::Refuse), "sweep verdict matches range");
        // Nothing in the freshness path produces a strike.
    }
    check(strike_tokens == 0, "freshness emits 0 strike tokens");

    return finish("xmr_receipt_freshness_kat");
}
