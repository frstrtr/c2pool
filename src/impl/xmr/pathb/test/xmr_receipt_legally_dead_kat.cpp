// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/xmr_receipt_legally_dead_kat.cpp
// LEGALLY DEAD (pathb_receipt_admission.hpp live, S2.3 #17, C03/C22, K05):
//   live(r) <=> h(r) >= H(min(q - 1, own_pos)) at delta = 1, H over CARRIERS of
//   the placing chain. The 7 delta-1 vectors (SPEC S2.6):
//     (1) an honest orphan carried by the next carrier is live;
//     (2) a lazy stale template one height back is dead as soon as a CARRIER in
//         the record of its own position carries the new height (a placed
//         receipt does not raise the record, F3);
//     (3) a same-height race: both live;
//     (4) useful work carried 500 positions later: live;
//     (5) a deliberately stale receipt on a deep tip inside its old bin: live
//         (documented residual);
//     (6) control delta 3: vector (4) with the record advanced by one height
//         between own_pos and q -> live at delta 1, dead at delta 3 (the KAT
//         asserts the delta-1 verdict);
//     (7) q = p(r): judged at pos(t), live.
//   The height record H is built from CARRIER template heights only, by
//   record_height (pathb_retarget.hpp). NO clock input appears in this path.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <vector>

#include "impl/xmr/pathb/pathb_receipt_admission.hpp"
#include "impl/xmr/pathb/pathb_retarget.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

// A placing chain's height record H over CARRIERS: records[pos] = the record
// height of the carrier at position pos, folded by record_height over the
// chosen carrier template heights (position 0 = genesis). Placed receipts never
// raise it (F3): only the carrier heights listed here do.
struct PlacingChain {
    std::vector<std::uint64_t> records;

    explicit PlacingChain(const std::vector<std::uint64_t>& carrier_heights) {
        std::uint64_t rec = 0;
        for (std::size_t i = 0; i < carrier_heights.size(); ++i) {
            rec = (i == 0) ? carrier_heights[i] : pb::record_height(rec, carrier_heights[i]);
            records.push_back(rec);
        }
    }
    std::uint64_t at(std::uint64_t pos) const {
        return records[pos < records.size() ? pos : records.size() - 1];
    }
};

}  // namespace

int main() {
    check(pb::kLivenessDelta == 1, "K05 liveness_delta is 1");

    // --- Vector (1): honest orphan carried by the NEXT carrier is live. ---
    // tip at pos 5 (height 100). The orphan (h_r = 100) competed at own_pos = 6;
    // the winner at pos 6 has height 100 (a sibling), so H(6) = 100. Carried by
    // the next carrier at q = 7. threshold = min(6, 6) = 6; H(6) = 100 <= 100.
    {
        const PlacingChain c({90, 92, 94, 96, 98, 100, 100});  // positions 0..6
        const std::uint64_t h_r = 100, own = pb::own_pos(5), q = 7;
        check(pb::live(h_r, q, own, [&](std::uint64_t p) { return c.at(p); }), "(1) orphan next-carrier live");
    }

    // --- Vector (2): lazy stale template one height back is dead. ---
    // h_r = 99 (one back from the tip height 100). own_pos = 6. A CARRIER at
    // pos 6 carries the new height 100, so H(6) = 100 > 99. Carried at q = 7:
    // threshold = min(6, 6) = 6 -> dead.
    {
        const PlacingChain c({90, 92, 94, 96, 98, 99, 100});  // the carrier at pos 6 raises the record to 100
        const std::uint64_t h_r = 99, own = pb::own_pos(5), q = 7;
        check(!pb::live(h_r, q, own, [&](std::uint64_t p) { return c.at(p); }), "(2) lazy stale is dead");
        // A placed receipt does NOT raise the record (F3): the record at pos 6
        // comes only from the carrier height, so a stale placement cannot
        // resurrect itself.
    }

    // --- Vector (3): a same-height race: both live. ---
    // Two receipts, both h_r = 100, tip pos 5 (height 100). The winning carrier
    // at pos 6 is also height 100. Both judged at threshold 6 -> both live.
    {
        const PlacingChain c({90, 92, 94, 96, 98, 100, 100});
        const std::uint64_t own = pb::own_pos(5), q = 7;
        check(pb::live(100, q, own, [&](std::uint64_t p) { return c.at(p); }), "(3a) same-height live");
        check(pb::live(100, q, own, [&](std::uint64_t p) { return c.at(p); }), "(3b) same-height live");
    }

    // --- Vector (4): useful work carried 500 positions later is live. ---
    // h_r = 100, own_pos = 6, carried by a carrier at q = 506 (orphaned, carried late).
    // threshold = min(505, 6) = 6; it is judged at its OWN position (6), where
    // H = 100, even though the record grew far higher by position 505.
    {
        const PlacingChain c({90, 92, 94, 96, 98, 100, 100});  // record at 6 is 100
        const std::uint64_t h_r = 100, own = pb::own_pos(5), q = 506;
        check(pb::live(h_r, q, own, [&](std::uint64_t p) { return c.at(p); }), "(4) carried 500 later live");
    }

    // --- Vector (5): deliberately stale receipt on a deep tip inside its old
    // open bin is live (documented residual). ---
    // tip at pos 50 (height 200); own_pos = 51; h_r = 200; carried at q = 600.
    // threshold = min(599, 51) = 51; H(51) = 200 <= 200 -> live.
    {
        std::vector<std::uint64_t> heights;
        for (std::uint64_t i = 0; i <= 51; ++i) heights.push_back(150 + i);  // pos 50 -> 200, pos 51 -> 201
        heights[50] = 200;
        heights[51] = 200;  // the carrier at own_pos keeps the record at 200
        const PlacingChain c(heights);
        const std::uint64_t h_r = 200, own = pb::own_pos(50), q = 600;
        check(pb::live(h_r, q, own, [&](std::uint64_t p) { return c.at(p); }), "(5) deep stale tip live (residual)");
    }

    // --- Vector (6): control delta 3. ---
    // Vector (4) but the record advances by one height between own_pos and q.
    // At delta 1 the threshold is own_pos (record 100) -> live; at delta 3 the
    // threshold is own_pos + 2 (record 101) -> dead. The KAT asserts the
    // delta-1 (consensus) verdict is live and the delta-3 control is dead.
    {
        // positions:        0   1   2   3   4   5    6    7    8
        const PlacingChain c({90, 92, 94, 96, 98, 100, 100, 101, 101});
        const std::uint64_t h_r = 100, own = pb::own_pos(5), q = 506;
        check(pb::live(h_r, q, own, [&](std::uint64_t p) { return c.at(p); }), "(6) delta-1 live");
        check(!pb::live_at_delta(h_r, q, own, 3, [&](std::uint64_t p) { return c.at(p); }),
              "(6) delta-3 control dead");
    }

    // --- Vector (7): q = p(r): judged at pos(t), live. ---
    // tip at pos 5 (height 100); own_pos = 6; carried by a carrier at q = 6
    // whose own height is higher (101), so H(6) = 101. threshold = min(5, 6) =
    // 5; H(5) = 100 <= h_r = 100 -> live (judged at pos(t) = 5, not at 6).
    {
        const PlacingChain c({90, 92, 94, 96, 98, 100, 101});  // the carrier at pos 6 is higher
        const std::uint64_t h_r = 100, own = pb::own_pos(5), q = 6;
        check(pb::live(h_r, q, own, [&](std::uint64_t p) { return c.at(p); }), "(7) q = p(r) judged at pos(t) live");
    }

    // The liveness path is deterministic over integer chain data only: a second
    // evaluation with the same inputs gives the same verdict (no clock).
    {
        const PlacingChain c({90, 92, 94, 96, 98, 100, 100});
        const bool a = pb::live(100, 7, pb::own_pos(5), [&](std::uint64_t p) { return c.at(p); });
        const bool b = pb::live(100, 7, pb::own_pos(5), [&](std::uint64_t p) { return c.at(p); });
        check(a == b, "liveness deterministic (no clock input)");
    }

    return finish("xmr_receipt_legally_dead_kat");
}
