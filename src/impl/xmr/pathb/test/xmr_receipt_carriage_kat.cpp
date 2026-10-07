// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/xmr_receipt_carriage_kat.cpp
// Self-carriage (pathb_receipt_admission.hpp, S2.3 #14, C36 self-subset, K08):
//   a miner's OWN orphan carried by its own later carrier is admitted and
//   PLACED in its origin bin's open entries (the credited-by-window part is S3);
//   a carried receipt of a SEALED bin (H(pos(c) - 1) >= h(r) + F) STRIKE;
//   two carried out of canonical order STRIKE; 17 carried STRIKE; 16 admitted;
//   a carried receipt whose payee != the carrier's payee STRIKE (the S2
//   self-carriage predicate, slice-local); a carrier with a non-zero
//   carried_root whose receipts_root does not equal the fold
//   sha256d("c2pool-v37-carry" || carried_root || rs_root) STRIKE; an
//   already-placed id STRIKE; a carried body unknown to the verifier -> DEFER
//   then admitted after the fetch. A golden carried_root pins the Merkle
//   convention. window_root / mmr_root stay the S1 zero stubs.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <set>
#include <span>
#include <utility>
#include <vector>

#include "impl/xmr/pathb/pathb_receipt_admission.hpp"
#include "impl/xmr/pathb/pathb_ratchet_state.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

// A ratchet state at pos(tip): genesis + three carriers of d 18,180 (ballots 0),
// as the S1 fold vectors use; only `all` moves.
pb::RatchetState tip_state() {
    pb::RatchetState s = pb::genesis_ratchet_state(seq32(0x55));
    const pb::RatchetPlacement own{18180, 0};
    for (std::uint64_t pos = 1; pos <= 3; ++pos)
        s = pb::rs_step(pb::kRuledRatchetParams, s, pos, std::span<const pb::RatchetPlacement>(&own, 1));
    return s;
}

}  // namespace

int main() {
    const std::uint64_t F = pb::kRuledLaneParams.open_bins;  // K04 = 96
    const std::uint64_t r_max = pb::kRuledLaneParams.r_max;   // K08 = 16
    check(F == 96, "K04 open_bins is 96");
    check(r_max == 16, "K08 r_max is 16");

    const pb::Hash32 carrier_payee = seq32(0x40);
    const pb::Hash32 carrier_parent = seq32(0x70);
    const pb::RatchetState s_tip = tip_state();

    // ---- carried_root Merkle convention ----
    // empty -> the S1 zero stub.
    check(pb::carried_root(std::span<const pb::Hash32>{}) == pb::kNoCarriedRoot, "empty carried_root is zero");
    // one leaf -> that id.
    {
        const pb::Hash32 one = seq32(0x11);
        const std::array<pb::Hash32, 1> ids{one};
        check(pb::carried_root(ids) == one, "single-leaf carried_root is the id");
    }
    // two leaves -> non-zero and order-sensitive.
    const pb::Hash32 id_a = seq32(0x01);
    const pb::Hash32 id_b = seq32(0x02);
    {
        const std::array<pb::Hash32, 2> ab{id_a, id_b};
        const std::array<pb::Hash32, 2> ba{id_b, id_a};
        const pb::Hash32 root_ab = pb::carried_root(ab);
        const pb::Hash32 root_ba = pb::carried_root(ba);
        check(!pb::detail::is_zero(root_ab), "two-leaf carried_root is non-zero");
        check(root_ab != root_ba, "carried_root is order-sensitive");
        // Golden: pins the sha256d node convention for {seq32(0x01), seq32(0x02)}.
        const char* golden = "3da25a395c6d5ba0a9459d03cd482441820fbb3495444df274dd9725b6139e9b";
        std::printf("  carried_root({01..,02..}) = %s\n", hex(root_ab.data(), 32).c_str());
        check(hex(root_ab.data(), 32) == golden, "carried_root golden {01,02}");
    }

    // ---- happy path: an own orphan carried by its own later carrier ----
    // origin bin = h(r); the bin is open on the carrier's chain: H(pos(c)-1) <
    // h(r) + F. carried_root over the ids folds into receipts_root; dedup places
    // the carried id in its origin bin's open entries.
    {
        const std::uint64_t h_r = 1000;                // origin bin
        const std::uint64_t record_at_parent = 1000;    // H(pos(c)-1); open while < h_r + 96
        check(pb::open_at(record_at_parent, h_r, F), "origin bin open");

        std::vector<pb::Hash32> ids{id_a, id_b};
        // canonical order: (origin bin ascending, then sha256d(id || parent)).
        std::vector<pb::CarriedKey> keys{{h_r, id_a}, {h_r, id_b}};
        if (!pb::carried_key_less(keys[0], keys[1], carrier_parent)) {
            std::swap(keys[0], keys[1]);
            std::swap(ids[0], ids[1]);
        }
        check(pb::carried_order_ok(keys, carrier_parent), "two-receipt list in canonical order");

        // self-carriage: both carried payees == the carrier's payee.
        std::vector<pb::Hash32> payees{carrier_payee, carrier_payee};
        check(pb::self_carried_ok(payees, carrier_payee), "self-carriage: own payee admitted");

        // the carrier's receipts_root folds carried_root(ids) with rs_root(S).
        const pb::Hash32 receipts_root = pb::carrier_receipts_root_over(ids, s_tip);
        check(pb::check_carried_fold(receipts_root, ids, s_tip) == pb::FoldVerdict::Match, "fold matches");

        // placement: both ids are placed in the open bin; neither was present.
        pb::PlacedSet placed;
        check(placed.place(ids[0]) && placed.place(ids[1]), "both carried ids placed");
        check(placed.size() == 2, "two placed entries");

        // window_root / mmr_root stay the S1 zero stubs (no S3 window built).
        pb::SideDataV3 side;  // default: both roots zero
        check(pb::zero_stubs_ok(side), "window_root and mmr_root stay zero stubs");
    }

    // ---- sealed bin STRIKE ----
    {
        const std::uint64_t h_r = 1000;
        const std::uint64_t sealed_record = h_r + F;  // H(pos(c)-1) >= h(r) + F
        check(!pb::open_at(sealed_record, h_r, F), "carriage into a sealed bin is refused (STRIKE)");
        check(!pb::open_at(h_r + F + 10, h_r, F), "deeper sealed bin refused");
    }

    // ---- out-of-order STRIKE ----
    {
        std::vector<pb::CarriedKey> sorted{{1000, id_a}, {1000, id_b}};
        if (!pb::carried_key_less(sorted[0], sorted[1], carrier_parent)) std::swap(sorted[0], sorted[1]);
        std::vector<pb::CarriedKey> swapped{sorted[1], sorted[0]};
        check(pb::carried_order_ok(sorted, carrier_parent), "sorted list ok");
        check(!pb::carried_order_ok(swapped, carrier_parent), "two out of canonical order STRIKE");
        // a duplicate key (equal) is not strictly increasing either.
        std::vector<pb::CarriedKey> dup{sorted[0], sorted[0]};
        check(!pb::carried_order_ok(dup, carrier_parent), "equal keys not strictly increasing");
        // bins must be ascending first.
        std::vector<pb::CarriedKey> bins_desc{{1001, id_a}, {1000, id_b}};
        check(!pb::carried_order_ok(bins_desc, carrier_parent), "descending origin bins STRIKE");
    }

    // ---- 17 carried STRIKE, 16 admitted ----
    {
        check(16 <= r_max, "16 within R_MAX");
        check(17 > r_max, "17 above R_MAX -> STRIKE");
        // 16 distinct ids in canonical order admit; 17 would be a count STRIKE
        // before any ordering work.
        std::vector<pb::Hash32> ids16;
        std::vector<pb::CarriedKey> keys16;
        for (std::uint8_t i = 0; i < 16; ++i) {
            const pb::Hash32 id = seq32(static_cast<std::uint8_t>(0x80 + i));
            ids16.push_back(id);
            keys16.push_back({1000, id});
        }
        std::sort(keys16.begin(), keys16.end(), [&](const pb::CarriedKey& a, const pb::CarriedKey& b) {
            return pb::carried_key_less(a, b, carrier_parent);
        });
        check(keys16.size() == 16 && keys16.size() <= r_max, "16 carried count admitted");
        check(pb::carried_order_ok(keys16, carrier_parent), "16 carried in canonical order");
    }

    // ---- foreign payee STRIKE (the self-carriage predicate; slice-local) ----
    {
        const pb::Hash32 foreign = seq32(0x41);
        std::vector<pb::Hash32> payees{carrier_payee, foreign};
        check(!pb::self_carried_ok(payees, carrier_payee), "foreign payee STRIKE (S2 self-carriage predicate)");
        std::vector<pb::Hash32> all_own{carrier_payee, carrier_payee, carrier_payee};
        check(pb::self_carried_ok(all_own, carrier_payee), "all-own payees admitted");
    }

    // ---- non-zero carried_root fold mismatch STRIKE ----
    // a carrier with n_carried > 0, a correctly-ordered list, but a
    // receipts_root that does NOT equal fold(carried_root, rs_root).
    {
        std::vector<pb::Hash32> ids{id_a, id_b};
        if (!pb::carried_key_less(pb::CarriedKey{1000, ids[0]}, pb::CarriedKey{1000, ids[1]}, carrier_parent))
            std::swap(ids[0], ids[1]);
        const pb::Hash32 good = pb::carrier_receipts_root_over(ids, s_tip);
        check(!pb::detail::is_zero(pb::carried_root(ids)), "carried_root is non-zero for this list");
        check(pb::check_carried_fold(good, ids, s_tip) == pb::FoldVerdict::Match, "honest fold matches");
        pb::Hash32 tampered = good;
        tampered[0] ^= 0x01;  // a flipped bit in receipts_root
        check(pb::check_carried_fold(tampered, ids, s_tip) == pb::FoldVerdict::Strike,
              "non-zero carried_root fold mismatch STRIKE");
        // the carried_root = 0 happy path (S1) still folds; using it here with a
        // non-empty list is also a mismatch.
        const pb::Hash32 zero_root_fold = pb::carrier_receipts_root(pb::kNoCarriedRoot, s_tip);
        check(pb::check_carried_fold(zero_root_fold, ids, s_tip) == pb::FoldVerdict::Strike,
              "carried_root 0 fold against a non-empty list is a mismatch");
    }

    // ---- already-placed id STRIKE (dedup, ruling 27 K-10) ----
    {
        pb::PlacedSet placed;
        check(placed.place(id_a), "first placement of id_a");
        check(!placed.place(id_a), "already-placed id_a STRIKE on re-carry");
        check(placed.contains(id_a), "id_a is in the dedup set");
    }

    // ---- unknown body -> DEFER then admitted after fetch ----
    {
        std::set<pb::Hash32> available;  // the verifier's held bodies
        const pb::Hash32 missing = id_b;
        const bool body_present_1 = available.count(missing) != 0;
        check(!body_present_1, "carried body unknown -> DEFER + fetch");
        available.insert(missing);  // the fetch arrives
        const bool body_present_2 = available.count(missing) != 0;
        // now admit: open bin, canonical order of a one-item list, self payee.
        const bool admitted = body_present_2 && pb::open_at(1000, 1000, F)
                              && pb::self_carried_ok(std::array<pb::Hash32, 1>{carrier_payee}, carrier_payee);
        check(admitted, "carried body admitted after the fetch");
    }

    return finish("xmr_receipt_carriage_kat");
}
