// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/xmr_receipt_carriage_kat.cpp
// Open carriage (pathb_receipt_admission.hpp check_carried_list, S2.3 #7 /
// #8 / #14, C36, K08), S2 part:
//   another miner's receipt carried by any carrier is admitted and PLACED in
//   its origin bin's open entries (the credited-by-window part is S3);
//   a carried receipt of a SEALED bin (H(pos(c) - 1) >= h(r) + F) STRIKE;
//   the fold carrier f may carry bin-b receipts, carrier f + 1 may not;
//   two carried out of canonical order STRIKE; 17 carried STRIKE; 16 admitted;
//   a carrier omitting a known higher-ranked receipt is ADMITTED and the
//   omission counted; a carrier carrying nothing while receipts are
//   pending is admitted; a carried body unknown to the verifier -> DEFER, then
//   admitted after the fetch; a carried receipt already placed on the chain
//   STRIKE, the same receipt on another branch admitted once there; a carrier
//   with a receipts_root other than the fold
//   sha256d("c2pool-v37-carry" || carried_root || rs_root) STRIKE. A golden
//   carried_root pins the Merkle convention. window_root / mmr_root stay the
//   S1 zero stubs.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <map>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/pathb/pathb_buckets.hpp"  // fold_pos
#include "impl/xmr/pathb/pathb_ratchet_state.hpp"
#include "impl/xmr/pathb/pathb_receipt_admission.hpp"
#include "pathb_kat_bodies.hpp"
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

struct Carried {
    pb::ReceiptBodyV3 body;
    std::uint64_t bin = 0;
};

// The canonical order of a carried list on a carrier whose tip is `parent`.
void sort_canonical(std::vector<Carried>& v, const pb::Hash32& parent) {
    std::sort(v.begin(), v.end(), [&](const Carried& a, const Carried& b) {
        return pb::carried_key_less({a.bin, pb::receipt_id(a.body)}, {b.bin, pb::receipt_id(b.body)}, parent);
    });
}

std::vector<pb::CarriedReceipt> as_list(const std::vector<Carried>& v) {
    std::vector<pb::CarriedReceipt> out;
    for (const Carried& c : v) out.push_back({c.body, c.bin});
    return out;
}

std::vector<pb::Hash32> ids_of(const std::vector<Carried>& v) {
    std::vector<pb::Hash32> out;
    for (const Carried& c : v) out.push_back(pb::receipt_id(c.body));
    return out;
}

// The carrier's own body with the honest receipts_root over `carried` (as listed).
pb::ReceiptBodyV3 carrier_over(pb::ReceiptBodyV3 own, const std::vector<Carried>& carried, const pb::RatchetState& s) {
    own.side.receipts_root = pb::carrier_receipts_root_over(ids_of(carried), s);
    return own;
}

bool admitted(const pb::CarriedListResult& r) { return !r.verdict.has_value() && r.fault == pb::CarriedFault::None; }

bool strike(const pb::CarriedListResult& r, pb::CarriedFault f) {
    return r.verdict == pb::AdmitVerdict::Strike && r.fault == f && pb::strike_tokens(*r.verdict) == 1;
}

}  // namespace

int main() {
    const pb::LaneParams& lp = pb::kRuledLaneParams;
    const std::uint64_t F = lp.open_bins;   // K04 = 96
    const std::uint64_t r_max = lp.r_max;   // K08 = 16
    check(F == 96, "K04 open_bins is 96");
    check(r_max == 16, "K08 r_max is 16");

    const pb::RatchetState s_tip = tip_state();
    // The carrier's own receipt: payee from seed 0x10; its tip is the carrier's parent.
    const pb::ReceiptBodyV3 own = make_body(2, false, 0x10);
    const pb::Hash32 parent = own.side.tip;
    const std::uint64_t h_r = 1000;            // origin bin of the carried receipts
    const std::uint64_t record_open = 1000;    // H(pos(c) - 1): open while < h_r + F

    // ---- carried_root Merkle convention ----
    check(pb::carried_root(std::span<const pb::Hash32>{}) == pb::kNoCarriedRoot, "empty carried_root is zero");
    {
        const pb::Hash32 one = seq32(0x11);
        const std::array<pb::Hash32, 1> ids{one};
        check(pb::carried_root(ids) == one, "single-leaf carried_root is the id");
    }
    {
        const std::array<pb::Hash32, 2> ab{seq32(0x01), seq32(0x02)};
        const std::array<pb::Hash32, 2> ba{seq32(0x02), seq32(0x01)};
        const pb::Hash32 root_ab = pb::carried_root(ab);
        check(!pb::detail::is_zero(root_ab), "two-leaf carried_root is non-zero");
        check(root_ab != pb::carried_root(ba), "carried_root is order-sensitive");
        // Golden: pins the sha256d node convention for {seq32(0x01), seq32(0x02)}.
        const char* golden = "3da25a395c6d5ba0a9459d03cd482441820fbb3495444df274dd9725b6139e9b";
        std::printf("  carried_root({01..,02..}) = %s\n", hex(root_ab.data(), 32).c_str());
        check(hex(root_ab.data(), 32) == golden, "carried_root golden {01,02}");
    }
    // odd counts (E-10): at a level with an odd count the last node is promoted
    // unchanged, never duplicated. Ids seq32(0x01) .. seq32(n).
    {
        const std::array<pb::Hash32, 3> ids3{seq32(0x01), seq32(0x02), seq32(0x03)};
        const std::array<pb::Hash32, 5> ids5{seq32(0x01), seq32(0x02), seq32(0x03), seq32(0x04), seq32(0x05)};
        const pb::Hash32 root3 = pb::carried_root(ids3);
        const pb::Hash32 root5 = pb::carried_root(ids5);
        std::printf("  carried_root({01..03}) = %s\n", hex(root3.data(), 32).c_str());
        std::printf("  carried_root({01..05}) = %s\n", hex(root5.data(), 32).c_str());
        check(hex(root3.data(), 32) == "75e683fcba0f631eea34521cf0c7cceb72cca7c99fb168e7ff8ba2888436dfdd",
              "carried_root golden n = 3 {01,02,03}");
        check(hex(root5.data(), 32) == "539f779632b3f3515f1edb3d1cc5040d3fbbdfbf758e4ff5db103540dad617c9",
              "carried_root golden n = 5 {01,02,03,04,05}");
    }

    // ---- open carriage: receipts of OTHER miners admitted and placed ----
    {
        std::vector<Carried> list{{make_body(2, false, 0x21), h_r}, {make_body(2, false, 0x22), h_r},
                                  {make_body(2, false, 0x23), h_r - 1}};
        // the carrier's own payee among them, and two foreign payees
        list[0].body.payee = own.payee;
        list[0].body.side.payee = own.side.payee;
        check(list[1].body.side.payee != own.side.payee && list[2].body.side.payee != own.side.payee
                      && list[1].body.side.payee != list[2].body.side.payee,
              "two carried payees differ from the carrier's and from each other");
        sort_canonical(list, parent);
        const pb::ReceiptBodyV3 c = carrier_over(own, list, s_tip);
        const std::vector<pb::CarriedReceipt> carried = as_list(list);
        pb::PlacedSet placed;
        const pb::CarriedListResult r = pb::check_carried_list(c, record_open, carried, placed, s_tip, lp);
        check(admitted(r), "receipts of other miners carried: admitted (open carriage)");
        check(r.ids == ids_of(list), "admitted ids in list order");
        // placement: each id enters its origin bin's open entries on the chain.
        std::map<std::uint64_t, std::vector<pb::Hash32>> open_entries;
        bool placed_all = true;
        for (std::size_t i = 0; i < r.ids.size(); ++i) {
            placed_all = placed_all && placed.place(r.ids[i]);
            open_entries[list[i].bin].push_back(r.ids[i]);
        }
        check(placed_all && placed.size() == 3, "every carried id placed on the chain");
        check(open_entries[h_r].size() == 2 && open_entries[h_r - 1].size() == 1,
              "each carried receipt placed in its own origin bin's open entries");
        // a carrier carrying ONLY a foreign miner's receipt
        std::vector<Carried> foreign{{make_body(2, false, 0x24), h_r}};
        check(foreign[0].body.side.payee != own.side.payee, "a foreign payee");
        const pb::ReceiptBodyV3 cf = carrier_over(own, foreign, s_tip);
        pb::PlacedSet placed_f;
        check(admitted(pb::check_carried_list(cf, record_open, as_list(foreign), placed_f, s_tip, lp)),
              "a foreign payee alone: admitted (no payee predicate)");
        // window_root / mmr_root stay the S1 zero stubs (no S3 window built).
        check(pb::zero_stubs_ok(pb::SideDataV3{}), "window_root and mmr_root stay zero stubs");
    }

    // ---- sealed bin STRIKE ----
    {
        std::vector<Carried> list{{make_body(2, false, 0x31), h_r}};
        const pb::ReceiptBodyV3 c = carrier_over(own, list, s_tip);
        pb::PlacedSet placed;
        check(admitted(pb::check_carried_list(c, h_r + F - 1, as_list(list), placed, s_tip, lp)),
              "H(pos(c) - 1) = h(r) + F - 1: bin open, admitted");
        const pb::CarriedListResult r = pb::check_carried_list(c, h_r + F, as_list(list), placed, s_tip, lp);
        check(strike(r, pb::CarriedFault::SealedBin) && r.index == 0,
              "H(pos(c) - 1) = h(r) + F: carriage into a sealed bin STRIKE");
        check(strike(pb::check_carried_list(c, h_r + F + 10, as_list(list), placed, s_tip, lp),
                     pb::CarriedFault::SealedBin),
              "deeper sealed bin STRIKE");
    }

    // ---- the fold carrier f may carry bin-b receipts; carrier f + 1 may not ----
    {
        // H(x) over carrier positions: one Monero height per 12 positions from h_r.
        const auto record = [&](std::uint64_t x) { return h_r + x / 12; };
        bool found = false;
        const std::uint64_t f = pb::fold_pos(record, 4000, h_r, F, found);
        check(found && f == 12 * F, "the fold carrier of bin h(r) is at position 12 F");
        std::vector<Carried> list{{make_body(2, false, 0x32), h_r}};
        const pb::ReceiptBodyV3 c = carrier_over(own, list, s_tip);
        pb::PlacedSet placed;
        check(admitted(pb::check_carried_list(c, record(f - 1), as_list(list), placed, s_tip, lp)),
              "the fold carrier f carries a bin-b receipt");
        check(strike(pb::check_carried_list(c, record(f), as_list(list), placed, s_tip, lp),
                     pb::CarriedFault::SealedBin),
              "carrier f + 1 carrying a bin-b receipt STRIKE");
    }

    // ---- canonical order ----
    {
        std::vector<Carried> list{{make_body(2, false, 0x41), h_r}, {make_body(2, false, 0x42), h_r}};
        sort_canonical(list, parent);
        std::vector<Carried> swapped{list[1], list[0]};
        const pb::ReceiptBodyV3 c_sorted = carrier_over(own, list, s_tip);
        const pb::ReceiptBodyV3 c_swapped = carrier_over(own, swapped, s_tip);
        pb::PlacedSet placed;
        check(admitted(pb::check_carried_list(c_sorted, record_open, as_list(list), placed, s_tip, lp)),
              "canonical order admitted");
        check(strike(pb::check_carried_list(c_swapped, record_open, as_list(swapped), placed, s_tip, lp),
                     pb::CarriedFault::Order),
              "two carried out of canonical order STRIKE");
        // origin bins ascend first: a later bin before an earlier one.
        std::vector<Carried> bins_desc{{make_body(2, false, 0x43), h_r}, {make_body(2, false, 0x44), h_r - 1}};
        check(strike(pb::check_carried_list(carrier_over(own, bins_desc, s_tip), record_open, as_list(bins_desc),
                                            placed, s_tip, lp),
                     pb::CarriedFault::Order),
              "descending origin bins STRIKE");
        // the same receipt twice in one list (equal keys)
        std::vector<Carried> twice{list[0], list[0]};
        check(strike(pb::check_carried_list(carrier_over(own, twice, s_tip), record_open, as_list(twice), placed,
                                            s_tip, lp),
                     pb::CarriedFault::Order),
              "a duplicate inside the carried list STRIKE");
    }

    // ---- 17 carried STRIKE, 16 admitted ----
    {
        std::vector<Carried> list;
        for (std::uint8_t i = 0; i < 17; ++i) list.push_back({make_body(2, false, static_cast<std::uint8_t>(0x80 + i)), h_r});
        std::vector<Carried> sixteen(list.begin(), list.begin() + 16);
        sort_canonical(sixteen, parent);
        sort_canonical(list, parent);
        pb::PlacedSet placed;
        const pb::CarriedListResult r16 =
                pb::check_carried_list(carrier_over(own, sixteen, s_tip), record_open, as_list(sixteen), placed, s_tip, lp);
        check(admitted(r16) && r16.ids.size() == 16, "16 carried (R_MAX) admitted");
        const pb::CarriedListResult r17 =
                pb::check_carried_list(carrier_over(own, list, s_tip), record_open, as_list(list), placed, s_tip, lp);
        check(strike(r17, pb::CarriedFault::Count), "17 carried (R_MAX + 1) STRIKE");
    }

    // ---- omission is not a refusal; an empty carrier with pending receipts is admitted ----
    {
        // the verifier holds two pending receipts in open bins; k_hi ranks first.
        Carried k_hi{make_body(2, false, 0x51), h_r - 1};
        Carried k_lo{make_body(2, false, 0x52), h_r};
        const std::vector<pb::Hash32> known{pb::receipt_id(k_hi.body), pb::receipt_id(k_lo.body)};
        check(pb::carried_key_less({k_hi.bin, known[0]}, {k_lo.bin, known[1]}, parent),
              "the omitted receipt ranks above the carried one");
        std::vector<Carried> only_lo{k_lo};
        pb::PlacedSet placed;
        const pb::CarriedListResult r =
                pb::check_carried_list(carrier_over(own, only_lo, s_tip), record_open, as_list(only_lo), placed, s_tip, lp);
        check(admitted(r), "a carrier omitting a known higher-ranked receipt is ADMITTED");
        check(pb::carried_omissions(r.ids, known) == 1, "the omission is counted for the per-peer log");
        const std::vector<Carried> none;
        const pb::CarriedListResult r0 =
                pb::check_carried_list(carrier_over(own, none, s_tip), record_open, as_list(none), placed, s_tip, lp);
        check(admitted(r0), "a carrier carrying nothing while receipts are pending is admitted");
        check(pb::carried_omissions(r0.ids, known) == 2, "both pending receipts counted as omitted");
        check(pb::carried_omissions(known, known) == 0, "a carrier carrying both omits none");
    }

    // ---- an unknown carried body -> DEFER, then admitted after the fetch ----
    {
        std::vector<Carried> list{{make_body(2, false, 0x61), h_r}, {make_body(2, false, 0x62), h_r}};
        sort_canonical(list, parent);
        const pb::ReceiptBodyV3 c = carrier_over(own, list, s_tip);
        std::vector<pb::CarriedReceipt> held = as_list(list);
        held[1].body.reset();  // the verifier does not hold the second body
        pb::PlacedSet placed;
        const pb::CarriedListResult r = pb::check_carried_list(c, record_open, held, placed, s_tip, lp);
        check(r.verdict == pb::AdmitVerdict::Defer && r.fault == pb::CarriedFault::MissingBody && r.index == 1
                      && pb::strike_tokens(*r.verdict) == 0,
              "carried body unknown -> DEFER + fetch, no strike");
        held[1].body = list[1].body;  // the fetch arrives
        check(admitted(pb::check_carried_list(c, record_open, held, placed, s_tip, lp)),
              "carried body admitted after the fetch");
    }

    // ---- dedup: already placed STRIKE; the carrier's own id STRIKE; another branch admits once ----
    {
        std::vector<Carried> list{{make_body(2, false, 0x71), h_r}};
        const pb::ReceiptBodyV3 c = carrier_over(own, list, s_tip);
        pb::PlacedSet chain_a;
        check(chain_a.place(pb::receipt_id(list[0].body)), "the receipt is placed on chain A");
        const pb::CarriedListResult ra = pb::check_carried_list(c, record_open, as_list(list), chain_a, s_tip, lp);
        check(strike(ra, pb::CarriedFault::Duplicate) && ra.index == 0,
              "a carried receipt already placed on the chain STRIKE");
        pb::PlacedSet chain_b;
        const pb::CarriedListResult rb = pb::check_carried_list(c, record_open, as_list(list), chain_b, s_tip, lp);
        check(admitted(rb), "the same receipt re-carried on another branch inside its open bin: admitted");
        check(rb.ids.size() == 1 && chain_b.place(rb.ids[0]) && !chain_b.place(rb.ids[0]), "placed once on that branch");
        check(strike(pb::check_carried_list(c, record_open, as_list(list), chain_b, s_tip, lp),
                     pb::CarriedFault::Duplicate),
              "a second carriage on that branch STRIKE");
        // a carrier carrying its own receipt
        std::vector<Carried> self{{own, h_r}};
        check(strike(pb::check_carried_list(carrier_over(own, self, s_tip), record_open, as_list(self), chain_b,
                                            s_tip, lp),
                     pb::CarriedFault::Duplicate),
              "a carrier carrying its own id STRIKE");
    }

    // ---- receipts_root fold mismatch STRIKE ----
    {
        std::vector<Carried> list{{make_body(2, false, 0x91), h_r}, {make_body(2, false, 0x92), h_r}};
        sort_canonical(list, parent);
        const pb::ReceiptBodyV3 good = carrier_over(own, list, s_tip);
        check(!pb::detail::is_zero(pb::carried_root(ids_of(list))), "carried_root is non-zero for this list");
        pb::PlacedSet placed;
        check(admitted(pb::check_carried_list(good, record_open, as_list(list), placed, s_tip, lp)), "honest fold admitted");
        pb::ReceiptBodyV3 tampered = good;
        tampered.side.receipts_root[0] ^= 0x01;
        check(strike(pb::check_carried_list(tampered, record_open, as_list(list), placed, s_tip, lp),
                     pb::CarriedFault::Fold),
              "non-zero carried_root fold mismatch STRIKE");
        pb::ReceiptBodyV3 zero_fold = good;
        zero_fold.side.receipts_root = pb::carrier_receipts_root(pb::kNoCarriedRoot, s_tip);
        check(strike(pb::check_carried_list(zero_fold, record_open, as_list(list), placed, s_tip, lp),
                     pb::CarriedFault::Fold),
              "carried_root 0 fold against a non-empty list STRIKE");
    }

    return finish("xmr_receipt_carriage_kat");
}
