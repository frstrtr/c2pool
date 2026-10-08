// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_bin_fold_kat (pathb_buckets.hpp, pathb_receipt_admission.hpp, C01,
// C33, K06, ruling 27 K-11): the fold carrier f is the first position with
// H(f) >= b + F; f still carries bin b, f+1 does not (open_at over H(pos - 1));
// the bin SEALS at f, D_fin = 0; a late push into a sealed bin is REFUSED by
// check_carried_list (STRIKE SealedBin, the entry named), never dropped
// silently; a reorg across the fold re-seals to the same bytes as a fresh node.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <vector>

#include "impl/xmr/pathb/pathb_buckets.hpp"
#include "impl/xmr/pathb/pathb_params.hpp"
#include "impl/xmr/pathb/pathb_ratchet_state.hpp"
#include "impl/xmr/pathb/pathb_receipt_admission.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 rep(std::uint8_t b) { pb::Hash32 h{}; h.fill(b); return h; }

int main() {
    const pb::LaneParams& lp = pb::kRuledLaneParams;
    const std::uint64_t F = lp.open_bins;  // 96
    check(pb::seal_depth(lp) == 0, "D_fin == 0 (K06, ruling 27 K-11)");

    // H over carriers: height advances by 1 every 12 positions (Monero/T cadence).
    auto h_at = [](std::uint64_t pos) -> std::uint64_t { return 1000 + pos / 12; };
    const std::uint64_t origin_bin = 1000;  // b

    // fold_pos: first f with H(f) >= b + F = 1096. H(f) = 1000 + f/12 >= 1096 ->
    // f/12 >= 96 -> f >= 1152.
    bool found = false;
    const std::uint64_t f = pb::fold_pos(h_at, /*n_positions=*/4000, origin_bin, F, found);
    check(found && f == 1152, "fold at the first f with H(f) >= b + F");
    check(h_at(f) >= origin_bin + F, "f carries: H(f) >= b + F");
    check(h_at(f - 1) < origin_bin + F, "f-1 does not: H(f-1) < b + F");

    // open_at reads H at the carrier's parent: the carrier at f (parent f-1) is
    // still open for bin b; the carrier at f+1 (parent f) is sealed.
    check(pb::open_at(h_at(f - 1), origin_bin, F), "carrier f: bin b open (H(f-1) < b + F)");
    check(!pb::open_at(h_at(f), origin_bin, F), "carrier f+1: bin b sealed (H(f) >= b + F)");
    check(!pb::open_at(h_at(f + 500), origin_bin, F), "every later carrier: bin b sealed");
    check(pb::open_at(h_at(f), origin_bin + 1, F), "carrier f+1: bin b+1 still open");

    // seal at f, D_fin 0: the live entries become a frozen L1 bucket + MMR leaf.
    pb::BucketRow x; x.miner = rep(0x41); x.w_miner = pb::Work(50000);
    pb::BucketRow y; y.miner = rep(0x42); y.w_miner = pb::Work(70000);
    const pb::L1Bucket sealed = pb::seal_bucket(origin_bin, {x, y}, pb::Work(120000), 2, 50000);
    const pb::Hash32 leaf = pb::mmr_leaf_of(sealed);

    // a late push into the SEALED bin is REFUSED (never dropped silently): a
    // carrier at f+1 carrying a bin-b receipt is STRIKE SealedBin naming the entry;
    // the same list on the carrier at f is admitted.
    {
        const pb::RatchetState s_tip = pb::genesis_ratchet_state(seq32(0x55));
        const pb::ReceiptBodyV3 late = make_body(2, false, 0x43);
        const pb::ReceiptBodyV3 open_one = make_body(2, false, 0x44);
        std::vector<pb::CarriedReceipt> list{{late, origin_bin}};
        std::vector<pb::Hash32> ids{pb::receipt_id(late)};
        pb::ReceiptBodyV3 c = make_body(2, false, 0x10);
        c.side.receipts_root = pb::carrier_receipts_root_over(ids, s_tip);
        pb::PlacedSet placed;
        const pb::CarriedListResult at_f = pb::check_carried_list(c, h_at(f - 1), list, placed, s_tip, lp);
        check(!at_f.verdict && at_f.fault == pb::CarriedFault::None && at_f.ids == ids,
              "carrier f carries the bin-b receipt");
        const pb::CarriedListResult at_f1 = pb::check_carried_list(c, h_at(f), list, placed, s_tip, lp);
        check(at_f1.verdict == pb::AdmitVerdict::Strike && at_f1.fault == pb::CarriedFault::SealedBin
                      && at_f1.index == 0 && pb::strike_tokens(*at_f1.verdict) == 1,
              "late push into a sealed bin REFUSED: STRIKE SealedBin at entry 0 (not dropped)");
        // the same carrier with a bin b+1 receipt instead: still open at f+1.
        std::vector<pb::CarriedReceipt> next{{open_one, origin_bin + 1}};
        std::vector<pb::Hash32> next_ids{pb::receipt_id(open_one)};
        c.side.receipts_root = pb::carrier_receipts_root_over(next_ids, s_tip);
        const pb::CarriedListResult r2 = pb::check_carried_list(c, h_at(f), next, placed, s_tip, lp);
        check(!r2.verdict && r2.fault == pb::CarriedFault::None, "carrier f+1 carries a bin b+1 receipt");
    }

    // a reorg across the fold rewinds and re-seals to the SAME bytes as a fresh
    // node (determinism of the seal).
    const pb::L1Bucket reseal = pb::seal_bucket(origin_bin, {y, x}, pb::Work(120000), 2, 50000);
    check(pb::mmr_leaf_of(reseal) == leaf, "reorg re-seal reproduces the same MMR leaf");
    check(reseal.comp_root_v == sealed.comp_root_v, "re-seal reproduces comp_root");

    return finish("v37_xmr_bin_fold_kat");
}
