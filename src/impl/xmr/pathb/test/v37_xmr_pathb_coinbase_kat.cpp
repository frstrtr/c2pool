// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_pathb_coinbase_kat (pathb_coinbase_split.hpp, C07, "kept name"
// xmr_coinbase_kat -- shipped pathb-scoped because the native settle
// xmr_coinbase_kat target already exists): Sum(vout) == R = base + fees through
// the Path B coinbase on a mainnet-tail vector; the canonical split coinbase is
// admitted; a wrong split is a BAN before RandomX (the RandomX stub is not called).
// The leaf commits mm_root_of(side_data_v3) of the receipt: a side_data_v3 field
// changed after the coinbase was built is a BAN before RandomX on the split and
// the finder-only path; a side_data_v3 that does not encode builds no leaf.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <span>
#include <string>

#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 id_of(std::uint64_t i) {
    pb::Hash32 h{};
    for (int b = 0; b < 8; ++b) h[31 - b] = static_cast<std::uint8_t>(i >> (8 * b));
    return h;
}

int main() {
    // mainnet-tail vector: base = 6e11, fees 5e9 -> R = 605e9.
    const std::uint64_t base = 600000000000ull, fees = 5000000000ull, R = base + fees;
    pb::Window w;
    for (std::uint64_t i = 1; i <= 32; ++i) { w.weight[id_of(i)] = pb::Work(1000 * i); w.W += pb::Work(1000 * i); }

    // Sum(vout) == R exactly through the Path B coinbase.
    const auto outs = pb::split(R, w);
    std::uint64_t s = 0;
    for (const auto& o : outs) s += o.amount;
    check(s == R, "Sum(vout) == R = base + fees (mainnet tail)");

    // the canonical split coinbase is admitted (tree_root folds to the leaf).
    pb::ReceiptBodyV3 r = make_body(/*depth=*/3, /*with_owner=*/false, 0x20);
    r.reward_total = R;
    const pb::Hash32 tip = r.side.tip, p_r = r.blob.prev_id;
    const pb::CanonLeaf cl = pb::canonical_coinbase_leaf(r, w, tip, p_r, /*hf=*/16);
    check(!cl.fork_fused && cl.leaf.has_value(), "hf16 canonical coinbase built");
    // the leaf: split -> PBX1 tx_extra with mm_root = mm_root_of(side_data_v3) -> leaf.
    const pb::Hash32 own_mm = pb::mm_root_of(r.side).value();
    check(cl.leaf == pb::canonical_cb_leaf(outs, tip, p_r, pb::canonical_tx_extra_hf16(p_r, r.extra_nonce, own_mm)),
          "canonical split leaf commits mm_root_of(side_data_v3)");
    r.blob.tree_root = pb::tree_root_fold(cl.leaf.value(), std::span<const pb::Hash32>(r.branch));
    check(pb::canonical_coinbase_ok_split(r, w, tip, p_r, 16), "canonical split coinbase admitted");

    // the admission runs #12 strictly before RandomX; a correct coinbase lets it run.
    {
        bool rx = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(
                pb::canonical_coinbase_ok_split(r, w, tip, p_r, 16), [&] { rx = true; return true; });
        check(t.verdict == pb::AdmitVerdict::AdmitCarrier && t.randomx_called && rx,
              "correct coinbase -> RandomX runs after #12");
    }

    // a WRONG split (tampered tree_root) -> BAN before RandomX (not called).
    {
        pb::ReceiptBodyV3 bad = r;
        bad.blob.tree_root = seq32(0xFF);  // not the canonical split leaf fold
        check(!pb::canonical_coinbase_ok_split(bad, w, tip, p_r, 16), "wrong split: coinbase NOT ok");
        bool rx = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(
                pb::canonical_coinbase_ok_split(bad, w, tip, p_r, 16), [&] { rx = true; return true; });
        check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx, "wrong split -> BAN, no RandomX");
    }

    // a coinbase that claims R' != R (over/under) -> different leaf -> BAN.
    {
        pb::ReceiptBodyV3 bad = r;
        bad.reward_total = R + 1;  // over-claim
        check(!pb::canonical_coinbase_ok_split(bad, w, tip, p_r, 16), "R' != R -> coinbase NOT ok");
    }

    // ---- side_data_v3 committed through mm_root on the split path: a field
    // changed after the coinbase was built -> coinbase NOT ok -> BAN before RandomX ----
    {
        pb::ReceiptBodyV3 o = make_body(3, /*with_owner=*/true, 0x21);
        o.reward_total = R;
        const pb::Hash32 tip_o = o.side.tip, pr_o = o.blob.prev_id;
        o.blob.tree_root = pb::tree_root_fold(pb::canonical_coinbase_leaf(o, w, tip_o, pr_o, 16).leaf.value(),
                                              std::span<const pb::Hash32>(o.branch));
        check(pb::canonical_coinbase_ok_split(o, w, tip_o, pr_o, 16), "side with owner committed: split admitted");
        auto changed = [&](void (*mutate)(pb::SideDataV3&), const char* what) {
            pb::ReceiptBodyV3 bad = o;
            mutate(bad.side);
            check(pb::mm_root_of(bad.side).has_value(), std::string(what) + " (side_data_v3 still encodes)");
            bool rx = false;
            const pb::TailResult t = pb::admit_coinbase_then_randomx(
                    pb::canonical_coinbase_ok_split(bad, w, tip_o, pr_o, 16), [&] { rx = true; return true; });
            check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx, what);
        };
        changed([](pb::SideDataV3& s) { s.pool_id[0] ^= 0x01; }, "split: pool_id changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.rules_epoch ^= 0x0001; }, "split: rules_epoch changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.ballot ^= 0x0001; }, "split: ballot changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.payee[0] ^= 0x01; }, "split: payee changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.t_origin ^= 0x01; }, "split: t_origin changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.tip[0] ^= 0x01; }, "split: tip changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.receipts_root[0] ^= 0x01; },
                "split: receipts_root changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.window_root[0] ^= 0x01; },
                "split: window_root changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.mmr_root[0] ^= 0x01; }, "split: mmr_root changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.fee_rate_bp ^= 0x0001; },
                "split: fee_rate_bp changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.owner[31] ^= 0x01; }, "split: owner changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.give_author_bp ^= 0x0001; },
                "split: give_author_bp changed -> BAN before RandomX");
    }

    // ---- side_data_v3 that does not encode: no leaf; a coinbase committing a
    // zero mm_root -> coinbase NOT ok -> BAN before RandomX ----
    {
        pb::ReceiptBodyV3 bad = make_body(3, false, 0x22);
        bad.reward_total = R;
        bad.side.owner = seq32(0x21);  // owner identity with fee_rate_bp 0
        check(!pb::mm_root_of(bad.side).has_value(), "owner with fee_rate_bp 0: side_data_v3 does not encode");
        const pb::Hash32 tip_b = bad.side.tip, pr_b = bad.blob.prev_id;
        const pb::CanonLeaf none = pb::canonical_coinbase_leaf(bad, w, tip_b, pr_b, 16);
        check(!none.fork_fused && !none.leaf.has_value(), "split: no canonical leaf");
        const auto zero_mm_extra = pb::canonical_tx_extra_hf16(pr_b, bad.extra_nonce, pb::Hash32{});
        bad.blob.tree_root = pb::tree_root_fold(pb::canonical_cb_leaf(outs, tip_b, pr_b, zero_mm_extra),
                                                std::span<const pb::Hash32>(bad.branch));
        bool rx = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(
                pb::canonical_coinbase_ok_split(bad, w, tip_b, pr_b, 16), [&] { rx = true; return true; });
        check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx,
              "split: side_data_v3 does not encode -> BAN before RandomX");
    }

    // ---- finder-only path (empty window): the stub leaf with mm_root_of(side_data_v3) ----
    {
        pb::Window wf;
        wf.empty_finder_only = true;
        pb::ReceiptBodyV3 f = make_body(3, /*with_owner=*/true, 0x23);
        f.reward_total = R;
        const pb::Hash32 tip_f = f.side.tip, pr_f = f.blob.prev_id;
        const pb::CanonLeaf clf = pb::canonical_coinbase_leaf(f, wf, tip_f, pr_f, 16);
        const pb::Hash32 own_leaf = pb::canonical_stub_leaf(
                R, pb::stub_output_key(tip_f, pr_f, f.side.payee), f.extra_nonce, pb::mm_root_of(f.side).value());
        check(clf.leaf == own_leaf, "finder-only leaf commits mm_root_of(side_data_v3)");
        f.blob.tree_root = pb::tree_root_fold(own_leaf, std::span<const pb::Hash32>(f.branch));
        check(pb::canonical_coinbase_ok_split(f, wf, tip_f, pr_f, 16), "finder-only canonical coinbase admitted");
        {
            pb::ReceiptBodyV3 bad = f;
            bad.side.receipts_root[0] ^= 0x01;
            bool rx = false;
            const pb::TailResult t = pb::admit_coinbase_then_randomx(
                    pb::canonical_coinbase_ok_split(bad, wf, tip_f, pr_f, 16), [&] { rx = true; return true; });
            check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx,
                  "finder-only: side_data_v3 changed -> BAN before RandomX");
        }
        {
            pb::ReceiptBodyV3 bad = f;
            bad.side.fee_rate_bp = 0;  // owner identity with fee_rate_bp 0
            check(!pb::mm_root_of(bad.side).has_value(), "finder-only: side_data_v3 does not encode");
            check(!pb::finder_only_leaf(bad, tip_f, pr_f).has_value(), "finder-only: no leaf");
            const pb::Hash32 zero_mm_leaf = pb::canonical_stub_leaf(
                    R, pb::stub_output_key(tip_f, pr_f, bad.side.payee), bad.extra_nonce, pb::Hash32{});
            bad.blob.tree_root = pb::tree_root_fold(zero_mm_leaf, std::span<const pb::Hash32>(bad.branch));
            bool rx = false;
            const pb::TailResult t = pb::admit_coinbase_then_randomx(
                    pb::canonical_coinbase_ok_split(bad, wf, tip_f, pr_f, 16), [&] { rx = true; return true; });
            check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx,
                  "finder-only: side_data_v3 does not encode -> BAN before RandomX");
        }
    }

    return finish("v37_xmr_pathb_coinbase_kat");
}
