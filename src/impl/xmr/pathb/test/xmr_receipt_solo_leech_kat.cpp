// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/xmr_receipt_solo_leech_kat.cpp
// Solo-leech, S2 STUB PART ONLY (pathb_receipt_admission.hpp, C37, ruling 4):
//   the canonical coinbase of S1 / S2 is one output of the whole reward R to the
//   receipt's own payee. A carrier AND a carried receipt whose coinbase is NOT
//   that single-output stub are each refused and the sender BANNED BEFORE
//   RandomX (a RandomX stub asserts it is not called); the correct one-output
//   stub is admitted; the one-time key is computed once per (tip, P_r). No
//   payout window is built (window_root / mmr_root stay the S1 zero stubs).
//   The full hf-16 split / window part of this KAT is deferred to S3.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <map>
#include <span>
#include <utility>

#include "impl/xmr/pathb/pathb_coinbase_split.hpp"  // S3 window/split part
#include "impl/xmr/pathb/pathb_receipt_admission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

// Commits the canonical stub coinbase into a receipt: tree_root = fold(leaf0,
// branch) with leaf0 = the canonical one-output stub leaf for (tip, P_r).
void commit_canonical(pb::ReceiptBodyV3& r, const pb::Hash32& tip, const pb::Hash32& p_r) {
    const pb::Hash32 leaf = pb::canonical_stub_leaf_of(r, tip, p_r);
    r.blob.tree_root = pb::tree_root_fold(leaf, std::span<const pb::Hash32>(r.branch));
}

}  // namespace

int main() {
    // A valid carrier's own receipt and a carried receipt (both exercise #12).
    pb::ReceiptBodyV3 own = make_body(/*depth=*/3, /*with_owner=*/false, 0x20);
    pb::ReceiptBodyV3 carried = make_body(/*depth=*/2, /*with_owner=*/false, 0x30);
    const pb::Hash32 tip = own.side.tip;
    const pb::Hash32 p_r = own.blob.prev_id;  // P_r = the receipt's Monero parent

    // ---- correct one-output stub is admitted, RandomX runs AFTER #12 ----
    {
        commit_canonical(own, tip, own.blob.prev_id);
        check(pb::canonical_coinbase_ok(own, tip, own.blob.prev_id), "correct stub: coinbase ok");
        bool rx_called = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(
                pb::canonical_coinbase_ok(own, tip, own.blob.prev_id), [&] { rx_called = true; return true; });
        check(t.verdict == pb::AdmitVerdict::AdmitCarrier, "correct stub admitted");
        check(t.randomx_called && rx_called, "RandomX runs only after #12 admits");
    }

    // same for a CARRIED receipt (admission #12 now applies to carried receipts).
    {
        commit_canonical(carried, carried.side.tip, carried.blob.prev_id);
        check(pb::canonical_coinbase_ok(carried, carried.side.tip, carried.blob.prev_id),
              "carried correct stub: coinbase ok");
        bool rx_called = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(
                pb::canonical_coinbase_ok(carried, carried.side.tip, carried.blob.prev_id),
                [&] { rx_called = true; return true; });
        check(t.verdict == pb::AdmitVerdict::AdmitCarrier && t.randomx_called, "carried correct stub admitted");
    }

    // ---- wrong stub: WRONG AMOUNT -> BAN before RandomX ----
    {
        pb::ReceiptBodyV3 bad = make_body(3, false, 0x20);
        const pb::Hash32 key = pb::stub_output_key(tip, bad.blob.prev_id, bad.side.payee);
        const pb::Hash32 wrong_leaf = pb::canonical_stub_leaf(bad.reward_total + 1, key, bad.extra_nonce);
        bad.blob.tree_root = pb::tree_root_fold(wrong_leaf, std::span<const pb::Hash32>(bad.branch));
        check(!pb::canonical_coinbase_ok(bad, tip, bad.blob.prev_id), "wrong amount: coinbase NOT ok");
        bool rx_called = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(
                pb::canonical_coinbase_ok(bad, tip, bad.blob.prev_id), [&] { rx_called = true; return true; });
        check(t.verdict == pb::AdmitVerdict::Ban, "wrong amount -> BAN");
        check(!t.randomx_called && !rx_called, "RandomX NOT called on a wrong coinbase");
    }

    // ---- wrong stub: WRONG PAYEE -> BAN before RandomX ----
    {
        pb::ReceiptBodyV3 bad = make_body(3, false, 0x20);
        const pb::Hash32 foreign_payee = seq32(0x7E);  // not bad.side.payee
        const pb::Hash32 key = pb::stub_output_key(tip, bad.blob.prev_id, foreign_payee);
        const pb::Hash32 wrong_leaf = pb::canonical_stub_leaf(bad.reward_total, key, bad.extra_nonce);
        bad.blob.tree_root = pb::tree_root_fold(wrong_leaf, std::span<const pb::Hash32>(bad.branch));
        check(!pb::canonical_coinbase_ok(bad, tip, bad.blob.prev_id), "wrong payee: coinbase NOT ok");
        bool rx_called = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(
                pb::canonical_coinbase_ok(bad, tip, bad.blob.prev_id), [&] { rx_called = true; return true; });
        check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called, "wrong payee -> BAN before RandomX");
    }

    // ---- garbage tree_root (a non-canonical coinbase of any shape) -> BAN ----
    {
        pb::ReceiptBodyV3 bad = make_body(3, false, 0x20);
        bad.blob.tree_root = seq32(0xFF);  // unrelated to any canonical stub
        check(!pb::canonical_coinbase_ok(bad, tip, bad.blob.prev_id), "garbage tree_root: coinbase NOT ok");
        bool rx_called = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(
                pb::canonical_coinbase_ok(bad, tip, bad.blob.prev_id), [&] { rx_called = true; return true; });
        check(t.verdict == pb::AdmitVerdict::Ban && !rx_called, "garbage coinbase -> BAN, no RandomX");
    }

    // ---- a correct coinbase but a failing PoW is a BAN at #15 (RandomX ran) ----
    {
        pb::ReceiptBodyV3 r = make_body(3, false, 0x20);
        commit_canonical(r, tip, r.blob.prev_id);
        bool rx_called = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(
                pb::canonical_coinbase_ok(r, tip, r.blob.prev_id), [&] { rx_called = true; return false; });
        check(t.verdict == pb::AdmitVerdict::Ban && t.randomx_called, "bad PoW -> BAN at #15 (after #12)");
    }

    // ---- the one-time key is computed ONCE per (tip, P_r) ----
    // Several receipts on one (tip, P_r) derive the key once (a cache keyed by
    // (tip, P_r)); a different (tip, P_r) derives it again.
    {
        std::map<std::pair<pb::Hash32, pb::Hash32>, pb::Hash32> key_cache;
        int key_derivations = 0;
        auto key_for = [&](const pb::Hash32& t, const pb::Hash32& pr, const pb::Hash32& payee) {
            const std::pair<pb::Hash32, pb::Hash32> k{t, pr};
            auto it = key_cache.find(k);
            if (it != key_cache.end()) return it->second;
            ++key_derivations;
            const pb::Hash32 key = pb::stub_output_key(t, pr, payee);
            key_cache.emplace(k, key);
            return key;
        };
        const pb::Hash32 payee = own.side.payee;
        // three receipts on the SAME (tip, p_r):
        key_for(tip, p_r, payee);
        key_for(tip, p_r, payee);
        key_for(tip, p_r, payee);
        check(key_derivations == 1, "key derived once per (tip, P_r)");
        // a different P_r derives again:
        key_for(tip, seq32(0x99), payee);
        check(key_derivations == 2, "a different (tip, P_r) derives again");
    }

    // =====================================================================
    // S3 WINDOW / SPLIT PART (deferred from S2): the canonical coinbase is now
    // the hf-16 SPLIT of R over window(tip, v), still checked BEFORE RandomX.
    // =====================================================================
    auto id_of = [](std::uint64_t i) {
        pb::Hash32 h{};
        for (int b = 0; b < 8; ++b) h[31 - b] = static_cast<std::uint8_t>(i >> (8 * b));
        return h;
    };
    {
        // a window of 24 payees for (tip, P_r); keys derived once per (tip, P_r).
        pb::Window w;
        for (std::uint64_t i = 1; i <= 24; ++i) { w.weight[id_of(i)] = pb::Work(1000 * i); w.W += pb::Work(1000 * i); }
        const pb::Hash32 mm = seq32(0x55);

        // ---- the correct hf-16 split is admitted; RandomX runs AFTER #12 ----
        pb::ReceiptBodyV3 r = make_body(3, false, 0x20);
        const pb::Hash32 tip_r = r.side.tip, pr_r = r.blob.prev_id;
        const pb::CanonLeaf cl = pb::canonical_coinbase_leaf(r, w, tip_r, pr_r, 16, mm);
        r.blob.tree_root = pb::tree_root_fold(cl.leaf, std::span<const pb::Hash32>(r.branch));
        check(pb::canonical_coinbase_ok_split(r, w, tip_r, pr_r, 16, mm), "correct hf-16 split admitted");
        {
            bool rx = false;
            const pb::TailResult t = pb::admit_coinbase_then_randomx(
                    pb::canonical_coinbase_ok_split(r, w, tip_r, pr_r, 16, mm), [&] { rx = true; return true; });
            check(t.verdict == pb::AdmitVerdict::AdmitCarrier && t.randomx_called, "split: RandomX after #12");
        }

        // ---- a carrier whose coinbase is NOT the canonical split -> BAN, no RandomX ----
        {
            pb::ReceiptBodyV3 bad = r;
            bad.blob.tree_root = seq32(0xFE);  // not the canonical split
            bool rx = false;
            const pb::TailResult t = pb::admit_coinbase_then_randomx(
                    pb::canonical_coinbase_ok_split(bad, w, tip_r, pr_r, 16, mm), [&] { rx = true; return true; });
            check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx,
                  "non-canonical split (carrier) -> BAN before RandomX");
        }

        // ---- the same #12 applies to a CARRIED receipt ----
        {
            pb::ReceiptBodyV3 carried = make_body(2, false, 0x30);
            const pb::Hash32 tip_c = carried.side.tip, pr_c = carried.blob.prev_id;
            const pb::CanonLeaf clc = pb::canonical_coinbase_leaf(carried, w, tip_c, pr_c, 16, mm);
            carried.blob.tree_root = pb::tree_root_fold(clc.leaf, std::span<const pb::Hash32>(carried.branch));
            check(pb::canonical_coinbase_ok_split(carried, w, tip_c, pr_c, 16, mm), "carried correct split admitted");
        }

        // ---- a receipt paying ANOTHER tip's window is refused ----
        // (a different payee SET, not a scaled copy: the split is scale-invariant.)
        {
            pb::Window w_other;
            for (std::uint64_t i = 1; i <= 24; ++i) { w_other.weight[id_of(i)] = pb::Work(1000 * i); w_other.W += pb::Work(1000 * i); }
            w_other.weight[id_of(999)] = pb::Work(123456);  // an extra payee the other tip saw
            w_other.W += pb::Work(123456);
            check(!pb::canonical_coinbase_ok_split(r, w_other, tip_r, pr_r, 16, mm),
                  "a receipt paying another tip's window refused");
        }
    }

    return finish("xmr_receipt_solo_leech_kat");
}
