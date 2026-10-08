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
#include <string>
#include <utility>

#include "impl/xmr/pathb/pathb_coinbase_split.hpp"  // S3 window/split part
#include "impl/xmr/pathb/pathb_receipt_admission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

// The canonical one-output stub leaf for (tip, P_r); the bodies here encode.
pb::Hash32 stub_leaf(const pb::ReceiptBodyV3& r, const pb::Hash32& tip, const pb::Hash32& p_r) {
    return pb::canonical_stub_leaf_of(r, tip, p_r).value();
}

// Commits the canonical stub coinbase into a receipt: tree_root = fold(leaf0,
// branch) with leaf0 = the canonical one-output stub leaf for (tip, P_r).
void commit_canonical(pb::ReceiptBodyV3& r, const pb::Hash32& tip, const pb::Hash32& p_r) {
    r.blob.tree_root = pb::tree_root_fold(stub_leaf(r, tip, p_r), std::span<const pb::Hash32>(r.branch));
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
        pb::ReceiptBodyV3 other = bad;
        other.reward_total = bad.reward_total + 1;
        const pb::Hash32 wrong_leaf = stub_leaf(other, tip, bad.blob.prev_id);
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
        pb::ReceiptBodyV3 other = bad;
        other.side.payee = foreign_payee;
        const pb::Hash32 wrong_leaf = stub_leaf(other, tip, bad.blob.prev_id);
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

    // ---- side_data_v3 committed through mm_root: a field changed after the
    // coinbase was built -> coinbase NOT ok -> BAN before RandomX ----
    {
        pb::ReceiptBodyV3 base = make_body(3, false, 0x20);
        commit_canonical(base, base.side.tip, base.blob.prev_id);
        check(pb::canonical_coinbase_ok(base, base.side.tip, base.blob.prev_id), "side committed: coinbase ok");
        pb::ReceiptBodyV3 owned = make_body(3, /*with_owner=*/true, 0x21);
        commit_canonical(owned, owned.side.tip, owned.blob.prev_id);
        check(pb::canonical_coinbase_ok(owned, owned.side.tip, owned.blob.prev_id),
              "side with owner committed: coinbase ok");
        auto changed_from = [&](const pb::ReceiptBodyV3& from, void (*mutate)(pb::SideDataV3&), const char* what) {
            pb::ReceiptBodyV3 bad = from;
            mutate(bad.side);
            check(pb::mm_root_of(bad.side).has_value(), std::string(what) + " (side_data_v3 still encodes)");
            bool rx_called = false;
            const pb::TailResult t = pb::admit_coinbase_then_randomx(
                    pb::canonical_coinbase_ok(bad, bad.side.tip, bad.blob.prev_id), [&] { rx_called = true; return true; });
            check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx_called, what);
        };
        auto changed = [&](void (*mutate)(pb::SideDataV3&), const char* what) { changed_from(base, mutate, what); };
        changed([](pb::SideDataV3& s) { s.receipts_root[0] ^= 0x01; }, "receipts_root changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.window_root[0] ^= 0x01; }, "window_root changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.mmr_root[0] ^= 0x01; }, "mmr_root changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.pool_id[0] ^= 0x01; }, "pool_id changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.rules_epoch ^= 0x0001; }, "rules_epoch changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.ballot ^= 0x0001; }, "ballot changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.t_origin ^= 0x01; }, "t_origin changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.give_author_bp ^= 0x0001; }, "give_author_bp changed -> BAN before RandomX");
        changed_from(owned, [](pb::SideDataV3& s) { s.fee_rate_bp ^= 0x0001; },
                     "fee_rate_bp changed -> BAN before RandomX");
        changed_from(owned, [](pb::SideDataV3& s) { s.owner[31] ^= 0x01; }, "owner changed -> BAN before RandomX");
    }

    // ---- side_data_v3 that does not encode: no stub leaf; a coinbase committing
    // a zero mm_root -> coinbase NOT ok -> BAN before RandomX ----
    {
        pb::ReceiptBodyV3 bad = make_body(3, false, 0x20);
        bad.side.owner = seq32(0x21);  // owner identity with fee_rate_bp 0
        check(!pb::mm_root_of(bad.side).has_value(), "owner with fee_rate_bp 0: side_data_v3 does not encode");
        const pb::Hash32 tip_b = bad.side.tip, pr_b = bad.blob.prev_id;
        check(!pb::canonical_stub_leaf_of(bad, tip_b, pr_b).has_value(), "no canonical stub leaf");
        const pb::Hash32 zero_mm_leaf = pb::canonical_stub_leaf(
                bad.reward_total, pb::stub_output_key(tip_b, pr_b, bad.side.payee), bad.extra_nonce, pb::Hash32{});
        bad.blob.tree_root = pb::tree_root_fold(zero_mm_leaf, std::span<const pb::Hash32>(bad.branch));
        bool rx_called = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(pb::canonical_coinbase_ok(bad, tip_b, pr_b),
                                                                 [&] { rx_called = true; return true; });
        check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx_called,
              "side_data_v3 does not encode -> BAN before RandomX");
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

        // ---- the correct hf-16 split is admitted; RandomX runs AFTER #12 ----
        pb::ReceiptBodyV3 r = make_body(3, false, 0x20);
        const pb::Hash32 tip_r = r.side.tip, pr_r = r.blob.prev_id;
        const pb::CanonLeaf cl = pb::canonical_coinbase_leaf(r, w, tip_r, pr_r, 16);
        r.blob.tree_root = pb::tree_root_fold(cl.leaf.value(), std::span<const pb::Hash32>(r.branch));
        check(pb::canonical_coinbase_ok_split(r, w, tip_r, pr_r, 16), "correct hf-16 split admitted");
        {
            bool rx = false;
            const pb::TailResult t = pb::admit_coinbase_then_randomx(
                    pb::canonical_coinbase_ok_split(r, w, tip_r, pr_r, 16), [&] { rx = true; return true; });
            check(t.verdict == pb::AdmitVerdict::AdmitCarrier && t.randomx_called, "split: RandomX after #12");
        }

        // ---- a carrier whose coinbase is NOT the canonical split -> BAN, no RandomX ----
        {
            pb::ReceiptBodyV3 bad = r;
            bad.blob.tree_root = seq32(0xFE);  // not the canonical split
            bool rx = false;
            const pb::TailResult t = pb::admit_coinbase_then_randomx(
                    pb::canonical_coinbase_ok_split(bad, w, tip_r, pr_r, 16), [&] { rx = true; return true; });
            check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx,
                  "non-canonical split (carrier) -> BAN before RandomX");
        }

        // ---- the same #12 applies to a CARRIED receipt ----
        {
            pb::ReceiptBodyV3 carried = make_body(2, false, 0x30);
            const pb::Hash32 tip_c = carried.side.tip, pr_c = carried.blob.prev_id;
            const pb::CanonLeaf clc = pb::canonical_coinbase_leaf(carried, w, tip_c, pr_c, 16);
            carried.blob.tree_root = pb::tree_root_fold(clc.leaf.value(), std::span<const pb::Hash32>(carried.branch));
            check(pb::canonical_coinbase_ok_split(carried, w, tip_c, pr_c, 16), "carried correct split admitted");
        }

        // ---- a receipt paying ANOTHER tip's window is refused ----
        // (a different payee SET, not a scaled copy: the split is scale-invariant.)
        {
            pb::Window w_other;
            for (std::uint64_t i = 1; i <= 24; ++i) { w_other.weight[id_of(i)] = pb::Work(1000 * i); w_other.W += pb::Work(1000 * i); }
            w_other.weight[id_of(999)] = pb::Work(123456);  // an extra payee the other tip saw
            w_other.W += pb::Work(123456);
            check(!pb::canonical_coinbase_ok_split(r, w_other, tip_r, pr_r, 16),
                  "a receipt paying another tip's window refused");
        }
    }

    return finish("xmr_receipt_solo_leech_kat");
}
