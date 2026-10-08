// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/xmr_receipt_solo_leech_kat.cpp
// Solo-leech (pathb_coinbase_split.hpp, pathb_receipt_admission.hpp; C37,
// ruling 4):
//   S2 part: on an empty window the canonical coinbase is the hf-16 miner tx
//   with one output of the whole reward R to the receipt's own payee. A carrier
//   AND a carried receipt whose coinbase is not that miner tx are each refused
//   and the sender BANNED BEFORE RandomX (a RandomX stub asserts it is not
//   called); the canonical one is admitted; the one-time key is computed once
//   per (tip, P_r, payee) through the KeyCache.
//   Window part: the hf-16 split of R over window(tip, v) as a miner tx, still
//   checked BEFORE RandomX; a receipt paying another tip's window is refused.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/pathb_receipt_admission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_miner.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    const pb::XmrKeyRef author = kat_author();
    RefBook book;
    const pb::RefLookup refs = book.lookup();
    const pb::Window empty;
    pb::KeyCache cache;

    // #12 of a receipt on its own tip and P_r at h = kKatHeight.
    auto check12 = [&](const pb::ReceiptBodyV3& r, const pb::Window& w) {
        return pb::canonical_coinbase_check(r, pb::WindowAt{&w}, r.side.tip, r.blob.prev_id, kKatHeight, 16, cache,
                                            refs, author);
    };
    // The receipt commits the miner tx its miner builds for (tip, P_r, window).
    auto commit = [&](pb::ReceiptBodyV3& r, const pb::Window& w) {
        return commit_miner_tx(r, w, r.side.tip, r.blob.prev_id, kKatHeight, book, author);
    };
    auto tail = [&](const pb::ReceiptBodyV3& r, const pb::Window& w, bool pow_ok, bool& rx_called) {
        return pb::admit_coinbase_then_randomx(check12(r, w), [&] { rx_called = true; return pow_ok; });
    };

    // A valid carrier's own receipt and a carried receipt (both exercise #12).
    pb::ReceiptBodyV3 own = make_body(/*depth=*/3, /*with_owner=*/false, 0x20);
    pb::ReceiptBodyV3 carried = make_body(/*depth=*/2, /*with_owner=*/false, 0x30);

    // ---- the canonical one-output miner tx is admitted, RandomX runs AFTER #12 ----
    {
        check(commit(own, empty), "own: the miner builds its one-output miner tx");
        check(check12(own, empty) == pb::CoinbaseCheck::Match, "correct one-output miner tx: Match");
        bool rx_called = false;
        const pb::TailResult t = tail(own, empty, true, rx_called);
        check(t.verdict == pb::AdmitVerdict::AdmitCarrier, "correct one-output miner tx admitted");
        check(t.randomx_called && rx_called, "RandomX runs only after #12 admits");
        const pb::CanonicalTx c = pb::canonical_miner_tx(own, pb::WindowAt{&empty}, own.side.tip, own.blob.prev_id,
                                                         kKatHeight, 16, cache, refs, author);
        check(c.tx && c.tx->outs.size() == 1 && c.tx->outs[0].amount == own.reward_total && c.tx->extra.size() == 74,
              "empty window: one output of R, PBX1 extra 74 B");
    }

    // same for a CARRIED receipt (admission #12 applies to carried receipts).
    {
        commit(carried, empty);
        check(check12(carried, empty) == pb::CoinbaseCheck::Match, "carried correct miner tx: Match");
        bool rx_called = false;
        const pb::TailResult t = tail(carried, empty, true, rx_called);
        check(t.verdict == pb::AdmitVerdict::AdmitCarrier && t.randomx_called, "carried correct miner tx admitted");
    }

    // ---- WRONG AMOUNT -> BAN before RandomX ----
    {
        pb::ReceiptBodyV3 bad = make_body(3, false, 0x20);
        pb::ReceiptBodyV3 other = bad;
        other.reward_total = bad.reward_total + 1;
        commit(other, empty);
        bad.blob.tree_root = other.blob.tree_root;
        check(check12(bad, empty) == pb::CoinbaseCheck::Mismatch, "wrong amount: Mismatch");
        bool rx_called = false;
        const pb::TailResult t = tail(bad, empty, true, rx_called);
        check(t.verdict == pb::AdmitVerdict::Ban, "wrong amount -> BAN");
        check(!t.randomx_called && !rx_called, "RandomX NOT called on a wrong coinbase");
    }

    // ---- WRONG PAYEE (the output pays another key) -> BAN before RandomX ----
    {
        pb::ReceiptBodyV3 bad = make_body(3, false, 0x20);
        pb::ReceiptBodyV3 other = bad;
        other.payee = key_ref(0x7E);  // not bad's payee
        other.side.payee = pb::key_ref_identity(other.payee);
        commit(other, empty);
        bad.blob.tree_root = other.blob.tree_root;
        check(check12(bad, empty) == pb::CoinbaseCheck::Mismatch, "wrong payee: Mismatch");
        bool rx_called = false;
        const pb::TailResult t = tail(bad, empty, true, rx_called);
        check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called, "wrong payee -> BAN before RandomX");
    }

    // ---- garbage tree_root (a non-canonical coinbase of any shape) -> BAN ----
    {
        pb::ReceiptBodyV3 bad = make_body(3, false, 0x20);
        bad.blob.tree_root = seq32(0xFF);
        check(check12(bad, empty) == pb::CoinbaseCheck::Mismatch, "garbage tree_root: Mismatch");
        bool rx_called = false;
        const pb::TailResult t = tail(bad, empty, true, rx_called);
        check(t.verdict == pb::AdmitVerdict::Ban && !rx_called, "garbage coinbase -> BAN, no RandomX");
    }

    // ---- side_data_v3 committed through mm_root: a field changed after the
    // coinbase was built -> BAN before RandomX ----
    {
        pb::ReceiptBodyV3 base = make_body(3, false, 0x20);
        commit(base, empty);
        check(check12(base, empty) == pb::CoinbaseCheck::Match, "side committed: Match");
        pb::ReceiptBodyV3 owned = make_body(3, /*with_owner=*/true, 0x21);
        commit(owned, empty);
        check(check12(owned, empty) == pb::CoinbaseCheck::Match, "side with owner committed: Match");
        auto changed_from = [&](const pb::ReceiptBodyV3& from, void (*mutate)(pb::SideDataV3&), const char* what) {
            pb::ReceiptBodyV3 bad = from;
            mutate(bad.side);
            check(pb::mm_root_of(bad.side).has_value(), std::string(what) + " (side_data_v3 still encodes)");
            bool rx_called = false;
            const pb::TailResult t = tail(bad, empty, true, rx_called);
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

    // ---- side_data_v3 that does not encode: Undefined; a coinbase committing a
    // zero mm_root -> BAN before RandomX ----
    {
        pb::ReceiptBodyV3 bad = make_body(3, false, 0x20);
        bad.side.owner = seq32(0x21);  // owner identity with fee_rate_bp 0
        check(!pb::mm_root_of(bad.side).has_value(), "owner with fee_rate_bp 0: side_data_v3 does not encode");
        check(check12(bad, empty) == pb::CoinbaseCheck::Undefined, "side_data_v3 does not encode: Undefined");
        const std::vector<pb::MinerPayee> one{pb::MinerPayee{bad.payee, bad.reward_total}};
        const std::optional<pb::MinerTx> zero_mm = pb::build_miner_tx_hf16(
                bad.side.pool_id, bad.side.tip, bad.blob.prev_id, kKatHeight, one, bad.extra_nonce, pb::Hash32{});
        check(zero_mm.has_value(), "a miner tx with a zero mm_root builds");
        bad.blob.tree_root = pb::tree_root_fold(zero_mm ? zero_mm->tx_hash : pb::Hash32{},
                                                std::span<const pb::Hash32>(bad.branch));
        bool rx_called = false;
        const pb::TailResult t = tail(bad, empty, true, rx_called);
        check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx_called,
              "side_data_v3 does not encode -> BAN before RandomX");
    }

    // ---- a correct coinbase but a failing PoW is a BAN at #15 (RandomX ran) ----
    {
        pb::ReceiptBodyV3 r = make_body(3, false, 0x20);
        commit(r, empty);
        bool rx_called = false;
        const pb::TailResult t = tail(r, empty, false, rx_called);
        check(t.verdict == pb::AdmitVerdict::Ban && t.randomx_called, "bad PoW -> BAN at #15 (after #12)");
    }

    // ---- the one-time key is computed ONCE per (tip, P_r, payee) ----
    {
        pb::KeyCache kc;
        pb::ReceiptBodyV3 a = make_body(3, false, 0x22);
        const pb::Hash32 tip = a.side.tip, p_r = a.blob.prev_id;
        int matches = 0;
        for (std::uint64_t R : {600000000000ull, 600000000001ull, 600000000002ull}) {
            pb::ReceiptBodyV3 x = a;
            x.reward_total = R;
            commit(x, empty);
            matches += pb::canonical_coinbase_check(x, pb::WindowAt{&empty}, tip, p_r, kKatHeight, 16, kc, refs,
                                                    author)
                               == pb::CoinbaseCheck::Match;
        }
        check(matches == 3 && kc.computations() == 1, "key derived once per (tip, P_r, payee): three receipts, Match");
        pb::ReceiptBodyV3 race = a;
        race.blob.prev_id = seq32(0x99);  // another P_r at the same h
        commit(race, empty);
        check(pb::canonical_coinbase_check(race, pb::WindowAt{&empty}, tip, race.blob.prev_id, kKatHeight, 16, kc, refs,
                                           author)
                      == pb::CoinbaseCheck::Match,
              "another P_r: Match");
        check(kc.computations() == 2, "a different (tip, P_r) derives again");
    }

    // =====================================================================
    // Window part: the canonical coinbase is the hf-16 split of R over
    // window(tip, v) as a miner tx, still checked BEFORE RandomX.
    // =====================================================================
    {
        std::vector<std::pair<pb::Hash32, std::uint64_t>> wts;
        for (std::uint64_t i = 1; i <= 24; ++i)
            wts.push_back({book.add(key_ref(static_cast<std::uint8_t>(0x80 + i))), 1000 * i});
        const pb::Window w = window_of(wts);

        // ---- the correct hf-16 split is admitted; RandomX runs AFTER #12 ----
        pb::ReceiptBodyV3 r = make_body(3, false, 0x20);
        commit(r, w);
        check(check12(r, w) == pb::CoinbaseCheck::Match, "correct hf-16 split: Match");
        {
            bool rx = false;
            const pb::TailResult t = tail(r, w, true, rx);
            check(t.verdict == pb::AdmitVerdict::AdmitCarrier && t.randomx_called, "split: RandomX after #12");
        }

        // ---- a carrier whose coinbase is NOT the canonical split -> BAN, no RandomX ----
        {
            pb::ReceiptBodyV3 bad = r;
            bad.blob.tree_root = seq32(0xFE);
            bool rx = false;
            const pb::TailResult t = tail(bad, w, true, rx);
            check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx,
                  "non-canonical split (carrier) -> BAN before RandomX");
        }

        // ---- the same #12 applies to a CARRIED receipt ----
        {
            pb::ReceiptBodyV3 c = make_body(2, false, 0x30);
            commit(c, w);
            check(check12(c, w) == pb::CoinbaseCheck::Match, "carried correct split: Match");
        }

        // ---- a receipt paying ANOTHER tip's window is refused ----
        // (a different payee SET, not a scaled copy: the split is scale-invariant.)
        {
            std::vector<std::pair<pb::Hash32, std::uint64_t>> wts_other = wts;
            wts_other.push_back({book.add(key_ref(0x7F)), 123456});
            const pb::Window w_other = window_of(wts_other);
            check(check12(r, w_other) == pb::CoinbaseCheck::Mismatch, "a receipt paying another tip's window: Mismatch");
            bool rx = false;
            const pb::TailResult t = tail(r, w_other, true, rx);
            check(t.verdict == pb::AdmitVerdict::Ban && !rx, "another tip's window -> BAN before RandomX");
        }
    }

    return finish("xmr_receipt_solo_leech_kat");
}
