// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_window_fork_height_kat (pathb_emission.hpp / pathb_coinbase_split.hpp,
// C41): a tip one height below the hf 17 fork gives two windows -- hf 16 (OUT 40,
// OVH 89) and hf 17 (OUT 90, OVH 61) -- each as a FORMAT; N(B) differs; at hf 17
// NO amount is produced until O-01 exists (the lane FORK-FUSEs): an hf-17
// receipt is REFUSED (Fused) with 0 strike tokens and no ban, RandomX not called.
// ---------------------------------------------------------------------------
#include <cstdint>

#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_miner.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

int main() {
    const std::uint64_t s = 600000000000ull;  // S_A = 6e11

    // FORMAT differs across the fork (K24a / K24b).
    check(pb::ovh(16) == 89 && pb::ovh(17) == 61, "OVH 89 (hf16) / 61 (hf17)");
    check(pb::out_size(16, s) == 40 && pb::out_size(17, s) == 90, "OUT 40 (hf16) / 90 (hf17)");

    // N(B) differs across the fork at the same Z.
    check(pb::n_rule(300000, 16, s) == 3747 && pb::n_rule(300000, 17, s) == 1665,
          "N(B) differs: 3747 (hf16) vs 1665 (hf17)");

    // hf 16 produces amounts; hf 17 FORK-FUSEs (no amount until O-01).
    check(!pb::amount_fork_fused(16), "hf16 amounts produced");
    check(pb::amount_fork_fused(17) && pb::amount_fork_fused(18), "hf >= 17 FORK-FUSEs the amount");

    // the canonical coinbase at hf 17 builds NOTHING (Fused), at hf 16 it does.
    RefBook book;
    const pb::XmrKeyRef author = kat_author();
    const pb::Window w = window_of({{book.add(key_ref(0xA1)), 100}});
    pb::ReceiptBodyV3 r = make_body(3, false, 0x30);
    r.reward_total = 700000000000ull;
    const pb::Hash32 tip = r.side.tip, p_r = r.blob.prev_id;
    commit_miner_tx(r, w, tip, p_r, kKatHeight, book, author);
    pb::KeyCache cache;
    const pb::CanonicalTx at16 =
            pb::canonical_miner_tx(r, at_of(&w, tip, 16), tip, p_r, kKatHeight, 16, cache, book.lookup(), author);
    const pb::CanonicalTx at17 =
            pb::canonical_miner_tx(r, at_of(&w, tip, 17), tip, p_r, kKatHeight, 17, cache, book.lookup(), author);
    check(at16.stop == pb::CoinbaseCheck::Match && at16.tx.has_value(), "hf16 canonical miner tx built");
    check(at17.stop == pb::CoinbaseCheck::Fused && !at17.tx.has_value(),
          "hf17 canonical coinbase FORK-FUSED (no miner tx, no amount invented)");

    // at hf 17 the receipt is REFUSED: no strike token, no ban, RandomX not called.
    for (std::uint8_t hf : {std::uint8_t{17}, std::uint8_t{18}}) {
        const pb::CoinbaseCheck c =
                pb::canonical_coinbase_check(r, at_of(&w, tip, hf), tip, p_r, kKatHeight, hf, cache, book.lookup(), author);
        bool rx = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(c, [&] { rx = true; return true; });
        check(c == pb::CoinbaseCheck::Fused, "hf " + std::to_string(hf) + ": Fused");
        check(t.verdict == pb::AdmitVerdict::Refuse && pb::strike_tokens(t.verdict) == 0 && !t.randomx_called && !rx,
              "hf " + std::to_string(hf) + ": REFUSED, 0 strike tokens, no ban, RandomX not called");
    }
    // the same receipt at hf 16 is admitted.
    {
        bool rx = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(
                pb::canonical_coinbase_check(r, at_of(&w, tip, 16), tip, p_r, kKatHeight, 16, cache, book.lookup(), author),
                [&] { rx = true; return true; });
        check(t.verdict == pb::AdmitVerdict::AdmitCarrier && rx, "hf16: admitted, RandomX after #12");
    }

    return finish("v37_xmr_window_fork_height_kat");
}
