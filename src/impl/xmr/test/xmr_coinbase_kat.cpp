// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/test/xmr_coinbase_kat.cpp  --  the Path B coinbase (case 4)
//
//   1. mainnet: the 47 payees of block 3,755,897, R 600,000,000,000: the
//      canonical hf-16 miner tx pays every payee and Sum(vout) == R
//   2. regtest: R = B(genesis) = 35,184,338,534,400 over three payees:
//      Sum(vout) == R
//   3. deterministic: the same receipt and window give the same miner tx bytes
//      (a fresh key cache); another tip gives another r and R_tx
//   4. R_tx == r G (secret_key_to_public_key)
//   5. hf 17: no miner tx (the fork fence)
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/test/pathb_kat_bodies.hpp"
#include "impl/xmr/pathb/test/pathb_kat_check.hpp"
#include "impl/xmr/pathb/test/pathb_kat_miner.hpp"
#include "impl/xmr/pathb/test/pathb_m2_blocks.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

std::uint64_t sum_of(const pb::CanonicalTx& c) {
    std::uint64_t s = 0;
    if (c.tx)
        for (const pb::MinerOut& o : c.tx->outs) s += o.amount;
    return s;
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== xmr_coinbase_kat: the Path B coinbase (case 4) ===\n");
    const pb::XmrKeyRef author = kat_author();
    RefBook book;

    // 1. mainnet
    const m2::Block& B = m2::kBlocks[0];
    std::vector<std::pair<pb::Hash32, std::uint64_t>> wts;
    for (std::size_t i = 0; i < B.n_payees; ++i) {
        pb::XmrKeyRef ref;
        ref.spend = h32(B.payees[i].spend);
        ref.view = h32(B.payees[i].view);
        wts.push_back({book.add(ref), 1000003u + 7919u * i});
    }
    const pb::RefLookup refs = book.lookup();
    const pb::Window w = window_of(wts);
    pb::ReceiptBodyV3 r = make_body(3, false, 0x24);
    r.reward_total = B.reward;
    pb::KeyCache cache;
    const pb::CanonicalTx c =
            pb::canonical_miner_tx(r, at_of(&w, r.side.tip, 16), r.side.tip, r.blob.prev_id, kKatHeight, 16, cache, refs, author);
    check(B.height == 3755897 && B.reward == 600000000000ull && c.tx && c.tx->outs.size() == B.n_payees &&
                  sum_of(c) == 600000000000ull,
          "1 mainnet: 47 payees of block 3,755,897, Sum(vout) == R 600,000,000,000");

    // 2. regtest
    const std::uint64_t R = pb::base_reward_at(17592186044415ull, 16);
    std::vector<std::pair<pb::Hash32, std::uint64_t>> wr;
    for (std::uint8_t i = 0; i < 3; ++i) wr.push_back({book.add(key_ref(static_cast<std::uint8_t>(0xA0 + i))), 1u << i});
    const pb::RefLookup refs2 = book.lookup();
    const pb::Window w_reg = window_of(wr);
    pb::ReceiptBodyV3 q = make_body(3, false, 0x25);
    q.reward_total = R;
    const pb::CanonicalTx cr = pb::canonical_miner_tx(q, at_of(&w_reg, q.side.tip, 16), q.side.tip, q.blob.prev_id,
                                                      kKatHeight, 16, cache, refs2, author);
    check(R == 35184338534400ull && cr.tx && sum_of(cr) == R, "2 regtest: Sum(vout) == R 35,184,338,534,400");

    // 3. deterministic
    pb::KeyCache fresh;
    const pb::CanonicalTx c2 =
            pb::canonical_miner_tx(r, at_of(&w, r.side.tip, 16), r.side.tip, r.blob.prev_id, kKatHeight, 16, fresh, refs2, author);
    pb::ReceiptBodyV3 r3 = r;
    r3.side.tip = seq32(0x55);
    const pb::CanonicalTx c3 = pb::canonical_miner_tx(r3, at_of(&w, r3.side.tip, 16), r3.side.tip, r3.blob.prev_id,
                                                      kKatHeight, 16, fresh, refs2, author);
    check(c.tx && c2.tx && c2.tx->prefix == c.tx->prefix && c3.tx && !(c3.tx->r == c.tx->r) && !(c3.tx->r_tx == c.tx->r_tx),
          "3 the same receipt and window -> the same miner tx bytes; another tip -> another r and R_tx");

    // 4. R_tx == r G
    bool rg = false;
    if (c.tx) {
        ::xmr::coin::SecretKey s;
        ::xmr::coin::PublicKey p;
        std::memcpy(s.data(), c.tx->r.data(), 32);
        rg = ::xmr::coin::secret_key_to_public_key(s, p) && std::memcmp(p.data(), c.tx->r_tx.data(), 32) == 0;
    }
    check(rg, "4 R_tx == r G");

    // 5. hf 17
    const pb::CanonicalTx c17 =
            pb::canonical_miner_tx(r, at_of(&w, r.side.tip, 17), r.side.tip, r.blob.prev_id, kKatHeight, 17, fresh, refs2, author);
    check(!c17.tx && c17.stop == pb::CoinbaseCheck::Fused, "5 hf 17: no miner tx (Fused)");

    return finish("xmr_coinbase_kat");
}
