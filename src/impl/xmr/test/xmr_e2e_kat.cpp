// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/test/xmr_e2e_kat.cpp -- case 4 end to end through the Path B
// coinbase (impl/xmr/pathb/pathb_coinbase_split.hpp, pathb_miner_tx.hpp):
//   window -> split -> the hf-16 miner tx (PBX1 extra with mm_root_of(side_data_v3))
//   -> tx hash -> tree_root folded over the receipt's branch -> the hashing blob
//   -> the v3 receipt body on the wire -> canonical_coinbase_check (#12) == Match;
//   Sum(vout) == R on the mainnet tail (block 3,755,897, R 600,000,000,000, 47 payees)
//   and on a regtest vector (R 35,184,338,534,400), both with a largest-remainder
//   deficit; a window weight, a side_data_v3 field or a branch byte changed after
//   the miner built its tx -> Mismatch.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "impl/xmr/pathb/test/pathb_kat_bodies.hpp"
#include "impl/xmr/pathb/test/pathb_kat_check.hpp"
#include "impl/xmr/pathb/test/pathb_kat_miner.hpp"
#include "impl/xmr/pathb/test/pathb_m2_blocks.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

std::uint64_t floor_sum(std::uint64_t R, const std::vector<std::pair<pb::Hash32, std::uint64_t>>& wts) {
    unsigned __int128 W = 0;
    for (const auto& [id, w] : wts) W += w;
    std::uint64_t s = 0;
    for (const auto& [id, w] : wts) s += static_cast<std::uint64_t>(static_cast<unsigned __int128>(R) * w / W);
    return s;
}

void run(const char* name, std::uint64_t R, const std::vector<std::pair<pb::Hash32, std::uint64_t>>& wts, RefBook& book,
         std::uint8_t seed) {
    const pb::XmrKeyRef author = kat_author();
    const pb::RefLookup refs = book.lookup();
    pb::KeyCache cache;
    const pb::Window w = window_of(wts);
    pb::ReceiptBodyV3 r = make_body(3, false, seed);
    r.reward_total = R;
    const std::string n = name;
    check(floor_sum(R, wts) < R, n + ": the floors sum below R (deficit > 0)");
    // the miner builds its own canonical miner tx and commits it into the blob's tree_root
    const std::optional<pb::MinerTx> mine = miner_built_tx(r, w, r.side.tip, r.blob.prev_id, kKatHeight, book, author);
    check(mine.has_value() && commit_miner_tx(r, w, r.side.tip, r.blob.prev_id, kKatHeight, book, author),
          n + ": the miner builds and commits its miner tx");
    if (!mine) return;
    check(r.blob.tree_root == pb::tree_root_fold(mine->tx_hash, std::span<const pb::Hash32>(r.branch)),
          n + ": the blob's tree_root = fold(miner tx hash, branch)");
    // the receipt on the wire, decoded as a node receives it
    std::vector<std::uint8_t> bytes;
    check(pb::encode_receipt_body_v3(r, bytes) == pb::WireError::None, n + ": the v3 body encodes");
    pb::ReceiptBodyV3 rx;
    check(pb::decode_receipt_body_v3(bytes.data(), bytes.size(), pb::ReceiptLimits{bytes.size()}, rx) == pb::WireError::None &&
                  rx == r,
          n + ": the v3 body decodes to the same receipt");
    const pb::WindowAt at = at_of(&w, rx.side.tip, 16);
    check(pb::canonical_coinbase_check(rx, at, rx.side.tip, rx.blob.prev_id, kKatHeight, 16, cache, refs, author) ==
                  pb::CoinbaseCheck::Match,
          n + ": the node's canonical miner tx matches the received receipt (#12 Match)");
    const pb::CanonicalTx c = pb::canonical_miner_tx(rx, at, rx.side.tip, rx.blob.prev_id, kKatHeight, 16, cache, refs, author);
    std::uint64_t s = 0;
    if (c.tx)
        for (const pb::MinerOut& o : c.tx->outs) s += o.amount;
    check(c.tx && c.tx->tx_hash == mine->tx_hash && c.tx->outs.size() == wts.size() && s == R,
          n + ": Sum(vout) of the miner tx == R = " + std::to_string(R));
    // a change after the miner built its tx
    {
        std::vector<std::pair<pb::Hash32, std::uint64_t>> w2 = wts;
        w2[0].second += 1;
        const pb::Window wb = window_of(w2);
        check(pb::canonical_coinbase_check(rx, at_of(&wb, rx.side.tip, 16), rx.side.tip, rx.blob.prev_id, kKatHeight, 16,
                                           cache, refs, author) == pb::CoinbaseCheck::Mismatch,
              n + ": another window weight -> Mismatch");
    }
    {
        pb::ReceiptBodyV3 t = rx;
        t.side.give_author_bp = 20;
        check(pb::canonical_coinbase_check(t, at, t.side.tip, t.blob.prev_id, kKatHeight, 16, cache, refs, author) ==
                      pb::CoinbaseCheck::Mismatch,
              n + ": a side_data_v3 field changed -> Mismatch");
    }
    {
        pb::ReceiptBodyV3 t = rx;
        t.branch[1][0] ^= 1;
        check(pb::canonical_coinbase_check(t, at, t.side.tip, t.blob.prev_id, kKatHeight, 16, cache, refs, author) ==
                      pb::CoinbaseCheck::Mismatch,
              n + ": a branch byte flipped -> Mismatch");
    }
}

}  // namespace

int main() {
    std::printf("=== xmr_e2e_kat: case 4 end to end through the Path B coinbase ===\n");
    RefBook book;
    // mainnet tail: the 47 payees of block 3,755,897, R 600,000,000,000
    const m2::Block& B = m2::kBlocks[0];
    check(B.height == 3755897 && B.reward == 600000000000ull, "case 4: block 3,755,897, R 600,000,000,000");
    std::vector<std::pair<pb::Hash32, std::uint64_t>> wts;
    for (std::size_t i = 0; i < B.n_payees; ++i) {
        pb::XmrKeyRef ref;
        ref.spend = h32(B.payees[i].spend);
        ref.view = h32(B.payees[i].view);
        wts.push_back({book.add(ref), 1000003u + 7919u * i});
    }
    run("case 4 mainnet", B.reward, wts, book, 0x24);
    // regtest: R = B(genesis), fees 0
    const std::uint64_t R = pb::base_reward_at(17592186044415ull, 16);
    check(R == 35184338534400ull, "case 4 regtest: R 35,184,338,534,400");
    std::vector<std::pair<pb::Hash32, std::uint64_t>> wr;
    for (std::uint8_t i = 0; i < 3; ++i) wr.push_back({book.add(key_ref(static_cast<std::uint8_t>(0xA0 + i))), 1u << i});
    run("case 4 regtest", R, wr, book, 0x25);
    return finish("xmr_e2e_kat");
}
