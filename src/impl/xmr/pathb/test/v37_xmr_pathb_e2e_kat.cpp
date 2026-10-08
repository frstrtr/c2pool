// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_pathb_e2e_kat (pathb_coinbase_split.hpp, C07, "kept name" xmr_e2e_kat
// -- shipped pathb-scoped, the native settle xmr_e2e_kat already exists): the
// whole window -> split -> miner tx (PBX1 extra with mm_root_of(side_data_v3))
// -> tx hash -> tree_root pipeline on a mainnet and a regtest vector, the window
// built by window() from WinBins (COVERAGE x D_net, f_spend and N(B) of the tip,
// owner and author shares); the
// receipt-level miner tx bytes (finder-only and a two-payee window) pinned;
// admission #13 (window_root / mmr_root == the node's own computation, lifting
// the S1/S2 zero stubs; a mismatch is BAN before RandomX, part of the #12
// prefix, for the S3 roots and the S2 zero stubs alike); a receipt paying
// ANOTHER tip's window is refused.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_miner.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 id_of(std::uint64_t i) {
    pb::Hash32 h{};
    for (int b = 0; b < 8; ++b) h[31 - b] = static_cast<std::uint8_t>(i >> (8 * b));
    return h;
}
// A payee's window weight, zero when it is not a payee.
static pb::Work weight_of(const pb::Window& w, const pb::Hash32& id) {
    const auto it = w.weight.find(id);
    return it == w.weight.end() ? pb::Work{} : it->second;
}

static pb::WinEntry entry(std::uint64_t miner, std::uint64_t work, std::uint64_t pos) {
    pb::WinEntry x;
    x.miner = id_of(miner);
    x.work = work;
    x.position = pos;
    x.id = id_of(1000000 + pos);
    return x;
}

static const pb::Hash32 kOwner = id_of(0x1000);
static const pb::Hash32 kAuthor = id_of(0x2000);

// Five bins newest first (1004..1000), 40,000 raw work each: miner 1 (10,000,
// owner 0x1000 at p 100 bp), miner 2 (10,100, give_author_bp 10), miner 3 (9,900)
// and one miner of its own per bin (4 + k, 10,000).
static std::vector<pb::WinBin> mainnet_bins() {
    std::vector<pb::WinBin> bins;
    for (std::uint64_t k = 0; k < 5; ++k) {
        pb::WinBin b;
        b.bin = 1004 - k;
        const std::uint64_t pos = 500 - 4 * k;
        pb::WinEntry m1 = entry(1, 10000, pos);
        m1.owner = kOwner;
        m1.p = 100;
        pb::WinEntry m2 = entry(2, 10100, pos - 1);
        m2.give_author_bp = 10;
        b.entries = {m1, m2, entry(3, 9900, pos - 2), entry(4 + k, 10000, pos - 3)};
        bins.push_back(b);
    }
    return bins;
}

// window() with every input of the tip: f_spend(B, M 300k, hf 16), N(B) at Z 300k.
static pb::Window window_at(const std::vector<pb::WinBin>& bins, std::uint64_t d_net, std::uint64_t B) {
    return pb::window(bins, d_net, B, pb::f_spend(B, 300000, 16), pb::n_rule(300000, 16, B), kAuthor);
}

int main() {
    // ---- mainnet-tail e2e: Sum == R and roots_ok lift the zero stubs ----
    {
        const std::uint64_t R = pb::kTailBaseReward + 3000000000ull;  // 6e11 + 3e9 fees
        // D_net 70,000: COVERAGE 140,000 takes the four newest bins (W 160,000).
        const pb::Window w = window_at(mainnet_bins(), 70000, pb::kTailBaseReward);
        check(w.W == pb::Work(160000) && w.weight.size() == 9, "mainnet e2e: four newest bins, W 160,000, 9 payees");
        check(weight_of(w, id_of(1)) == pb::Work(39600) && weight_of(w, id_of(2)) == pb::Work(40360)
                      && weight_of(w, id_of(3)) == pb::Work(39600) && weight_of(w, id_of(7)) == pb::Work(10000)
                      && w.weight.count(id_of(8)) == 0 && weight_of(w, kOwner) == pb::Work(400)
                      && weight_of(w, kAuthor) == pb::Work(40),
              "mainnet e2e: weights 39,600 / 40,360 / 39,600 / 10,000 x 4, owner 400, author 40");
        pb::BinMmr mmr;
        pb::BucketRow row; row.miner = id_of(1); row.w_miner = pb::Work(10001);
        mmr.append(pb::mmr_leaf_of(pb::seal_bucket(1000, {row}, pb::Work(10001), 1, 18180)));

        const auto outs = pb::split(R, w);
        std::uint64_t s = 0; for (const auto& o : outs) s += o.amount;
        check(s == R, "mainnet e2e: Sum(vout) == R");
        check(outs.size() == 9 && outs[0].amount == 149242500000ull && outs[1].amount == 152106750000ull
                      && outs[6].amount == 37687500000ull && outs[7].payee == kOwner && outs[7].amount == 1507500000ull
                      && outs[8].payee == kAuthor && outs[8].amount == 150750000ull,
              "mainnet e2e: amounts 149,242,500,000 / 152,106,750,000 / 37,687,500,000, owner 1,507,500,000, author 150,750,000");

        // admission #13: side_data roots match the node's own computation.
        pb::SideDataV3 side;
        pb::Work sum;
        side.window_root = pb::window_root(w, &sum);
        side.mmr_root = mmr.root();
        check(pb::roots_ok(side, w, mmr), "roots_ok: window_root & mmr_root == node computation (#13)");
        check(!(side.window_root == pb::Hash32{}) && !(side.mmr_root == pb::Hash32{}),
              "window_root (141) and mmr_root (173) go NON-ZERO (lift the S1/S2 stubs)");

        // a tampered window_root / mmr_root is a BAN (#13), decided before RandomX.
        int rx_calls = 0;
        const auto rx = [&rx_calls] { ++rx_calls; return true; };
        const pb::CoinbaseCheck match = pb::CoinbaseCheck::Match;
        pb::SideDataV3 bad = side; bad.window_root[0] ^= 1;
        check(!pb::roots_ok(bad, w, mmr), "tampered window_root: roots_ok false");
        const pb::TailResult t1 = pb::admit_coinbase_roots_then_randomx(match, pb::roots_ok(bad, w, mmr), rx);
        check(t1.verdict == pb::AdmitVerdict::Ban && !t1.randomx_called, "tampered window_root -> BAN before RandomX");
        pb::SideDataV3 bad2 = side; bad2.mmr_root[0] ^= 1;
        check(!pb::roots_ok(bad2, w, mmr), "tampered mmr_root: roots_ok false");
        const pb::TailResult t2 = pb::admit_coinbase_roots_then_randomx(match, pb::roots_ok(bad2, w, mmr), rx);
        check(t2.verdict == pb::AdmitVerdict::Ban && !t2.randomx_called, "tampered mmr_root -> BAN before RandomX");
        const pb::TailResult t3 = pb::admit_coinbase_roots_then_randomx(match, pb::roots_ok(side, w, mmr), rx);
        check(t3.verdict == pb::AdmitVerdict::AdmitCarrier && t3.randomx_called, "matching roots: RandomX runs");
        check(rx_calls == 1, "RandomX called once, only for the matching roots");
        check(pb::strike_tokens(t1.verdict) == 0, "#13 is not a STRIKE");
    }

    // ---- S2 #13: a non-zero stub is a BAN before RandomX ----
    {
        int rx_calls = 0;
        const auto rx = [&rx_calls] { ++rx_calls; return true; };
        pb::SideDataV3 stub;  // both roots zero
        check(pb::zero_stubs_ok(stub), "zero stubs pass");
        pb::SideDataV3 wr = stub; wr.window_root[5] = 1;
        pb::SideDataV3 mr = stub; mr.mmr_root[31] = 1;
        const pb::TailResult a = pb::admit_coinbase_roots_then_randomx(pb::CoinbaseCheck::Match, pb::zero_stubs_ok(wr), rx);
        const pb::TailResult b = pb::admit_coinbase_roots_then_randomx(pb::CoinbaseCheck::Match, pb::zero_stubs_ok(mr), rx);
        check(a.verdict == pb::AdmitVerdict::Ban && !a.randomx_called, "S2: a non-zero window_root stub -> BAN before RandomX");
        check(b.verdict == pb::AdmitVerdict::Ban && !b.randomx_called, "S2: a non-zero mmr_root stub -> BAN before RandomX");
        const pb::TailResult c = pb::admit_coinbase_roots_then_randomx(pb::CoinbaseCheck::Mismatch, true, rx);
        check(c.verdict == pb::AdmitVerdict::Ban && !c.randomx_called, "#12 Mismatch still BAN before RandomX");
        check(rx_calls == 0, "RandomX never called");
    }

    // ---- regtest vector: B from a low-supply anchor, R = its own base, no fees ----
    {
        const std::uint64_t agc = 1000000000000ull;  // ~1e12 emitted (regtest)
        const std::uint64_t B = pb::base_reward_at(agc, 16);
        const std::uint64_t R = B;  // fees 0
        check(pb::f_spend(B, 300000, 16) == 734240000ull, "regtest e2e: f_spend(B(1e12), 300k, hf16) == 734,240,000");
        std::vector<pb::WinBin> bins;  // three bins newest first, 20,600 raw each
        for (std::uint64_t k = 0; k < 3; ++k) {
            pb::WinBin b;
            b.bin = 30 - k;
            for (std::uint64_t j = 0; j < 4; ++j) b.entries.push_back(entry((k % 2 ? 5 : 1) + j, 5000 + 100 * j, 90 - 4 * k - j));
            bins.push_back(b);
        }
        const pb::Window w = window_at(bins, 20000, B);  // COVERAGE 40,000: two bins
        check(w.W == pb::Work(41200) && w.weight.size() == 8, "regtest e2e: two newest bins, W 41,200, 8 payees");
        const auto outs = pb::split(R, w);
        std::uint64_t s = 0; for (const auto& o : outs) s += o.amount;
        check(s == R && outs.size() == 8, "regtest e2e: Sum(vout) == R (= own base, fees 0)");
    }

    // ---- the receipt-level miner tx, bytes pinned: finder-only and a window ----
    const pb::XmrKeyRef X = ref_from_secrets(11, 13), Y = ref_from_secrets(17, 19);
    RefBook book;
    const pb::Hash32 idX = book.add(X), idY = book.add(Y);
    const pb::XmrKeyRef author = kat_author();
    pb::ReceiptBodyV3 r;
    r.blob.major = 16;
    r.blob.minor = 16;
    r.blob.prev_id = seq32(0x41);
    r.extra_nonce = {1, 2, 3, 4};
    r.branch = {seq32(0x81)};
    r.side.pool_id = seq32(0x01);
    r.side.payee = idX;
    r.side.t_origin = 18180;
    r.side.tip = seq32(0x21);
    r.side.receipts_root = seq32(0xA0);
    r.payee = X;
    r.reward_total = pb::kTailBaseReward;
    const pb::Hash32 tip = r.side.tip, p_r = r.blob.prev_id;
    check(hex32(pb::mm_root_of(r.side).value()) == "a91fa596e29d6355723d37de8cc61b9243b474cc0cb2cc013b9c83135b5b9507",
          "e2e receipt: mm_root_of(side_data_v3)");
    {
        pb::KeyCache cache;
        const pb::Window empty;
        const pb::CanonicalTx f = pb::canonical_miner_tx(r, pb::WindowAt{&empty}, tip, p_r, kKatHeight, 16, cache,
                                                         book.lookup(), author);
        check(f.tx && f.tx->prefix.size() == 127
                      && hex32(f.tx->tx_hash) == "57c33152bd14fd28d54e627693516640bf794943ba801596b4143bfb3c6d1b29",
              "e2e finder-only: one output of R to X, prefix 127 B, tx hash 57c33152..");
        pb::ReceiptBodyV3 x = r;
        x.blob.tree_root = h32("9ad4924071b1223f57f0d48632d8c9ab75443e831af7f32873a8d831fe7bc9b8");
        check(pb::canonical_coinbase_check(x, pb::WindowAt{&empty}, tip, p_r, kKatHeight, 16, cache, book.lookup(),
                                           author)
                      == pb::CoinbaseCheck::Match,
              "e2e finder-only: tree_root 9ad49240.. -> Match");
    }
    {
        pb::KeyCache cache;
        const pb::Window w = window_of({{idX, 120000}, {idY, 100000}});
        const pb::CanonicalTx c = pb::canonical_miner_tx(r, pb::WindowAt{&w}, tip, p_r, kKatHeight, 16, cache,
                                                         book.lookup(), author);
        check(c.tx && c.tx->outs.size() == 2 && c.tx->outs[0].amount == 272727272727ull
                      && c.tx->outs[1].amount == 327272727273ull,
              "e2e window: vout 0 = Y 272,727,272,727, vout 1 = X 327,272,727,273 (Sum == R)");
        check(c.tx && c.tx->prefix.size() == 167
                      && hex32(c.tx->tx_hash) == "11e1f5aa396db1fcd12d6011fe12d3d8a9d7715d02ba21a93122662808b13b15",
              "e2e window: prefix 167 B, tx hash 11e1f5aa..");
        pb::ReceiptBodyV3 x = r;
        x.blob.tree_root = h32("3fa241b5f26885c6cb6c25964b7dda13c89eb9e6aecef8cc2d6c31c1a40bdc80");
        check(pb::canonical_coinbase_check(x, pb::WindowAt{&w}, tip, p_r, kKatHeight, 16, cache, book.lookup(), author)
                      == pb::CoinbaseCheck::Match,
              "e2e window: tree_root 3fa241b5.. -> Match");
    }

    // ---- a receipt paying ANOTHER tip's window is refused ----
    {
        const pb::Window w_a0 = window_at(mainnet_bins(), 30000, pb::kTailBaseReward);  // tip A: D_net 30,000, two bins
        const pb::Window w_b0 = window_at(mainnet_bins(), 70000, pb::kTailBaseReward);  // tip B: D_net 70,000, four bins
        check(w_a0.W == pb::Work(80000) && w_b0.W == pb::Work(160000), "tip A window W 80,000, tip B window W 160,000");
        std::vector<std::pair<pb::Hash32, std::uint64_t>> wa, wb;
        for (std::uint8_t i = 1; i <= 10; ++i) {
            const pb::Hash32 id = book.add(key_ref(static_cast<std::uint8_t>(0x40 + i)));
            wa.push_back({id, 20000u + i});
            wb.push_back({id, 70000u + 3u * i});
        }
        const pb::Window w_a = window_of(wa);  // tip A's window
        const pb::Window w_b = window_of(wb);  // tip B's window (different)
        pb::ReceiptBodyV3 q = make_body(3, false, 0x30);
        q.reward_total = pb::kTailBaseReward;
        // the receipt commits the canonical coinbase for tip A's window ...
        check(commit_miner_tx(q, w_a, q.side.tip, q.blob.prev_id, kKatHeight, book, author), "e2e: tip A's miner tx");
        pb::KeyCache cache;
        check(pb::canonical_coinbase_check(q, pb::WindowAt{&w_a}, q.side.tip, q.blob.prev_id, kKatHeight, 16, cache,
                                           book.lookup(), author)
                      == pb::CoinbaseCheck::Match,
              "correct tip-A window: Match");
        // ... checked against tip B's window -> refused.
        check(pb::canonical_coinbase_check(q, pb::WindowAt{&w_b}, q.side.tip, q.blob.prev_id, kKatHeight, 16, cache,
                                           book.lookup(), author)
                      == pb::CoinbaseCheck::Mismatch,
              "paying another tip's window: Mismatch");
    }

    return finish("v37_xmr_pathb_e2e_kat");
}
