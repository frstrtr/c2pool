// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_pathb_e2e_kat (pathb_coinbase_split.hpp, C07, "kept name" xmr_e2e_kat
// -- shipped pathb-scoped, the native settle xmr_e2e_kat already exists): the
// whole window -> split -> PBX1 extra -> leaf -> tree_root pipeline on a mainnet
// and a regtest vector, the window built by window() from WinBins (COVERAGE x
// D_net, f_spend and N(B) of the tip, owner and author shares); admission #13 (window_root / mmr_root == the node's own
// computation, lifting the S1/S2 zero stubs; a mismatch is BAN before RandomX,
// part of the #12 prefix, for the S3 roots and the S2 zero stubs alike); a
// receipt paying ANOTHER tip's window is refused.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <span>
#include <vector>

#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/pathb_emission.hpp"
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
        pb::SideDataV3 bad = side; bad.window_root[0] ^= 1;
        check(!pb::roots_ok(bad, w, mmr), "tampered window_root: roots_ok false");
        const pb::TailResult t1 = pb::admit_coinbase_roots_then_randomx(true, pb::roots_ok(bad, w, mmr), rx);
        check(t1.verdict == pb::AdmitVerdict::Ban && !t1.randomx_called, "tampered window_root -> BAN before RandomX");
        pb::SideDataV3 bad2 = side; bad2.mmr_root[0] ^= 1;
        check(!pb::roots_ok(bad2, w, mmr), "tampered mmr_root: roots_ok false");
        const pb::TailResult t2 = pb::admit_coinbase_roots_then_randomx(true, pb::roots_ok(bad2, w, mmr), rx);
        check(t2.verdict == pb::AdmitVerdict::Ban && !t2.randomx_called, "tampered mmr_root -> BAN before RandomX");
        const pb::TailResult t3 = pb::admit_coinbase_roots_then_randomx(true, pb::roots_ok(side, w, mmr), rx);
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
        const pb::TailResult a = pb::admit_coinbase_roots_then_randomx(true, pb::zero_stubs_ok(wr), rx);
        const pb::TailResult b = pb::admit_coinbase_roots_then_randomx(true, pb::zero_stubs_ok(mr), rx);
        check(a.verdict == pb::AdmitVerdict::Ban && !a.randomx_called, "S2: a non-zero window_root stub -> BAN before RandomX");
        check(b.verdict == pb::AdmitVerdict::Ban && !b.randomx_called, "S2: a non-zero mmr_root stub -> BAN before RandomX");
        const pb::TailResult c = pb::admit_coinbase_roots_then_randomx(false, true, rx);
        check(c.verdict == pb::AdmitVerdict::Ban && !c.randomx_called, "#12 still BAN before RandomX");
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

    // ---- a receipt paying ANOTHER tip's window is refused ----
    {
        const std::uint64_t R = pb::kTailBaseReward;
        const pb::Window w_a = window_at(mainnet_bins(), 30000, pb::kTailBaseReward);  // tip A: D_net 30,000, two bins
        const pb::Window w_b = window_at(mainnet_bins(), 70000, pb::kTailBaseReward);  // tip B: D_net 70,000, four bins
        check(w_a.W == pb::Work(80000) && w_b.W == pb::Work(160000), "tip A window W 80,000, tip B window W 160,000");
        pb::ReceiptBodyV3 r = make_body(3, false, 0x30);
        r.reward_total = R;
        const pb::Hash32 tip = r.side.tip, p_r = r.blob.prev_id;
        // the receipt commits the canonical coinbase for tip A's window ...
        const pb::CanonLeaf cl = pb::canonical_coinbase_leaf(r, w_a, tip, p_r, 16);
        // window -> split -> PBX1 extra (mm_root = mm_root_of(side_data_v3)) -> leaf.
        const auto extra = pb::canonical_tx_extra_hf16(p_r, r.extra_nonce, pb::mm_root_of(r.side).value());
        check(cl.leaf == pb::canonical_cb_leaf(pb::split(R, w_a), tip, p_r, extra),
              "e2e leaf = split -> PBX1(mm_root_of(side_data_v3)) -> leaf");
        r.blob.tree_root = pb::tree_root_fold(cl.leaf.value(), std::span<const pb::Hash32>(r.branch));
        check(pb::canonical_coinbase_ok_split(r, w_a, tip, p_r, 16), "correct tip-A window admitted");
        // ... checked against tip B's window -> refused.
        check(!pb::canonical_coinbase_ok_split(r, w_b, tip, p_r, 16), "paying another tip's window refused");
    }

    return finish("v37_xmr_pathb_e2e_kat");
}
