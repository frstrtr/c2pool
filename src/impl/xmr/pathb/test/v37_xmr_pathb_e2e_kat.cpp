// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_pathb_e2e_kat (pathb_coinbase_split.hpp, C07, "kept name" xmr_e2e_kat
// -- shipped pathb-scoped, the native settle xmr_e2e_kat already exists): the
// whole window -> split -> PBX1 extra -> leaf -> tree_root pipeline on a mainnet
// and a regtest vector; admission #13 (window_root / mmr_root == the node's own
// computation, lifting the S1/S2 zero stubs); a receipt paying ANOTHER tip's
// window is refused.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <span>

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
static pb::Window mk_window(std::uint64_t n, std::uint64_t base_w) {
    pb::Window w;
    for (std::uint64_t i = 1; i <= n; ++i) { w.weight[id_of(i)] = pb::Work(base_w + i); w.W += pb::Work(base_w + i); }
    return w;
}

int main() {
    // ---- mainnet-tail e2e: Sum == R and roots_ok lift the zero stubs ----
    {
        const std::uint64_t R = pb::kTailBaseReward + 3000000000ull;  // 6e11 + 3e9 fees
        const pb::Window w = mk_window(16, 10000);
        pb::BinMmr mmr;
        pb::BucketRow row; row.miner = id_of(1); row.w_miner = pb::Work(10001);
        mmr.append(pb::mmr_leaf_of(pb::seal_bucket(1000, {row}, pb::Work(10001), 1, 18180)));

        const auto outs = pb::split(R, w);
        std::uint64_t s = 0; for (const auto& o : outs) s += o.amount;
        check(s == R, "mainnet e2e: Sum(vout) == R");

        // admission #13: side_data roots match the node's own computation.
        pb::SideDataV3 side;
        pb::Work sum;
        side.window_root = pb::window_root(w, &sum);
        side.mmr_root = mmr.root();
        check(pb::roots_ok(side, w, mmr), "roots_ok: window_root & mmr_root == node computation (#13)");
        check(!(side.window_root == pb::Hash32{}) && !(side.mmr_root == pb::Hash32{}),
              "window_root (141) and mmr_root (173) go NON-ZERO (lift the S1/S2 stubs)");

        // a tampered window_root is a STRIKE (#13).
        pb::SideDataV3 bad = side; bad.window_root[0] ^= 1;
        check(!pb::roots_ok(bad, w, mmr), "tampered window_root -> STRIKE");
        pb::SideDataV3 bad2 = side; bad2.mmr_root[0] ^= 1;
        check(!pb::roots_ok(bad2, w, mmr), "tampered mmr_root -> STRIKE");
    }

    // ---- regtest vector: B from a low-supply anchor, R = its own base, no fees ----
    {
        const std::uint64_t agc = 1000000000000ull;  // ~1e12 emitted (regtest)
        const std::uint64_t B = pb::base_reward_at(agc, 16);
        const std::uint64_t R = B;  // fees 0
        const pb::Window w = mk_window(8, 5000);
        const auto outs = pb::split(R, w);
        std::uint64_t s = 0; for (const auto& o : outs) s += o.amount;
        check(s == R, "regtest e2e: Sum(vout) == R (= own base, fees 0)");
    }

    // ---- a receipt paying ANOTHER tip's window is refused ----
    {
        const std::uint64_t R = pb::kTailBaseReward;
        const pb::Window w_a = mk_window(10, 20000);  // tip A's window
        const pb::Window w_b = mk_window(10, 70000);  // tip B's window (different)
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
