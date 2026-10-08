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
// ---------------------------------------------------------------------------
#include <cstdint>
#include <span>

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
    const pb::Hash32 tip = r.side.tip, p_r = r.blob.prev_id, mm = seq32(0x55);
    const pb::CanonLeaf cl = pb::canonical_coinbase_leaf(r, w, tip, p_r, /*hf=*/16, mm);
    check(!cl.fork_fused, "hf16 canonical coinbase built");
    r.blob.tree_root = pb::tree_root_fold(cl.leaf, std::span<const pb::Hash32>(r.branch));
    check(pb::canonical_coinbase_ok_split(r, w, tip, p_r, 16, mm), "canonical split coinbase admitted");

    // the admission runs #12 strictly before RandomX; a correct coinbase lets it run.
    {
        bool rx = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(
                pb::canonical_coinbase_ok_split(r, w, tip, p_r, 16, mm), [&] { rx = true; return true; });
        check(t.verdict == pb::AdmitVerdict::AdmitCarrier && t.randomx_called && rx,
              "correct coinbase -> RandomX runs after #12");
    }

    // a WRONG split (tampered tree_root) -> BAN before RandomX (not called).
    {
        pb::ReceiptBodyV3 bad = r;
        bad.blob.tree_root = seq32(0xFF);  // not the canonical split leaf fold
        check(!pb::canonical_coinbase_ok_split(bad, w, tip, p_r, 16, mm), "wrong split: coinbase NOT ok");
        bool rx = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(
                pb::canonical_coinbase_ok_split(bad, w, tip, p_r, 16, mm), [&] { rx = true; return true; });
        check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx, "wrong split -> BAN, no RandomX");
    }

    // a coinbase that claims R' != R (over/under) -> different leaf -> BAN.
    {
        pb::ReceiptBodyV3 bad = r;
        bad.reward_total = R + 1;  // over-claim
        check(!pb::canonical_coinbase_ok_split(bad, w, tip, p_r, 16, mm), "R' != R -> coinbase NOT ok");
    }

    return finish("v37_xmr_pathb_coinbase_kat");
}
