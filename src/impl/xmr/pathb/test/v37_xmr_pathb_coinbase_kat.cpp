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
// admitted; a wrong split is a BAN before RandomX (the RandomX stub is not called);
// a receipt with p + give_author_bp > 10000 is refused (BAN before RandomX) and
// at p + give_author_bp == 10000 the window weights sum to W and Sum(vout) == R;
// a window holding such an entry has no split and no canonical coinbase; no
// leaf is built when the shares are undefined or the amount is fork-fused, and
// a tree_root folded from the zero leaf is refused.
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
    check(!cl.fork_fused && !cl.shares_undefined && cl.leaf.has_value(), "hf16 canonical coinbase built");
    r.blob.tree_root = pb::tree_root_fold(cl.leaf.value(), std::span<const pb::Hash32>(r.branch));
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

    // ---- p + give_author_bp: > 10000 refused (BAN before RandomX); == 10000 exact ----
    {
        const pb::Hash32 au = id_of(0xA0);
        auto entry_of = [](const pb::ReceiptBodyV3& b, std::uint64_t work, std::uint64_t pos) {
            pb::WinEntry e;
            e.miner = b.side.payee;
            e.owner = b.side.owner;
            e.work = work;
            e.p = b.side.fee_rate_bp;
            e.give_author_bp = b.side.give_author_bp;
            e.position = pos;
            e.id = id_of(pos);
            return e;
        };
        auto weights_sum = [](const pb::Window& win) {
            pb::Work tot;
            for (const auto& [id, wt] : win.weight) tot += wt;
            return tot;
        };
        // the leaf a receipt commits when its coinbase pays split(R, win).
        auto split_leaf_of = [&](const pb::ReceiptBodyV3& b, const pb::Window& win) {
            const auto outs_b = pb::split(b.reward_total, win);
            const auto extra_b = pb::canonical_tx_extra_hf16(b.blob.prev_id, b.extra_nonce, mm);
            return pb::canonical_cb_leaf(outs_b, b.side.tip, b.blob.prev_id, extra_b);
        };
        auto commit = [](pb::ReceiptBodyV3& b, const pb::Hash32& leaf) {
            b.blob.tree_root = pb::tree_root_fold(leaf, std::span<const pb::Hash32>(b.branch));
        };
        struct Verdict {
            pb::AdmitVerdict v;
            bool rx;
        };
        auto admit = [&](const pb::ReceiptBodyV3& b, const pb::Window& win, std::uint8_t hf) {
            bool rx = false;
            const pb::TailResult t = pb::admit_coinbase_then_randomx(
                    pb::canonical_coinbase_ok_split(b, win, b.side.tip, b.blob.prev_id, hf, mm),
                    [&] { rx = true; return true; });
            return Verdict{t.verdict, t.randomx_called || rx};
        };
        auto ban_before_randomx = [](const Verdict& v) { return v.v == pb::AdmitVerdict::Ban && !v.rx; };
        auto admitted = [](const Verdict& v) { return v.v == pb::AdmitVerdict::AdmitCarrier && v.rx; };

        const pb::ReceiptBodyV3 honest = make_body(3, false, 0x30);
        struct Case {
            std::uint16_t p;
            std::uint16_t ga;
            bool defined;
        };
        // (a) the receipt's own entry is in the window.
        for (const Case c : {Case{5001, 5000, false}, Case{10000, 10, false}, Case{9990, 10, true}}) {
            pb::ReceiptBodyV3 x = make_body(3, true, 0x40);
            x.side.fee_rate_bp = c.p;
            x.side.give_author_bp = c.ga;
            pb::WinBin bin;
            bin.bin = 7;
            bin.entries.push_back(entry_of(honest, 1000000, 2));
            bin.entries.push_back(entry_of(x, 1000000, 1));
            const pb::Window wx = pb::window({bin}, 1000000000ull, base, /*f_spend=*/1, 3747, au);
            // the coinbase x commits: the split of its R over that window.
            const pb::Hash32 tip_x = x.side.tip, pr_x = x.blob.prev_id;
            const auto outs_x = pb::split(x.reward_total, wx);
            const auto extra_x = pb::canonical_tx_extra_hf16(pr_x, x.extra_nonce, mm);
            x.blob.tree_root = pb::tree_root_fold(pb::canonical_cb_leaf(outs_x, tip_x, pr_x, extra_x),
                                                  std::span<const pb::Hash32>(x.branch));
            bool rx = false;
            const pb::TailResult t = pb::admit_coinbase_then_randomx(
                    pb::canonical_coinbase_ok_split(x, wx, tip_x, pr_x, 16, mm), [&] { rx = true; return true; });
            if (c.defined) {
                std::uint64_t sx = 0;
                for (const auto& o : outs_x) sx += o.amount;
                check(weights_sum(wx) == wx.W && sx == x.reward_total,
                      "p + give_author_bp == 10000: weights sum to W, Sum(vout) == R");
                check(t.verdict == pb::AdmitVerdict::AdmitCarrier && rx, "p + give_author_bp == 10000 admitted");
            } else {
                check(outs_x.empty(), "window with an entry p + give_author_bp > 10000: split has no outputs");
                check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx,
                      "p + give_author_bp > 10000 -> refused, BAN before RandomX");
            }
        }

        // (b) a window of entries with defined shares (the receipt is not in its
        // own window): the receipt commits split(R, window), its canonical coinbase
        // were its shares defined.
        pb::WinBin ok_bin;
        ok_bin.bin = 7;
        ok_bin.entries.push_back(entry_of(honest, 1000000, 2));
        ok_bin.entries.push_back(entry_of(make_body(3, true, 0x50), 2000000, 3));
        const pb::Window w_ok = pb::window({ok_bin}, 1000000000ull, base, /*f_spend=*/1, 3747, au);
        check(weights_sum(w_ok) == w_ok.W && !pb::split(R, w_ok).empty(), "defined window: weights sum to W");
        for (const Case c : {Case{5001, 5000, false}, Case{10000, 10, false}, Case{10000, 1, false},
                             Case{9990, 10, true}, Case{10000, 0, true}}) {
            pb::ReceiptBodyV3 x = make_body(3, true, 0x40);
            x.side.fee_rate_bp = c.p;
            x.side.give_author_bp = c.ga;
            commit(x, split_leaf_of(x, w_ok));
            const pb::CanonLeaf clx = pb::canonical_coinbase_leaf(x, w_ok, x.side.tip, x.blob.prev_id, 16, mm);
            if (c.defined) {
                check(clx.leaf.has_value() && admitted(admit(x, w_ok, 16)),
                      "p + give_author_bp <= 10000 paying the window split -> admitted");
            } else {
                check(clx.shares_undefined && !clx.leaf.has_value(), "p + give_author_bp > 10000: no canonical leaf");
                check(ban_before_randomx(admit(x, w_ok, 16)),
                      "p + give_author_bp > 10000 paying the window split -> BAN before RandomX");
            }
        }

        // (c) no usable leaf: a tree_root folded from the zero leaf is refused for
        // undefined shares (hf 16) and for a fork-fused amount (hf 17).
        {
            pb::ReceiptBodyV3 x = make_body(3, true, 0x40);
            x.side.fee_rate_bp = 10000;
            x.side.give_author_bp = 10;
            commit(x, pb::Hash32{});
            check(ban_before_randomx(admit(x, w_ok, 16)),
                  "p + give_author_bp > 10000, tree_root from the zero leaf -> BAN before RandomX");
            pb::ReceiptBodyV3 y = make_body(3, true, 0x40);
            const pb::CanonLeaf c17 = pb::canonical_coinbase_leaf(y, w_ok, y.side.tip, y.blob.prev_id, 17, mm);
            check(c17.fork_fused && !c17.leaf.has_value(), "hf17: no canonical leaf");
            commit(y, pb::Hash32{});
            check(ban_before_randomx(admit(y, w_ok, 17)), "hf17, tree_root from the zero leaf -> BAN before RandomX");
        }

        // (d) a window holding an entry with p + give_author_bp > 10000: its weights
        // do not sum to W, split() has no outputs, and no receipt on it has a
        // canonical coinbase.
        {
            pb::ReceiptBodyV3 u = make_body(3, true, 0x60);
            u.side.fee_rate_bp = 10000;
            u.side.give_author_bp = 10;
            pb::WinBin bin;
            bin.bin = 7;
            bin.entries.push_back(entry_of(honest, 1000000, 2));
            bin.entries.push_back(entry_of(u, 1000000, 1));
            const pb::Window w_bad = pb::window({bin}, 1000000000ull, base, /*f_spend=*/1, 3747, au);
            check(!(weights_sum(w_bad) == w_bad.W), "undefined entry: window weights != W");
            check(pb::split(R, w_bad).empty(), "undefined entry: split has no outputs");
            pb::ReceiptBodyV3 h = make_body(3, false, 0x70);
            const pb::CanonLeaf clh = pb::canonical_coinbase_leaf(h, w_bad, h.side.tip, h.blob.prev_id, 16, mm);
            check(clh.shares_undefined && !clh.leaf.has_value(), "undefined window: no canonical leaf");
            commit(h, split_leaf_of(h, w_bad));
            check(ban_before_randomx(admit(h, w_bad, 16)),
                  "undefined window, tree_root from its split -> BAN before RandomX");
            commit(h, pb::Hash32{});
            check(ban_before_randomx(admit(h, w_bad, 16)),
                  "undefined window, tree_root from the zero leaf -> BAN before RandomX");
        }
    }

    return finish("v37_xmr_pathb_coinbase_kat");
}
