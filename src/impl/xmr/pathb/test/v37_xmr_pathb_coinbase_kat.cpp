// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_pathb_coinbase_kat (pathb_coinbase_split.hpp, C07, "kept name"
// xmr_coinbase_kat -- shipped pathb-scoped because the native settle
// xmr_coinbase_kat target already exists): Sum(vout) == R = base + fees through
// the Path B coinbase on a mainnet-tail vector, the window built by window() from
// WinBins (two of three bins, owner and author shares); the canonical split
// coinbase is admitted; a wrong split is a BAN before RandomX (the RandomX stub is not called).
// The leaf commits mm_root_of(side_data_v3) of the receipt: a side_data_v3 field
// changed after the coinbase was built is a BAN before RandomX on the split and
// the finder-only path; a side_data_v3 that does not encode builds no leaf.
// S2.3 #2 p + give_author_bp <= 10000, the received bytes through the codec,
// the resolution, #12 and RandomX: 10000 + 1, 5001 + 5000, 10000 + 10 -> STRIKE
// at #2 (ShareSum), no fetch, no RandomX, on a window and on an empty window
// (finder-only), tip known or unknown, tree_root from the leaf its miner builds
// or from the zero leaf; 9990 + 10 and 10000 + 0 -> admitted (tip known) or
// DEFER (tip unknown); the receipt's own entry at 9990 + 10 / 10000 + 0: weights
// sum to W, Sum(vout) == R, miner weight 0 at 10000 + 0. A window holding an
// entry above 10000 has no split and no canonical coinbase; no leaf is built
// when the amount is fork-fused; a tree_root folded from the zero leaf is
// refused.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/pathb_header_rules.hpp"
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

int main() {
    // mainnet-tail vector: base = 6e11, fees 5e9 -> R = 605e9.
    const std::uint64_t base = 600000000000ull, fees = 5000000000ull, R = base + fees;
    // The window through window(): three bins newest first, miner i (1..32) with
    // 500 i of raw work in each; miner 32 pays owner 0x1000 at p 100 bp, miner 31
    // gives 10 bp to the author 0x2000; D_net 200,000 (COVERAGE 400,000) takes
    // the two newest bins; f_spend and N(B) of the tip (M 300k, Z 300k, hf 16).
    const pb::Hash32 cb_owner = id_of(0x1000), cb_author = id_of(0x2000);
    std::vector<pb::WinBin> cb_bins;
    for (std::uint64_t k = 0; k < 3; ++k) {
        pb::WinBin b;
        b.bin = 2000 - k;
        for (std::uint64_t i = 1; i <= 32; ++i) {
            pb::WinEntry x;
            x.miner = id_of(i);
            x.work = 500 * i;
            x.position = 900 - 40 * k - i;
            x.id = id_of(100000 + x.position);
            if (i == 32) { x.owner = cb_owner; x.p = 100; }
            if (i == 31) x.give_author_bp = 10;
            b.entries.push_back(x);
        }
        cb_bins.push_back(b);
    }
    const pb::Window w = pb::window(cb_bins, 200000, base, pb::f_spend(base, 300000, 16), pb::n_rule(300000, 16, base),
                                    cb_author);
    check(w.W == pb::Work(528000) && w.weight.size() == 34, "window(): two newest bins, W 528,000, 34 payees");
    check(weight_of(w, id_of(32)) == pb::Work(31680) && weight_of(w, cb_owner) == pb::Work(320)
                  && weight_of(w, id_of(31)) == pb::Work(30970) && weight_of(w, cb_author) == pb::Work(30)
                  && weight_of(w, id_of(1)) == pb::Work(1000),
          "window(): miner 32 31,680 + owner 320, miner 31 30,970 + author 30, miner 1 1,000");

    // Sum(vout) == R exactly through the Path B coinbase.
    const auto outs = pb::split(R, w);
    std::uint64_t s = 0;
    for (const auto& o : outs) s += o.amount;
    check(s == R, "Sum(vout) == R = base + fees (mainnet tail)");
    {
        std::uint64_t a_owner = 0, a_author = 0, a_1 = 0, a_32 = 0;
        for (const auto& o : outs) {
            if (o.payee == cb_owner) a_owner = o.amount;
            if (o.payee == cb_author) a_author = o.amount;
            if (o.payee == id_of(1)) a_1 = o.amount;
            if (o.payee == id_of(32)) a_32 = o.amount;
        }
        check(outs.size() == 34 && a_owner == 366666667ull && a_author == 34375000ull && a_1 == 1145833333ull
                      && a_32 == 36300000000ull,
              "split: owner 366,666,667, author 34,375,000, miner 1 1,145,833,333, miner 32 36,300,000,000");
    }

    // the canonical split coinbase is admitted (tree_root folds to the leaf).
    pb::ReceiptBodyV3 r = make_body(/*depth=*/3, /*with_owner=*/false, 0x20);
    r.reward_total = R;
    const pb::Hash32 tip = r.side.tip, p_r = r.blob.prev_id;
    const pb::CanonLeaf cl = pb::canonical_coinbase_leaf(r, w, tip, p_r, /*hf=*/16);
    check(!cl.fork_fused && cl.leaf.has_value(), "hf16 canonical coinbase built");
    // the leaf: split -> PBX1 tx_extra with mm_root = mm_root_of(side_data_v3) -> leaf.
    const pb::Hash32 own_mm = pb::mm_root_of(r.side).value();
    check(cl.leaf == pb::canonical_cb_leaf(outs, tip, p_r, pb::canonical_tx_extra_hf16(p_r, r.extra_nonce, own_mm)),
          "canonical split leaf commits mm_root_of(side_data_v3)");
    r.blob.tree_root = pb::tree_root_fold(cl.leaf.value(), std::span<const pb::Hash32>(r.branch));
    check(pb::canonical_coinbase_ok_split(r, w, tip, p_r, 16), "canonical split coinbase admitted");

    // the admission runs #12 strictly before RandomX; a correct coinbase lets it run.
    {
        bool rx = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(
                pb::canonical_coinbase_ok_split(r, w, tip, p_r, 16), [&] { rx = true; return true; });
        check(t.verdict == pb::AdmitVerdict::AdmitCarrier && t.randomx_called && rx,
              "correct coinbase -> RandomX runs after #12");
    }

    // a WRONG split (tampered tree_root) -> BAN before RandomX (not called).
    {
        pb::ReceiptBodyV3 bad = r;
        bad.blob.tree_root = seq32(0xFF);  // not the canonical split leaf fold
        check(!pb::canonical_coinbase_ok_split(bad, w, tip, p_r, 16), "wrong split: coinbase NOT ok");
        bool rx = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(
                pb::canonical_coinbase_ok_split(bad, w, tip, p_r, 16), [&] { rx = true; return true; });
        check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx, "wrong split -> BAN, no RandomX");
    }

    // a coinbase that claims R' != R (over/under) -> different leaf -> BAN.
    {
        pb::ReceiptBodyV3 bad = r;
        bad.reward_total = R + 1;  // over-claim
        check(!pb::canonical_coinbase_ok_split(bad, w, tip, p_r, 16), "R' != R -> coinbase NOT ok");
    }

    // ---- side_data_v3 committed through mm_root on the split path: a field
    // changed after the coinbase was built -> coinbase NOT ok -> BAN before RandomX ----
    {
        pb::ReceiptBodyV3 o = make_body(3, /*with_owner=*/true, 0x21);
        o.reward_total = R;
        const pb::Hash32 tip_o = o.side.tip, pr_o = o.blob.prev_id;
        o.blob.tree_root = pb::tree_root_fold(pb::canonical_coinbase_leaf(o, w, tip_o, pr_o, 16).leaf.value(),
                                              std::span<const pb::Hash32>(o.branch));
        check(pb::canonical_coinbase_ok_split(o, w, tip_o, pr_o, 16), "side with owner committed: split admitted");
        auto changed = [&](void (*mutate)(pb::SideDataV3&), const char* what) {
            pb::ReceiptBodyV3 bad = o;
            mutate(bad.side);
            check(pb::mm_root_of(bad.side).has_value(), std::string(what) + " (side_data_v3 still encodes)");
            bool rx = false;
            const pb::TailResult t = pb::admit_coinbase_then_randomx(
                    pb::canonical_coinbase_ok_split(bad, w, tip_o, pr_o, 16), [&] { rx = true; return true; });
            check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx, what);
        };
        changed([](pb::SideDataV3& s) { s.pool_id[0] ^= 0x01; }, "split: pool_id changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.rules_epoch ^= 0x0001; }, "split: rules_epoch changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.ballot ^= 0x0001; }, "split: ballot changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.payee[0] ^= 0x01; }, "split: payee changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.t_origin ^= 0x01; }, "split: t_origin changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.tip[0] ^= 0x01; }, "split: tip changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.receipts_root[0] ^= 0x01; },
                "split: receipts_root changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.window_root[0] ^= 0x01; },
                "split: window_root changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.mmr_root[0] ^= 0x01; }, "split: mmr_root changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.fee_rate_bp ^= 0x0001; },
                "split: fee_rate_bp changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.owner[31] ^= 0x01; }, "split: owner changed -> BAN before RandomX");
        changed([](pb::SideDataV3& s) { s.give_author_bp ^= 0x0001; },
                "split: give_author_bp changed -> BAN before RandomX");
    }

    // ---- side_data_v3 that does not encode: no leaf; a coinbase committing a
    // zero mm_root -> coinbase NOT ok -> BAN before RandomX ----
    {
        pb::ReceiptBodyV3 bad = make_body(3, false, 0x22);
        bad.reward_total = R;
        bad.side.owner = seq32(0x21);  // owner identity with fee_rate_bp 0
        check(!pb::mm_root_of(bad.side).has_value(), "owner with fee_rate_bp 0: side_data_v3 does not encode");
        const pb::Hash32 tip_b = bad.side.tip, pr_b = bad.blob.prev_id;
        const pb::CanonLeaf none = pb::canonical_coinbase_leaf(bad, w, tip_b, pr_b, 16);
        check(!none.fork_fused && !none.leaf.has_value(), "split: no canonical leaf");
        const auto zero_mm_extra = pb::canonical_tx_extra_hf16(pr_b, bad.extra_nonce, pb::Hash32{});
        bad.blob.tree_root = pb::tree_root_fold(pb::canonical_cb_leaf(outs, tip_b, pr_b, zero_mm_extra),
                                                std::span<const pb::Hash32>(bad.branch));
        bool rx = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(
                pb::canonical_coinbase_ok_split(bad, w, tip_b, pr_b, 16), [&] { rx = true; return true; });
        check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx,
              "split: side_data_v3 does not encode -> BAN before RandomX");
    }

    // ---- finder-only path (empty window): the stub leaf with mm_root_of(side_data_v3) ----
    {
        pb::Window wf;
        wf.empty_finder_only = true;
        pb::ReceiptBodyV3 f = make_body(3, /*with_owner=*/true, 0x23);
        f.reward_total = R;
        const pb::Hash32 tip_f = f.side.tip, pr_f = f.blob.prev_id;
        const pb::CanonLeaf clf = pb::canonical_coinbase_leaf(f, wf, tip_f, pr_f, 16);
        const pb::Hash32 own_leaf = pb::canonical_stub_leaf(
                R, pb::stub_output_key(tip_f, pr_f, f.side.payee), f.extra_nonce, pb::mm_root_of(f.side).value());
        check(clf.leaf == own_leaf, "finder-only leaf commits mm_root_of(side_data_v3)");
        f.blob.tree_root = pb::tree_root_fold(own_leaf, std::span<const pb::Hash32>(f.branch));
        check(pb::canonical_coinbase_ok_split(f, wf, tip_f, pr_f, 16), "finder-only canonical coinbase admitted");
        {
            pb::ReceiptBodyV3 bad = f;
            bad.side.receipts_root[0] ^= 0x01;
            bool rx = false;
            const pb::TailResult t = pb::admit_coinbase_then_randomx(
                    pb::canonical_coinbase_ok_split(bad, wf, tip_f, pr_f, 16), [&] { rx = true; return true; });
            check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx,
                  "finder-only: side_data_v3 changed -> BAN before RandomX");
        }
        {
            pb::ReceiptBodyV3 bad = f;
            bad.side.fee_rate_bp = 0;  // owner identity with fee_rate_bp 0
            check(!pb::mm_root_of(bad.side).has_value(), "finder-only: side_data_v3 does not encode");
            check(!pb::finder_only_leaf(bad, tip_f, pr_f).has_value(), "finder-only: no leaf");
            const pb::Hash32 zero_mm_leaf = pb::canonical_stub_leaf(
                    R, pb::stub_output_key(tip_f, pr_f, bad.side.payee), bad.extra_nonce, pb::Hash32{});
            bad.blob.tree_root = pb::tree_root_fold(zero_mm_leaf, std::span<const pb::Hash32>(bad.branch));
            bool rx = false;
            const pb::TailResult t = pb::admit_coinbase_then_randomx(
                    pb::canonical_coinbase_ok_split(bad, wf, tip_f, pr_f, 16), [&] { rx = true; return true; });
            check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx,
                  "finder-only: side_data_v3 does not encode -> BAN before RandomX");
        }
    }

    // ---- p + give_author_bp (S2.3 #2): above 10000 a STRIKE at #2, decided by the
    // codec before the resolution (#3 DEFER + fetch) and before RandomX; 10000
    // exactly is valid (miner weight 0) ----
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
        auto commit = [](pb::ReceiptBodyV3& b, const pb::Hash32& leaf) {
            b.blob.tree_root = pb::tree_root_fold(leaf, std::span<const pb::Hash32>(b.branch));
        };
        auto put_ga = [](std::vector<std::uint8_t>& bytes, std::size_t side_off, std::uint16_t ga) {
            bytes[side_off + pb::side_v3::kGiveAuthorOff] = static_cast<std::uint8_t>(ga & 0xff);
            bytes[side_off + pb::side_v3::kGiveAuthorOff + 1] = static_cast<std::uint8_t>(ga >> 8);
        };
        // the mm_root of a receipt's own side_data_v3 bytes, written field by field
        // (the encoder refuses p + give_author_bp > 10000).
        auto raw_mm_of = [&](const pb::ReceiptBodyV3& b) {
            pb::SideDataV3 v = b.side;
            v.give_author_bp = 0;
            std::vector<std::uint8_t> bytes;
            if (pb::encode_side_data_v3(v, bytes) != pb::WireError::None) return pb::Hash32{};  // no bytes
            put_ga(bytes, 0, b.side.give_author_bp);
            return pb::mm_root_of(bytes);
        };
        // the leaf the receipt's miner builds: the finder-only output on an empty
        // window, else split(R, win); PBX1 extra with the receipt's own mm_root.
        auto leaf_of = [&](const pb::ReceiptBodyV3& b, const pb::Window& win) {
            const pb::Hash32 mm = raw_mm_of(b);
            if (win.empty_finder_only)
                return pb::canonical_stub_leaf(b.reward_total,
                                               pb::stub_output_key(b.side.tip, b.blob.prev_id, b.side.payee),
                                               b.extra_nonce, mm);
            return pb::canonical_cb_leaf(pb::split(b.reward_total, win), b.side.tip, b.blob.prev_id,
                                         pb::canonical_tx_extra_hf16(b.blob.prev_id, b.extra_nonce, mm));
        };
        // the bytes the receipt is received as.
        auto wire_of = [&](const pb::ReceiptBodyV3& b) {
            pb::ReceiptBodyV3 v = b;
            v.side.give_author_bp = 0;
            std::vector<std::uint8_t> bytes = enc(v);
            if (bytes.empty()) return bytes;  // does not encode: received as no bytes
            put_ga(bytes, 1 + bytes[0] + pb::kExtraNonceBytes + 1 + v.branch.size() * pb::kHashBytes,
                   b.side.give_author_bp);
            return bytes;
        };
        // one received receipt in S2.3 order: codec (#1a / #1b / #2), resolution
        // (#3 / #5), #12 on win, #15 (RandomX stub).
        struct Path {
            pb::CodecHead head;
            pb::AdmitVerdict v = pb::AdmitVerdict::Strike;
            bool rx = false;
        };
        auto receive = [&](const pb::ReceiptBodyV3& b, const pb::Window& win, pb::Resolve res) {
            Path out;
            const std::vector<std::uint8_t> bytes = wire_of(b);
            pb::ReceiptBodyV3 got;
            out.head = pb::admit_codec_then_resolve(bytes.data(), bytes.size(),
                                                    pb::ReceiptLimits{pb::receipt_max(16)}, got,
                                                    [&](const pb::ReceiptBodyV3&) { return res; });
            if (out.head.verdict) {
                out.v = *out.head.verdict;
                return out;
            }
            const pb::TailResult t = pb::admit_coinbase_then_randomx(
                    pb::canonical_coinbase_ok_split(got, win, got.side.tip, got.blob.prev_id, 16),
                    [&] { out.rx = true; return true; });
            out.v = t.verdict;
            return out;
        };
        auto strike_at_2 = [](const Path& pa) {
            return pa.v == pb::AdmitVerdict::Strike && pa.head.error == pb::WireError::ShareSum
                   && pb::wire_row(pa.head.error) == pb::WireRow::Row2 && !pa.head.resolved && !pa.rx;
        };
        struct Verdict {
            pb::AdmitVerdict v;
            bool rx;
        };
        auto admit = [&](const pb::ReceiptBodyV3& b, const pb::Window& win, std::uint8_t hf) {
            bool rx = false;
            const pb::TailResult t = pb::admit_coinbase_then_randomx(
                    pb::canonical_coinbase_ok_split(b, win, b.side.tip, b.blob.prev_id, hf),
                    [&] { rx = true; return true; });
            return Verdict{t.verdict, t.randomx_called || rx};
        };
        auto ban_before_randomx = [](const Verdict& v) { return v.v == pb::AdmitVerdict::Ban && !v.rx; };

        check(pb::wire_row(pb::WireError::ShareSum) == pb::WireRow::Row2
                      && pb::wire_row(pb::WireError::FeeRateRange) == pb::WireRow::Row2
                      && pb::wire_row(pb::WireError::GiveAuthorRange) == pb::WireRow::Row2
                      && pb::wire_verdict(pb::WireError::ShareSum) == pb::AdmitVerdict::Strike
                      && pb::strike_tokens(pb::AdmitVerdict::Strike) == 1,
              "ShareSum is row #2, STRIKE, one token");

        const pb::ReceiptBodyV3 honest = make_body(3, false, 0x30);
        struct Case {
            std::uint16_t p;
            std::uint16_t ga;
            bool valid;
        };
        const Case cases[] = {Case{10000, 1, false}, Case{5001, 5000, false}, Case{10000, 10, false},
                              Case{9990, 10, true}, Case{10000, 0, true}};

        // (a) a window of valid entries (the receipt is not in it), and the empty
        // window (finder-only); the receipt commits the leaf its miner builds; the
        // tip known (Ready) or unknown (DEFER + fetch).
        pb::WinBin ok_bin;
        ok_bin.bin = 7;
        ok_bin.entries.push_back(entry_of(honest, 1000000, 2));
        ok_bin.entries.push_back(entry_of(make_body(3, true, 0x50), 2000000, 3));
        const pb::Window w_ok = pb::window({ok_bin}, 1000000000ull, base, /*f_spend=*/1, 3747, au);
        check(weights_sum(w_ok) == w_ok.W && !pb::split(R, w_ok).empty(), "valid window: weights sum to W");
        const pb::Window wf = [] {
            pb::Window v;
            v.empty_finder_only = true;
            return v;
        }();
        for (const Case c : cases) {
            for (const pb::Window* win : {&w_ok, &wf}) {
                pb::ReceiptBodyV3 x = make_body(3, true, 0x40);
                x.side.fee_rate_bp = c.p;
                x.side.give_author_bp = c.ga;
                commit(x, leaf_of(x, *win));
                const std::string tag = std::string(win == &wf ? "empty window (finder-only)" : "window") + ", p "
                                        + std::to_string(c.p) + " + give_author_bp " + std::to_string(c.ga);
                if (c.valid) {
                    const pb::CanonLeaf clx = pb::canonical_coinbase_leaf(x, *win, x.side.tip, x.blob.prev_id, 16);
                    check(clx.leaf.has_value() && clx.leaf == leaf_of(x, *win)
                                  && pb::mm_root_of(x.side) == raw_mm_of(x),
                          tag + ": the canonical leaf is the leaf its miner builds");
                }
                for (const pb::Resolve res : {pb::Resolve::Ready, pb::Resolve::DeferUnknownTip}) {
                    const Path pa = receive(x, *win, res);
                    const std::string t = tag + (res == pb::Resolve::Ready ? ", tip known" : ", tip unknown");
                    if (!c.valid)
                        check(strike_at_2(pa), t + " -> STRIKE at #2, no fetch, no RandomX");
                    else if (res == pb::Resolve::Ready)
                        check(pa.v == pb::AdmitVerdict::AdmitCarrier && pa.head.resolved && pa.rx,
                              t + " -> admitted, RandomX runs after #12");
                    else
                        check(pa.v == pb::AdmitVerdict::Defer && pa.head.resolved && !pa.rx,
                              t + " -> DEFER, no strike, no RandomX");
                }
            }
        }
        {
            pb::ReceiptBodyV3 x = make_body(3, true, 0x40);
            x.side.fee_rate_bp = 10000;
            x.side.give_author_bp = 10;
            commit(x, pb::Hash32{});
            check(strike_at_2(receive(x, w_ok, pb::Resolve::Ready)),
                  "p 10000 + give_author_bp 10, tree_root from the zero leaf -> STRIKE at #2");
        }

        // (b) the receipt's own entry in the window at p + give_author_bp == 10000:
        // the weights sum to W and Sum(vout) == R; at 10000 + 0 the miner weight is 0.
        for (const Case c : {Case{9990, 10, true}, Case{10000, 0, true}}) {
            pb::ReceiptBodyV3 x = make_body(3, true, 0x40);
            x.side.fee_rate_bp = c.p;
            x.side.give_author_bp = c.ga;
            pb::WinBin bin;
            bin.bin = 7;
            bin.entries.push_back(entry_of(honest, 1000000, 2));
            bin.entries.push_back(entry_of(x, 1000000, 1));
            const pb::Window wx = pb::window({bin}, 1000000000ull, base, /*f_spend=*/1, 3747, au);
            const auto outs_x = pb::split(x.reward_total, wx);
            std::uint64_t sx = 0;
            for (const auto& o : outs_x) sx += o.amount;
            const std::string tag = "own entry p " + std::to_string(c.p) + " + give_author_bp " + std::to_string(c.ga);
            check(weights_sum(wx) == wx.W && sx == x.reward_total, tag + ": weights sum to W, Sum(vout) == R");
            if (c.ga == 0) check(wx.weight.count(x.side.payee) == 0, tag + ": miner weight 0");
            commit(x, leaf_of(x, wx));
            const Path pa = receive(x, wx, pb::Resolve::Ready);
            check(pa.v == pb::AdmitVerdict::AdmitCarrier && pa.rx, tag + ": admitted");
        }

        // (c) a fork-fused amount (hf 17): no leaf; a tree_root folded from the zero
        // leaf -> BAN before RandomX.
        {
            pb::ReceiptBodyV3 y = make_body(3, true, 0x40);
            const pb::CanonLeaf c17 = pb::canonical_coinbase_leaf(y, w_ok, y.side.tip, y.blob.prev_id, 17);
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
            const pb::CanonLeaf clh = pb::canonical_coinbase_leaf(h, w_bad, h.side.tip, h.blob.prev_id, 16);
            check(clh.shares_undefined && !clh.leaf.has_value(), "undefined window: no canonical leaf");
            commit(h, leaf_of(h, w_bad));
            check(ban_before_randomx(admit(h, w_bad, 16)),
                  "undefined window, tree_root from its split -> BAN before RandomX");
            commit(h, pb::Hash32{});
            check(ban_before_randomx(admit(h, w_bad, 16)),
                  "undefined window, tree_root from the zero leaf -> BAN before RandomX");
        }
    }

    return finish("v37_xmr_pathb_coinbase_kat");
}
