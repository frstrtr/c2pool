// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_pathb_coinbase_kat (pathb_coinbase_split.hpp, C07, "kept name"
// xmr_coinbase_kat -- shipped pathb-scoped because the native settle
// xmr_coinbase_kat target already exists): Sum(vout) == R = base + fees through
// the Path B coinbase (the hf-16 miner tx) on the payees of mainnet block
// 3,755,897 (R 600,000,000,000) and on a regtest vector (R 35,184,338,534,400,
// fees 0), both with a non-zero largest-remainder deficit; the canonical split
// miner tx is admitted; a wrong one is a BAN before RandomX (the RandomX stub is
// not called). The miner tx commits mm_root_of(side_data_v3) of the receipt: a
// side_data_v3 field changed after the coinbase was built is a BAN before
// RandomX on the split and the finder-only path; a side_data_v3 that does not
// encode builds nothing (BAN).
// S2.3 #2 p + give_author_bp <= 10000, the received bytes through the codec,
// the resolution, #12 and RandomX: 10000 + 1, 5001 + 5000, 10000 + 10 -> STRIKE
// at #2 (ShareSum), no fetch, no RandomX, on a window and on an empty window
// (finder-only), tip known or unknown, tree_root from the miner tx its miner
// builds or from the zero leaf; 9990 + 10 and 10000 + 0 -> admitted (tip known)
// or DEFER (tip unknown); the receipt's own entry at 9990 + 10 / 10000 + 0:
// weights sum to W, Sum(vout) == R, miner weight 0 at 10000 + 0. A window
// holding an entry above 10000 has no split and no canonical coinbase (BAN); an
// hf-17 receipt is REFUSED (Fused) with no token and RandomX not called.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/pathb_header_rules.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_miner.hpp"
#include "pathb_m2_blocks.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 id_of(std::uint64_t i) {
    pb::Hash32 h{};
    for (int b = 0; b < 8; ++b) h[31 - b] = static_cast<std::uint8_t>(i >> (8 * b));
    return h;
}

// Sum of floor(R w_i / W) over the window (no largest remainder).
static std::uint64_t floor_sum(std::uint64_t R, const std::vector<std::pair<pb::Hash32, std::uint64_t>>& wts) {
    unsigned __int128 W = 0;
    for (const auto& [id, w] : wts) W += w;
    std::uint64_t s = 0;
    for (const auto& [id, w] : wts) s += static_cast<std::uint64_t>(static_cast<unsigned __int128>(R) * w / W);
    return s;
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    const pb::XmrKeyRef author = kat_author();
    RefBook book;
    const pb::RefLookup refs = book.lookup();
    pb::KeyCache cache;
    auto check12 = [&](const pb::ReceiptBodyV3& r, const pb::Window& w, std::uint8_t hf) {
        return pb::canonical_coinbase_check(r, pb::WindowAt{&w}, r.side.tip, r.blob.prev_id, kKatHeight, hf, cache,
                                            refs, author);
    };
    auto commit = [&](pb::ReceiptBodyV3& r, const pb::Window& w) {
        return commit_miner_tx(r, w, r.side.tip, r.blob.prev_id, kKatHeight, book, author);
    };

    // ---- case 4: Sum(vout) == R through the Path B coinbase ----
    {
        // mainnet tail: the 47 payees of block 3,755,897, R 600,000,000,000.
        const m2::Block& B = m2::kBlocks[0];
        check(B.height == 3755897 && B.reward == 600000000000ull, "case 4: block 3,755,897, R 600,000,000,000");
        std::vector<std::pair<pb::Hash32, std::uint64_t>> wts;
        for (std::size_t i = 0; i < B.n_payees; ++i) {
            pb::XmrKeyRef ref;
            ref.spend = h32(B.payees[i].spend);
            ref.view = h32(B.payees[i].view);
            wts.push_back({book.add(ref), 1000003u + 7919u * i});
        }
        const pb::Window w = window_of(wts);
        pb::ReceiptBodyV3 r = make_body(3, false, 0x24);
        r.reward_total = B.reward;
        check(floor_sum(r.reward_total, wts) < r.reward_total, "case 4 mainnet: the floors sum below R (deficit > 0)");
        const pb::CanonicalTx c = pb::canonical_miner_tx(r, pb::WindowAt{&w}, r.side.tip, r.blob.prev_id, kKatHeight,
                                                         16, cache, refs, author);
        std::uint64_t s = 0;
        if (c.tx)
            for (const pb::MinerOut& o : c.tx->outs) s += o.amount;
        check(c.tx && c.tx->outs.size() == B.n_payees && s == 600000000000ull,
              "case 4 mainnet: Sum(vout) of the miner tx == R 600,000,000,000");

        // regtest: R = B(genesis) = 35,184,338,534,400, fees 0.
        const std::uint64_t R = pb::base_reward_at(17592186044415ull, 16);
        check(R == 35184338534400ull, "case 4 regtest: R 35,184,338,534,400");
        std::vector<std::pair<pb::Hash32, std::uint64_t>> wr;
        for (std::uint8_t i = 0; i < 3; ++i) wr.push_back({book.add(key_ref(static_cast<std::uint8_t>(0xA0 + i))), 1u << i});
        const pb::Window w_reg = window_of(wr);
        pb::ReceiptBodyV3 q = make_body(3, false, 0x25);
        q.reward_total = R;
        check(floor_sum(R, wr) < R, "case 4 regtest: the floors sum below R (deficit > 0)");
        const pb::CanonicalTx cr = pb::canonical_miner_tx(q, pb::WindowAt{&w_reg}, q.side.tip, q.blob.prev_id,
                                                          kKatHeight, 16, cache, refs, author);
        std::uint64_t sr = 0;
        if (cr.tx)
            for (const pb::MinerOut& o : cr.tx->outs) sr += o.amount;
        check(cr.tx && sr == R, "case 4 regtest: Sum(vout) of the miner tx == R");
    }

    // mainnet-tail split vector: base = 6e11, fees 5e9 -> R = 605e9.
    const std::uint64_t base = 600000000000ull, fees = 5000000000ull, R = base + fees;
    pb::Window w;
    for (std::uint64_t i = 1; i <= 32; ++i) { w.weight[id_of(i)] = pb::Work(1000 * i); w.W += pb::Work(1000 * i); }
    {
        const auto outs = pb::split(R, w);
        std::uint64_t s = 0;
        for (const auto& o : outs) s += o.amount;
        check(s == R, "Sum(vout) == R = base + fees (mainnet tail)");
    }

    // a window over referenced payees.
    std::vector<std::pair<pb::Hash32, std::uint64_t>> wts;
    for (std::uint64_t i = 1; i <= 32; ++i) wts.push_back({book.add(key_ref(static_cast<std::uint8_t>(i))), 1000 * i});
    const pb::Window wk = window_of(wts);

    // the canonical split miner tx is admitted (tree_root folds to its tx hash).
    pb::ReceiptBodyV3 r = make_body(/*depth=*/3, /*with_owner=*/false, 0x20);
    r.reward_total = R;
    check(commit(r, wk), "the miner builds the canonical split miner tx");
    {
        const pb::CanonicalTx c = pb::canonical_miner_tx(r, pb::WindowAt{&wk}, r.side.tip, r.blob.prev_id, kKatHeight,
                                                         16, cache, refs, author);
        const pb::Hash32 own_mm = pb::mm_root_of(r.side).value_or(pb::Hash32{});
        check(c.tx && c.tx->extra.size() == 74 && std::equal(own_mm.begin(), own_mm.end(), c.tx->extra.begin() + 42),
              "canonical miner tx commits mm_root_of(side_data_v3) in tx_extra 0x03");
    }
    check(check12(r, wk, 16) == pb::CoinbaseCheck::Match, "canonical split miner tx: Match");

    // the admission runs #12 strictly before RandomX; a correct coinbase lets it run.
    {
        bool rx = false;
        const pb::TailResult t =
                pb::admit_coinbase_then_randomx(check12(r, wk, 16), [&] { rx = true; return true; });
        check(t.verdict == pb::AdmitVerdict::AdmitCarrier && t.randomx_called && rx,
              "correct coinbase -> RandomX runs after #12");
    }

    // a WRONG split (tampered tree_root) -> BAN before RandomX (not called).
    {
        pb::ReceiptBodyV3 bad = r;
        bad.blob.tree_root = seq32(0xFF);
        check(check12(bad, wk, 16) == pb::CoinbaseCheck::Mismatch, "wrong split: Mismatch");
        bool rx = false;
        const pb::TailResult t =
                pb::admit_coinbase_then_randomx(check12(bad, wk, 16), [&] { rx = true; return true; });
        check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx, "wrong split -> BAN, no RandomX");
    }

    // a coinbase that claims R' != R (over/under) -> another miner tx -> Mismatch.
    {
        pb::ReceiptBodyV3 bad = r;
        bad.reward_total = R + 1;
        check(check12(bad, wk, 16) == pb::CoinbaseCheck::Mismatch, "R' != R -> Mismatch");
    }

    // ---- side_data_v3 committed through mm_root on the split path ----
    {
        pb::ReceiptBodyV3 o = make_body(3, /*with_owner=*/true, 0x21);
        o.reward_total = R;
        commit(o, wk);
        check(check12(o, wk, 16) == pb::CoinbaseCheck::Match, "side with owner committed: split Match");
        auto changed = [&](void (*mutate)(pb::SideDataV3&), const char* what) {
            pb::ReceiptBodyV3 bad = o;
            mutate(bad.side);
            check(pb::mm_root_of(bad.side).has_value(), std::string(what) + " (side_data_v3 still encodes)");
            bool rx = false;
            const pb::TailResult t =
                    pb::admit_coinbase_then_randomx(check12(bad, wk, 16), [&] { rx = true; return true; });
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

    // ---- side_data_v3 that does not encode: Undefined; a miner tx committing a
    // zero mm_root -> BAN before RandomX ----
    auto zero_mm_tx_hash = [&](const pb::ReceiptBodyV3& b, const pb::Window& win) {
        std::vector<pb::MinerPayee> payees;
        if (win.weight.empty()) {
            payees.push_back(pb::MinerPayee{b.payee, b.reward_total});
        } else {
            for (const pb::SplitOutput& o : pb::hf16_outputs(b.reward_total, win))
                payees.push_back(pb::MinerPayee{book.refs.at(o.payee), o.amount});
        }
        const std::optional<pb::MinerTx> t = pb::build_miner_tx_hf16(b.side.pool_id, b.side.tip, b.blob.prev_id,
                                                                     kKatHeight, payees, b.extra_nonce, pb::Hash32{});
        return t ? t->tx_hash : pb::Hash32{};
    };
    {
        pb::ReceiptBodyV3 bad = make_body(3, false, 0x22);
        bad.reward_total = R;
        bad.side.owner = seq32(0x21);  // owner identity with fee_rate_bp 0
        check(!pb::mm_root_of(bad.side).has_value(), "owner with fee_rate_bp 0: side_data_v3 does not encode");
        check(check12(bad, wk, 16) == pb::CoinbaseCheck::Undefined, "split: side_data_v3 does not encode -> Undefined");
        bad.blob.tree_root = pb::tree_root_fold(zero_mm_tx_hash(bad, wk), std::span<const pb::Hash32>(bad.branch));
        bool rx = false;
        const pb::TailResult t =
                pb::admit_coinbase_then_randomx(check12(bad, wk, 16), [&] { rx = true; return true; });
        check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx,
              "split: side_data_v3 does not encode -> BAN before RandomX");
    }

    // ---- finder-only path (empty window): one output of R with mm_root_of(side_data_v3) ----
    {
        const pb::Window wf;
        pb::ReceiptBodyV3 f = make_body(3, /*with_owner=*/true, 0x23);
        f.reward_total = R;
        commit(f, wf);
        check(check12(f, wf, 16) == pb::CoinbaseCheck::Match, "finder-only canonical miner tx: Match");
        {
            pb::ReceiptBodyV3 bad = f;
            bad.side.receipts_root[0] ^= 0x01;
            bool rx = false;
            const pb::TailResult t =
                    pb::admit_coinbase_then_randomx(check12(bad, wf, 16), [&] { rx = true; return true; });
            check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx,
                  "finder-only: side_data_v3 changed -> BAN before RandomX");
        }
        {
            pb::ReceiptBodyV3 bad = f;
            bad.side.fee_rate_bp = 0;  // owner identity with fee_rate_bp 0
            check(!pb::mm_root_of(bad.side).has_value(), "finder-only: side_data_v3 does not encode");
            check(check12(bad, wf, 16) == pb::CoinbaseCheck::Undefined, "finder-only: Undefined");
            bad.blob.tree_root = pb::tree_root_fold(zero_mm_tx_hash(bad, wf), std::span<const pb::Hash32>(bad.branch));
            bool rx = false;
            const pb::TailResult t =
                    pb::admit_coinbase_then_randomx(check12(bad, wf, 16), [&] { rx = true; return true; });
            check(t.verdict == pb::AdmitVerdict::Ban && !t.randomx_called && !rx,
                  "finder-only: side_data_v3 does not encode -> BAN before RandomX");
        }
    }

    // ---- p + give_author_bp (S2.3 #2): above 10000 a STRIKE at #2, decided by the
    // codec before the resolution (#3 DEFER + fetch) and before RandomX; 10000
    // exactly is valid (miner weight 0) ----
    {
        const pb::Hash32 au = pb::key_ref_identity(author);
        auto entry_of = [&](const pb::ReceiptBodyV3& b, std::uint64_t work, std::uint64_t pos) {
            book.add(b.payee);
            if (b.owner) book.add(*b.owner);
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
        auto commit_hash = [](pb::ReceiptBodyV3& b, const pb::Hash32& tx_hash) {
            b.blob.tree_root = pb::tree_root_fold(tx_hash, std::span<const pb::Hash32>(b.branch));
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
        // the tx hash of the miner tx the receipt's miner builds: one output of R
        // on an empty window, else hf16_outputs(R, win); PBX1 extra with the
        // receipt's own mm_root.
        auto miner_tx_hash_of = [&](const pb::ReceiptBodyV3& b, const pb::Window& win) {
            std::vector<pb::MinerPayee> payees;
            if (win.weight.empty()) {
                payees.push_back(pb::MinerPayee{b.payee, b.reward_total});
            } else {
                for (const pb::SplitOutput& o : pb::hf16_outputs(b.reward_total, win))
                    payees.push_back(pb::MinerPayee{o.payee == au ? author : book.refs.at(o.payee), o.amount});
            }
            const std::optional<pb::MinerTx> t = pb::build_miner_tx_hf16(
                    b.side.pool_id, b.side.tip, b.blob.prev_id, kKatHeight, payees, b.extra_nonce, raw_mm_of(b));
            return t ? t->tx_hash : pb::Hash32{};
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
            const pb::TailResult t = pb::admit_coinbase_then_randomx(check12(got, win, 16),
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
            const pb::TailResult t = pb::admit_coinbase_then_randomx(check12(b, win, hf), [&] { rx = true; return true; });
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
        // window (finder-only); the receipt commits the miner tx its miner builds;
        // the tip known (Ready) or unknown (DEFER + fetch).
        pb::WinBin ok_bin;
        ok_bin.bin = 7;
        ok_bin.entries.push_back(entry_of(honest, 1000000, 2));
        ok_bin.entries.push_back(entry_of(make_body(3, true, 0x50), 2000000, 3));
        const pb::Window w_ok = pb::window({ok_bin}, 1000000000ull, base, /*f_spend=*/1, 3747, au);
        check(weights_sum(w_ok) == w_ok.W && !pb::split(R, w_ok).empty(), "valid window: weights sum to W");
        const pb::Window wf;
        for (const Case c : cases) {
            for (const pb::Window* win : {&w_ok, &wf}) {
                pb::ReceiptBodyV3 x = make_body(3, true, 0x40);
                x.side.fee_rate_bp = c.p;
                x.side.give_author_bp = c.ga;
                commit_hash(x, miner_tx_hash_of(x, *win));
                const std::string tag = std::string(win == &wf ? "empty window (finder-only)" : "window") + ", p "
                                        + std::to_string(c.p) + " + give_author_bp " + std::to_string(c.ga);
                if (c.valid) {
                    const pb::CanonicalTx cx = pb::canonical_miner_tx(x, pb::WindowAt{win}, x.side.tip,
                                                                      x.blob.prev_id, kKatHeight, 16, cache, refs,
                                                                      author);
                    check(cx.tx && cx.tx->tx_hash == miner_tx_hash_of(x, *win) && pb::mm_root_of(x.side) == raw_mm_of(x),
                          tag + ": the canonical miner tx is the one its miner builds");
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
            commit_hash(x, pb::Hash32{});
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
            commit_hash(x, miner_tx_hash_of(x, wx));
            const Path pa = receive(x, wx, pb::Resolve::Ready);
            check(pa.v == pb::AdmitVerdict::AdmitCarrier && pa.rx, tag + ": admitted");
        }

        // (c) hf 17: Fused -> REFUSE, no token, no ban, RandomX not called.
        {
            pb::ReceiptBodyV3 y = make_body(3, true, 0x40);
            const pb::CanonicalTx c17 = pb::canonical_miner_tx(y, pb::WindowAt{&w_ok}, y.side.tip, y.blob.prev_id,
                                                               kKatHeight, 17, cache, refs, author);
            check(c17.stop == pb::CoinbaseCheck::Fused && !c17.tx.has_value(), "hf17: Fused, no miner tx");
            commit_hash(y, pb::Hash32{});
            const Verdict v = admit(y, w_ok, 17);
            check(v.v == pb::AdmitVerdict::Refuse && !v.rx && pb::strike_tokens(v.v) == 0,
                  "hf17 -> REFUSE, no token, RandomX not called");
        }

        // (d) a window holding an entry with p + give_author_bp > 10000: its weights
        // do not sum to W, split() has no outputs, and no receipt on it has a
        // canonical coinbase (Undefined, BAN).
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
            check(check12(h, w_bad, 16) == pb::CoinbaseCheck::Undefined, "undefined window: Undefined");
            commit_hash(h, pb::Hash32{});
            check(ban_before_randomx(admit(h, w_bad, 16)),
                  "undefined window, tree_root from the zero leaf -> BAN before RandomX");
        }
    }

    return finish("v37_xmr_pathb_coinbase_kat");
}
