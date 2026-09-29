// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_mainnet_rehearsal_kat -- the MAINNET settlement configuration,
// rehearsed in-process on three nodes, before any mainnet node runs it.
//
// Isolated: no daemon, no network, no RandomX, no wall clock. Every lane
// block is a REAL assembled Monero block (XmrOwedSettlementSource ->
// XmrBlockAssembler, fee model v1 with the MAINNET donation identity), and
// every node books every block the way the daemon books it:
//
//   booking point  all nodes book block h with their finalize cursor at
//                  h - 1 - D_conf (R6), then FINALIZE(h - D_conf) at bin h;
//   decode         decode_lane_coinbase_fee (coinbase authority + the
//                  donation rule), candidates = the node's own digest ring;
//   verdict        xmr_coinbase_recompute.hpp against the node's ledger and
//                  its BOOKED refs;
//   canonical      FOUND(E_b at the cut net of pay-now, payout net of pay-now)
//                  exactly as paynow_net books it;
//   mismatch       FOUND(credit = {}, payout = the gross on-chain map);
//   booked refs    learned only after the booking succeeds.
//
// Builders rotate over the three nodes. Owed seeds (lane config, identical on
// every node) keep a real owed queue alive, so blocks carry owed outputs,
// pay-now outputs and the donation output together.
//
//   M1  honest run, 3 nodes x 48 heights: every lane block is canonical on
//       every node, one owed_digest on every node at every height, exact
//       conservation per payee (credited == paid on-chain + still owed), no
//       key ever negative, and the donation paid exactly its marker.
//   M2  one lagging builder (it builds before booking the tip's lane block,
//       the #1861 H/H+1 case): that block is a MISMATCH on every node,
//       including the builder's own booking; the digests never split.
//   M3  one modified builder over-pays a known key: MISMATCH on every node;
//       the over-payment is carried as that key's debt (never forgotten) and
//       later honest blocks pay the key nothing until it is repaid.
//   M4  one node knows an extra payee ref out of band (its own relay order):
//       it never changes a verdict, the digests never split.
//   M5  the booking-point gate: a template is served only at cursor
//       T - 1 - D_conf (recon::builder_cut), and mainnet refuses
//       --coinbase v37 without --fee-model v1.
// The lane rule rehearsed includes the salted K_fair tie-break (#1867).
// ---------------------------------------------------------------------------
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/settle/xmr_coinbase.hpp"
#include "impl/xmr/template/xmr_block_assembly.hpp"
#include "c2pool/v37/xmr/xmr_coinbase_authority.hpp"
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/xmr_node_config.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_paynow.hpp"
#include "c2pool/v37/xmr/xmr_recon_ring.hpp"
#if __has_include("c2pool/v37/xmr/xmr_coinbase_recompute.hpp")
#include "c2pool/v37/xmr/xmr_coinbase_recompute.hpp"
#define RECOMPUTE_FIX 1
#else
#define RECOMPUTE_FIX 0
#endif

namespace x6   = ::v37::xmr::settle;
namespace fee  = c2pool::v37n::xmr::fee;
namespace o2   = c2pool::v37n::xmr::o2;
namespace st   = c2pool::v37n::settle;
namespace pn   = c2pool::v37n::xmr::paynow;
namespace cr   = c2pool::v37n::xmr::credit;
namespace auth = c2pool::v37n::xmr::authority;
namespace asm_ = ::c2pool::xmr::assembly;
namespace akat = ::c2pool::xmr::assembly::kat;
using Amounts = std::map<::v37::bytes32, long long>;

namespace {

int g_fail = 0, g_checks = 0;
#define CHECK(cond, ...)                                       \
    do {                                                       \
        const bool _ok = (cond);                               \
        ++g_checks;                                            \
        if (!_ok) ++g_fail;                                    \
        std::printf("  [%s] ", _ok ? "PASS" : "FAIL");         \
        std::printf(__VA_ARGS__);                              \
        std::printf("\n");                                     \
    } while (0)

constexpr fee::DonationNet kNet = fee::DonationNet::Mainnet;   // the MAINNET donation identity
constexpr std::uint32_t kChain = 0x0000ABCD;
constexpr std::uint64_t kD = 4;                                 // D_conf (mainnet: 60; the pipeline shape is the same)
constexpr std::uint64_t kAgc = 18000000000000000000ull;        // tail emission: 0.6 XMR subsidy

std::array<std::uint8_t, 32> point_of(std::uint8_t k, std::uint8_t salt) {
    ::xmr::coin::SecretKey sec{};
    sec.data()[0] = k; sec.data()[1] = salt;
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), pub.data(), 32);
    return out;
}
struct Payee { ::v37::ScriptRef ref; ::v37::bytes32 id; };
Payee payee(std::uint8_t k) {
    Payee p; p.ref = ::v37::xmr::make_xmr_std(point_of(k, 0x31), point_of(k, 0x77)); p.id = ::v37::xmr::xmr_identity_key(p.ref); return p;
}

// A payee resolver over a ref map (RAW for an unknown key: carried).
o2::PayOfFn pay_of_map(const std::map<::v37::bytes32, ::v37::ScriptRef>& m) {
    auto r = m;
    return [r](const ::v37::bytes32& k) {
        auto it = r.find(k); if (it != r.end()) return it->second;
        ::v37::ScriptRef raw; raw.kind = ::v37::ScriptKind::RAW; return raw;
    };
}

// The lane: miners whose shares are in the view at each cut, and the owed seeds.
struct LaneWorld {
    std::vector<Payee> miners;                    // m0..m5
    std::vector<Payee> seeded;                    // s0..s2: old owed balances (lane config)
    std::vector<long long> seed_amount;
    std::map<::v37::bytes32, ::v37::ScriptRef> universe;   // every ref (for decoding outputs)
    LaneWorld() {
        for (int i = 0; i < 6; ++i) miners.push_back(payee(static_cast<std::uint8_t>(10 + i)));
        for (int i = 0; i < 3; ++i) seeded.push_back(payee(static_cast<std::uint8_t>(60 + i)));
        seed_amount = {700000000000ll, 250000000000ll, 90000000000ll};   // 0.7 / 0.25 / 0.09 XMR
        for (const auto& p : miners) universe[p.id] = p.ref;
        for (const auto& p : seeded) universe[p.id] = p.ref;
        universe[fee::donation_identity(kNet)] = fee::donation_ref(kNet);
    }
    // The view at height h's cut: which miners have shares there, and their weights.
    std::vector<st::WeightedPayee> view_at(std::uint64_t h) const {
        std::vector<st::WeightedPayee> v;
        for (std::size_t i = 0; i < miners.size(); ++i) {
            if ((h + i) % 4 == 0) continue;   // not every miner is in every window
            st::WeightedPayee w; w.key = miners[i].id; w.pay = miners[i].ref;
            w.weight = ::v37::U256(1 + (h * 7 + i * 3) % 5);
            v.push_back(w);
        }
        std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.key < b.key; });
        return v;
    }
    cr::CreditCut cut_at(std::uint64_t h) const { cr::CreditCut c; c.next_pos = 100 + 10 * h; c.spine_digest[0] = static_cast<std::uint8_t>(h); c.spine_digest[1] = 0x5c; return c; }
};
::v37::bytes32 the_tag() { ::v37::bytes32 t{}; t[0] = 0xC2; t[31] = 0x37; return t; }

// E_b at the cut: fold_eb's exact split (settle::split_reward), key-aggregated.
Amounts fold(std::uint64_t reward, const std::vector<st::WeightedPayee>& wp) {
    const auto a = st::split_reward(reward, wp);
    Amounts m;
    for (std::size_t i = 0; i < wp.size(); ++i) if (a[i]) m[wp[i].key] += static_cast<long long>(a[i]);
    return m;
}

struct Block { bool ok = false; std::string why; std::vector<std::uint8_t> blob; std::uint64_t reward = 0; };

// The builder pipeline, exactly as the provider runs it (fee model v1, mainnet donation).
Block build(const st::OwedLedger& L, const o2::PayOfFn& owed_pay_of, const LaneWorld& W, std::uint64_t h,
            const std::function<void(x6::CoinbaseInputs&)>& mutate = {}) {
    Block out;
    const auto md = akat::miner(3000000 + h, 300000, kAgc);
    const std::uint64_t subsidy = asm_::xmr_base_reward(md.already_generated_coins);
    const auto mempool = akat::txs(2, 1500, 20000000);
    std::uint64_t fees = 0; for (const auto& t : mempool) fees += t.fee;
    o2::XmrCoinbaseContext ctx;
    ctx.monero_major_version = md.major_version; ctx.height = md.height;
    std::memcpy(ctx.prev_id.data(), md.prev_id.h, 32);
    ctx.base_reward = subsidy; ctx.fees = fees; ctx.chain_id = kChain;
    ctx.lane_commitment = L.owed_digest();
    ctx.residual_sink = fee::donation_ref(kNet); ctx.residual_sink_identity = fee::donation_identity(kNet);
    ctx.fixed = {fee::donation_marker(kNet)};
    ctx.h_min = 0; ctx.output_cap = 2700;
    ctx.kfair_salted_ties = true;   // mainnet: #1867 salted tie-break
    ctx.has_credit_cut = true; ctx.credit_cut = W.cut_at(h);
    ctx.has_pool_tag = true; ctx.pool_tag = the_tag();
    ctx.has_paynow = true; ctx.paynow_payees = W.view_at(h);
    std::string why;
    auto src = o2::XmrOwedSettlementSource::build(L, owed_pay_of, ctx, subsidy + fees, &why);
    if (!src) { out.why = "source: " + why; return out; }
    asm_::AssemblyInputs a;
    a.miner = md; a.mempool = mempool;
    a.settle = o2::assembly_settle_inputs(*src, true);
    a.extra_nonce_tail = src->extra_nonce_tail();
    if (mutate) {   // a MODIFIED builder: tails re-derived from its edited inputs
        mutate(a.settle);
        std::vector<std::uint8_t> t;
        std::uint64_t B = 0;
        for (const auto& f : a.settle.fixed) B += f.amount;
        for (const auto& e : a.settle.owed) B += e.owed;
        auto app = [&](const std::vector<std::uint8_t>& v) { t.insert(t.end(), v.begin(), v.end()); };
        app(pn::encode_tail(B));
        app(fee::encode_donation_owed_tail(x6::fold_identity_owed(a.settle)));
        app(cr::encode_pool_tag_field(the_tag()));
        app(cr::encode_tail(W.cut_at(h)));
        a.extra_nonce_tail = t;
    }
    a.extra_nonce_bind_size = 32;
    a.extra_nonce_bind = [](std::uint32_t en, std::uint8_t* b) { for (int i = 0; i < 32; ++i) b[i] = static_cast<std::uint8_t>(en * 5 + i); return true; };
    auto tpl = asm_::XmrBlockAssembler::build(a, &why);
    if (!tpl) { out.why = "assembler: " + why; return out; }
    asm_::BlockBytes bb;
    if (!tpl->materialize(3, bb, &why)) { out.why = "materialize: " + why; return out; }
    out.ok = true; out.blob = bb.full_blob; out.reward = tpl->reward();
    return out;
}

#if RECOMPUTE_FIX
namespace rc = c2pool::v37n::xmr::recompute;

// One node: its ledger, its digest ring, its booked refs, its local (out-of-band) refs.
struct Node {
    st::OwedLedger L{kChain};
    std::vector<::v37::bytes32> ring;                           // owed_digest history, newest last
    std::map<::v37::bytes32, ::v37::ScriptRef> booked;          // BOOKED refs (owed pass)
    std::map<::v37::bytes32, ::v37::ScriptRef> local;           // + out-of-band refs (decoding only)
    std::vector<st::OwedLedger> history;                         // ledger before booking each height (for a lagging builder)
    void note() { const auto d = L.owed_digest(); if (ring.empty() || !(ring.back() == d)) ring.push_back(d); }
};

struct Booked { rc::Verdict v = rc::Verdict::Undecidable; std::string why; Amounts credit, payout; bool decoded = false; };

// What book_from_chain_ex does with one lane block on one node.
Booked book(Node& n, const Block& b, const LaneWorld& W, std::uint64_t h, const std::string& bid) {
    Booked r;
    std::vector<::v37::bytes32> cands(n.ring.rbegin(), n.ring.rend());   // newest first, live at 0
    std::map<::v37::bytes32, ::v37::ScriptRef> resolve = n.local;
    for (const auto& [k, v] : n.booked) resolve[k] = v;
    for (const auto& w : W.view_at(h)) resolve[w.key] = w.pay;          // REJOIN-PAYEE: the block's own cut
    std::vector<::v37::bytes32> keys;
    for (const auto& [k, v] : resolve) { (void)v; keys.push_back(k); }
    const ::v37::bytes32 tag = the_tag();
    const auto bk = auth::decode_lane_coinbase_fee(b.blob, kChain, cands, keys, pay_of_map(resolve), kNet, &tag);
    if (!bk.ok) { r.why = "decode: " + bk.why; return r; }
    r.decoded = true;
    rc::LaneInputs li;
    li.chain_id = kChain; li.h_min = 0; li.owed_cap = 2700; li.wire_cap = 2700;
    li.residual_sink = fee::donation_ref(kNet); li.residual_sink_identity = fee::donation_identity(kNet);
    li.fixed = {fee::donation_marker(kNet)}; li.pool_tag = the_tag();
    li.kfair_salted_ties = true;
    rc::CutInputs ci; ci.has_view = true; ci.payees = W.view_at(h);
    const auto res = rc::verify_lane_coinbase(b.blob, bk, n.L, pay_of_map(n.booked), li, ci);
    r.v = res.verdict; r.why = res.why;
    n.history.push_back(n.L);
    if (res.verdict == rc::Verdict::Mismatch) {
        r.payout = bk.payout;                                           // DEBITED, credit DROPPED
    } else if (res.verdict == rc::Verdict::Canonical) {
        r.credit = fold(bk.total, W.view_at(h));
        r.payout = bk.payout;
        const auto nb = pn::net_booking(bk.paynow_base, bk.total, r.credit, r.payout, bk.sink_total,
                                        fee::donation_identity(kNet), static_cast<long long>(fee::kDonationDustPico));
        if (!nb.ok) { r.v = rc::Verdict::Undecidable; r.why = nb.why; return r; }
    } else {
        return r;
    }
    n.L.on_block_found(bid, r.credit, r.payout);
    n.note();
    for (const auto& w : W.view_at(h)) n.booked[w.key] = w.pay;         // BOOKED refs, after success
    for (const auto& [k, v] : bk.payout) { (void)v; if (resolve.count(k)) n.booked[k] = resolve.at(k); }
    return r;
}

struct Run {
    std::size_t canonical = 0, mismatch = 0, other = 0, split_heights = 0, verdict_splits = 0;
    std::set<std::uint64_t> mismatch_at;
    std::map<::v37::bytes32, long long> credited, paid, eb_gross;   // per identity (node 0 / on-chain / E_b at each cut)
    long long donation_paid = 0;
    std::uint64_t blocks = 0;
    std::vector<Node> nodes;
};

// Simulate H heights with builders rotating over the nodes. `lag_at`: the
// builder at that height builds from its ledger BEFORE booking the tip (h-1).
// `overpay_at`: the builder adds `overpay` to key `victim`'s owed take.
Run simulate(const LaneWorld& W, std::uint64_t H, std::set<std::uint64_t> lag_at = {},
             std::set<std::uint64_t> overpay_at = {}, ::v37::bytes32 victim = {}, long long overpay = 0,
             std::optional<Payee> oob_ref_on_node2 = std::nullopt) {
    Run run;
    run.nodes.resize(3);
    for (auto& n : run.nodes) {
        for (std::size_t i = 0; i < W.seeded.size(); ++i) {
            const std::string bid = "seed-" + std::to_string(i);
            n.L.on_block_found(bid, Amounts{{W.seeded[i].id, W.seed_amount[i]}}, {});
            n.L.on_block_finalized(bid, i + 1);
            n.booked[W.seeded[i].id] = W.seeded[i].ref;                 // a seed is lane config
        }
        n.booked[fee::donation_identity(kNet)] = fee::donation_ref(kNet);   // compiled in
        n.note();
    }
    if (oob_ref_on_node2) {
        // an owed key no booked block ever taught (a DROPS-style credit): owed on every
        // node, its ref known to node 2 only, out of band
        for (auto& n : run.nodes) {
            n.L.on_block_found("seed-oob", Amounts{{oob_ref_on_node2->id, 50000000000ll}}, {});
            n.L.on_block_finalized("seed-oob", 4);
            n.note();
        }
        run.nodes[2].local[oob_ref_on_node2->id] = oob_ref_on_node2->ref;
    }
    std::map<std::uint64_t, std::string> bid_at;
    for (std::uint64_t h = 1; h <= H + kD; ++h) {
        if (h <= H) {
            Node& builder = run.nodes[h % 3];
            const st::OwedLedger& bl = (lag_at.count(h) && builder.history.size() >= 1) ? builder.history.back() : builder.L;
            std::function<void(x6::CoinbaseInputs&)> mut;
            if (overpay_at.count(h))
                mut = [&](x6::CoinbaseInputs& in) {
                    bool found = false;
                    for (auto& e : in.owed) if (e.identity == victim) { e.owed += static_cast<std::uint64_t>(overpay); found = true; }
                    if (!found) {
                        x6::OwedEntry e; e.identity = victim; e.pay = W.universe.at(victim); e.owed = static_cast<std::uint64_t>(overpay);
                        e.first_eligible = in.owed.size(); in.owed.push_back(e);
                    }
                };
            const Block b = build(bl, pay_of_map(builder.booked), W, h, mut);
            if (!b.ok) { ++run.other; std::printf("    h=%llu build failed: %s\n", (unsigned long long)h, b.why.c_str()); continue; }
            ++run.blocks;
            const std::string bid = "lane-" + std::to_string(h);
            bid_at[h] = bid;
            std::optional<rc::Verdict> v0;
            std::string why0;
            for (std::size_t i = 0; i < run.nodes.size(); ++i) {
                const Booked r = book(run.nodes[i], b, W, h, bid);
                if (i == 0) {
                    v0 = r.v; why0 = r.why;
                    if (r.v == rc::Verdict::Canonical) ++run.canonical;
                    else if (r.v == rc::Verdict::Mismatch) { ++run.mismatch; run.mismatch_at.insert(h); }
                    else { ++run.other; std::printf("    h=%llu node0 %s: %s\n", (unsigned long long)h, rc::to_string(r.v), r.why.c_str()); }
                    for (const auto& [k, c] : r.credit) run.credited[k] += c;
                } else if (r.v != *v0) {
                    ++run.verdict_splits;
                    std::printf("    h=%llu VERDICT SPLIT node%zu %s (%s) vs node0 %s (%s)\n", (unsigned long long)h, i,
                                rc::to_string(r.v), r.why.c_str(), rc::to_string(*v0), why0.c_str());
                }
            }
            // gross on-chain payout of this block (decoded once, node-independent)
            {
                const ::v37::bytes32 tag = the_tag();
                std::vector<::v37::bytes32> keys; for (const auto& [k, v] : W.universe) { (void)v; keys.push_back(k); }
                std::vector<::v37::bytes32> cands = {run.nodes[0].history.back().owed_digest()};
                const auto bk = auth::decode_lane_coinbase_fee(b.blob, kChain, cands, keys, pay_of_map(W.universe), kNet, &tag);
                for (const auto& [k, v] : bk.payout) run.paid[k] += v;
                if (!run.mismatch_at.count(h))
                    for (const auto& [k, v] : fold(bk.total, W.view_at(h))) run.eb_gross[k] += v;
                std::uint64_t don = 0;
                for (std::size_t o = 0; o < bk.out_identity.size(); ++o) if (bk.out_identity[o] == fee::donation_identity(kNet)) don += bk.out_amount[o];
                run.donation_paid += static_cast<long long>(don);
            }
        }
        // FINALIZE(h - D) at bin h on every node (the synced order: book(h) -> FINALIZE(h - D))
        if (h > kD) {
            const auto it = bid_at.find(h - kD);
            if (it != bid_at.end())
                for (auto& n : run.nodes) { n.L.on_block_finalized(it->second, h); n.note(); }
        }
        const auto d0 = run.nodes[0].L.owed_digest();
        bool same = true;
        for (const auto& n : run.nodes) if (!(n.L.owed_digest() == d0)) same = false;
        if (!same) ++run.split_heights;
    }
    return run;
}

long long eo(const Run& r, const ::v37::bytes32& k) { return r.nodes[0].L.effective_owed(k); }

void m1_honest() {
    std::printf("== M1. honest run: mainnet config, 3 nodes, rotating builders ==\n");
    LaneWorld W;
    const std::uint64_t H = 48;
    Run r = simulate(W, H);
    CHECK(r.blocks == H && r.canonical == H && r.mismatch == 0 && r.other == 0,
          "every one of %llu lane blocks is CANONICAL on every node (canonical=%zu mismatch=%zu other=%zu)",
          (unsigned long long)H, r.canonical, r.mismatch, r.other);
    CHECK(r.verdict_splits == 0 && r.split_heights == 0, "one verdict per block and one owed_digest per height across the 3 nodes");
    // conservation, everything finalized: per key, what it was owed == paid on-chain + still owed
    bool conserve = true, never_negative = true;
    for (std::size_t i = 0; i < W.seeded.size(); ++i) {
        const long long paid = r.paid.count(W.seeded[i].id) ? r.paid.at(W.seeded[i].id) : 0;
        if (paid + eo(r, W.seeded[i].id) != W.seed_amount[i]) conserve = false;
        if (eo(r, W.seeded[i].id) < 0) never_negative = false;
        std::printf("    seed s%zu: owed %lld, paid on-chain %lld, still owed %lld\n", i, W.seed_amount[i], paid, eo(r, W.seeded[i].id));
    }
    for (const auto& p : W.miners) {
        const long long eb = r.eb_gross.count(p.id) ? r.eb_gross.at(p.id) : 0;
        const long long paid = r.paid.count(p.id) ? r.paid.at(p.id) : 0;
        if (eb != paid + eo(r, p.id)) conserve = false;
        if (eo(r, p.id) < 0) never_negative = false;
        std::printf("    miner: E_b credited %lld, paid on-chain %lld, still owed %lld\n", eb, paid, eo(r, p.id));
    }
    CHECK(conserve, "exact conservation per key: credited (E_b at every cut, and the seeds) == paid on-chain + still owed");
    CHECK(never_negative, "no key is ever left negative on an honest run");
    CHECK(eo(r, W.seeded[0].id) == 0 && eo(r, W.seeded[1].id) == 0 && eo(r, W.seeded[2].id) == 0,
          "the whole seeded owed queue (1.04 XMR, more than one block reward) was paid out through the owed pass");
    CHECK(r.donation_paid >= static_cast<long long>(H * fee::kDonationDustPico),
          "the MAINNET donation output is in every block (%lld piconero over %llu blocks)", r.donation_paid, (unsigned long long)H);
}

void m2_lagging_builder() {
    std::printf("== M2. #1861: one builder builds before booking the tip's lane block ==\n");
    LaneWorld W;
    Run r = simulate(W, 30, {17});
    CHECK(r.mismatch_at == std::set<std::uint64_t>{17}, "exactly the lagging builder's block (h=17) is a MISMATCH (%zu mismatch(es))", r.mismatch);
    CHECK(r.verdict_splits == 0 && r.split_heights == 0,
          "every node, the builder's own booking included, reaches the same verdict; the digests never split");
}

void m3_overpay() {
    std::printf("== M3. a modified builder over-pays a known key ==\n");
    LaneWorld W;
    const ::v37::bytes32 victim = W.seeded[2].id;           // s2: owed 0.09 XMR
    const long long extra = 50000000000ll;                  // +0.05 XMR beyond what it is owed
    Run r = simulate(W, 30, {}, {9}, victim, extra);
    CHECK(r.mismatch_at == std::set<std::uint64_t>{9}, "the over-paying block (h=9) is a MISMATCH on every node (%zu)", r.mismatch);
    CHECK(r.verdict_splits == 0 && r.split_heights == 0, "the digests never split");
    const long long paid = r.paid.count(victim) ? r.paid.at(victim) : 0;
    CHECK(paid + eo(r, victim) == W.seed_amount[2], "the over-payment is carried as s2's debt: paid %lld + owed %lld == seeded %lld",
          paid, eo(r, victim), W.seed_amount[2]);
    CHECK(eo(r, victim) <= 0, "later honest blocks pay s2 nothing while it is in debt (owed %lld)", eo(r, victim));
}

void m4_out_of_band_ref() {
    std::printf("== M4. one node knows an extra payee ref out of band ==\n");
    LaneWorld W;
    const Payee ghost = payee(90);   // owed on every node; its ref known to node 2 only
    W.universe[ghost.id] = ghost.ref;
    Run r = simulate(W, 20, {}, {}, {}, 0, ghost);
    CHECK(r.verdict_splits == 0 && r.split_heights == 0 && r.mismatch == 0,
          "the node with the out-of-band ref agrees with the others on every block (no split, no mismatch)");
}

void m5_gate_and_config() {
    std::printf("== M5. the booking-point gate and the mainnet configuration ==\n");
    namespace recon = c2pool::v37n::xmr::recon;
    CHECK(recon::builder_cut(1000, 60) == 939, "a template for height T is served only at finalize cursor T-1-D_conf (1000, D=60 -> 939)");
    CHECK(recon::builder_cut(10, 60) == 0, "below D_conf the booking point is the genesis cursor");
    using c2pool::v37n::xmr::XmrNodeConfig;
    XmrNodeConfig c;
    c.network = c2pool::v37n::xmr::MoneroNetwork::Mainnet;
    c.coinbase = c2pool::v37n::xmr::CoinbaseMode::V37Settlement;
    CHECK(!c2pool::v37n::xmr::settlement_fee_model_refusal(c).empty(), "mainnet --coinbase v37 without --fee-model v1: refused");
    c.lane_params.fee = ::v37::FeeModelGate::for_version(1);
    CHECK(c2pool::v37n::xmr::settlement_fee_model_refusal(c).empty(), "mainnet --coinbase v37 --fee-model v1: the configuration rehearsed here");
    XmrNodeConfig s; s.network = c2pool::v37n::xmr::MoneroNetwork::Stagenet; s.coinbase = c2pool::v37n::xmr::CoinbaseMode::V37Settlement;
    CHECK(c2pool::v37n::xmr::settlement_fee_model_refusal(s).empty(), "stagenet and regtest rigs keep running as they are");
}
#else
void suite_base() {
    std::printf("== BASE: no recompute on this tree ==\n");
    CHECK(false, "xmr_coinbase_recompute.hpp is absent: nothing to rehearse");
}
#endif

}  // namespace

int main() {
    std::printf("v37_xmr_mainnet_rehearsal_kat (%s)\n", RECOMPUTE_FIX ? "fix" : "base");
#if RECOMPUTE_FIX
    m1_honest();
    m2_lagging_builder();
    m3_overpay();
    m4_out_of_band_ref();
    m5_gate_and_config();
#else
    suite_base();
#endif
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
