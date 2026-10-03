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
//   M12 the DROPS due (A5): a DROPS-only miner is paid on-chain from the
//       ledger due, a J = 0 share miner never goes negative (the clamp writes
//       the rest off), conservation holds; M12b: a builder that omits or
//       doubles the due is a MISMATCH on every node.
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
#include "c2pool/v37/xmr/xmr_drops_wiring.hpp"   // M13 (A3): lane_enrollment_ex
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
// SPEND-COST FLOOR (payout-threshold.md §2-§3), as the daemon runs it; M7 turns it on.
bool g_spend_floor = false;
std::uint64_t g_cap_at = 0; std::uint32_t g_cap = 0;
long long g_seed_scale = 1;   // M10b: the seeded old balances times this (a pool with no cash to spare)
bool g_no_seeds = false;   // M7b: a fresh pool, no seeded owed balances
// M7c: THE DRAIN RULE (rulings R1/R2/R5 2026-10-02) on every node and builder,
// lane blocks g_hstep Monero heights apart (dh), the lane height in the ledger.
o2::DrainRule g_drain{};
std::uint64_t g_hstep = 1;
std::uint64_t mheight(std::uint64_t h) { return 3000000 + h * g_hstep; }
std::uint64_t g_reorg_at = 0;
std::uint64_t g_decay_h = 0, g_decay_hl = 0;   // M10: dust decay horizon / half-life (bins); 0 = the lane's
bool g_anchor = false;                          // M11: the ANCHOR rule (pay-now / E_b at the ledger's anchor)
// M12: the DROPS-due rule (handoff A5): each canonical lane block deposits a
// DROPS delta (g_deposit) into the ledger due and claims the whole avail.
bool g_drops_due = false;
std::function<std::map<::v37::bytes32, long long>(std::uint64_t)> g_deposit;
std::set<std::uint64_t> g_due_omit, g_due_double;   // M12b: builders that omit / double the due
// M13 (handoff A3): raindrop enrolment. g_compose composes a node's DROPS
// deposit (and, where the rule exists, enrol_add) from ITS ledger at the
// booking point; g_late_node never learns a deposit payee's ref out of band
// (a late joiner: it never saw the payee's raindrops).
bool g_raindrop_enrol = false;
int g_late_node = -1;
// M12/M13 under the DROPS WINDOW rule (handoff A4b, ruling 2026-10-01): the
// daemon turns it on with the due; DROPS work is window weight (g_window /
// EnrolOut::win), split with the anchor's payees in every lane block of its
// window, never a deposit. Rehearsal geometry: W 60 positions (6 lane blocks
// of 10), the canonical decay tables, rw 1, work_lz 62 (work == lane weight).
bool g_drops_window = false;
const st::DropsWindowRule kRehearsalWindow{60, 2160, 4096, 1, 62};
std::function<st::DropsWindow(std::uint64_t)> g_window;
using EnrolAdd = std::map<::v37::bytes32, std::pair<std::uint64_t, ::v37::ScriptRef>>;   // key -> (eff, ref)
struct EnrolOut { Amounts deposit; EnrolAdd add; st::DropsWindow win; };
std::function<EnrolOut(const st::OwedLedger&, std::uint64_t)> g_compose;
std::uint64_t g_leave_at = 0;                   // M10: tiny miners with an even index stop mining after this height   // M9: a lane block at this height is booked by nodes 0 and 1, then reorged out   // M8: the block at g_cap_at is built with this output cap

struct LaneWorld {
    std::vector<Payee> miners;                    // m0..m5 (+ tiny miners, M7)
    std::size_t n_big = 6;                        // miners[n_big..] are tiny: E_b below c
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
            if (g_leave_at && h > g_leave_at && i >= n_big && i % 2 == 0) continue;   // M10: gone
            st::WeightedPayee w; w.key = miners[i].id; w.pay = miners[i].ref;
            const bool tiny = i >= n_big;
            w.weight = tiny ? ::v37::U256(1 + (h + i * 7) % 30)                          // a few CPU hashes
                            : ::v37::U256((1 + (h * 7 + i * 3) % 5) * (n_big < miners.size() ? 1000000ull : 1ull));
            v.push_back(w);
        }
        std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.key < b.key; });
        return v;
    }
    cr::CreditCut cut_at(std::uint64_t h) const { cr::CreditCut c; c.next_pos = 100 + 10 * h; c.spine_digest[0] = static_cast<std::uint8_t>(h); c.spine_digest[1] = 0x5c; return c; }
};
::v37::bytes32 the_tag() { ::v37::bytes32 t{}; t[0] = 0xC2; t[31] = 0x37; return t; }   // the pool_id of this rig
cr::PoolField the_field() { return cr::PoolField{the_tag(), 1, 1}; }                         // RULES RATCHET: V37P v2 (epoch 1 of 1)

// The payees pay-now pays at height h on ledger L: the block's own cut, or,
// under the ANCHOR rule, the view at L's anchor (the cut of the latest lane
// block finalized into L; none = nobody).
std::vector<st::WeightedPayee> paynow_view(const LaneWorld& W, const st::OwedLedger& L, std::uint64_t h) {
    if (!g_anchor) return W.view_at(h);
    const auto a = L.anchor_cut();
    if (!a) return {};
    return W.view_at((a->next_pos - 100) / 10);   // cut_at(h).next_pos == 100 + 10 h
}

// DROPS WINDOW: the split input at the anchor, the anchor's payees plus the
// ledger's window weight there (main fold_credit / the source's pay-now).
std::vector<st::WeightedPayee> win_input(const st::OwedLedger& L, const std::vector<st::WeightedPayee>& pv) {
    const auto a = L.anchor_cut();
    if (!g_drops_window || !a) return pv;
    return L.drops_window_merge(pv, a->next_pos);
}

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
    const auto md = akat::miner(mheight(h), 300000, kAgc);
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
    ctx.spend_floor = g_spend_floor;
    ctx.has_credit_cut = true; ctx.credit_cut = W.cut_at(h);
    ctx.has_pool_field = true; ctx.pool_field = the_field();   // RULES RATCHET: the V37P v2 head
    ctx.has_paynow = true; ctx.paynow_payees = paynow_view(W, L, h);
    ctx.drain = g_drain;   // M7c: THE DRAIN RULE
    std::string why;
    auto src = o2::XmrOwedSettlementSource::build(L, owed_pay_of, ctx, subsidy + fees, &why);
    if (!src) { out.why = "source: " + why; return out; }
    asm_::AssemblyInputs a;
    a.miner = md; a.mempool = mempool;
    for (int pass = 0; src->drain_on() && pass < 4; ++pass) {   // THE DRAIN RULE: the provider's final-reward fixpoint
        asm_::AssemblyInputs p = a;
        p.settle = o2::assembly_settle_inputs(*src, true);
        p.extra_nonce_tail = src->extra_nonce_tail(); p.extra_nonce_head = src->extra_nonce_head();
        auto t0 = asm_::XmrBlockAssembler::build(p, &why);
        if (!t0 || t0->reward() == src->reward_hint()) break;
        src = o2::XmrOwedSettlementSource::build(L, owed_pay_of, ctx, t0->reward(), &why);
        if (!src) { out.why = "source (fixpoint): " + why; return out; }
    }
    a.settle = o2::assembly_settle_inputs(*src, true);
    if (g_cap_at && h == g_cap_at) a.settle.output_cap = g_cap;   // M8: a claimed-full builder
    a.extra_nonce_tail = src->extra_nonce_tail();
    a.extra_nonce_head = src->extra_nonce_head();   // RULES RATCHET: the V37P v2 head
    if (mutate) {   // a MODIFIED builder: tails re-derived from its edited inputs
        mutate(a.settle);
        std::vector<std::uint8_t> t;
        std::uint64_t B = 0;
        for (const auto& f : a.settle.fixed) B += f.amount;
        for (const auto& e : a.settle.owed) B += e.owed;
        auto app = [&](const std::vector<std::uint8_t>& v) { t.insert(t.end(), v.begin(), v.end()); };
        app(pn::encode_tail(B));
        app(fee::encode_donation_owed_tail(x6::fold_identity_owed(a.settle)));
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
    std::map<::v37::bytes32, ::v37::ScriptRef> local;           // out-of-band refs: used by neither pass
    std::vector<st::OwedLedger> history;                         // ledger before booking each height (for a lagging builder)
    bool late = false;                                           // M13: a late joiner (no out-of-band deposit refs)
    void note() { const auto d = L.owed_digest(); if (ring.empty() || !(ring.back() == d)) ring.push_back(d); }
};

struct Booked { rc::Verdict v = rc::Verdict::Undecidable; std::string why; Amounts credit, payout; bool decoded = false;
                Amounts gross, claimed, writeoff, deposit;      // M12: E' before the net, the due claimed / written off, D_B
                EnrolAdd enrol_add;                             // M13: the payees this booking enrolled by raindrop
                st::DropsWindow window;
                std::set<::v37::bytes32> gross_keys; };                // THE DRAIN RULE: G_b                      // DROPS WINDOW: the booking's window entries                          // M13: the payees this booking enrolled by raindrop

// What book_from_chain_ex does with one lane block on one node.
Booked book(Node& n, const Block& b, const LaneWorld& W, std::uint64_t h, const std::string& bid) {
    Booked r;
    std::vector<::v37::bytes32> cands(n.ring.rbegin(), n.ring.rend());   // newest first, live at 0
    // BOOKING MAP (main_v37_xmr.cpp decode_blob): outputs map only through the
    // booked refs and the refs of the block's own cut, never n.local.
    std::map<::v37::bytes32, ::v37::ScriptRef> resolve = n.booked;
    const auto pv = paynow_view(W, n.L, h);                              // ANCHOR: the payees pay-now paid
    for (const auto& w : pv) resolve[w.key] = w.pay;                     // REJOIN-PAYEE: the block's credit cut
#if defined(C2POOL_XMR_RAINDROP_ENROL)
    for (const auto& [k, rec] : n.L.drops_enrol_registry()) resolve.emplace(k, rec.ref);   // A3 (a): registry refs map outputs
#endif
    std::vector<::v37::bytes32> keys;
    for (const auto& [k, v] : resolve) { (void)v; keys.push_back(k); }
    const ::v37::bytes32 tag = the_tag();
    const auto bk = auth::decode_lane_coinbase_fee(b.blob, kChain, cands, keys, pay_of_map(resolve), kNet, &tag);
    if (!bk.ok) { r.why = "decode: " + bk.why; return r; }
    r.decoded = true;
    rc::LaneInputs li;
    li.chain_id = kChain; li.h_min = 0; li.owed_cap = 2700; li.wire_cap = 2700;
    li.residual_sink = fee::donation_ref(kNet); li.residual_sink_identity = fee::donation_identity(kNet);
    li.fixed = {fee::donation_marker(kNet)}; li.pool_field = the_field();
    li.kfair_salted_ties = true;
    li.spend_floor = g_spend_floor;
    li.drain = g_drain;   // M7c
    rc::CutInputs ci; ci.has_view = true; ci.payees = pv;
    const auto res = rc::verify_lane_coinbase(b.blob, bk, n.L, pay_of_map(n.booked), li, ci);
    r.v = res.verdict; r.why = res.why;
    n.history.push_back(n.L);
    if (res.verdict == rc::Verdict::Mismatch) {
        r.payout = bk.payout;                                           // DEBITED, credit DROPPED
    } else if (res.verdict == rc::Verdict::Canonical) {
        // THE DRAIN RULE (D7): the window is booked at P, where the canonical coinbase split it
        r.credit = fold(res.drain_on ? res.split_at : bk.total, win_input(n.L, pv));   // DROPS WINDOW: + the window at the anchor
        if (g_drops_due) {   // M12 (A5): claim the whole avail BEFORE the redistribution, as paynow_net does
            r.claimed = n.L.drops_available();
            st::apply_drops_due(r.credit, r.claimed, &r.writeoff);
            if (g_deposit) r.deposit = g_deposit(h);
            if (g_compose) { EnrolOut e = g_compose(n.L, h); r.deposit = e.deposit; r.enrol_add = e.add; r.window = e.win; }   // M13
            if (g_window) r.window = g_window(h);
            if (g_drops_window) r.deposit.clear();   // DROPS WINDOW: window weight, never a deposit
        }
        for (const auto& [k, v] : r.credit) if (v > 0) r.gross_keys.insert(k);   // THE DRAIN RULE: G_b, before the redistribution
        for (const auto& [k, d] : res.credit_delta) {   // SPEND-COST FLOOR: the redistribution
            r.credit[k] += d;
            if (r.credit[k] == 0) r.credit.erase(k);
        }
        r.gross = r.credit;
        r.payout = bk.payout;
        const auto nb = pn::net_booking(bk.paynow_base, bk.total, r.credit, r.payout, bk.sink_total,
                                        fee::donation_identity(kNet), static_cast<long long>(fee::kDonationMarkerPico),
                                        g_spend_floor);
        if (!nb.ok) { r.v = rc::Verdict::Undecidable; r.why = nb.why; return r; }
    } else {
        return r;
    }
    std::optional<st::AnchorCut> cut;   // ANCHOR: a canonical block's own cut is the next anchor
    if (g_anchor && res.verdict == rc::Verdict::Canonical) { cut = st::AnchorCut{}; cut->next_pos = W.cut_at(h).next_pos; cut->spine = W.cut_at(h).spine_digest; }
    std::optional<st::DropsFound> df;   // M12: canonical bookings only (a debit-only block claims and deposits nothing)
    if (g_drops_due && res.verdict == rc::Verdict::Canonical) {
        df = st::DropsFound{}; df->deposit = r.deposit; df->claim = true; df->claimed = r.claimed; df->writeoff = r.writeoff;
        df->window = r.window;   // DROPS WINDOW
#if defined(C2POOL_XMR_RAINDROP_ENROL)
        for (const auto& [k, e] : r.enrol_add) df->enrol_add[k] = st::DropsEnrolRec{e.first, e.second};   // M13 (A3)
#endif
    }
    st::LaneFound lf; lf.height = mheight(h); lf.gross = r.gross_keys;   // THE DRAIN RULE (ignored with the rules off)
    n.L.on_block_found(bid, r.credit, r.payout, cut, df ? &*df : nullptr, &lf);
    n.note();
    if (!n.late)   // M13: a late joiner never saw the deposit payee's raindrop (drop_ref_of is node-local)
        for (const auto& [k, v] : r.deposit) { (void)v; if (W.universe.count(k)) n.booked[k] = W.universe.at(k); }   // BOOKED REFS: the deposit payees
    if (!n.late)   // DROPS WINDOW: the window payees, as note_booked_refs teaches the composition's payees
        for (const auto& [ck, v] : r.window) { (void)v; if (W.universe.count(ck.payee)) n.booked[ck.payee] = W.universe.at(ck.payee); }
#if defined(C2POOL_XMR_RAINDROP_ENROL)
    if (!n.late)   // the late joiner keeps NO registry ref in its booked map: its recompute resolves X from the ledger alone
        for (const auto& [k, rec] : n.L.drops_enrol_registry()) n.booked[k] = rec.ref;   // A3 (a): note_booked_refs teaches the registry refs
#endif
    for (const auto& w : pv) n.booked[w.key] = w.pay;                   // BOOKED refs, after success
    for (const auto& [k, v] : bk.payout) { (void)v; if (resolve.count(k)) n.booked[k] = resolve.at(k); }
    return r;
}

struct Run {
    std::size_t canonical = 0, mismatch = 0, other = 0, split_heights = 0, verdict_splits = 0;
    std::set<std::uint64_t> mismatch_at;
    std::map<::v37::bytes32, long long> credited, paid, eb_gross;   // per identity (node 0 / on-chain / E_b at each cut)
    long long donation_paid = 0;
    std::uint64_t donation_outputs = 0;   // blocks whose LAST output is the donation output (any amount)
    std::uint64_t blocks = 0;
    std::uint64_t min_payout = ~std::uint64_t{0}, min_floor = ~std::uint64_t{0};   // smallest non-donation output / smallest c seen
    std::size_t below_floor = 0;                                                     // outputs below their own block's c
    std::size_t reorg_booked = 0;                                                    // M9: bookings of the reorged-out block
    std::vector<Node> nodes;
    std::map<::v37::bytes32, long long> gross, claimed, writeoff, deposited;   // M12 (node 0)
    std::size_t neg_seen = 0;                                                   // M12: finalW < 0 on any node at any height
    std::size_t late_noncanon = 0;                                              // M13: blocks the late joiner did not find CANONICAL
    std::map<::v37::bytes32, std::uint64_t> enrolled_at;                        // M13: eff of each raindrop enrolment (node 0)
    std::map<::v37::bytes32, long long> windowed;                               // DROPS WINDOW: work booked into the window (node 0)
    std::size_t win_max = 0;                                                    // DROPS WINDOW: the largest committed window (node 0)
    std::vector<long long> F_at;                                                // M7c: SUM max(0, EffectiveOwed) on node 0 after each height
};

// Simulate H heights with builders rotating over the nodes. `lag_at`: the
// builder at that height builds from its ledger BEFORE booking the tip (h-1).
// `overpay_at`: the builder adds `overpay` to key `victim`'s owed take.
Run simulate(const LaneWorld& W, std::uint64_t H, std::set<std::uint64_t> lag_at = {},
             std::set<std::uint64_t> overpay_at = {}, ::v37::bytes32 victim = {}, long long overpay = 0,
             std::optional<Payee> oob_ref_on_node2 = std::nullopt) {
    Run run;
    run.nodes.resize(3);
    if (g_spend_floor) {   // the daemon's XMR ledger rules come with the floor (payout-threshold.md §6, §6a)
        st::OwedLedgerRules rules;
        rules.arm_floor = static_cast<long long>(x6::spend_floor(x6::kTailSubsidy));
        rules.rotate_on_payment = true;
        const ::v37::LaneParams lp{};
        rules.decay_horizon = g_decay_h ? g_decay_h : ::c2pool::v37n::xmr::kXmrDustDecayHorizonHeights;     // as the daemon sets them
        rules.decay_half_life = g_decay_hl ? g_decay_hl : ::c2pool::v37n::xmr::kXmrDustDecayHalfLifeHeights;
        rules.anchor_cut = g_anchor;
        rules.merkle_rows = g_anchor;   // the daemon turns both on together (§13 light-client proofs)
        rules.drops_due = g_drops_due;  // M12: the daemon turns it on with the anchor (DROPS gate on)
#if defined(C2POOL_XMR_RAINDROP_ENROL)
        rules.raindrop_enrol = g_raindrop_enrol;   // M13: the daemon turns it on with the due
#endif
        if (g_drops_window) rules.drops_window = kRehearsalWindow;   // A4b: the daemon turns it on with the due
        rules.lane_height = rules.decay_from_gross = g_drain.on();   // THE DRAIN RULE's ledger bits
        for (auto& n : run.nodes) n.L = st::OwedLedger(kChain, rules);
    }
    if (g_late_node >= 0) run.nodes[static_cast<std::size_t>(g_late_node)].late = true;
    for (auto& n : run.nodes) {
        for (std::size_t i = 0; i < (g_no_seeds ? 0 : W.seeded.size()); ++i) {
            const std::string bid = "seed-" + std::to_string(i);
            n.L.on_block_found(bid, Amounts{{W.seeded[i].id, W.seed_amount[i] * g_seed_scale}}, {});
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
        if (h == g_reorg_at) {
            // M9: a competing lane block at h. Nodes 0 and 1 book it; node 2 saw
            // the other branch first and never does. It is then reorged out
            // (pre-settle) on 0 and 1, and the loop below books the winner.
            Node& other = run.nodes[(h + 1) % 3];
            const Block ob = build(other.L, pay_of_map(other.booked), W, h);
            if (ob.ok) {
                const std::string obid = "orphan-" + std::to_string(h);
                for (std::size_t i = 0; i < 2; ++i) {
                    const Booked r = book(run.nodes[i], ob, W, h, obid);
                    if (r.v == rc::Verdict::Canonical) ++run.reorg_booked;
                }
                for (std::size_t i = 0; i < 2; ++i) { run.nodes[i].L.on_block_orphaned(obid, {}); run.nodes[i].note(); }
            }
        }
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
            if (g_drops_window && (g_due_omit.count(h) || g_due_double.count(h))) {   // M12b (window): omit / double the DROPS payees
                std::set<::v37::bytes32> dk;
                for (const auto& [ck, v] : bl.drops_window()) if (v > 0) dk.insert(ck.payee);
                const bool dbl = g_due_double.count(h) != 0;
                mut = [dk, dbl](x6::CoinbaseInputs& in) {
                    auto orig = in.paynow_at;
                    in.paynow_at = [orig, dk, dbl](std::uint64_t budget) {
                        std::vector<x6::PayNowEntry> out;
                        for (auto e : orig(budget)) {
                            if (dk.count(e.identity)) { if (!dbl) continue; e.eb *= 2; }
                            out.push_back(e);
                        }
                        return out;
                    };
                };
            } else if (g_due_omit.count(h) || g_due_double.count(h)) {   // M12b: a builder that omits / doubles the due
                const auto av = bl.drops_available();
                const bool dbl = g_due_double.count(h) != 0;
                mut = [av, dbl](x6::CoinbaseInputs& in) {
                    auto orig = in.paynow_at;
                    in.paynow_at = [orig, av, dbl](std::uint64_t budget) {
                        std::vector<x6::PayNowEntry> out;
                        for (auto e : orig(budget)) {
                            const auto a = av.find(e.identity);
                            if (a != av.end() && a->second > 0) {
                                const long long v = static_cast<long long>(e.eb) + (dbl ? a->second : -a->second);
                                if (v <= 0) continue;
                                e.eb = static_cast<std::uint64_t>(v);
                            }
                            out.push_back(e);
                        }
                        return out;
                    };
                };
            }
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
                    for (const auto& [k, c] : r.gross) run.gross[k] += c;
                    for (const auto& [k, c] : r.claimed) run.claimed[k] += c;
                    for (const auto& [k, c] : r.writeoff) run.writeoff[k] += c;
                    for (const auto& [k, c] : r.deposit) run.deposited[k] += c;
                    for (const auto& [k, e] : r.enrol_add) run.enrolled_at.emplace(k, e.first);
                    for (const auto& [ck, w] : r.window) run.windowed[ck.payee] += w;
                }
                if (static_cast<int>(i) == g_late_node && r.v != rc::Verdict::Canonical) {
                    ++run.late_noncanon;
                    if (run.late_noncanon <= 2) std::printf("    h=%llu late node%zu %s: %s\n", (unsigned long long)h, i, rc::to_string(r.v), r.why.substr(0, 160).c_str());
                }
                if (i != 0 && r.v != *v0) {
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
                    for (const auto& [k, v] : fold(bk.total, win_input(run.nodes[0].history.back(), paynow_view(W, run.nodes[0].history.back(), h)))) run.eb_gross[k] += v;
                std::uint64_t don = 0;
                for (std::size_t o = 0; o < bk.out_identity.size(); ++o) if (bk.out_identity[o] == fee::donation_identity(kNet)) don += bk.out_amount[o];
                run.donation_paid += static_cast<long long>(don);
                if (bk.ok && !bk.out_identity.empty() && bk.out_identity.back() == fee::donation_identity(kNet)) ++run.donation_outputs;
                for (std::size_t o = 0; o < bk.out_identity.size(); ++o)
                    if (!(bk.out_identity[o] == fee::donation_identity(kNet))) {
                        run.min_payout = std::min(run.min_payout, bk.out_amount[o]);
                        if (bk.out_amount[o] < x6::spend_floor(bk.total)) ++run.below_floor;
                    }
                run.min_floor = std::min(run.min_floor, x6::spend_floor(bk.total));
            }
        }
        // FINALIZE(h - D) at bin h on every node (the synced order: book(h) -> FINALIZE(h - D))
        if (h > kD) {
            const auto it = bid_at.find(h - kD);
            if (it != bid_at.end())
                for (auto& n : run.nodes) { n.L.on_block_finalized(it->second, h); n.note(); }
        }
        for (const auto& n : run.nodes)
            for (const auto& [k, v] : n.L.finalW()) { (void)k; if (v < 0) ++run.neg_seen; }
        run.win_max = std::max(run.win_max, run.nodes[0].L.drops_window().size());
        {   long long F = 0; for (const auto& [k, v] : run.nodes[0].L.effective_owed_all()) { (void)k; if (v > 0) F += v; } run.F_at.push_back(F); }
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
    CHECK(r.donation_outputs == H,
          "the MAINNET donation output is the last output of every block (%llu of %llu; %lld piconero)",
          (unsigned long long)r.donation_outputs, (unsigned long long)H, r.donation_paid);
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

void m6_thief_pays_local_ref() {
    std::printf("== M6. a modified builder pays a ref only one node knows ==\n");
    LaneWorld W;
    const Payee ghost = payee(91);   // owed on every node; its ref known to node 2 only (its own payee, say)
    W.universe[ghost.id] = ghost.ref;
    Run r = simulate(W, 20, {}, {9}, ghost.id, 40000000000ll, ghost);
    CHECK(r.verdict_splits == 0 && r.split_heights == 0,
          "every node books h=9 the same way: outputs map only through refs every node holds at the booking point");
    CHECK(r.mismatch == 0 && r.other == 1, "h=9 pays an output no booked or cut ref maps: refused on every node, ledger untouched (other=%zu)", r.other);
    CHECK(eo(r, ghost.id) == 50000000000ll, "the ghost's owed balance is untouched by a block the pool never booked (owed %lld)", eo(r, ghost.id));
}

void m7_spend_floor() {
    std::printf("== M7. the spend-cost floor with many tiny miners ==\n");
    g_spend_floor = true;
    LaneWorld W;
    for (int i = 0; i < 40; ++i) {                                   // 40 tiny miners: E_b far below c
        const Payee p = payee(static_cast<std::uint8_t>(120 + i));
        W.miners.push_back(p); W.universe[p.id] = p.ref;
    }
    const std::uint64_t H = 48;
    Run r = simulate(W, H);
    g_spend_floor = false;
    CHECK(r.blocks == H && r.canonical == H && r.mismatch == 0 && r.other == 0,
          "every one of %llu lane blocks is CANONICAL on every node (canonical=%zu mismatch=%zu other=%zu)",
          (unsigned long long)H, r.canonical, r.mismatch, r.other);
    CHECK(r.verdict_splits == 0 && r.split_heights == 0, "one verdict and one owed_digest on all three nodes, every height");
    CHECK(r.min_payout < r.min_floor, "the block has room, so dust outputs below c are paid (smallest payout %llu < c %llu)",
          (unsigned long long)r.min_payout, (unsigned long long)r.min_floor);
    bool exact = true, bounded = true;
    long long tiny_paid = 0, tiny_bal = 0, big_bal = 0;
    for (const auto& [k, eb] : r.eb_gross) {
        const long long paid = r.paid.count(k) ? r.paid.at(k) : 0;
        const long long bal = eo(r, k);
        if (eb - paid != bal) exact = false;
        bool tiny = false;
        for (std::size_t i = W.n_big; i < W.miners.size(); ++i) if (W.miners[i].id == k) tiny = true;
        if (tiny) { tiny_paid += paid; tiny_bal += bal; if (bal < 0 || bal > eb / 2) bounded = false; }
        else big_bal += bal;
    }
    CHECK(exact, "every key: E_b credited - paid on chain == its ledger balance (nothing lost, nothing invented)");
    bool none_negative = true;
    for (const auto& [k, eb] : r.eb_gross) { (void)eb; if (eo(r, k) < 0) none_negative = false; }
    CHECK(none_negative, "no balance is negative: nobody is ever paid ahead of its work (no advance)");
    CHECK(bounded, "while the seeded float is repaid, a tiny miner is paid the same fraction of its E_b as everyone "
                   "(its balance stays under half of what it earned)");
    CHECK(tiny_paid > 0, "tiny miners are paid: %lld piconero reached them through the owed pass", tiny_paid);
    long long seeds_now = 0, seeds_then = 0;
    for (std::size_t i = 0; i < W.seeded.size(); ++i) { seeds_now += eo(r, W.seeded[i].id); seeds_then += W.seed_amount[i]; }
    const long long total = tiny_bal + big_bal + seeds_now;
    CHECK(total >= seeds_then && total - seeds_then <= static_cast<long long>(H),
          "the ledger does not grow: total owed %lld == the seeded float %lld (+ at most 1 piconero marker per block); "
          "the seeds moved to the miners (%lld), tiny crumbs %lld",
          total, seeds_then, big_bal, tiny_bal);
}


// M7c (B7): THE DRAIN RULE on three nodes. Its claim "a canonical block
// creates no new balance" holds under three stated preconditions (amendment
// A3), each KATted: (iii) seeds do create owed -- the 1.04 XMR float -- and
// the drain pays it to 0 within ceil(F / (R * min(dh, 64) / 256)) blocks and
// it stays 0; (ii) a DROPS due with the window rule OFF creates owed through
// its claim, which the drain pays back once the deposits stop; (i) the empty-
// cut finder is v37_xmr_coinbase_recompute_kat R19.
void m7c_drain() {
    std::printf("== M7c. THE DRAIN RULE: the seeded 1.04 XMR float reaches 0 and stays 0; A3 preconditions ==\n");
    g_spend_floor = true; g_drain = o2::DrainRule{1, 16, 64}; g_hstep = 64;   // a lane block every 64 Monero heights: R/4 each
    LaneWorld W;
    for (int i = 0; i < 40; ++i) { const Payee p = payee(static_cast<std::uint8_t>(120 + i)); W.miners.push_back(p); W.universe[p.id] = p.ref; }
    const std::uint64_t H = 24;
    Run r = simulate(W, H);
    CHECK(r.blocks == H && r.canonical == H && r.mismatch == 0 && r.other == 0 && r.verdict_splits == 0 && r.split_heights == 0,
          "(iii) every one of %llu drain blocks is CANONICAL on every node, one owed_digest per height (canonical=%zu)",
          (unsigned long long)H, r.canonical);
    long long seeds = 0; for (const auto a : W.seed_amount) seeds += a;
    const auto blk = asm_::xmr_base_reward(kAgc) + 2 * 20000000ull;   // the rig's coinbase total
    const std::uint64_t bound = (static_cast<std::uint64_t>(seeds) + blk / 4 - 1) / (blk / 4);
    std::size_t zero_at = r.F_at.size();
    for (std::size_t i = 0; i < r.F_at.size(); ++i) if (r.F_at[i] == 0) { zero_at = i; break; }
    bool stays = zero_at < r.F_at.size();
    for (std::size_t i = zero_at; i < r.F_at.size(); ++i) if (r.F_at[i] != 0) stays = false;
    std::printf("    float %lld, R/4 %llu: F reaches 0 after block %zu (bound %llu blocks); F series:", seeds,
                (unsigned long long)(blk / 4), zero_at + 1, (unsigned long long)bound);
    for (std::size_t i = 0; i < r.F_at.size() && i < 10; ++i) std::printf(" %lld", r.F_at[i]);
    std::printf("\n");
    CHECK(r.F_at.size() > 0 && r.F_at[0] < seeds && zero_at + 1 <= bound && stays,
          "(iii) the seeded %lld piconero reaches 0 within ceil(F / (R/4)) = %llu blocks and stays 0 (no canonical block creates a balance)",
          seeds, (unsigned long long)bound);
    bool none = true;
    for (const auto& [k, eb] : r.eb_gross) { (void)eb; if (eo(r, k) != 0) none = false; }
    CHECK(none, "every miner, dust included, ends with no balance: each block paid its window E_b(P) in full");
    g_hstep = 1; g_drain = o2::DrainRule{}; g_spend_floor = false;

    // (ii) DROPS due with the window rule OFF: the claim adds avail to E_b, so the
    // window is short and keeps a balance; the drain pays it back after the deposits.
    g_spend_floor = true; g_anchor = true; g_drops_due = true; g_drops_window = false; g_no_seeds = true;
    g_drain = o2::DrainRule{1, 16, 64}; g_hstep = 64;
    LaneWorld W2;
    const Payee X = payee(0x5e);
    W2.universe[X.id] = X.ref;
    g_deposit = [&](std::uint64_t h) { return (h >= 6 && h <= 8) ? std::map<::v37::bytes32, long long>{{X.id, 300000000000ll}} : std::map<::v37::bytes32, long long>{}; };
    Run r2 = simulate(W2, 30);
    long long fmax = 0; for (const auto f : r2.F_at) fmax = std::max(fmax, f);
    CHECK(r2.canonical == 30 && r2.verdict_splits == 0 && r2.split_heights == 0, "(ii) 30 blocks canonical on every node, one digest");
    CHECK(fmax > 0 && !r2.F_at.empty() && r2.F_at.back() == 0,
          "(ii) a DROPS due claimed with the window rule off creates owed (F up to %lld): the stated precondition; the drain "
          "pays it back to 0 once the deposits stop (F at the end %lld)", fmax, r2.F_at.empty() ? -1 : r2.F_at.back());
    g_deposit = nullptr;
    g_hstep = 1; g_drain = o2::DrainRule{};
    g_spend_floor = false; g_anchor = false; g_drops_due = false; g_no_seeds = false;
}

void m7b_fresh_pool() {
    std::printf("== M7b. a fresh pool (no seeded debt), many tiny miners ==\n");
    g_spend_floor = true; g_no_seeds = true;
    LaneWorld W;
    for (int i = 0; i < 40; ++i) { const Payee p = payee(static_cast<std::uint8_t>(120 + i)); W.miners.push_back(p); W.universe[p.id] = p.ref; }
    Run r = simulate(W, 24);
    g_spend_floor = false; g_no_seeds = false;
    CHECK(r.canonical == 24 && r.verdict_splits == 0 && r.split_heights == 0, "all 24 blocks canonical on every node, one digest");
    long long worst = 0, total = 0;
    for (const auto& [k, eb] : r.eb_gross) { (void)eb; const long long b = eo(r, k); total += b; worst = std::max(worst, b < 0 ? -b : b); }
    CHECK(total == 0 && worst == 0,
          "every miner, dust included, is paid its E_b in the block itself: no balance is left (the donation marker is 0) "
          "(total %lld over 24 blocks, largest %lld piconero)", total, worst);
    CHECK(r.donation_paid == 0 && r.donation_outputs == 24,
          "the donation output is in all 24 blocks, as the 0-amount marker (%lld piconero)", r.donation_paid);
}

void m9_reorg() {
    std::printf("== M9. a lane block is reorged out after two of three nodes booked it ==\n");
    g_spend_floor = true;
    LaneWorld W;
    for (int i = 0; i < 40; ++i) { const Payee p = payee(static_cast<std::uint8_t>(120 + i)); W.miners.push_back(p); W.universe[p.id] = p.ref; }
    g_reorg_at = 12;
    Run r = simulate(W, 30);
    g_reorg_at = 0;
    LaneWorld W2;
    for (int i = 0; i < 40; ++i) { const Payee p = payee(static_cast<std::uint8_t>(120 + i)); W2.miners.push_back(p); W2.universe[p.id] = p.ref; }
    Run base = simulate(W2, 30);
    g_spend_floor = false;
    CHECK(r.reorg_booked == 2, "the losing block was canonical and booked on nodes 0 and 1 (%zu)", r.reorg_booked);
    CHECK(r.canonical == 30 && r.verdict_splits == 0 && r.split_heights == 0,
          "after the reorg every node books every later block the same way: one verdict, one owed_digest at every height");
    CHECK(r.nodes[0].L.owed_digest() == base.nodes[0].L.owed_digest(),
          "the final ledger equals a run where the losing block never existed (rotation, redistribution and credit all undone)");
}

void m10_decay() {
    // A8 (operator ruling 2026-09-30): a balance below c is PAID when the block
    // has room. Here every block has room, so the gone miners' dust is paid out
    // and nothing is left to decay.
    std::printf("== M10. tiny miners leave; with room, their dust is PAID (A8), nothing is lost ==\n");
    g_spend_floor = true; g_leave_at = 10; g_decay_h = 6; g_decay_hl = 3;
    LaneWorld W;
    for (int i = 0; i < 40; ++i) { const Payee p = payee(static_cast<std::uint8_t>(120 + i)); W.miners.push_back(p); W.universe[p.id] = p.ref; }
    Run r = simulate(W, 40);
    g_spend_floor = false; g_leave_at = 0; g_decay_h = g_decay_hl = 0;
    CHECK(r.canonical == 40 && r.verdict_splits == 0 && r.split_heights == 0, "all 40 blocks canonical, one verdict, one owed_digest at every height");
    long long gone_bal = 0, gone_eb = 0, gone_paid = 0;
    for (std::size_t i = W.n_big; i < W.miners.size(); i += 2) {
        const auto& k = W.miners[i].id;
        gone_bal += eo(r, k);
        gone_eb += r.eb_gross.count(k) ? r.eb_gross.at(k) : 0;
        gone_paid += r.paid.count(k) ? r.paid.at(k) : 0;
    }
    CHECK(gone_bal == 0 && gone_eb > 0 && gone_paid == gone_eb,
          "the gone miners' dust is paid in full when there is room (credited %lld, paid %lld, left %lld)", gone_eb, gone_paid, gone_bal);
    CHECK(r.nodes[0].L.decayed_total() == 0 && r.nodes[1].L.decayed_total() == 0 && r.nodes[2].L.decayed_total() == 0,
          "nothing decays: an owed balance never waits while a block has a slot for it");
    bool exact = true;
    for (std::size_t i = W.n_big; i < W.miners.size(); ++i) {
        const auto& k = W.miners[i].id;
        const long long eb = r.eb_gross.count(k) ? r.eb_gross.at(k) : 0, paid = r.paid.count(k) ? r.paid.at(k) : 0;
        if (eb - paid != eo(r, k)) exact = false;
    }
    CHECK(exact, "every tiny miner: credited - paid == balance, exactly");

    // M10b: no cash to spare (old balances 1000x the seeds take every pool in
    // the owed pass), so the gone miners' dust waits and decays, alike on
    // every node, as before.
    std::printf("== M10b. no cash to spare: their dust waits and decays alike on every node ==\n");
    g_spend_floor = true; g_leave_at = 10; g_decay_h = 6; g_decay_hl = 3; g_seed_scale = 1000;
    LaneWorld W2;
    for (int i = 0; i < 40; ++i) { const Payee p = payee(static_cast<std::uint8_t>(120 + i)); W2.miners.push_back(p); W2.universe[p.id] = p.ref; }
    Run r2 = simulate(W2, 40);
    g_spend_floor = false; g_leave_at = 0; g_decay_h = g_decay_hl = 0; g_seed_scale = 1;
    CHECK(r2.canonical == 40 && r2.verdict_splits == 0 && r2.split_heights == 0, "all 40 blocks canonical, one verdict, one owed_digest at every height");
    CHECK(r2.nodes[0].L.decayed_total() > 0 && r2.nodes[0].L.decayed_total() == r2.nodes[1].L.decayed_total() &&
          r2.nodes[1].L.decayed_total() == r2.nodes[2].L.decayed_total(),
          "the gone miners' dust decays, the same amount on every node (%lld piconero)", r2.nodes[0].L.decayed_total());
    bool none_negative = true;
    for (const auto& [k, eb] : r2.eb_gross) { (void)eb; if (eo(r2, k) < 0) none_negative = false; }
    CHECK(none_negative, "no balance is negative");
}

void m11_anchor() {
    std::printf("== M11. the ANCHOR rule: pay-now and E_b at the ledger's anchor (ruling A) ==\n");
    g_spend_floor = true; g_anchor = true;
    LaneWorld W;
    const std::uint64_t H = 30;
    Run r = simulate(W, H);
    g_anchor = false; g_spend_floor = false;
    CHECK(r.blocks == H && r.canonical == H && r.verdict_splits == 0 && r.split_heights == 0,
          "every lane block canonical on every node, one verdict, one owed_digest at every height (canonical=%zu)", r.canonical);
    const auto a = r.nodes[0].L.anchor_cut();
    CHECK(a && a->next_pos == W.cut_at(H).next_pos && a->spine == W.cut_at(H).spine_digest,
          "the anchor walked to the cut of the last finalized lane block (h=%llu, P=%llu)", (unsigned long long)H,
          a ? (unsigned long long)a->next_pos : 0ull);
    bool same_anchor = true;
    for (const auto& n : r.nodes) if (!(n.L.anchor_cut() == a)) same_anchor = false;
    CHECK(same_anchor, "every node holds the same anchor (it is in owed_digest)");
    bool never_negative = true;
    for (const auto& [k, v] : W.universe) { (void)v; if (eo(r, k) < 0) never_negative = false; }
    CHECK(never_negative, "no balance is negative");
    // the first blocks have no anchor: they credit nobody (a fresh pool's first blocks)
    long long eb = 0; for (const auto& [k, c] : r.eb_gross) { (void)k; eb += c; }
    CHECK(eb > 0, "once an anchor exists, blocks credit the miners of the window at it (E_b %lld piconero)", eb);

    std::printf("== M11b. the ANCHOR rule without the floor: exact conservation per key ==\n");
    g_anchor = true;
    LaneWorld W2;
    Run r2 = simulate(W2, 48);
    g_anchor = false;
    CHECK(r2.canonical == 48 && r2.verdict_splits == 0 && r2.split_heights == 0, "48 lane blocks canonical, one digest");
    bool conserve = true;
    for (std::size_t i = 0; i < W2.seeded.size(); ++i) {
        const long long paid = r2.paid.count(W2.seeded[i].id) ? r2.paid.at(W2.seeded[i].id) : 0;
        if (paid + eo(r2, W2.seeded[i].id) != W2.seed_amount[i]) conserve = false;
    }
    for (const auto& p : W2.miners) {
        const long long e = r2.eb_gross.count(p.id) ? r2.eb_gross.at(p.id) : 0;
        const long long paid = r2.paid.count(p.id) ? r2.paid.at(p.id) : 0;
        if (e != paid + eo(r2, p.id)) conserve = false;
    }
    CHECK(conserve, "credited (E_b at each block's anchor, and the seeds) == paid on-chain + still owed, per key");
}

// M12 (handoffs A5 + A4b): DROPS work under the WINDOW rule. Every canonical
// lane block books window entries at its own cut: +1,000,000 of work for a
// DROPS-only miner X (never in any view, so it has no share) and -20,000,000
// for share miner m1 (J = 0: its REPLACE delta is negative and larger than its
// share weight). Every lane block splits its reward over the anchor's payees
// plus the window at the anchor; a net-negative key weighs nothing.
void m12_drops_due() {
    std::printf("== M12. DROPS window (A4b): a DROPS-only miner paid on-chain in every block of its window; a J = 0 miner never negative ==\n");
    g_spend_floor = true; g_anchor = true; g_drops_due = true; g_drops_window = true;
    LaneWorld W;
    const Payee X = payee(0x5d);
    W.universe[X.id] = X.ref;
    const ::v37::bytes32 Y = W.miners[1].id;
    g_window = [&](std::uint64_t h) {
        const std::uint64_t c = W.cut_at(h).next_pos;
        return st::DropsWindow{{{c, X.id}, 1000000ll}, {{c, Y}, -20000000ll}};
    };
    const std::uint64_t H = 36;
    Run r = simulate(W, H);
    CHECK(r.blocks == H && r.canonical == H && r.mismatch == 0 && r.verdict_splits == 0 && r.split_heights == 0,
          "honest builders: every one of %llu lane blocks CANONICAL on every node (canonical=%zu mismatch=%zu), one owed_digest per height",
          (unsigned long long)H, r.canonical, r.mismatch);
    const long long xpaid = r.paid.count(X.id) ? r.paid.at(X.id) : 0;
    const long long xeb = r.eb_gross.count(X.id) ? r.eb_gross.at(X.id) : 0;
    CHECK(xpaid > 0 && xeb > 0, "the DROPS-only miner X is in the split and paid ON-CHAIN: E_b %lld, paid %lld piconero", xeb, xpaid);
    CHECK(r.neg_seen == 0, "no finalW is ever negative on any node at any height (J = 0 miner m1 included): %zu negative rows seen", r.neg_seen);
    CHECK(eo(r, Y) >= 0, "m1's net-negative window weight is clamped at zero: EffectiveOwed %lld >= 0", eo(r, Y));
    CHECK(r.win_max > 0 && r.win_max <= 2 * 7, "the committed window is bounded by W (largest %zu entries: 2 keys x <= 7 cuts)", r.win_max);
    // conservation over every key: seeds + SUM E_b == SUM paid (without the donation) + SUM owed + decayed
    const ::v37::bytes32 don = fee::donation_identity(kNet);
    long long seeds = 0, eb = 0, cl = 0, paid = 0, owed = 0, dep = 0;
    for (std::size_t i = 0; i < W.seeded.size(); ++i) seeds += W.seed_amount[i];
    for (const auto& [k, v] : r.eb_gross) { (void)k; eb += v; }
    for (const auto& [k, v] : r.claimed) { (void)k; cl += v; }
    for (const auto& [k, v] : r.paid) if (!(k == don)) paid += v;
    for (const auto& [k, v] : W.universe) { (void)v; if (!(k == don)) owed += eo(r, k); }
    for (const auto& [k, v] : r.deposited) { (void)k; dep += v; }
    const long long decayed = r.nodes[0].L.decayed_total();
    std::printf("    seeds=%lld E_b=%lld | paid=%lld owed=%lld decayed=%lld | deposited=%lld claimed=%lld due=%zu window<=%zu\n",
                seeds, eb, paid, owed, decayed, dep, cl, r.nodes[0].L.drops_due().size(), r.win_max);
    CHECK(seeds + eb == paid + owed + decayed,
          "conservation: seeds + SUM E_b (%lld) == SUM paid + SUM owed + decayed (%lld)", seeds + eb, paid + owed + decayed);
    CHECK(dep == 0 && cl == 0 && r.nodes[0].L.drops_due().empty() && r.nodes[0].L.drops_written_off() == 0,
          "never paid twice: no deposit, no claim, the due stays empty (window only)");

    std::printf("== M12b. a builder that omits or doubles the DROPS payees is a MISMATCH on every node ==\n");
    LaneWorld W2;
    W2.universe[X.id] = X.ref;
    g_window = [&](std::uint64_t h) { return st::DropsWindow{{{W2.cut_at(h).next_pos, X.id}, 1000000ll}}; };
    g_due_omit = {14}; g_due_double = {22};
    Run r2 = simulate(W2, 30);
    g_due_omit.clear(); g_due_double.clear();
    CHECK(r2.mismatch_at == (std::set<std::uint64_t>{14, 22}),
          "h=14 (DROPS omitted) and h=22 (DROPS doubled) are MISMATCH, every other block canonical (mismatch=%zu canonical=%zu)",
          r2.mismatch, r2.canonical);
    CHECK(r2.verdict_splits == 0 && r2.split_heights == 0, "one verdict per block, one owed_digest at every height");
    std::printf("    debit-only rows carried as debt (node-height samples): %zu\n", r2.neg_seen);
    g_window = nullptr;
    g_spend_floor = false; g_anchor = false; g_drops_due = false; g_drops_window = false;
}

// M13 (handoff A3): raindrop enrolment across 3 nodes. X is a raindrop-only
// miner (no share in any view) from block 3: raindrops at bins 10(h-1)+3 and
// +7 of block h's harvest range [10(h-1), 10h). Every node composes its
// deposit from ITS ledger at the booking point with the real rule
// (lane_enrollment_ex: min of the share rule, the registry, the first raindrop
// + 1): 0.001 XMR per enrolled raindrop interval. Node 2 is a LATE JOINER: it
// never saw X's raindrops, so X's ref reaches it only as ledger state.
void m13_raindrop_enrol() {
    std::printf("== M13. raindrop enrolment (A3): a raindrop-only miner enrolled and paid on-chain; node 2 a late joiner ==\n");
    g_spend_floor = true; g_anchor = true; g_drops_due = true; g_raindrop_enrol = true; g_late_node = 2;
    g_drops_window = true;   // A4b: the daemon's rule set (the raindrop work is window weight)
    LaneWorld W;
    const Payee X = payee(0x5e);
    W.universe[X.id] = X.ref;
    const auto x_bins = [](std::uint64_t h) {
        std::vector<std::uint64_t> v;
        if (h >= 3) { v.push_back(10 * (h - 1) + 3); v.push_back(10 * (h - 1) + 7); }
        return v;
    };
    g_compose = [X, x_bins](const st::OwedLedger& L, std::uint64_t h) {
        EnrolOut o;
        const auto bins = x_bins(h);
        if (bins.empty()) return o;
#if defined(C2POOL_XMR_RAINDROP_ENROL)
        namespace dw = c2pool::v37n::xmr::drops;
        const auto reg = L.drops_enrol_registry();
        const std::map<::v37::bytes32, std::uint64_t> fdb{{X.id, bins.front()}};
        const auto book = dw::lane_enrollment_ex(dw::LanePrefix{}, {}, c2pool::v37n::xmr::relay::EnrolMode::Auto, reg, fdb);
        for (const auto b : bins)   // DROPS WINDOW: each enrolled raindrop bin at its end position
            if (book.enrolled(X.id, b)) o.win[st::DropsWindowKey(std::uint64_t{101} + b, X.id)] = 1000000ll;
        if (!reg.count(X.id)) o.add[X.id] = {bins.front() + 1, X.ref};
#else
        (void)L;   // the base: enrolment needs a lane share; X has none -> never enrolled, nothing composed
#endif
        return o;
    };
    const std::uint64_t H = 36;
    Run r = simulate(W, H);
    const auto ea = r.enrolled_at.find(X.id);
    std::printf("    X enrolled at eff=%llu; canonical=%zu mismatch=%zu verdict_splits=%zu digest_split_heights=%zu late_noncanon=%zu\n",
                ea == r.enrolled_at.end() ? 0ull : (unsigned long long)ea->second, r.canonical, r.mismatch, r.verdict_splits,
                r.split_heights, r.late_noncanon);
    CHECK(ea != r.enrolled_at.end() && ea->second == 24, "X is enrolled at its first raindrop bin 23 + 1 = 24 (in [20,30) of h=3)");
    CHECK(r.blocks == H && r.canonical == H && r.mismatch == 0 && r.verdict_splits == 0 && r.split_heights == 0 && r.late_noncanon == 0,
          "every one of %llu lane blocks CANONICAL on all 3 nodes incl. the late joiner (late non-canonical %zu), 0 digest splits (%zu)",
          (unsigned long long)H, r.late_noncanon, r.split_heights);
    const long long xpaid = r.paid.count(X.id) ? r.paid.at(X.id) : 0;
    const long long xdep = r.windowed.count(X.id) ? r.windowed.at(X.id) : 0;
    CHECK(xpaid > 0 && xdep > 0, "the raindrop-only miner X is credited (window work %lld) and paid ON-CHAIN (%lld piconero)", xdep, xpaid);
    const ::v37::bytes32 don = fee::donation_identity(kNet);
    long long seeds = 0, eb = 0, cl = 0, wo = 0, paid = 0, owed = 0, dep = 0, due = 0;
    for (std::size_t i = 0; i < W.seeded.size(); ++i) seeds += W.seed_amount[i];
    for (const auto& [k, v] : r.eb_gross) { (void)k; eb += v; }
    for (const auto& [k, v] : r.claimed) { (void)k; cl += v; }
    for (const auto& [k, v] : r.writeoff) { (void)k; wo += v; }
    for (const auto& [k, v] : r.paid) if (!(k == don)) paid += v;
    for (const auto& [k, v] : W.universe) { (void)v; if (!(k == don)) owed += eo(r, k); }
    for (const auto& [k, v] : r.deposited) { (void)k; dep += v; }
    for (const auto& [k, v] : r.nodes[0].L.drops_due()) { (void)k; due += v; }
    const long long decayed = r.nodes[0].L.decayed_total();
    std::printf("    seeds=%lld E_b=%lld claimed=%lld written_off=%lld | paid=%lld owed=%lld decayed=%lld | deposited=%lld due_left=%lld\n",
                seeds, eb, cl, wo, paid, owed, decayed, dep, due);
    CHECK(seeds + eb + cl == paid + owed + wo + decayed && dep == cl + due,
          "conservation exact: seeds + E_b + claimed (%lld) == paid + owed + written_off + decayed (%lld); deposited %lld == claimed + due left %lld",
          seeds + eb + cl, paid + owed + wo + decayed, dep, cl + due);

    // M13b (addition a): X has a due from h=1 (a synthetic deposit) and its
    // enrolment record rides the first deposit block; node 2 never saw X's
    // raindrops. The base resolves X only from node-local refs: node 2 cannot
    // pay X (payable=false) and refuses every block that does.
    std::printf("== M13b. the late joiner recomputes an honest block CANONICAL from the V37G registry ref ==\n");
    LaneWorld W2;
    W2.universe[X.id] = X.ref;
    g_compose = [X, &W2](const st::OwedLedger& L, std::uint64_t h) {
        EnrolOut o;
        o.win[st::DropsWindowKey(W2.cut_at(h).next_pos, X.id)] = 1000000ll;   // DROPS WINDOW
#if defined(C2POOL_XMR_RAINDROP_ENROL)
        if (!L.drops_enrol_registry().count(X.id)) o.add[X.id] = {1, X.ref};   // X's first raindrop at bin 0
#else
        (void)L;
#endif
        return o;
    };
    Run r2 = simulate(W2, 30);
    const long long xpaid2 = r2.paid.count(X.id) ? r2.paid.at(X.id) : 0;
    std::printf("    late joiner: non-canonical=%zu of %llu; verdict_splits=%zu digest_split_heights=%zu; X paid %lld\n",
                r2.late_noncanon, (unsigned long long)r2.blocks, r2.verdict_splits, r2.split_heights, xpaid2);
    CHECK(r2.late_noncanon == 0 && r2.verdict_splits == 0 && r2.split_heights == 0 && r2.canonical == r2.blocks && xpaid2 > 0,
          "the late joiner finds every block CANONICAL (non-canonical %zu), one owed_digest (split heights %zu), X paid %lld",
          r2.late_noncanon, r2.split_heights, xpaid2);
    g_compose = nullptr; g_late_node = -1;
    g_spend_floor = false; g_anchor = false; g_drops_due = false; g_raindrop_enrol = false; g_drops_window = false;
}

void m8_claimed_full() {
    std::printf("== M8. a builder claims too few output slots ==\n");
    g_spend_floor = true;
    LaneWorld W;
    for (int i = 0; i < 6; ++i) { const Payee p = payee(static_cast<std::uint8_t>(170 + i)); W.miners.push_back(p); W.universe[p.id] = p.ref; }
    W.n_big = W.miners.size();                                    // every miner is payable: nobody is a crumb
    // h=9: the builder caps its coinbase at 4 outputs, so the payees without a
    // slot wait and their cash is advanced to the ones paid (itself among them).
    g_cap_at = 9; g_cap = 4;
    Run r = simulate(W, 20);
    g_cap_at = 0; g_spend_floor = false;
    CHECK(r.mismatch_at == std::set<std::uint64_t>{9}, "the short-capped block (h=9) is a MISMATCH on every node (%zu)", r.mismatch);
    CHECK(r.verdict_splits == 0 && r.split_heights == 0, "one verdict, one digest");
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
    c2pool::v37n::xmr::apply_network_drain(c);   // as main() does before run_live: RULES RATCHET R1, mainnet runs the drain at the R-MIN floor (16 / 64 / 1)
    XmrNodeConfig s; s.network = c2pool::v37n::xmr::MoneroNetwork::Stagenet; s.coinbase = c2pool::v37n::xmr::CoinbaseMode::V37Settlement;
    CHECK(c2pool::v37n::xmr::settlement_fee_model_refusal(s).empty(), "stagenet and regtest rigs keep running as they are");

    // O-4/O-5: every input of the recompute is a network constant on mainnet.
    using c2pool::v37n::xmr::lane_knob_refusal;
    CHECK(lane_knob_refusal(c, false, false).empty(), "mainnet with every lane knob at its default: allowed");
    { XmrNodeConfig k = c; k.d_conf = 61;
      CHECK(!lane_knob_refusal(k, false, false).empty(), "mainnet --d-conf 61: refused (moves the booking point)"); }
    { XmrNodeConfig k = c; k.settle_h_min = 1;
      CHECK(!lane_knob_refusal(k, false, false).empty(), "mainnet --settle-h-min 1: refused (the recompute rebuilds with it)"); }
    { XmrNodeConfig k = c; k.settle_output_cap = 16;
      CHECK(!lane_knob_refusal(k, false, false).empty(), "mainnet --settle-output-cap 16: refused (the recompute rebuilds with it)"); }
    CHECK(!lane_knob_refusal(c, true, false).empty(), "mainnet --recon-max-root-age: refused");
    CHECK(!lane_knob_refusal(c, false, true).empty(), "mainnet --no-book-deferral: refused");
    // LANE-RULES (K6): the regtest rigs keep every knob (D_conf 3/4/10 included); stagenet and
    // testnet keep the settlement knobs but not a D_conf below Monero's coinbase maturity.
    { XmrNodeConfig k = s; k.network = c2pool::v37n::xmr::MoneroNetwork::Regtest; k.d_conf = 4; k.settle_output_cap = 16;
      k.owed_demo_amount = 1; k.drain_q = 16; k.drain_h_cap = 64; k.drain_rule_version = 1;
      CHECK(lane_knob_refusal(k, true, true).empty(), "regtest keeps every knob for rigs (d_conf 4, output cap, demo, the drain triple)"); }
    // THE DRAIN RULE (B17): the triple is checked on every network, pinned on mainnet.
    for (const auto net : {c2pool::v37n::xmr::MoneroNetwork::Regtest, c2pool::v37n::xmr::MoneroNetwork::Stagenet,
                           c2pool::v37n::xmr::MoneroNetwork::Testnet}) {
        XmrNodeConfig k = s; k.network = net;
        k.drain_q = 16; k.drain_h_cap = 64; k.drain_rule_version = 1;
        CHECK(lane_knob_refusal(k, false, false).empty(), "K6 drain {1,16,64} on %s: accepted", c2pool::v37n::xmr::to_string(net));
        struct T { std::uint32_t v, q, cap; const char* what; };
        for (const T t : {T{0, 16, 0, "Q without the rule version (v == 0 needs Q == H_cap == 0)"},
                          T{0, 0, 64, "H_cap without the rule version"},
                          T{1, 0, 64, "version 1 with Q == 0"},
                          T{1, 16, 0, "version 1 with H_cap == 0"},
                          T{1, 16, 256, "H_cap >= Q * 16 (Delta could reach R: nobody admitted)"},
                          T{2, 16, 64, "a newer rule version than this build"}}) {
            XmrNodeConfig b = s; b.network = net; b.drain_rule_version = t.v; b.drain_q = t.q; b.drain_h_cap = t.cap;
            const std::string why = lane_knob_refusal(b, false, false);
            CHECK(!why.empty() && why.find("drain rule") != std::string::npos, "K6 drain {%u,%u,%u} on %s: refused, %s",
                  t.v, t.q, t.cap, c2pool::v37n::xmr::to_string(net), t.what);
        }
    }
    // RULES RATCHET R1 (operator rulings 2026-10-03, spec sec. 7(c)): the drain rule is constitutional and the
    // ratchet is the LAST flag day before the mainnet genesis, so mainnet runs the drain AT the R-MIN floor
    // (16 / 64 / 1) from its genesis; 0 / 0 / 0 is refused on mainnet as any other value is.
    { XmrNodeConfig k = c; k.drain_q = 16; k.drain_h_cap = 64; k.drain_rule_version = 1;
      CHECK(lane_knob_refusal(k, false, false).empty(), "K6 mainnet drain {1,16,64}: accepted (the R-MIN floor, the mainnet constant from the genesis)"); }
    { XmrNodeConfig k = c; k.drain_q = 0; k.drain_h_cap = 0; k.drain_rule_version = 0;
      CHECK(!lane_knob_refusal(k, false, false).empty(), "K6 mainnet drain {0,0,0} (master's coinbase): refused (no longer a mainnet state)"); }
    CHECK(c2pool::v37n::xmr::kMainnetDrainQ == 16 && c2pool::v37n::xmr::kMainnetDrainHCap == 64 && c2pool::v37n::xmr::kMainnetDrainRuleVersion == 1 &&
          c2pool::v37n::xmr::kLaneDrainQ == 16 && c2pool::v37n::xmr::kLaneDrainHCap == 64 && c2pool::v37n::xmr::kLaneDrainRuleVersion == 1,
          "K6 the network constants: mainnet 16/64/1 (at the R-MIN floor), the test networks 16/64/1");
    { XmrNodeConfig k = s; k.settle_output_cap = 16; k.owed_demo_amount = 1;
      CHECK(lane_knob_refusal(k, true, true).empty(), "stagenet keeps the settlement knobs (the lane-rules HELLO/pool_tag name a mismatch)"); }
    { XmrNodeConfig k = c; k.owed_demo_amount = 1;
      CHECK(!lane_knob_refusal(k, false, false).empty(), "K6 mainnet --owed-demo-amount 1: refused (seeds rows no other node has)"); }
    { XmrNodeConfig k = c; k.drain_q = 8; k.drain_h_cap = 64; k.drain_rule_version = 1;
      CHECK(!lane_knob_refusal(k, false, false).empty(), "K6 mainnet drain_q 8: refused (the drain Q is a network constant, 16)"); }
    for (const auto net : {c2pool::v37n::xmr::MoneroNetwork::Mainnet, c2pool::v37n::xmr::MoneroNetwork::Stagenet,
                           c2pool::v37n::xmr::MoneroNetwork::Testnet}) {
        XmrNodeConfig k = s; k.network = net; k.d_conf = 59;
        const std::string why = lane_knob_refusal(k, false, false);
        CHECK(!why.empty() && why.find("coinbase maturity") != std::string::npos,
              "K6 --d-conf 59 on %s: refused below the coinbase maturity (%s)", c2pool::v37n::xmr::to_string(net), why.substr(0, 48).c_str());
        k.d_conf = 3;
        CHECK(!lane_knob_refusal(k, false, false).empty(), "K6 --d-conf 3 on %s: refused", c2pool::v37n::xmr::to_string(net));
    }
    { XmrNodeConfig k = s; k.network = c2pool::v37n::xmr::MoneroNetwork::Regtest; k.d_conf = 3;
      CHECK(lane_knob_refusal(k, false, false).empty(), "K6 --d-conf 3 on regtest: accepted (the KAT rigs)"); }
    { XmrNodeConfig k = s; k.d_conf = 61;
      CHECK(lane_knob_refusal(k, false, false).empty(), "K6 --d-conf 61 on stagenet: accepted (above the floor; LANE-RULES names a mismatch)"); }
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
    m6_thief_pays_local_ref();
    m7_spend_floor();
    m7b_fresh_pool();
    m7c_drain();
    m9_reorg();
    m10_decay();
    m11_anchor();
    m12_drops_due();
    m13_raindrop_enrol();
    m8_claimed_full();
    m5_gate_and_config();
#else
    suite_base();
#endif
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
