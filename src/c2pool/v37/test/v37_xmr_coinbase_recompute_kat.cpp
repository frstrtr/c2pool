// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_coinbase_recompute_kat -- every node recomputes the lane coinbase
// (xmr_coinbase_recompute.hpp; operator rulings 2026-09-29).
//
// Every block here is a REAL assembled Monero block: the builder pipeline the
// node runs (XmrOwedSettlementSource::build -> XmrBlockAssembler, fee model v1,
// 32-byte rbind, credit cut, pool tag), materialized to bytes, decoded by the
// receiver exactly as booking decodes it (decode_lane_coinbase_fee), then
// recomputed from the RECEIVER's ledger.
//
//   R1  honest block, owed + pay-now + donation: CANONICAL.
//   R2  honest block whose builder chose its owed takes at a larger reward
//       hint than the final total (a trimmed mempool): CANONICAL (the takes
//       are rebuilt from the committed V37N base).
//   R3  empty cut: the default job (no finder) and a per-job finder (V37F):
//       CANONICAL.
//   R4  the weight-aware cap truncates the owed pass (heavy mempool):
//       CANONICAL at the cap the block's output count implies.
//   R5  #1861 H/H+1: the builder had not booked the previous lane block that
//       already paid key K, so it pays K again: MISMATCH (same owed_digest --
//       the digest commits the finalized partition only).
//   R6  a modified builder over-pays a known key: MISMATCH.
//   R7  a modified builder pays the owed queue out of K_fair order: MISMATCH.
//   R8  under-take: fewer owed takes than the K_fair pass pays at the total
//       (owed money shifted to pay-now): MISMATCH.
//   R9  pay-now to a payee set other than the cut's: MISMATCH.
//   R10 a block built on a ledger state that is not the booking point's
//       (the receiver's cursor has moved on): MISMATCH.
//   R11 the booking of a MISMATCH (ruling 2) on two receivers: payouts
//       debited, credit dropped, one owed_digest, the double pay carried as
//       a debt.
//   R12 ruling 1: --coinbase v37 on mainnet refuses without --fee-model v1.
//   R13 booked refs: a payee ref one node learned out of band never changes
//       the verdict (the fork hazard of the full resolver, shown).
//   R14 pay-now refs come from the view at the cut, not the resolver.
//   R15 #1867 salted tie-break: a raw-identity order is a mismatch.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/settle/xmr_coinbase.hpp"
#include "impl/xmr/template/xmr_block_assembly.hpp"
#include "c2pool/v37/xmr/xmr_coinbase_authority.hpp"
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_paynow.hpp"
#include "c2pool/v37/xmr/xmr_node_config.hpp"
#include "c2pool/v37/xmr/xmr_finalize_driver.hpp"   // THE DRAIN RULE: FOUND (height, G_b) through the store
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

constexpr fee::DonationNet kNet = fee::DonationNet::Regtest;
constexpr std::uint32_t kChain = 0x0000ABCD;
constexpr std::uint64_t kHeight = 3000000;
constexpr std::uint64_t kAgc = 18000000000000000000ull;   // tail emission: 0.6 XMR subsidy

std::array<std::uint8_t, 32> point_of(std::uint8_t k) {
    ::xmr::coin::SecretKey sec{};
    sec.data()[0] = k;
    sec.data()[1] = 0x5a;
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), pub.data(), 32);
    return out;
}
::v37::ScriptRef ref_of(std::uint8_t k) { return ::v37::xmr::make_xmr_std(point_of(k), point_of(static_cast<std::uint8_t>(k + 100))); }
::v37::bytes32 id_of(const ::v37::ScriptRef& r) { return ::v37::xmr::xmr_identity_key(r); }

struct Payee { ::v37::ScriptRef ref; ::v37::bytes32 id; std::uint64_t w = 1; };
Payee payee(std::uint8_t k, std::uint64_t w = 1) { Payee p; p.ref = ref_of(k); p.id = id_of(p.ref); p.w = w; return p; }

// Everything a lane shares: the payee resolver (every ref the lane taught).
struct Lane {
    std::map<::v37::bytes32, ::v37::ScriptRef> refs;
    void learn(const Payee& p) { refs[p.id] = p.ref; }
    o2::PayOfFn pay_of() const {
        auto r = refs;
        return [r](const ::v37::bytes32& k) {
            auto it = r.find(k); if (it != r.end()) return it->second;
            ::v37::ScriptRef raw; raw.kind = ::v37::ScriptKind::RAW; return raw;
        };
    }
    std::vector<::v37::bytes32> keys() const { std::vector<::v37::bytes32> v; for (const auto& [k, r] : refs) { (void)r; v.push_back(k); } return v; }
    Lane() {
        Payee d; d.ref = fee::donation_ref(kNet); d.id = fee::donation_identity(kNet);
        learn(d);
    }
};

// Seed a finalized owed row: FOUND + FINALIZE at `bin`.
int g_seed = 0;
void seed(st::OwedLedger& L, const ::v37::bytes32& k, long long amount, std::uint64_t bin) {
    const std::string bid = "seed-" + std::to_string(g_seed++);
    L.on_block_found(bid, Amounts{{k, amount}}, {});
    L.on_block_finalized(bid, bin);
}

std::vector<st::WeightedPayee> weighted(const std::vector<Payee>& ps) {
    std::vector<st::WeightedPayee> v;
    for (const auto& p : ps) { st::WeightedPayee w; w.key = p.id; w.weight = ::v37::U256(p.w); w.pay = p.ref; v.push_back(w); }
    return v;
}

cr::CreditCut the_cut() { cr::CreditCut c; c.next_pos = 4242; c.spine_digest[3] = 0x77; return c; }
::v37::bytes32 the_tag() { ::v37::bytes32 t{}; t[0] = 0xC2; t[31] = 0x37; return t; }

// The builder's knobs. Everything defaults to the honest node.
struct BuildOpts {
    std::vector<Payee> cut_payees;
    bool has_view = true;
    std::uint64_t hint_extra = 0;                    // reward_hint = subsidy + fees + this
    std::vector<::c2pool::xmr::XmrTxMempoolData> mempool = akat::txs(3, 2000, 30000000);
    std::optional<::v37::ScriptRef> finder;          // per-job empty-cut finder
    std::optional<::v37::bytes32> commit_digest;     // commit another lane_commitment (R10)
    // A modified builder: edit the X6 inputs after the honest snapshot; the
    // V37N / V37D tails are then re-derived from the edited inputs.
    std::function<void(x6::CoinbaseInputs&)> mutate;
    std::function<void(o2::XmrCoinbaseContext&)> mutate_ctx;
    // THE DRAIN RULE: an honest rule-on builder (spend floor, {1,16,64}) cuts
    // its snapshot at the template's FINAL reward (the provider's fixpoint);
    // fixpoint = false keeps the takes chosen at the first reward hint.
    bool drain = false;
    bool fixpoint = true;
    std::uint32_t cap = 2700;
};

struct Block {
    bool ok = false;
    std::string why;
    std::vector<std::uint8_t> blob;
    std::size_t n_outputs = 0;
    std::uint64_t reward = 0;
};

Block build_block(const st::OwedLedger& L, const Lane& lane, const BuildOpts& o) {
    Block out;
    const auto md = akat::miner(kHeight, 300000, kAgc);
    const std::uint64_t subsidy = asm_::xmr_base_reward(md.already_generated_coins);
    std::uint64_t fees = 0; for (const auto& t : o.mempool) fees += t.fee;
    o2::XmrCoinbaseContext ctx;
    ctx.monero_major_version = md.major_version;
    ctx.height = md.height;
    std::memcpy(ctx.prev_id.data(), md.prev_id.h, 32);
    ctx.base_reward = subsidy; ctx.fees = fees;
    ctx.chain_id = kChain;
    ctx.lane_commitment = o.commit_digest ? *o.commit_digest : L.owed_digest();
    ctx.residual_sink = fee::donation_ref(kNet); ctx.residual_sink_identity = fee::donation_identity(kNet);
    ctx.fixed = {fee::donation_marker(kNet)};
    ctx.h_min = 0; ctx.output_cap = o.cap;
    if (o.drain) { ctx.spend_floor = true; ctx.drain = o2::DrainRule{1, 16, 64}; }
    ctx.has_credit_cut = true; ctx.credit_cut = the_cut();
    ctx.has_pool_tag = true; ctx.pool_tag = the_tag();
    ctx.has_paynow = o.has_view;
    ctx.paynow_payees = weighted(o.cut_payees);
    if (o.mutate_ctx) o.mutate_ctx(ctx);
    std::string why;
    auto src = o2::XmrOwedSettlementSource::build(L, lane.pay_of(), ctx, subsidy + fees + o.hint_extra, &why);
    if (!src) { out.why = "source: " + why; return out; }
    if (o.finder) {
        auto f = src->with_finder(*o.finder, &why);
        if (!f) { out.why = "finder: " + why; return out; }
        src = std::move(f);
    }
    asm_::AssemblyInputs a;
    a.miner = md;
    a.mempool = o.mempool;
    a.wire_cap = o.cap;
    auto settle_from = [&]() {
    a.settle = o2::assembly_settle_inputs(*src, /*weight_aware_cap=*/true);
    a.extra_nonce_tail = src->extra_nonce_tail();
    if (o.mutate) {
        o.mutate(a.settle);
        // the modified builder's tails, re-derived from its edited inputs
        std::vector<std::uint8_t> t;
        if (src->ecut_finder()) t = pn::encode_finder_field(*src->ecut_finder());
        if (src->paynow_on()) {
            std::uint64_t B = 0;
            for (const auto& f : a.settle.fixed) B += f.amount;
            for (const auto& e : a.settle.owed) B += e.owed;
            const auto n = pn::encode_tail(B); t.insert(t.end(), n.begin(), n.end());
        }
        const auto d = fee::encode_donation_owed_tail(x6::fold_identity_owed(a.settle)); t.insert(t.end(), d.begin(), d.end());
        const auto p = cr::encode_pool_tag_field(the_tag()); t.insert(t.end(), p.begin(), p.end());
        const auto c = cr::encode_tail(the_cut()); t.insert(t.end(), c.begin(), c.end());
        a.extra_nonce_tail = t;
    }
    };
    settle_from();
    a.extra_nonce_bind_size = 32;
    a.extra_nonce_bind = [](std::uint32_t en, std::uint8_t* b) { for (int i = 0; i < 32; ++i) b[i] = static_cast<std::uint8_t>(en * 13 + i); return true; };
    auto t = asm_::XmrBlockAssembler::build(a, &why);
    if (!t) { out.why = "assembler: " + why; return out; }
    // THE DRAIN RULE: the provider's fixpoint (xmr_o2_settlement_provider.hpp)
    for (int pass = 0; o.fixpoint && src->drain_on() && t->reward() != src->reward_hint() && pass < 4; ++pass) {
        src = o2::XmrOwedSettlementSource::build(L, lane.pay_of(), ctx, t->reward(), &why);
        if (!src) { out.why = "source (fixpoint): " + why; return out; }
        if (o.finder) { auto f = src->with_finder(*o.finder, &why); if (!f) { out.why = "finder: " + why; return out; } src = std::move(f); }
        settle_from();
        t = asm_::XmrBlockAssembler::build(a, &why);
        if (!t) { out.why = "assembler (fixpoint): " + why; return out; }
    }
    asm_::BlockBytes b;
    if (!t->materialize(7, b, &why)) { out.why = "materialize: " + why; return out; }
    out.ok = true;
    out.blob = b.full_blob;
    out.n_outputs = t->outputs().size();
    out.reward = t->reward();
    return out;
}

#if RECOMPUTE_FIX
namespace rc = c2pool::v37n::xmr::recompute;
bool g_salted = false;   // the lane rule the receivers recompute with (#1867)
bool g_drain = false;    // THE DRAIN RULE on the receivers (spend floor + {1,16,64})
std::uint32_t g_cap = 2700;

struct Verified {
    auth::CoinbaseBooking bk;
    rc::Result r;
};

// The receiver: decode under coinbase authority (candidates = the receiver's
// ring, newest first), then recompute from ITS ledger.
Verified receive(const Block& b, const st::OwedLedger& R, const Lane& lane, const std::vector<Payee>& cut_payees,
                 std::vector<::v37::bytes32> ring = {}, bool has_view = true, const Lane* booked = nullptr) {
    Verified v;
    ring.insert(ring.begin(), R.owed_digest());
    std::vector<::v37::bytes32> keys = lane.keys();
    for (const auto& [k, e] : R.effective_owed_all()) { (void)e; keys.push_back(k); }
    const ::v37::bytes32 tag = the_tag();
    v.bk = auth::decode_lane_coinbase_fee(b.blob, kChain, ring, keys, lane.pay_of(), kNet, &tag);
    rc::LaneInputs li;
    li.chain_id = kChain; li.h_min = 0; li.owed_cap = g_cap; li.wire_cap = g_cap;
    if (g_drain) { li.spend_floor = true; li.drain = o2::DrainRule{1, 16, 64}; }
    li.residual_sink = fee::donation_ref(kNet); li.residual_sink_identity = fee::donation_identity(kNet);
    li.fixed = {fee::donation_marker(kNet)};
    li.pool_tag = the_tag();
    li.kfair_salted_ties = g_salted;
    rc::CutInputs ci; ci.has_view = has_view; ci.payees = weighted(cut_payees);
    v.r = rc::verify_lane_coinbase(b.blob, v.bk, R, (booked ? *booked : lane).pay_of(), li, ci);
    return v;
}

const char* verdict(const Verified& v) { return rc::to_string(v.r.verdict); }

// The common lane: two owed keys (K1 older than K2) and three cut payees.
struct World {
    Lane lane;
    Payee K1 = payee(21), K2 = payee(22), K3 = payee(23);
    std::vector<Payee> cut = {payee(11, 1), payee(12, 2), payee(13, 3)};
    st::OwedLedger L{kChain};
    World() {
        for (const auto& p : cut) lane.learn(p);
        lane.learn(K1); lane.learn(K2); lane.learn(K3);
        seed(L, K1.id, 40000000000ll, 10);   // 0.04 XMR, armed at 10 (oldest)
        seed(L, K2.id, 25000000000ll, 11);   // 0.025 XMR, armed at 11
    }
};

void r1_honest() {
    std::printf("== R1. honest block: owed + pay-now + donation ==\n");
    World w;
    BuildOpts o; o.cut_payees = w.cut;
    const Block b = build_block(w.L, w.lane, o);
    CHECK(b.ok, "builds: %s", b.ok ? "ok" : b.why.c_str());
    if (!b.ok) return;
    st::OwedLedger R = w.L;   // the receiver's ledger at the booking point == the builder's
    const auto v = receive(b, R, w.lane, w.cut);
    CHECK(v.bk.ok && v.bk.paynow_base.has_value(), "decodes under coinbase authority, V37N committed (base %llu)",
          v.bk.paynow_base ? (unsigned long long)*v.bk.paynow_base : 0ull);
    CHECK(v.r.canonical(), "recompute: %s (cap %u) %s", verdict(v), v.r.cap, v.r.why.c_str());
    CHECK(v.r.expected_payout.count(w.K1.id) && v.r.expected_payout.at(w.K1.id) == 40000000000ll &&
          v.r.expected_payout.count(w.K2.id) && v.r.expected_payout.at(w.K2.id) == 25000000000ll,
          "the canonical coinbase pays K1 and K2 their EffectiveOwed in full");
}

void r2_hint_above_total() {
    std::printf("== R2. owed takes chosen at a reward hint above the final total ==\n");
    World w;
    seed(w.L, w.K3.id, 900000000000ll, 12);   // 0.9 XMR owed: more than the whole reward
    BuildOpts o; o.cut_payees = w.cut; o.hint_extra = 400000000000ull;   // mempool fees the template did not keep
    const Block b = build_block(w.L, w.lane, o);
    CHECK(b.ok, "builds: %s", b.ok ? "ok" : b.why.c_str());
    if (!b.ok) return;
    st::OwedLedger R = w.L;
    const auto v = receive(b, R, w.lane, w.cut);
    const std::uint64_t took = v.bk.paynow_base ? *v.bk.paynow_base - fee::kDonationMarkerPico : 0;
    CHECK(v.bk.ok && took > b.reward, "V37N commits owed takes %llu > the block's total %llu (the builder's hint was larger)",
          (unsigned long long)took, (unsigned long long)b.reward);
    CHECK(v.r.canonical(), "recompute from the committed base: %s %s", verdict(v), v.r.why.c_str());
}

void r3_empty_cut() {
    std::printf("== R3. empty cut: default job and a per-job finder ==\n");
    World w;
    st::OwedLedger E{kChain};   // a brand-new pool: nothing owed yet
    BuildOpts o;                // the view at the cut exists but credits nobody
    const Block b0 = build_block(E, w.lane, o);
    CHECK(b0.ok, "default job builds: %s", b0.ok ? "ok" : b0.why.c_str());
    if (b0.ok) {
        const auto v = receive(b0, E, w.lane, {});
        CHECK(v.bk.ok && !v.bk.ecut_finder && v.r.canonical(), "default job (residual to the donation, no V37F): %s %s", verdict(v), v.r.why.c_str());
    }
    Payee f = payee(51);
    BuildOpts of; of.finder = f.ref;
    const Block b1 = build_block(E, w.lane, of);
    CHECK(b1.ok, "finder job builds: %s", b1.ok ? "ok" : b1.why.c_str());
    if (b1.ok) {
        const auto v = receive(b1, E, w.lane, {});
        CHECK(v.bk.ok && v.bk.ecut_finder.has_value() && v.r.canonical(), "per-job finder (V37F + V37N): %s %s", verdict(v), v.r.why.c_str());
        CHECK(v.r.expected_payout.count(f.id) && v.r.expected_payout.at(f.id) == static_cast<long long>(b1.reward - fee::kDonationMarkerPico),
              "the finder is paid the whole reward (the donation keeps only its 0-amount marker)");
    }
}

void r4_cap_binds() {
    std::printf("== R4. the weight-aware cap truncates the owed pass ==\n");
    World w;
    st::OwedLedger L{kChain};
    std::vector<Payee> many;
    for (int i = 0; i < 30; ++i) { Payee p = payee(static_cast<std::uint8_t>(120 + i)); w.lane.learn(p); many.push_back(p); seed(L, p.id, 1000000000ll + i, 20 + static_cast<std::uint64_t>(i)); }
    BuildOpts o;
    o.cut_payees = {many[0]};                          // pay-now merges into its owed output: no extra slot
    o.mempool = akat::txs(5, 59802, 100000000);       // Σ weight 299010 -> weight-aware cap 20
    const Block b = build_block(L, w.lane, o);
    CHECK(b.ok, "builds: %s", b.ok ? "ok" : b.why.c_str());
    if (!b.ok) return;
    CHECK(b.n_outputs == 20, "the assembler's weight-aware cap binds: %zu outputs (30 owed takes proposed)", b.n_outputs);
    const auto v = receive(b, L, w.lane, {many[0]});
    CHECK(v.r.canonical() && v.r.cap == 20, "recompute: %s at cap %u %s", verdict(v), v.r.cap, v.r.why.c_str());
}

void r5_double_pay() {
    std::printf("== R5. #1861: the builder had not booked the previous lane block ==\n");
    World w;
    st::OwedLedger R = w.L;
    // lane block A (height H) paid K1 its whole balance; the receiver booked it (pending)
    R.on_block_found("A", Amounts{}, Amounts{{w.K1.id, 40000000000ll}});
    CHECK(R.owed_digest() == w.L.owed_digest(), "owed_digest is blind to A (it commits the finalized partition only)");
    BuildOpts o; o.cut_payees = w.cut;
    const Block b = build_block(w.L, w.lane, o);   // the lagging builder: no FOUND(A)
    if (!b.ok) { CHECK(false, "builds: %s", b.why.c_str()); return; }
    const auto v = receive(b, R, w.lane, w.cut);
    CHECK(v.bk.ok && v.bk.payout.count(w.K1.id), "the block decodes and pays K1 again (%lld)",
          v.bk.payout.count(w.K1.id) ? v.bk.payout.at(w.K1.id) : 0ll);
    CHECK(v.r.verdict == rc::Verdict::Mismatch, "recompute: %s -- %s", verdict(v), v.r.why.c_str());
    CHECK(!v.r.expected_payout.count(w.K1.id) || v.r.expected_payout.at(w.K1.id) < 40000000000ll,
          "the canonical coinbase does not pay K1's already-paid balance");
    // the same block against a receiver that is also missing A: canonical (both lag alike)
    st::OwedLedger R2 = w.L;
    CHECK(receive(b, R2, w.lane, w.cut).r.canonical(), "control: a receiver in the builder's state calls it canonical");
}

void r6_overpay() {
    std::printf("== R6. a modified builder over-pays a known key ==\n");
    World w;
    BuildOpts o; o.cut_payees = w.cut;
    o.mutate = [&](x6::CoinbaseInputs& in) {
        for (auto& e : in.owed) if (e.identity == w.K2.id) e.owed += 7000000000ull;
    };
    const Block b = build_block(w.L, w.lane, o);
    if (!b.ok) { CHECK(false, "builds: %s", b.why.c_str()); return; }
    const auto v = receive(b, w.L, w.lane, w.cut);
    CHECK(v.bk.ok, "the block decodes (every output maps to a known payee)");
    CHECK(v.r.verdict == rc::Verdict::Mismatch, "recompute: %s -- %s", verdict(v), v.r.why.c_str());
}

void r7_order() {
    std::printf("== R7. a modified builder pays the owed queue out of K_fair order ==\n");
    World w;
    BuildOpts o; o.cut_payees = w.cut;
    o.mutate = [&](x6::CoinbaseInputs& in) {
        if (in.owed.size() >= 2) std::swap(in.owed[0].first_eligible, in.owed[1].first_eligible);   // K2 first
    };
    const Block b = build_block(w.L, w.lane, o);
    if (!b.ok) { CHECK(false, "builds: %s", b.why.c_str()); return; }
    const auto v = receive(b, w.L, w.lane, w.cut);
    CHECK(v.bk.ok && v.r.verdict == rc::Verdict::Mismatch, "recompute: %s -- %s", verdict(v), v.r.why.c_str());
}

void r8_undertake() {
    std::printf("== R8. under-take: owed money shifted to pay-now ==\n");
    World w;
    BuildOpts o; o.cut_payees = w.cut;
    o.mutate = [&](x6::CoinbaseInputs& in) {
        in.owed.erase(std::remove_if(in.owed.begin(), in.owed.end(), [&](const x6::OwedEntry& e) { return e.identity == w.K2.id; }), in.owed.end());
    };
    const Block b = build_block(w.L, w.lane, o);
    if (!b.ok) { CHECK(false, "builds: %s", b.why.c_str()); return; }
    const auto v = receive(b, w.L, w.lane, w.cut);
    CHECK(v.bk.ok && v.r.verdict == rc::Verdict::Mismatch && v.r.why.find("under-take") != std::string::npos,
          "recompute: %s -- %s", verdict(v), v.r.why.c_str());
}

void r9_paynow_misdirected() {
    std::printf("== R9. pay-now to a payee set other than the cut's ==\n");
    World w;
    BuildOpts o; o.cut_payees = {w.cut[0]};   // the builder claims its own payee is the whole cut
    const Block b = build_block(w.L, w.lane, o);
    if (!b.ok) { CHECK(false, "builds: %s", b.why.c_str()); return; }
    const auto v = receive(b, w.L, w.lane, w.cut);   // the receiver folds the real cut
    CHECK(v.r.verdict == rc::Verdict::Mismatch, "recompute: %s -- %s", verdict(v), v.r.why.c_str());
}

void r10_stale_state() {
    std::printf("== R10. built on a ledger state that is not the booking point's ==\n");
    World w;
    const ::v37::bytes32 old = w.L.owed_digest();
    BuildOpts o; o.cut_payees = w.cut;
    const Block b = build_block(w.L, w.lane, o);
    if (!b.ok) { CHECK(false, "builds: %s", b.why.c_str()); return; }
    st::OwedLedger R = w.L;
    seed(R, w.K3.id, 5000000000ll, 30);   // the receiver finalized one more lane block since
    const auto v = receive(b, R, w.lane, w.cut, {old});
    CHECK(v.bk.ok && v.bk.digest_index == 1, "decodes against the receiver's ring (historical candidate #%zu)", v.bk.digest_index);
    CHECK(v.r.verdict == rc::Verdict::Mismatch && v.r.why.find("owed_digest") != std::string::npos,
          "recompute: %s -- %s", verdict(v), v.r.why.c_str());
}

// R11: the booking outcome of a non-canonical block (ruling 2) on two
// receivers: payouts DEBITED, credit DROPPED, the same owed_digest on both,
// and the double-paid key carried as a debt (forward repair, never a
// clawback), not forgotten.
void r11_debit_only_booking() {
    std::printf("== R11. booking a non-canonical block: debit payouts, drop credit ==\n");
    World w;
    st::OwedLedger R = w.L;
    R.on_block_found("A", Amounts{}, Amounts{{w.K1.id, 40000000000ll}});   // A paid K1 already
    BuildOpts o; o.cut_payees = w.cut;
    const Block b = build_block(w.L, w.lane, o);   // the lagging builder pays K1 again
    if (!b.ok) { CHECK(false, "builds: %s", b.why.c_str()); return; }
    st::OwedLedger R1 = R, R2 = R;
    const auto v1 = receive(b, R1, w.lane, w.cut), v2 = receive(b, R2, w.lane, w.cut);
    CHECK(v1.r.verdict == rc::Verdict::Mismatch && v2.r.verdict == rc::Verdict::Mismatch && v1.r.why == v2.r.why,
          "both receivers reach the same verdict: %s", v1.r.why.c_str());
    // what book_from_chain_ex books on a mismatch: FOUND(credit = {}, payout = the gross on-chain map)
    for (st::OwedLedger* L : {&R1, &R2}) {
        L->on_block_found("B", Amounts{}, v1.bk.payout);
        L->on_block_finalized("A", 50);
        L->on_block_finalized("B", 51);
    }
    CHECK(R1.owed_digest() == R2.owed_digest(), "the same owed_digest on both receivers after FINALIZE");
    const long long k1 = R1.effective_owed(w.K1.id);
    CHECK(k1 == -40000000000ll, "K1 carries the double payment as a debt (EffectiveOwed %lld): forward repair, never forgotten", k1);
    long long credited = 0;
    for (const auto& p : w.cut) credited += R1.effective_owed(p.id) + (v1.bk.payout.count(p.id) ? v1.bk.payout.at(p.id) : 0);
    CHECK(credited == 0, "the block's credit is DROPPED: its cut payees are debited exactly the pay-now they received (net %lld)", credited);
}

// R12: ruling 1 -- fee model v1 is mandatory for --coinbase v37 on mainnet
// (the one refusal the daemon applies, as a pure function).
void r12_fee_model_mandatory() {
    std::printf("== R12. fee model v1 is mandatory for --coinbase v37 on mainnet ==\n");
    using c2pool::v37n::xmr::XmrNodeConfig;
    using c2pool::v37n::xmr::CoinbaseMode;
    using c2pool::v37n::xmr::MoneroNetwork;
    XmrNodeConfig c;
    c.network = MoneroNetwork::Mainnet; c.coinbase = CoinbaseMode::V37Settlement;
    CHECK(!c2pool::v37n::xmr::settlement_fee_model_refusal(c).empty(), "mainnet + --coinbase v37 + fee model OFF: REFUSED");
    c.lane_params.fee = ::v37::FeeModelGate::for_version(1);
    CHECK(c2pool::v37n::xmr::settlement_fee_model_refusal(c).empty(), "mainnet + --coinbase v37 + --fee-model v1: allowed");
    XmrNodeConfig t; t.network = MoneroNetwork::Regtest; t.coinbase = CoinbaseMode::V37Settlement;
    CHECK(c2pool::v37n::xmr::settlement_fee_model_refusal(t).empty(), "regtest rigs keep the OFF mode (one shared sink)");
    XmrNodeConfig a; a.network = MoneroNetwork::Mainnet; a.coinbase = CoinbaseMode::MonerodTemplate;
    CHECK(c2pool::v37n::xmr::settlement_fee_model_refusal(a).empty(), "option A (monerod template) is not the settlement coinbase");
}

// R13: BOOKED REFS. The owed pass resolves only the refs every node holds at
// the booking point. A node that learned K3's ref out of band (its own relay
// arrival, its own payee) must not call a block whose builder carried K3 a
// mismatch -- with the full resolver it would, and book it debit-only while
// the builder booked it canonical: a ledger fork.
void r13_booked_refs() {
    std::printf("== R13. booked refs: out-of-band payee knowledge never changes the verdict ==\n");
    World w;
    seed(w.L, w.K3.id, 15000000000ll, 9);   // K3 is the OLDEST owed key
    Lane booked = w.lane;                    // what every node's bookings taught: not K3
    booked.refs.erase(w.K3.id);
    BuildOpts o; o.cut_payees = w.cut;
    const Block b = build_block(w.L, booked, o);   // the builder carries K3 (no booked ref)
    if (!b.ok) { CHECK(false, "builds: %s", b.why.c_str()); return; }
    const auto full = receive(b, w.L, w.lane, w.cut);             // a receiver that knows K3 locally
    const auto bkd  = receive(b, w.L, w.lane, w.cut, {}, true, &booked);
    CHECK(full.bk.ok && !full.bk.payout.count(w.K3.id), "the block carries K3 (its builder holds no booked ref for it)");
    CHECK(full.r.verdict == rc::Verdict::Mismatch, "with the FULL resolver the receiver would call it a mismatch (the fork hazard): %s",
          full.r.why.c_str());
    CHECK(bkd.r.canonical(), "with the BOOKED resolver it is canonical on every node: %s %s", verdict(bkd), bkd.r.why.c_str());
}

// R14: pay-now takes each payee's ref from the view at the cut, so a builder
// whose resolver has not learned a cut payee still pays it (every node reads
// the same view).
void r14_paynow_refs_from_view() {
    std::printf("== R14. pay-now refs come from the view at the cut ==\n");
    World w;
    Lane bare = w.lane;
    for (const auto& p : w.cut) bare.refs.erase(p.id);   // the builder's resolver knows no cut payee
    BuildOpts o; o.cut_payees = w.cut;
    const Block b = build_block(w.L, bare, o);
    if (!b.ok) { CHECK(false, "builds: %s", b.why.c_str()); return; }
    const auto v = receive(b, w.L, w.lane, w.cut, {}, true, &bare);
    CHECK(v.bk.ok && v.bk.paynow_base.has_value(), "pay-now is armed (V37N committed) without the resolver knowing the cut payees");
    CHECK(v.r.canonical(), "and the block is canonical: %s %s", verdict(v), v.r.why.c_str());
}

// R15: #1867 salted tie-break is part of the recomputed rule. Keys armed at
// the same FINALIZE share first_eligible; the lane orders that cohort by
// sha256d("V37T" || prev_id || key). A builder that orders it by the raw
// identity instead (the grindable order) is a MISMATCH.
void r15_salted_ties() {
    std::printf("== R15. salted K_fair tie-break (#1867) ==\n");
    World w;
    st::OwedLedger L{kChain};
    std::vector<Payee> tied;
    for (int i = 0; i < 6; ++i) { Payee p = payee(static_cast<std::uint8_t>(70 + i)); w.lane.learn(p); tied.push_back(p); }
    {
        Amounts c; for (const auto& p : tied) c[p.id] = 20000000000ll + 1000 * static_cast<long long>(p.id[0]);
        L.on_block_found("cohort", c, {});
        L.on_block_finalized("cohort", 40);   // one FINALIZE: one age for all six
    }
    g_salted = true;
    BuildOpts salted; salted.cut_payees = w.cut; salted.mutate_ctx = [](o2::XmrCoinbaseContext& c) { c.kfair_salted_ties = true; };
    const Block bs = build_block(L, w.lane, salted);
    BuildOpts plain; plain.cut_payees = w.cut;   // the raw identity order
    const Block bp = build_block(L, w.lane, plain);
    if (!bs.ok || !bp.ok) { CHECK(false, "builds: %s %s", bs.why.c_str(), bp.why.c_str()); g_salted = false; return; }
    const auto vs = receive(bs, L, w.lane, w.cut), vp = receive(bp, L, w.lane, w.cut);
    CHECK(vs.r.canonical(), "a builder with the salted order is canonical: %s %s", verdict(vs), vs.r.why.c_str());
    CHECK(vp.r.verdict == rc::Verdict::Mismatch, "a builder with the raw identity order is a MISMATCH: %s", vp.r.why.c_str());
    g_salted = false;
}

// ---------------------------------------------------------------------------
// THE DRAIN RULE (rulings R1/R2/R5 2026-10-02, settlement-drain.md).
// R16 (B12): dh lives in the ledger: the FOUND height, prev = max(pending,
// settled), seeds never move it, an orphan drops out, "V37Z" in owed_digest
// under the rule only, and the settle-store replay reproduces it.
void r16_lane_height_in_ledger() {
    std::printf("== R16. THE DRAIN RULE: the previous lane block's height is ledger state ==\n");
    st::OwedLedgerRules on; on.lane_height = true; on.decay_from_gross = true;
    st::OwedLedger L(kChain, on), M(kChain), M2(kChain);
    const ::v37::bytes32 k = payee(31).id;
    auto lf = [](std::uint64_t h) { st::LaneFound f; f.height = h; return f; };
    L.on_block_found("seed", Amounts{{k, 5000}}, {}); L.on_block_finalized("seed", 1);
    CHECK(L.prev_lane_height() == 0, "a seed is not a lane block: prev_lane_height 0");
    const auto f100 = lf(100), f130 = lf(130);
    L.on_block_found("b100", {}, {}, std::nullopt, nullptr, &f100);
    L.on_block_found("b130", {}, {}, std::nullopt, nullptr, &f130);
    CHECK(L.prev_lane_height() == 130 && L.heights_since_last_lane(150) == 20, "pending lane blocks count: prev 130, dh(150) = 20");
    L.on_block_orphaned("b130", {});
    CHECK(L.prev_lane_height() == 100, "an orphaned pending lane block drops out: prev 100");
    const ::v37::bytes32 d_before = L.owed_digest();
    L.on_block_finalized("b100", 160);
    CHECK(L.last_settled_lane_height() == 100 && !(L.owed_digest() == d_before), "FINALIZE commits it (V37Z): settled 100, owed_digest moves");
    // rule off: the same calls (the lane info ignored) leave master's ledger, byte for byte
    for (st::OwedLedger* X : {&M, &M2}) { X->on_block_found("seed", Amounts{{k, 5000}}, {}); X->on_block_finalized("seed", 1); }
    M.on_block_found("b100", {}, {}, std::nullopt, nullptr, &f100); M2.on_block_found("b100", {}, {});
    M.on_block_finalized("b100", 160); M2.on_block_finalized("b100", 160);
    CHECK(M.owed_digest() == M2.owed_digest() && M.owed_event_mmr_root() == M2.owed_event_mmr_root() && M.prev_lane_height() == 0,
          "rule off: owed_digest and the event MMR are master's (no V37Z, no lane leaf)");
    CHECK(!(L.owed_digest() == M.owed_digest()), "rule on: the V37Z section makes the digest differ from master's");
    // the settle store: FOUND events carry (height, G_b); a replay rebuilds the same ledger
    namespace xs = c2pool::v37n::xmr;
    xs::MemSettleStore store;
    st::OwedLedger D(kChain, on);
    st::SettleHW hw;
    xs::XmrFinalizeDriver drv(D, hw, store, kChain, 2, 0, 0, [](std::uint64_t, const std::string&) { return true; });
    xs::FoundBlock a; a.bid = "aa01"; a.height = 200; a.gross = {k};
    xs::FoundBlock b; b.bid = "aa02"; b.height = 230; b.gross = {};
    drv.on_block_found(a); drv.on_block_found(b);
    (void)drv.advance_to_tip(203, ::v37::bytes32{});   // finalizes a (200 + D_conf 2 <= 203)
    st::OwedLedger D2(kChain, on);
    bool ok = false;
    xs::RecoveryDriver(store, kChain).recover(D2, ok);
    CHECK(ok && D.last_settled_lane_height() == 200 && D.prev_lane_height() == 230 &&
          D2.prev_lane_height() == 230 && D2.last_settled_lane_height() == 200 && D2.owed_digest() == D.owed_digest() &&
          D2.owed_event_mmr_root() == D.owed_event_mmr_root(),
          "the store replay reproduces the lane heights (settled 200, pending 230), owed_digest and the event MMR");
}

// A world whose float is larger than one block's slice (F > Delta).
struct DrainWorld : World {
    Payee K4 = payee(24);
    DrainWorld() { lane.learn(K4); seed(L, K4.id, 900000000000ll, 12); }   // 0.9 XMR: F = 0.965 XMR
};

// R17 (B13): a REAL drain block is canonical on a receiver; it books at P.
void r17_drain_block_canonical() {
    std::printf("== R17. THE DRAIN RULE: a real drain block is canonical; the receiver books at P ==\n");
    DrainWorld w;
    g_drain = true;
    BuildOpts o; o.cut_payees = w.cut; o.drain = true;
    const Block b = build_block(w.L, w.lane, o);
    CHECK(b.ok, "builds: %s", b.ok ? "ok" : b.why.c_str());
    if (!b.ok) { g_drain = false; return; }
    st::OwedLedger R = w.L;
    const auto v = receive(b, R, w.lane, w.cut);
    CHECK(v.r.canonical() && v.r.drain_on, "recompute: %s %s", verdict(v), v.r.why.c_str());
    CHECK(v.r.F == 965000000000ull && v.r.dh == 0 && v.r.delta == b.reward / 4 && v.r.debt_paid == v.r.delta &&
          v.r.split_at == b.reward - v.r.debt_paid,
          "F %llu, dh 0 (first lane block: the cap), Delta = R/4 = %llu, debt_paid = Delta, split_at = R - debt_paid = %llu",
          (unsigned long long)v.r.F, (unsigned long long)v.r.delta, (unsigned long long)v.r.split_at);
    // the booking (main: drain_refold + paynow_net): E_b refolded at P, + the redistribution, net of the pay-now
    Amounts credit;
    const auto wp = weighted(w.cut);
    const auto amt = st::split_reward(v.r.split_at, wp);
    for (std::size_t i = 0; i < wp.size(); ++i) if (amt[i]) credit[wp[i].key] += static_cast<long long>(amt[i]);
    for (const auto& [k, d] : v.r.credit_delta) credit[k] += d;
    Amounts payout = v.bk.payout;
    const auto nb = pn::net_booking(v.bk.paynow_base, v.bk.total, credit, payout, v.bk.sink_total, fee::donation_identity(kNet),
                                    static_cast<long long>(fee::kDonationMarkerPico), true);
    long long left = 0, owed_paid = 0;
    for (const auto& [k, c] : credit) if (c > 0) left += c;
    for (const auto& [k, p] : payout) owed_paid += p;
    CHECK(nb.ok && left == 0 && owed_paid == static_cast<long long>(v.r.debt_paid),
          "the window rows net to 0 (left %lld); what stays booked is exactly the old debt paid (%lld)", left, owed_paid);
    g_drain = false;
}

// R18 (B15): every deviation from the drain rule is a Mismatch, the same on
// every receiver (booked debit-only by main, one owed_digest everywhere).
void r18_drain_deviations() {
    std::printf("== R18. THE DRAIN RULE: every deviation is a MISMATCH on every receiver ==\n");
    g_drain = true;
    auto judge = [&](const char* name, const st::OwedLedger& builder_ledger, const st::OwedLedger& Lr, const Lane& lane,
                     const std::vector<Payee>& cut, BuildOpts o) {
        o.drain = true;
        const Block b = build_block(builder_ledger, lane, o);
        if (!b.ok) { CHECK(false, "%s: builds: %s", name, b.why.c_str()); return; }
        st::OwedLedger R1 = Lr, R2 = Lr;   // two receivers at the same booking point
        const auto v1 = receive(b, R1, lane, cut), v2 = receive(b, R2, lane, cut);
        CHECK(v1.r.verdict == rc::Verdict::Mismatch && v2.r.verdict == rc::Verdict::Mismatch && v1.r.why == v2.r.why,
              "%s: MISMATCH on both receivers: %s", name, v1.r.why.c_str());
    };
    {   // the honest block first: canonical
        DrainWorld w;
        BuildOpts o; o.cut_payees = w.cut; o.drain = true;
        const Block b = build_block(w.L, w.lane, o);
        const auto v = b.ok ? receive(b, w.L, w.lane, w.cut) : Verified{};
        CHECK(b.ok && v.r.canonical(), "honest drain block: %s %s", b.ok ? verdict(v) : b.why.c_str(), v.r.why.c_str());
    }
    {   DrainWorld w; BuildOpts o; o.cut_payees = w.cut;
        o.mutate = [](x6::CoinbaseInputs& in) { in.owed.back().owed += 1000000000ull; in.drain_budget += 1000000000ull; };
        judge("(a) old debt beyond Delta (over-take)", w.L, w.L, w.lane, w.cut, o); }
    {   DrainWorld w; BuildOpts o; o.cut_payees = w.cut;
        o.mutate = [](x6::CoinbaseInputs& in) { in.owed.back().owed -= 1000000000ull; };
        judge("(b) less than the Delta pass (under-take)", w.L, w.L, w.lane, w.cut, o); }
    {   DrainWorld w; BuildOpts o; o.cut_payees = w.cut; o.hint_extra = 400000000000ull; o.fixpoint = false;
        judge("(c) takes chosen at a larger reward hint (master's R2 case)", w.L, w.L, w.lane, w.cut, o); }
    {   DrainWorld w; BuildOpts o; o.cut_payees = w.cut;
        o.mutate = [](x6::CoinbaseInputs& in) { in.paynow_first = false; };
        judge("(d) the window credited at R with DEBT FIRST (master's pay-now)", w.L, w.L, w.lane, w.cut, o); }
    {   // (e) a contested block: 30 debts of 2c, 30 window payees, a 24-output wire cap
        g_cap = 24;
        World w;
        const std::uint64_t c2 = 2 * x6::spend_floor(600090000000ull);
        for (std::uint8_t i = 0; i < 30; ++i) { Payee d = payee(static_cast<std::uint8_t>(120 + i)); w.lane.learn(d); seed(w.L, d.id, static_cast<long long>(c2), 20 + i); }
        std::vector<Payee> cut;
        for (std::uint8_t i = 0; i < 30; ++i) { Payee p = payee(static_cast<std::uint8_t>(160 + i), 1); w.lane.learn(p); cut.push_back(p); }
        BuildOpts h; h.cut_payees = cut; h.drain = true; h.cap = 24;
        const Block hb = build_block(w.L, w.lane, h);
        const auto hv = hb.ok ? receive(hb, w.L, w.lane, cut) : Verified{};
        CHECK(hb.ok && hv.r.canonical(), "(e) the honest contested block (K_o cut) is canonical: %s %s", hb.ok ? verdict(hv) : hb.why.c_str(), hv.r.why.c_str());
        BuildOpts o; o.cut_payees = cut; o.cap = 24;
        o.mutate = [](x6::CoinbaseInputs& in) { in.paynow_first = false; };   // no K_o: the owed pass keeps every slot it filled
        judge("(e) more than K_o owed slots in a contested block", w.L, w.L, w.lane, cut, o);
        g_cap = 2700;
    }
    {   // (f) a band balance (in [arm floor, c(R)) at a 1.2 XMR reward) skipped instead of routed to the dust pass
        World w;
        Payee g = payee(77); w.lane.learn(g);
        seed(w.L, g.id, 20000000ll, 13);
        BuildOpts o; o.cut_payees = w.cut; o.mempool = akat::txs(3, 2000, 200000000000ull);
        o.mutate = [g](x6::CoinbaseInputs& in) {
            in.owed_dust.erase(std::remove_if(in.owed_dust.begin(), in.owed_dust.end(), [&](const x6::OwedEntry& e) { return e.identity == g.id; }),
                               in.owed_dust.end());
        };
        judge("(f) a sub-c proposed take skipped instead of routed", w.L, w.L, w.lane, w.cut, o);
    }
    {   // (g) dh from another predecessor: the builder holds a lane block the receivers do not
        st::OwedLedgerRules on; on.lane_height = true; on.decay_from_gross = true;
        DrainWorld w;
        st::OwedLedger Lr(kChain, on);
        seed(Lr, w.K1.id, 40000000000ll, 10); seed(Lr, w.K2.id, 25000000000ll, 11); seed(Lr, w.K4.id, 900000000000ll, 12);
        st::OwedLedger Lb = Lr;
        st::LaneFound f; f.height = kHeight - 5;
        Lb.on_block_found("phantom", {}, {}, std::nullopt, nullptr, &f);   // pending: owed_digest unchanged
        CHECK(Lb.owed_digest() == Lr.owed_digest(), "(g) the builder's ledger commits the same owed_digest");
        BuildOpts o; o.cut_payees = w.cut;
        judge("(g) dh from another predecessor (Delta at dh 5, not the cap)", Lb, Lr, w.lane, w.cut, o);
    }
    {   DrainWorld w; BuildOpts o; o.cut_payees = w.cut;
        o.mutate_ctx = [](o2::XmrCoinbaseContext& c) { c.drain = o2::DrainRule{}; };
        judge("(h) a version-0 (master) builder on a rule-on receiver", w.L, w.L, w.lane, w.cut, o); }
    g_drain = false;
}

// R19 (B7 (i), amendment A3): the empty-cut finder under the drain rule. A
// fresh pool (F = 0): the finder's credit is the pool and it nets to 0. With
// old debt and dust paid in an empty cut the finder is credited P = R -
// debt_paid (main paynow_net under the rule), which is what it was paid: no
// new balance either way.
void r19_ecut_finder_drain() {
    std::printf("== R19. THE DRAIN RULE: the empty-cut finder is credited what it is paid (no new owed) ==\n");
    g_drain = true;
    World w;
    const Payee f = payee(52), dust = payee(53);
    w.lane.learn(f); w.lane.learn(dust);
    seed(w.L, dust.id, 5000000ll, 14);   // a sub-floor balance: the dust pass pays it (debt beyond the owed takes)
    st::OwedLedger E{kChain};
    for (int pass = 0; pass < 2; ++pass) {
        const st::OwedLedger& L = pass == 0 ? E : w.L;
        BuildOpts o; o.finder = f.ref; o.drain = true;
        const Block b = build_block(L, w.lane, o);
        if (!b.ok) { CHECK(false, "R19 %s: builds: %s", pass ? "debt" : "fresh", b.why.c_str()); continue; }
        const auto v = receive(b, L, w.lane, {});
        Amounts credit; std::string ew; ::v37::bytes32 fid{};
        const bool fok = pn::apply_empty_cut_finder(v.bk.ecut_finder, v.bk.ecut_finder_malformed, v.bk.paynow_base, v.bk.total, credit, &ew, &fid);
        if (v.r.drain_on && v.r.split_at != 0 && v.r.split_at != v.bk.total) { credit.clear(); credit[fid] = static_cast<long long>(v.r.split_at); }
        for (const auto& [k, d] : v.r.credit_delta) credit[k] += d;
        Amounts payout = v.bk.payout;
        const auto nb = pn::net_booking(v.bk.paynow_base, v.bk.total, credit, payout, v.bk.sink_total, fee::donation_identity(kNet),
                                        static_cast<long long>(fee::kDonationMarkerPico), true);
        long long left = 0; for (const auto& [k, c] : credit) if (c > 0) left += c;
        CHECK(v.r.canonical() && v.bk.ecut_finder && fok && nb.ok && left == 0,
              "R19 %s: canonical (%s), V37F finder credited %s and netted: left %lld (debt_paid %llu, P %llu, total %llu)",
              pass ? "old debt + dust in an empty cut" : "fresh pool (F = 0)", verdict(v), pass ? "P = R - debt_paid" : "the pool",
              left, (unsigned long long)v.r.debt_paid, (unsigned long long)v.r.split_at, (unsigned long long)v.bk.total);
    }
    g_drain = false;
}
#else
void suite_base() {
    std::printf("== BASE: no recompute on this tree ==\n");
    CHECK(false, "xmr_coinbase_recompute.hpp is absent: a receiver books whatever payout map a lane block carries");
}
#endif

}  // namespace

int main() {
    std::printf("v37_xmr_coinbase_recompute_kat (%s)\n", RECOMPUTE_FIX ? "fix" : "base");
#if RECOMPUTE_FIX
    r1_honest();
    r2_hint_above_total();
    r3_empty_cut();
    r4_cap_binds();
    r5_double_pay();
    r6_overpay();
    r7_order();
    r8_undertake();
    r9_paynow_misdirected();
    r10_stale_state();
    r11_debit_only_booking();
    r12_fee_model_mandatory();
    r13_booked_refs();
    r14_paynow_refs_from_view();
    r15_salted_ties();
    r16_lane_height_in_ledger();
    r17_drain_block_canonical();
    r18_drain_deviations();
    r19_ecut_finder_drain();
#else
    suite_base();
#endif
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
