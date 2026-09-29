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
    ctx.h_min = 0; ctx.output_cap = 2700;
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
    a.extra_nonce_bind_size = 32;
    a.extra_nonce_bind = [](std::uint32_t en, std::uint8_t* b) { for (int i = 0; i < 32; ++i) b[i] = static_cast<std::uint8_t>(en * 13 + i); return true; };
    auto t = asm_::XmrBlockAssembler::build(a, &why);
    if (!t) { out.why = "assembler: " + why; return out; }
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
    li.chain_id = kChain; li.h_min = 0; li.owed_cap = 2700; li.wire_cap = 2700;
    li.residual_sink = fee::donation_ref(kNet); li.residual_sink_identity = fee::donation_identity(kNet);
    li.fixed = {fee::donation_marker(kNet)};
    li.pool_tag = the_tag();
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
    const std::uint64_t took = v.bk.paynow_base ? *v.bk.paynow_base - fee::kDonationDustPico : 0;
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
        CHECK(v.r.expected_payout.count(f.id) && v.r.expected_payout.at(f.id) == static_cast<long long>(b1.reward - 1),
              "the finder is paid reward - 1 (the donation keeps its marker)");
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
#else
    suite_base();
#endif
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
