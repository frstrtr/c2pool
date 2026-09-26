// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_paynow_kat -- SAME-BLOCK PAY-NOW (operator ruling 09-25).
//
// The defect: with --coinbase v37 (fee model ON or OFF) a pool block built
// while EffectiveOwed is 0 -- the first block, and every block found before
// the first one finalizes -- paid its WHOLE reward to the donation output /
// residual sink, while its miners were still credited that block's E_b in
// full at finalization. The fix pays THIS block's miners out of what the
// oldest-first owed pass leaves, pro rata to their E_b at the block's credit
// cut, each <= its own E_b, and books the block NET of that pay-now.
//
//   P1  paynow_split: exact-sum, each <= E_b, pool >= ΣE_b pays E_b in full,
//       largest-remainder rounding (ties by identity order), random sweep.
//   P2  the X6 allocation (fee model ON: the one donation output folds the
//       residual): (a) empty ledger, (b) partial owed + merge into an owed
//       output, (c) full owed (no pay-now, S2 dust unchanged), (d) rounding,
//       (e) the donation identity's own E_b stays in the donation output,
//       (f) cap -> fail closed, (g) fee model OFF (separate residual sink).
//   P3  the receive side: the V37N tail round-trips beside V37D and V37C; the
//       receiver's allocation equals the builder's; net-at-FOUND booking on a
//       real OwedLedger never lets EffectiveOwed go negative and FINALIZE
//       books E_b - paid (no double pay); an under-paying coinbase is REFUSED;
//       an orphan nets nothing (ledger == a run without it).
//   P4  the settlement source end-to-end (XmrOwedSettlementSource::build with
//       a credit cut + the cut's projected payees): V37N base committed, the
//       first block pays its miners reward - 1, the donation output is the
//       1-piconero marker, shape stable across the reward fixpoint.
//
// RED on the base: the pay-now API does not exist there, so this file builds
// its BASE branch (no xmr_paynow.hpp): the same empty-ledger block goes
// through master's X6 and the "miners are paid" checks FAIL with the measured
// donation amount (the whole reward).
// ---------------------------------------------------------------------------
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <random>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/settle/xmr_coinbase.hpp"
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_settlement_coinbase_shape.hpp"
#if __has_include("c2pool/v37/xmr/xmr_paynow.hpp")
#include "c2pool/v37/xmr/xmr_paynow.hpp"
#define PAYNOW_FIX 1
#include "impl/xmr/template/xmr_block_assembly.hpp"
static_assert(::c2pool::xmr::assembly::PAYNOW_TAIL_BYTES == c2pool::v37n::xmr::paynow::kPayNowTailBytes,
              "impl-tree PAYNOW_TAIL_BYTES must mirror paynow::kPayNowTailBytes (12)");
#else
#define PAYNOW_FIX 0
#endif

namespace x6  = ::v37::xmr::settle;
namespace fee = c2pool::v37n::xmr::fee;
namespace o2  = c2pool::v37n::xmr::o2;
namespace st  = c2pool::v37n::settle;
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

std::array<std::uint8_t, 32> point_of(std::uint8_t k) {
    ::xmr::coin::SecretKey sec{};
    sec.data()[0] = k;
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), pub.data(), 32);
    return out;
}
::v37::ScriptRef ref_of(std::uint8_t k) { return ::v37::xmr::make_xmr_std(point_of(k), point_of(static_cast<std::uint8_t>(k + 100))); }
::v37::bytes32 id_of(const ::v37::ScriptRef& r) { return ::v37::xmr::xmr_identity_key(r); }
std::string hex8(const ::v37::bytes32& b) {
    static const char* d = "0123456789abcdef"; std::string s;
    for (int i = 0; i < 4; ++i) { s += d[b[i] >> 4]; s += d[b[i] & 15]; }
    return s;
}

constexpr std::uint64_t kReward = 600000000000ull + 12345ull;   // regtest tail subsidy + fees
constexpr fee::DonationNet kNet = fee::DonationNet::Regtest;

// fee model ON inputs: ONE donation output (marker 1, residual folds in).
x6::CoinbaseInputs fee_on_inputs(std::uint64_t reward) {
    x6::CoinbaseInputs in;
    in.monero_major_version = 16;
    in.height = 1234;
    in.base_reward = reward;
    in.fees = 0;
    in.chain_id = 7;
    in.fixed = {fee::donation_marker(kNet)};
    in.residual_sink = fee::donation_ref(kNet);
    in.residual_sink_identity = fee::donation_identity(kNet);
    in.output_cap = 16;
    in.h_min = 0;
    return in;
}

struct Payee { ::v37::ScriptRef ref; ::v37::bytes32 id; std::uint64_t w; };
std::vector<Payee> three_payees() {
    std::vector<Payee> v;
    const std::uint64_t w[3] = {1, 2, 3};
    for (int i = 0; i < 3; ++i) { auto r = ref_of(static_cast<std::uint8_t>(11 + i)); v.push_back({r, id_of(r), w[i]}); }
    std::sort(v.begin(), v.end(), [](const Payee& a, const Payee& b) { return a.id < b.id; });
    return v;
}
// E_b at `budget` over `ps` (the fold's exact split), identity-keyed.
std::map<::v37::bytes32, std::uint64_t> eb_at(std::uint64_t budget, const std::vector<Payee>& ps) {
    std::vector<st::WeightedPayee> wp;
    for (const auto& p : ps) { st::WeightedPayee x; x.key = p.id; x.weight = ::v37::U256(p.w); x.pay = p.ref; wp.push_back(x); }
    const std::vector<std::uint64_t> a = st::split_reward(budget, wp);
    std::map<::v37::bytes32, std::uint64_t> m;
    for (std::size_t i = 0; i < ps.size(); ++i) if (a[i]) m[ps[i].id] += a[i];
    return m;
}
std::uint64_t amount_to(const std::vector<x6::CoinbaseOutput>& outs, const ::v37::bytes32& id) {
    std::uint64_t s = 0; for (const auto& o : outs) if (o.identity == id) s += o.amount; return s;
}
std::uint64_t sum_of(const std::vector<x6::CoinbaseOutput>& outs) { std::uint64_t s = 0; for (const auto& o : outs) s += o.amount; return s; }

#if PAYNOW_FIX
void arm_paynow(x6::CoinbaseInputs& in, const std::vector<Payee>& ps) {
    in.paynow_at = [ps](std::uint64_t budget) {
        std::vector<x6::PayNowEntry> out;
        const auto m = eb_at(budget, ps);
        for (const auto& [k, v] : m) {
            x6::PayNowEntry e; e.identity = k; e.eb = v;
            for (const auto& p : ps) if (p.id == k) e.pay = p.ref;
            out.push_back(e);
        }
        return out;
    };
    in.paynow_n = ps.size();
}

// ---------------------------------------------------------------------------
void suite_split() {
    std::printf("== P1. paynow_split ==\n");
    auto s = x6::paynow_split(10, {1, 2, 3, 4});
    CHECK(s == std::vector<std::uint64_t>({1, 2, 3, 4}), "pool == ΣE_b pays every E_b in full");
    s = x6::paynow_split(1000, {1, 2, 3});
    CHECK(s == std::vector<std::uint64_t>({1, 2, 3}), "pool > ΣE_b is capped at each E_b (never an advance)");
    s = x6::paynow_split(7, {3, 3, 3});
    CHECK(s == std::vector<std::uint64_t>({3, 2, 2}), "rounding: floor 2,2,2 + leftover 1 by largest remainder, tie -> first (got %llu,%llu,%llu)",
          (unsigned long long)s[0], (unsigned long long)s[1], (unsigned long long)s[2]);
    s = x6::paynow_split(0, {5, 5});
    CHECK(s == std::vector<std::uint64_t>({0, 0}), "empty pool pays nothing");
    std::mt19937_64 rng(0x9A7);
    bool ok = true; std::size_t n_cases = 0;
    for (int t = 0; t < 4000; ++t) {
        const std::size_t n = 1 + rng() % 9;
        std::vector<std::uint64_t> eb(n);
        unsigned __int128 sum = 0;
        for (auto& e : eb) { e = rng() % 4 == 0 ? 0 : (rng() % 700000000000ull); sum += e; }
        const std::uint64_t pool = rng() % 800000000000ull;
        const auto a = x6::paynow_split(pool, eb);
        unsigned __int128 got = 0;
        for (std::size_t i = 0; i < n; ++i) { if (a[i] > eb[i]) ok = false; got += a[i]; }
        const unsigned __int128 want = sum < pool ? sum : pool;
        if (got != want) ok = false;
        ++n_cases;
    }
    CHECK(ok, "random sweep (%zu cases): Σ == min(pool, ΣE_b) exactly, every share <= its E_b", n_cases);
}

// ---------------------------------------------------------------------------
void suite_alloc() {
    std::printf("== P2. X6 allocation with pay-now ==\n");
    const auto ps = three_payees();
    const ::v37::bytes32 D = fee::donation_identity(kNet);
    const auto eb = eb_at(kReward, ps);
    // (a) empty ledger
    {
        auto in = fee_on_inputs(kReward); arm_paynow(in, ps);
        x6::BuildError err{};
        const auto outs = x6::allocate_exact_sum(in, &err);
        const std::uint64_t don = amount_to(outs, D);
        std::uint64_t miners = 0; bool capped = true;
        for (const auto& p : ps) { const auto a = amount_to(outs, p.id); miners += a; if (a > eb.at(p.id)) capped = false; }
        CHECK(err == x6::BuildError::None && sum_of(outs) == kReward, "(a) empty ledger: exact-sum %llu == reward", (unsigned long long)sum_of(outs));
        CHECK(don == fee::kDonationDustPico, "(a) the donation output carries ONLY its 1-piconero marker (got %llu)", (unsigned long long)don);
        CHECK(miners == kReward - 1 && capped, "(a) the block's own miners are paid reward-1 = %llu, each <= its E_b", (unsigned long long)miners);
        CHECK(outs.size() == 4 && outs.back().identity == D && outs[0].identity == ps[0].id && outs[2].identity == ps[2].id,
              "(a) canonical order: pay-now outputs identity ASC, then the ONE donation output LAST");
        CHECK(fee::inspect_donation_marker(outs, kNet).ok, "(a) the serve-side donation property still ACCEPTS the shape");
    }
    // (b) partial owed: A owed 1e11 (oldest), X (no work in this block) owed 5e10
    {
        auto in = fee_on_inputs(kReward); arm_paynow(in, ps);
        const auto X = ref_of(55);
        x6::OwedEntry oa; oa.pay = ps[0].ref; oa.identity = ps[0].id; oa.owed = 100000000000ull; oa.first_eligible = 0;
        x6::OwedEntry ox; ox.pay = X; ox.identity = id_of(X); ox.owed = 50000000000ull; ox.first_eligible = 1;
        in.owed = {oa, ox};
        x6::BuildError err{};
        const auto outs = x6::allocate_exact_sum(in, &err);
        const std::uint64_t pool = kReward - 1 - 150000000000ull;
        std::vector<std::uint64_t> ebv; for (const auto& p : ps) ebv.push_back(eb.at(p.id));
        const auto al = x6::paynow_split(pool, ebv);
        CHECK(err == x6::BuildError::None && sum_of(outs) == kReward, "(b) exact-sum");
        CHECK(amount_to(outs, ps[0].id) == 100000000000ull + al[0], "(b) A: owed 1e11 + its pay-now %llu MERGED in one output", (unsigned long long)al[0]);
        CHECK(amount_to(outs, id_of(X)) == 50000000000ull, "(b) X (no work in this block) gets exactly its owed, no pay-now");
        CHECK(amount_to(outs, ps[1].id) == al[1] && amount_to(outs, ps[2].id) == al[2], "(b) B, C get their pay-now shares");
        CHECK(amount_to(outs, D) == 1, "(b) donation == 1 (marker only)");
        std::size_t nA = 0; for (const auto& o : outs) if (o.identity == ps[0].id) ++nA;
        CHECK(nA == 1 && outs.size() == 5, "(b) one output per identity (5 = A, X, B, C, donation)");
    }
    // (c) full owed: the owed pass exhausts the budget -> no pay-now, S2 dust from the largest
    {
        auto in = fee_on_inputs(kReward);
        x6::OwedEntry oa; oa.pay = ps[0].ref; oa.identity = ps[0].id; oa.owed = kReward; oa.first_eligible = 0;
        in.owed = {oa};
        const auto base_outs = x6::allocate_exact_sum(in);
        arm_paynow(in, ps);
        const auto outs = x6::allocate_exact_sum(in);
        bool same = base_outs.size() == outs.size();
        for (std::size_t i = 0; same && i < outs.size(); ++i) same = outs[i].amount == base_outs[i].amount && outs[i].identity == base_outs[i].identity;
        CHECK(same, "(c) full owed: byte-identical to master's allocation (no pay-now)");
        CHECK(amount_to(outs, ps[0].id) == kReward - 1 && amount_to(outs, D) == 1, "(c) S2 unchanged: the 1-piconero marker comes from the largest payee");
    }
    // (d) rounding: a tiny budget over 1:1:1 weights
    {
        std::vector<Payee> eq = ps; for (auto& p : eq) p.w = 7;
        const std::uint64_t R = 1000003;
        auto in = fee_on_inputs(R); arm_paynow(in, eq);
        const auto outs = x6::allocate_exact_sum(in);
        const auto e = eb_at(R, eq);
        bool capped = true; for (const auto& p : eq) if (amount_to(outs, p.id) > e.at(p.id)) capped = false;
        CHECK(sum_of(outs) == R && amount_to(outs, D) == 1 && capped,
              "(d) rounding: pool %llu over 3 equal E_b -> exact-sum, donation 1, each <= E_b (%llu/%llu/%llu)",
              (unsigned long long)(R - 1), (unsigned long long)amount_to(outs, eq[0].id),
              (unsigned long long)amount_to(outs, eq[1].id), (unsigned long long)amount_to(outs, eq[2].id));
    }
    // (e) the donation identity has E_b (give-author credit): its share stays IN the donation output
    {
        std::vector<Payee> wd = ps; wd.push_back({fee::donation_ref(kNet), D, 1});
        std::sort(wd.begin(), wd.end(), [](const Payee& a, const Payee& b) { return a.id < b.id; });
        auto in = fee_on_inputs(kReward); arm_paynow(in, wd);
        const auto outs = x6::allocate_exact_sum(in);
        const auto e = eb_at(kReward, wd);
        std::vector<std::uint64_t> ebv; for (const auto& p : wd) ebv.push_back(e.at(p.id));
        const auto al = x6::paynow_split(kReward - 1, ebv);
        std::uint64_t alD = 0; for (std::size_t i = 0; i < wd.size(); ++i) if (wd[i].id == D) alD = al[i];
        std::size_t nD = 0; for (const auto& o : outs) if (o.identity == D) ++nD;
        CHECK(nD == 1 && outs.back().identity == D && amount_to(outs, D) == 1 + alD && outs.back().owed_part == 0,
              "(e) donation E_b share %llu merges into the ONE donation output (1 + share), owed_part 0 (coverage)", (unsigned long long)alD);
    }
    // (f) cap: pay-now needs 3 new slots, the cap leaves 1 -> fail closed (the provider then drops pay-now)
    {
        auto in = fee_on_inputs(kReward); arm_paynow(in, ps); in.output_cap = 2;
        x6::BuildError err{};
        const auto outs = x6::allocate_exact_sum(in, &err);
        CHECK(outs.empty() && err == x6::BuildError::CapTooSmall, "(f) pay-now never exceeds the output cap: CapTooSmall");
    }
    // (g) fee model OFF: separate residual sink, pay-now still applies (sink keeps nothing)
    {
        x6::CoinbaseInputs in = fee_on_inputs(kReward);
        in.fixed.clear();
        const auto S = ref_of(77); in.residual_sink = S; in.residual_sink_identity = id_of(S);
        arm_paynow(in, ps);
        const auto outs = x6::allocate_exact_sum(in);
        std::uint64_t miners = 0; for (const auto& p : ps) miners += amount_to(outs, p.id);
        CHECK(sum_of(outs) == kReward && miners == kReward && amount_to(outs, id_of(S)) == 0,
              "(g) fee OFF: the block's miners are paid the whole reward %llu, the residual sink gets 0", (unsigned long long)miners);
    }
}

// ---------------------------------------------------------------------------
void suite_booking() {
    std::printf("== P3. receive side: V37N commitment + net-at-FOUND booking ==\n");
    namespace pn = c2pool::v37n::xmr::paynow;
    // tail round trip beside V37D and V37C
    {
        std::vector<std::uint8_t> p = {1, 2, 3, 4};
        const auto n = pn::encode_tail(0x0102030405060708ull);
        p.insert(p.end(), n.begin(), n.end());
        const auto d = fee::encode_donation_owed_tail(777);
        p.insert(p.end(), d.begin(), d.end());
        c2pool::v37n::xmr::credit::CreditCut cc; cc.next_pos = 42; cc.spine_digest[0] = 9;
        const auto c = c2pool::v37n::xmr::credit::encode_tail(cc);
        p.insert(p.end(), c.begin(), c.end());
        CHECK(pn::parse_payload(p) == std::optional<std::uint64_t>(0x0102030405060708ull), "V37N base parses back before V37D + V37C");
        CHECK(fee::parse_donation_owed_payload(p) == std::optional<std::uint64_t>(777), "V37D still parses (V37N sits before it)");
        std::vector<std::uint8_t> q = {1, 2, 3, 4};
        q.insert(q.end(), d.begin(), d.end()); q.insert(q.end(), c.begin(), c.end());
        CHECK(!pn::parse_payload(q), "no V37N tail -> no pay-now (nullopt)");
    }
    const auto ps = three_payees();
    const ::v37::bytes32 D = fee::donation_identity(kNet);
    const auto X = ref_of(55);
    const std::uint64_t owedA = 100000000000ull, owedX = 50000000000ull;
    auto in = fee_on_inputs(kReward); arm_paynow(in, ps);
    x6::OwedEntry oa; oa.pay = ps[0].ref; oa.identity = ps[0].id; oa.owed = owedA; oa.first_eligible = 0;
    x6::OwedEntry ox; ox.pay = X; ox.identity = id_of(X); ox.owed = owedX; ox.first_eligible = 1;
    in.owed = {oa, ox};
    const auto outs = x6::allocate_exact_sum(in);
    const std::uint64_t base = owedA + owedX + fee::kDonationDustPico;   // Σ owed takes + Σ fixed
    // what the receiver reads from the chain: E_b at the cut, payout (non-donation), donation coverage
    Amounts credit; for (const auto& [k, v] : eb_at(kReward, ps)) credit[k] = static_cast<long long>(v);
    Amounts payout; long long sink_total = 0;
    for (const auto& o : outs) { if (o.identity == D) sink_total += static_cast<long long>(o.amount - o.owed_part); else payout[o.identity] += static_cast<long long>(o.amount); }
    const Amounts gross_credit = credit, gross_payout = payout;
    const auto r = pn::net_booking(base, kReward, credit, payout, sink_total, D, 1);
    CHECK(r.ok && r.pool == kReward - base, "receiver pool = total - V37N base = %llu", (unsigned long long)r.pool);
    bool same_alloc = true;
    for (const auto& p : ps) {
        const long long builder_paynow = static_cast<long long>(amount_to(outs, p.id)) - (p.id == ps[0].id ? static_cast<long long>(owedA) : 0);
        const auto it = r.alloc.find(p.id);
        if ((it == r.alloc.end() ? 0 : it->second) != builder_paynow) same_alloc = false;
    }
    CHECK(same_alloc, "receiver allocation == the builder's emitted pay-now, per payee");
    CHECK(payout.size() == 2 && payout.at(ps[0].id) == static_cast<long long>(owedA) && payout.at(id_of(X)) == static_cast<long long>(owedX),
          "net payout == the owed takes exactly (A 1e11, X 5e10): pay-now left the payout map");
    bool credit_net_ok = true;
    for (const auto& [k, v] : gross_credit) {
        const long long net = credit.count(k) ? credit.at(k) : 0;
        if (net != v - (r.alloc.count(k) ? r.alloc.at(k) : 0) || net < 0) credit_net_ok = false;
    }
    CHECK(credit_net_ok, "net credit == E_b - pay-now >= 0 for every payee");
    // under-paying coinbase: refused, maps untouched
    {
        Amounts c2 = gross_credit, p2 = gross_payout; p2[ps[2].id] -= 1;
        const auto rr = pn::net_booking(base, kReward, c2, p2, sink_total, D, 1);
        CHECK(!rr.ok && c2 == gross_credit, "a coinbase paying 1 piconero less than its committed pay-now is REFUSED: %s", rr.why.c_str());
    }
    // the ledger: seed A and X as finalized owed, then FOUND(b1) net, FINALIZE(b1)
    auto seeded = [&](st::OwedLedger& L) {
        L.on_block_found("seed", Amounts{{ps[0].id, static_cast<long long>(owedA)}, {id_of(X), static_cast<long long>(owedX)}}, {});
        L.on_block_finalized("seed", 1);
    };
    st::OwedLedger L(7);
    seeded(L);
    L.on_block_found("b1", credit, payout);
    long long eo_min = 0;
    for (const auto& [k, v] : L.effective_owed_all()) if (v < eo_min) eo_min = v;
    CHECK(eo_min == 0, "pending window: EffectiveOwed never negative (min %lld)", eo_min);
    {
        st::OwedLedger G(7); seeded(G);
        G.on_block_found("b1", gross_credit, gross_payout);   // master's GROSS booking of a pay-now coinbase
        long long gmin = 0; for (const auto& [k, v] : G.effective_owed_all()) if (v < gmin) gmin = v;
        CHECK(gmin < 0, "(contrast) GROSS booking of the same coinbase drives EffectiveOwed negative (%lld): the net booking is required", gmin);
    }
    L.on_block_finalized("b1", 2);
    bool conserve = true;
    for (const auto& p : ps) {
        const long long credited = static_cast<long long>(eb_at(kReward, ps).at(p.id)) + (p.id == ps[0].id ? static_cast<long long>(owedA) : 0);
        const long long paid = static_cast<long long>(amount_to(outs, p.id));
        const auto it = L.finalW().find(p.id);
        const long long outstanding = it == L.finalW().end() ? 0 : it->second;
        if (paid != credited - outstanding || outstanding < 0) conserve = false;
        std::printf("    payee %s…: credited %lld paid %lld outstanding %lld\n", hex8(p.id).c_str(), credited, paid, outstanding);
    }
    CHECK(conserve, "FINALIZE: paid on-chain == credited - outstanding owed, exactly, per payee (no double pay)");
    // orphan: the pending row goes whole; the ledger == a run that never saw b1
    {
        st::OwedLedger O(7); seeded(O);
        Amounts c3 = gross_credit, p3 = gross_payout;
        (void)pn::net_booking(base, kReward, c3, p3, sink_total, D, 1);
        O.on_block_found("b1", c3, p3);
        O.on_block_orphaned("b1", {});
        st::OwedLedger N(7); seeded(N);
        CHECK(O.owed_digest() == N.owed_digest() && O.effective_owed_all() == N.effective_owed_all() && O.finalW() == N.finalW(),
              "ORPHAN(b1) pre-SETTLED: nothing netted, owed_digest + EffectiveOwed == the run without b1");
    }
}

// ---------------------------------------------------------------------------
void suite_source() {
    std::printf("== P4. settlement source end-to-end (credit cut + projected payees) ==\n");
    const auto ps = three_payees();
    st::OwedLedger L(7);
    std::map<::v37::bytes32, ::v37::ScriptRef> refs;
    for (const auto& p : ps) refs[p.id] = p.ref;
    refs[fee::donation_identity(kNet)] = fee::donation_ref(kNet);
    o2::PayOfFn pay_of = [refs](const ::v37::bytes32& k) {
        auto it = refs.find(k); if (it != refs.end()) return it->second;
        ::v37::ScriptRef r; r.kind = ::v37::ScriptKind::RAW; return r; };
    o2::XmrCoinbaseContext ctx;
    ctx.monero_major_version = 16; ctx.height = 1234; ctx.base_reward = kReward; ctx.fees = 0; ctx.chain_id = 7;
    ctx.lane_commitment = L.owed_digest();
    ctx.residual_sink = fee::donation_ref(kNet); ctx.residual_sink_identity = fee::donation_identity(kNet);
    ctx.fixed = {fee::donation_marker(kNet)}; ctx.h_min = 0; ctx.output_cap = 64;
    ctx.has_credit_cut = true; ctx.credit_cut.next_pos = 99;
    ctx.has_paynow = true;
    for (const auto& p : ps) { st::WeightedPayee w; w.key = p.id; w.weight = ::v37::U256(p.w); w.pay = p.ref; ctx.paynow_payees.push_back(w); }
    std::string why;
    auto src = o2::XmrOwedSettlementSource::build(L, pay_of, ctx, kReward, &why);
    CHECK(src != nullptr, "source builds: %s", why.empty() ? "ok" : why.c_str());
    if (!src) return;
    CHECK(src->paynow_on() && src->paynow_base() == 1, "pay-now armed, V37N base = Σ owed (0) + Σ fixed (1) = %llu", (unsigned long long)src->paynow_base());
    const auto tail = src->extra_nonce_tail();
    CHECK(c2pool::v37n::xmr::paynow::parse_payload(tail) == std::optional<std::uint64_t>(1) &&
          fee::parse_donation_owed_payload(tail).has_value(),
          "the 0x02 tail carries V37N(1) || V37D || V37C (%zu bytes)", tail.size());
    for (std::uint64_t R : std::vector<std::uint64_t>{kReward, kReward + 777777ull}) {
        const auto pm = src->payout_map_at(R);
        long long miners = 0; for (const auto& p : ps) miners += pm.count(p.id) ? pm.at(p.id) : 0;
        const long long don = pm.count(fee::donation_identity(kNet)) ? pm.at(fee::donation_identity(kNet)) : -1;
        CHECK(src->shape_matches_at(R) && miners == static_cast<long long>(R - 1) && don == 1,
              "first block @ reward %llu: miners paid %lld (= reward-1), donation %lld (marker only), shape stable",
              (unsigned long long)R, miners, don);
    }
    // no cut payees -> master's shape, no V37N
    o2::XmrCoinbaseContext c0 = ctx; c0.has_paynow = false; c0.paynow_payees.clear();
    auto s0 = o2::XmrOwedSettlementSource::build(L, pay_of, c0, kReward, &why);
    CHECK(s0 && !s0->paynow_on() && !c2pool::v37n::xmr::paynow::parse_payload(s0->extra_nonce_tail()),
          "no pay-now source (gate unset) -> no V37N tail, master's residual shape");
}

// ---------------------------------------------------------------------------
// P5 -- a REAL assembled block (XmrBlockAssembler, fee model ON, 32-byte rbind,
// owed + pay-now + donation, the widest 0x02 payload V37N|V37D|V37C): it
// builds (regression: the assembler's extra-nonce bound must admit the 12-byte
// V37N tail -- the live rig refused every template before), the K_fair shape
// gate ACCEPTS the pay-now outputs, and the block's own bytes parse back to the
// committed base.
void suite_assembled() {
    std::printf("== P5. assembled block: widest payload + shape gate ==\n");
    namespace asm_ = ::c2pool::xmr::assembly;
    namespace akat = ::c2pool::xmr::assembly::kat;
    namespace pn = c2pool::v37n::xmr::paynow;
    const auto ps = three_payees();
    asm_::AssemblyInputs a;
    a.miner = akat::miner(3000000, 300000, 18000000000000000000ull);
    a.settle = akat::lane_ctx();
    a.settle.residual_sink = fee::donation_ref(kNet);
    a.settle.residual_sink_identity = fee::donation_identity(kNet);
    a.settle.fixed = {fee::donation_marker(kNet)};
    a.mempool = akat::txs(5, 2000, 30000000);
    x6::OwedEntry oa; oa.pay = ps[0].ref; oa.identity = ps[0].id; oa.owed = 1000000000ull; oa.first_eligible = 0;
    a.settle.owed = {oa};
    arm_paynow(a.settle, ps);
    const std::uint64_t base = oa.owed + fee::kDonationDustPico;
    a.extra_nonce_tail = pn::encode_tail(base);
    { const auto d = fee::encode_donation_owed_tail(x6::fold_identity_owed(a.settle)); a.extra_nonce_tail.insert(a.extra_nonce_tail.end(), d.begin(), d.end()); }
    c2pool::v37n::xmr::credit::CreditCut cc; cc.next_pos = 77; cc.spine_digest[5] = 0x33;
    { const auto c = c2pool::v37n::xmr::credit::encode_tail(cc); a.extra_nonce_tail.insert(a.extra_nonce_tail.end(), c.begin(), c.end()); }
    a.extra_nonce_bind_size = 32;
    a.extra_nonce_bind = [](std::uint32_t en, std::uint8_t* out) { for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(en * 7 + i); return true; };
    std::string why;
    auto t = asm_::XmrBlockAssembler::build(a, &why);
    CHECK(t != nullptr, "the widest pay-now payload assembles (bound 14 + 32 + 12 + 12 + 44 = %zu): %s",
          static_cast<std::size_t>(::c2pool::xmr::EXTRA_NONCE_MAX_SIZE) + ::c2pool::xmr::EXTRA_NONCE_BIND_MAX +
              asm_::PAYNOW_TAIL_BYTES + asm_::DONATION_OWED_TAIL_BYTES + asm_::CREDIT_CUT_TAIL_BYTES,
          t ? "ok" : why.c_str());
    if (!t) return;
    asm_::BlockBytes b;
    CHECK(t->materialize(5, b, &why), "materializes: %s", why.c_str());
    x6::ReceivedCoinbase rc; std::uint64_t h = 0; std::size_t used = 0;
    const bool pp = asm_::parse_coinbase_prefix(b.full_blob.data() + b.miner_tx_offset, b.miner_tx_size, rc, &h, &used);
    CHECK(pp && pn::parse(rc.tx_extra) == std::optional<std::uint64_t>(base) && fee::parse_donation_owed(rc.tx_extra).has_value() &&
          c2pool::v37n::xmr::credit::parse_from_tx_extra(rc.tx_extra) == std::optional<c2pool::v37n::xmr::credit::CreditCut>(cc),
          "the block's 0x02 carries V37N base %llu, V37D, then the credit cut (P=77)", (unsigned long long)base);
    const auto& o = t->outputs();
    std::uint64_t sum = 0, miners = 0; std::size_t n_pn = 0;
    for (const auto& x : o) { sum += x.amount; if (x.role == x6::CoinbaseOutput::Role::PayNow) ++n_pn; }
    for (const auto& p : ps) miners += amount_to(o, p.id);
    CHECK(sum == t->reward() && amount_to(o, fee::donation_identity(kNet)) == 1 && miners == t->reward() - 1 && n_pn == 2,
          "assembled: exact-sum %llu, donation 1, miners reward-1 (A merged owed+pay-now, 2 PayNow outputs)", (unsigned long long)sum);
    const auto shp = o2::inspect_kfair_coinbase(*t, a.settle.lane_commitment, 5);
    CHECK(shp.kfair_order, "the K_fair coinbase shape gate ACCEPTS the pay-now outputs: %s", shp.why.empty() ? "ok" : shp.why.c_str());
}
#else
void suite_base() {
    std::printf("== BASE: no pay-now API on this tree ==\n");
    const auto ps = three_payees();
    const ::v37::bytes32 D = fee::donation_identity(kNet);
    const auto in = fee_on_inputs(kReward);   // empty ledger: the first pool block
    const auto outs = x6::allocate_exact_sum(in);
    std::uint64_t miners = 0; for (const auto& p : ps) miners += amount_to(outs, p.id);
    CHECK(amount_to(outs, D) == fee::kDonationDustPico,
          "(a) the donation output carries ONLY its marker -- got %llu of %llu (the WHOLE reward)",
          (unsigned long long)amount_to(outs, D), (unsigned long long)kReward);
    CHECK(miners == kReward - 1, "(a) the block's own miners are paid reward-1 -- got %llu", (unsigned long long)miners);
    CHECK(false, "net-at-FOUND pay-now booking (xmr_paynow.hpp) is absent");
}
#endif

}  // namespace

int main() {
    std::printf("v37_xmr_paynow_kat (%s)\n", PAYNOW_FIX ? "fix" : "base");
#if PAYNOW_FIX
    suite_split();
    suite_alloc();
    suite_booking();
    suite_source();
    suite_assembled();
#else
    suite_base();
#endif
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
