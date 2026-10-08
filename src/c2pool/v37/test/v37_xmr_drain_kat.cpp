// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_drain_kat -- THE DRAIN RULE (operator rulings R1/R2/R5, 2026-10-02;
// docs/xmr-lane/settlement-drain.md). Old balances are paid only out of
//     Delta = min(F, floor(R * min(dh, H_cap) / (Q * 16)))     Q = 16, H_cap = 64
// per lane block; the window's E_b is split at P = R - debt_paid and paid in
// full when everyone fits, so a canonical block creates no new balance.
//
//   A (B1)  0 new owed over 24 blocks: no window payee keeps a balance, dT =
//           -debt_paid, F falls strictly to 0 and stays there.
//   B (B2)  F = 0 is master byte for byte: a golden over 10,000 random X6
//           inputs captured from master, and the rule on with F = 0 equal to
//           the rule off on 10,000 more; the whole coinbase on a real source.
//   C (B3)  debt_paid <= Delta, Delta = min(F, R*min(dh,64)/256), exact sum,
//           never an advance, split_at = R - debt_paid, over R x dh x F.
//   D (B4, B8) contested slots: K_o = max(1, 2699 * owed_paid_1 / R) from the
//           FIRST pass's cash; the window keeps >= 2699 - K_o slots; nobody
//           admitted is unreachable; the donation takes no spare.
//   E (B5)  F over the whole ledger (A1): a key whose ref does not resolve
//           counts in F and Delta and is carried.
//   F (B6)  Delta per Monero height on two cadences; the first lane block of
//           a pool takes the cap.
//   G (B9)  E_b(P) > 0 with E_b(R) == 0 fails closed (BuildError::PayNowSplit).
//   H (B14) the dust write-off under the gross-set clock.
//   I (F4-partial, ruling 2026-10-02) only a balance below c(R) goes to the
//           dust pass; a budget-stopped take below c of a balance >= c carries
//           (balance and age kept), the unspent Delta stays in P.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/settle/xmr_coinbase.hpp"
#include "c2pool/v37/w4_settlement.hpp"
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/xmr_paynow.hpp"
#ifndef DRAIN_KAT_GOLDEN_CAPTURE
#include "c2pool/v37/xmr/xmr_o2_settlement_source.hpp"
#endif
#include <sharechain/v37/v37_hash.hpp>

namespace x6  = ::v37::xmr::settle;
namespace fee = c2pool::v37n::xmr::fee;
namespace pn  = c2pool::v37n::xmr::paynow;
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

using u64 = std::uint64_t;
constexpr u64 kTail = 600000000000ull;                 // Monero tail emission: 0.6 XMR
constexpr u64 kXmr  = 1000000000000ull;
constexpr fee::DonationNet kNet = fee::DonationNet::Regtest;
constexpr std::uint32_t kChain = 7;

std::array<std::uint8_t, 32> point_of(std::uint16_t k) {
    ::xmr::coin::SecretKey sec{};
    sec.data()[0] = static_cast<std::uint8_t>(k & 0xff);
    sec.data()[1] = static_cast<std::uint8_t>(k >> 8);
    sec.data()[2] = 0x3c;
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), pub.data(), 32);
    return out;
}
::v37::ScriptRef ref_of(std::uint16_t k) { return ::v37::xmr::make_xmr_std(point_of(k), point_of(static_cast<std::uint16_t>(k + 20000))); }
::v37::bytes32 id_of(const ::v37::ScriptRef& r) { return ::v37::xmr::xmr_identity_key(r); }

// A small cache of refs: point derivation is the slow part of the rigs.
const ::v37::ScriptRef& cref(std::uint16_t k) {
    static std::map<std::uint16_t, ::v37::ScriptRef> m;
    auto it = m.find(k);
    if (it == m.end()) it = m.emplace(k, ref_of(k)).first;
    return it->second;
}

// The pay-now provider exactly as the source builds it: E_b(budget) =
// split_reward(budget, weights), key ASC, eb > 0 only, with the K_fair age.
struct WP { ::v37::ScriptRef ref; ::v37::bytes32 id; ::v37::U256 w; u64 age = 0; };
std::vector<st::WeightedPayee> weighted(const std::vector<WP>& ps) {
    std::vector<st::WeightedPayee> v;
    for (const auto& p : ps) { st::WeightedPayee w; w.key = p.id; w.weight = p.w; w.pay = p.ref; v.push_back(w); }
    return v;
}
std::map<::v37::bytes32, u64> eb_at(u64 budget, const std::vector<WP>& ps) {
    std::map<::v37::bytes32, u64> m;
    const auto wp = weighted(ps);
    const auto amt = st::split_reward(budget, wp);
    for (std::size_t i = 0; i < wp.size(); ++i) if (amt[i] > 0) m[wp[i].key] += amt[i];
    return m;
}
void arm_weights(x6::CoinbaseInputs& in, const std::vector<WP>& ps) {
    in.paynow_at = [ps](u64 budget) {
        std::map<::v37::bytes32, WP> by;
        for (const auto& p : ps) by[p.id] = p;
        std::vector<x6::PayNowEntry> out;
        for (const auto& [k, v] : eb_at(budget, ps)) {
            x6::PayNowEntry e; e.pay = by[k].ref; e.identity = k; e.eb = v; e.age = by[k].age;
            out.push_back(e);
        }
        return out;
    };
    in.paynow_n = ps.size();
}

// ---------------------------------------------------------------------------
// The random X6 inputs of suite B (xorshift64, fixed seed: the golden below is
// a function of this generator and master's allocate_exact_sum).
struct Rng {
    u64 s;
    u64 next() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
    u64 in(u64 lo, u64 hi) { return lo + next() % (hi - lo + 1); }
};
struct RandIn {
    x6::CoinbaseInputs in;
    std::vector<WP> payees;
    std::map<::v37::bytes32, u64> owed_left;
};
RandIn random_inputs(Rng& r, bool with_debt) {
    RandIn ri;
    x6::CoinbaseInputs& in = ri.in;
    in.monero_major_version = 16;
    in.height = r.in(1, 3000000);
    in.chain_id = kChain;
    in.base_reward = r.in(kTail / 4, 3 * kTail);
    in.fees = r.in(0, 3) == 0 ? r.in(0, kTail) : 0;
    const u64 budget = in.base_reward + in.fees;
    const bool fold = r.in(0, 1) == 1;
    if (fold) {
        in.fixed = {fee::donation_marker(kNet)};
        in.residual_sink = fee::donation_ref(kNet);
        in.residual_sink_identity = fee::donation_identity(kNet);
    } else {
        in.residual_sink = cref(900);
        in.residual_sink_identity = id_of(cref(900));
        const u64 nfix = r.in(0, 2);
        for (u64 i = 0; i < nfix; ++i) {
            x6::FixedOutput f; f.pay = cref(static_cast<std::uint16_t>(910 + i)); f.identity = id_of(f.pay); f.amount = r.in(1, budget / 8);
            in.fixed.push_back(f);
        }
    }
    const u64 need = in.fixed.size() + (fold ? 0 : 1);
    in.output_cap = r.in(0, 4) == 0 ? 2700u : static_cast<std::uint32_t>(r.in(need, 14));
    in.spend_floor = r.in(0, 3) != 0;
    if (with_debt) {
        const u64 nowed = r.in(0, 6);
        for (u64 j = 0; j < nowed; ++j) {
            x6::OwedEntry e; e.pay = cref(static_cast<std::uint16_t>(100 + j)); e.identity = id_of(e.pay);
            e.owed = r.in(1, budget / 3); e.first_eligible = r.in(0, 50);
            in.owed.push_back(e);
        }
        const u64 ndust = in.spend_floor ? r.in(0, 4) : 0;
        for (u64 j = 0; j < ndust; ++j) {
            x6::OwedEntry e; e.pay = cref(static_cast<std::uint16_t>(200 + j)); e.identity = id_of(e.pay);
            e.owed = r.in(1, 30000000);
            in.owed_dust.push_back(e);
        }
    }
    const u64 np = r.in(0, 8);
    for (u64 j = 0; j < np; ++j) {
        // some payees are also owed keys (merge), one may be the sink identity
        const std::uint16_t k = (with_debt && r.in(0, 4) == 0) ? static_cast<std::uint16_t>(100 + r.in(0, 5)) : static_cast<std::uint16_t>(300 + j);
        WP p; p.ref = cref(k); p.id = id_of(p.ref); p.w = ::v37::U256(r.in(1, 1000000)); p.age = r.in(0, 1) ? r.in(1, 60) : 0;
        if (r.in(0, 15) == 0) { p.ref = in.residual_sink; p.id = in.residual_sink_identity; }
        bool dup = false; for (const auto& q : ri.payees) if (q.id == p.id) dup = true;
        if (dup) continue;
        ri.payees.push_back(p);
        if (with_debt && r.in(0, 2) == 0) ri.owed_left[p.id] = r.in(1, budget / 4);
    }
    if (!ri.payees.empty() || r.in(0, 1)) {
        const auto ps = ri.payees; const auto ol = ri.owed_left;
        in.paynow_at = [ps, ol](u64 b) {
            std::map<::v37::bytes32, WP> by;
            for (const auto& p : ps) by[p.id] = p;
            std::vector<x6::PayNowEntry> out;
            for (const auto& [k, v] : eb_at(b, ps)) {
                x6::PayNowEntry e; e.pay = by[k].ref; e.identity = k; e.eb = v; e.age = by[k].age;
                if (auto it = ol.find(k); it != ol.end()) e.owed_left = it->second;
                out.push_back(e);
            }
            return out;
        };
        in.paynow_n = ps.size();
    }
    return ri;
}
void put64(std::vector<std::uint8_t>& v, u64 x) { for (int i = 0; i < 8; ++i) v.push_back(static_cast<std::uint8_t>(x >> (8 * i))); }
void serialize_alloc(std::vector<std::uint8_t>& v, const std::vector<x6::CoinbaseOutput>& outs, x6::BuildError err, const Amounts& cd) {
    v.push_back(static_cast<std::uint8_t>(err));
    put64(v, outs.size());
    for (const auto& o : outs) {
        v.push_back(static_cast<std::uint8_t>(o.role));
        put64(v, o.amount); put64(v, o.owed_part);
        v.insert(v.end(), o.identity.begin(), o.identity.end());
    }
    put64(v, cd.size());
    for (const auto& [k, d] : cd) { v.insert(v.end(), k.begin(), k.end()); put64(v, static_cast<u64>(d)); }
}
constexpr u64 kGoldenSeed = 0x5eed0d2a1b3c4d5eull;
constexpr int kGoldenN = 10000;
// master's allocate_exact_sum over the kGoldenN inputs, captured on master
// (93471eeb2 + the lane-rules slice, which leaves X6 untouched) by building
// this file with -DDRAIN_KAT_GOLDEN_CAPTURE.
const char* kMasterGolden = "321174eb4bd61f4155b246a132ef0cbe9cd9353440aad7c34d0d9f0db2ad7297";
std::string golden_of_master_path() {
    Rng r{kGoldenSeed};
    std::vector<std::uint8_t> all;
    for (int i = 0; i < kGoldenN; ++i) {
        const RandIn ri = random_inputs(r, true);
        x6::BuildError err{};
        Amounts cd;
        const auto outs = x6::allocate_exact_sum(ri.in, &err, &cd);
        serialize_alloc(all, outs, err, cd);
    }
    const ::v37::bytes32 d = ::v37::sha256d(all);
    static const char* hx = "0123456789abcdef";
    std::string s;
    for (auto b : d) { s.push_back(hx[b >> 4]); s.push_back(hx[b & 15]); }
    return s;
}

#ifndef DRAIN_KAT_GOLDEN_CAPTURE
namespace o2 = c2pool::v37n::xmr::o2;
constexpr o2::DrainRule kRule{1, 16, 64};
constexpr o2::DrainRule kMaster{0, 0, 0};

// The ledger rules the daemon runs with the drain rule's flag day.
st::OwedLedgerRules lane_rules() {
    st::OwedLedgerRules r;
    r.arm_floor = static_cast<long long>(x6::spend_floor(x6::kTailSubsidy));
    r.rotate_on_payment = true;
    r.decay_horizon = 8640;
    r.decay_half_life = 2160;
    r.lane_height = true;
    r.decay_from_gross = true;
    return r;
}

// One pool: its ledger, the refs its lane taught, its window (the cut's
// payees). build() runs the REAL source (D0-D2) and X6 (D3-D6); book() books
// the block exactly as main's booking does: E_b refolded at P (D7), the
// recompute's credit_delta, the net booking, FOUND with (height, G_b).
struct Pool {
    st::OwedLedger L;
    std::map<::v37::bytes32, ::v37::ScriptRef> refs;
    std::vector<WP> window;
    o2::DrainRule drain = kRule;
    std::uint32_t cap = 2700;
    int nblk = 0;
    explicit Pool(st::OwedLedgerRules r = lane_rules()) : L(kChain, r) {
        refs[fee::donation_identity(kNet)] = fee::donation_ref(kNet);
    }
    void learn(const ::v37::ScriptRef& r) { refs[id_of(r)] = r; }
    o2::PayOfFn pay_of() const {
        auto m = refs;
        return [m](const ::v37::bytes32& k) {
            auto it = m.find(k); if (it != m.end()) return it->second;
            ::v37::ScriptRef raw; raw.kind = ::v37::ScriptKind::RAW; return raw;
        };
    }
    void seed(const ::v37::ScriptRef& r, long long amount, u64 bin) {   // a seed: not a lane block
        learn(r);
        const std::string bid = "seed-" + std::to_string(nblk++);
        L.on_block_found(bid, Amounts{{id_of(r), amount}}, {});
        L.on_block_finalized(bid, bin);
    }
    o2::XmrCoinbaseContext ctx(u64 h, u64 R) const {
        o2::XmrCoinbaseContext c;
        c.monero_major_version = 16;
        c.height = h;
        c.prev_id.data()[0] = static_cast<std::uint8_t>(h); c.prev_id.data()[1] = static_cast<std::uint8_t>(h >> 8); c.prev_id.data()[31] = 0x37;
        c.base_reward = R; c.fees = 0;
        c.chain_id = kChain;
        c.lane_commitment = L.owed_digest();
        c.residual_sink = fee::donation_ref(kNet); c.residual_sink_identity = fee::donation_identity(kNet);
        c.fixed = {fee::donation_marker(kNet)};
        c.h_min = 0; c.output_cap = cap;
        c.kfair_salted_ties = true; c.spend_floor = true;
        c.has_credit_cut = true; c.credit_cut.next_pos = 1000 + h; c.credit_cut.spine_digest[0] = 0x5c;
        c.has_paynow = true;
        c.paynow_payees = weighted(window);
        c.drain = drain;
        return c;
    }
    struct Built {
        bool ok = false; std::string why;
        std::unique_ptr<o2::XmrOwedSettlementSource> src;
        std::vector<x6::CoinbaseOutput> outs; Amounts cd; x6::AllocStats st; x6::BuildError err{};
    };
    Built build(u64 h, u64 R) const {
        Built b;
        b.src = o2::XmrOwedSettlementSource::build(L, pay_of(), ctx(h, R), R, &b.why);
        if (!b.src) return b;
        b.outs = x6::allocate_exact_sum(b.src->inputs_at(R, {}), &b.err, &b.cd, &b.st);
        b.ok = !b.outs.empty() && b.err == x6::BuildError::None;
        if (!b.ok && b.why.empty()) b.why = x6::to_string(b.err);
        return b;
    }
    // The booking (main: drain_refold + paynow_net + FOUND). Returns the
    // NETTED credit (what the block leaves as new balance) in *left.
    void book(u64 h, u64 R, const Built& b, Amounts* left = nullptr, Amounts* paid_out = nullptr) {
        Amounts credit;
        for (const auto& [k, v] : eb_at(b.src->drain_on() ? b.st.split_at : R, window)) credit[k] = static_cast<long long>(v);
        std::set<::v37::bytes32> gross;
        for (const auto& [k, v] : credit) if (v > 0) gross.insert(k);
        for (const auto& [k, d] : b.cd) { credit[k] += d; if (credit[k] == 0) credit.erase(k); }
        Amounts payout; long long sink_total = 0;
        for (const auto& o : b.outs) {
            if (o.identity == fee::donation_identity(kNet)) { sink_total += static_cast<long long>(o.amount); continue; }
            payout[o.identity] += static_cast<long long>(o.amount);
        }
        if (paid_out) *paid_out = payout;
        std::uint64_t base = 0;
        for (const auto& e : b.src->inputs().owed) base += e.owed;
        const auto r = pn::net_booking(std::optional<std::uint64_t>(base), R, credit, payout, sink_total,
                                       fee::donation_identity(kNet), static_cast<long long>(fee::kDonationMarkerPico), true);
        (void)r;
        if (left) *left = credit;
        st::LaneFound lf; lf.height = h; lf.gross = gross;
        L.on_block_found("blk-" + std::to_string(h), credit, payout, std::nullopt, nullptr, &lf);
    }
    void finalize(u64 h, u64 bin) { L.on_block_finalized("blk-" + std::to_string(h), bin); }
    u64 F() const { u64 f = 0; for (const auto& [k, v] : L.effective_owed_all()) { (void)k; if (v > 0) f += static_cast<u64>(v); } return f; }
    long long sum_final() const { long long s = 0; for (const auto& [k, v] : L.finalW()) { (void)k; s += v; } return s; }
};
u64 expect_delta(u64 F, u64 R, u64 dh) {
    const u64 eff = (dh == 0 || dh > 64) ? 64 : dh;
    const u64 d = static_cast<u64>(static_cast<unsigned __int128>(R) * eff / 256);
    return std::min(F, d);
}

// ---------------------------------------------------------------------------
void suite_a_no_new_owed() {
    std::printf("== A (B1). 0 new owed: 24 lane blocks drain a 1.2 XMR float ==\n");
    Pool p;
    for (std::uint16_t k = 11; k <= 16; ++k) { WP w; w.ref = cref(k); w.id = id_of(w.ref); w.w = ::v37::U256(static_cast<u64>(k - 10)); p.window.push_back(w); p.learn(w.ref); }
    for (std::uint16_t k = 21; k <= 23; ++k) p.seed(cref(k), static_cast<long long>(4 * kXmr / 10), k - 20);   // 3 gone keys, 0.4 XMR each
    const u64 R = kTail + 12345678;
    int built = 0, delta_ok = 0, bound_ok = 0, no_new = 0, full = 0, dT_ok = 0, f_ok = 0;
    u64 F_prev = p.F();
    std::printf("  float F=%llu piconero over 3 gone keys, window of 6 payees, R=%llu, dh=40\n", (unsigned long long)F_prev, (unsigned long long)R);
    for (int i = 0; i < 24; ++i) {
        const u64 h = 100000 + 40 * static_cast<u64>(i);
        const auto b = p.build(h, R);
        if (!b.ok) { std::printf("  block %d: build failed: %s\n", i, b.why.c_str()); continue; }
        ++built;
        const u64 dh = i == 0 ? 0 : 40;
        if (b.src->drain_delta() == expect_delta(F_prev, R, dh) && b.src->drain_F() == F_prev) ++delta_ok;
        if (b.st.debt_paid <= b.src->drain_delta() && b.st.split_at == R - b.st.debt_paid) ++bound_ok;
        const long long before = p.sum_final();
        Amounts left, paid;
        p.book(h, R, b, &left, &paid);
        bool neg = true;
        for (const auto& [k, v] : left) if (v > 0) neg = false;
        if (neg) ++no_new;
        bool all = true;
        for (const auto& [k, v] : eb_at(b.st.split_at, p.window)) if (!paid.count(k) || static_cast<u64>(paid.at(k)) != v) all = false;
        if (all) ++full;
        p.finalize(h, h);
        if (p.sum_final() - before == -static_cast<long long>(b.st.debt_paid)) ++dT_ok;
        const u64 F_now = p.F();
        if ((F_prev > 0 && F_now < F_prev) || (F_prev == 0 && F_now == 0)) ++f_ok;
        if (i < 3 || i % 6 == 5 || F_now == 0)
            std::printf("  block %2d h=%llu F=%llu Delta=%llu debt_paid=%llu P=%llu -> F=%llu\n", i, (unsigned long long)h,
                        (unsigned long long)F_prev, (unsigned long long)b.src->drain_delta(), (unsigned long long)b.st.debt_paid,
                        (unsigned long long)b.st.split_at, (unsigned long long)F_now);
        F_prev = F_now;
    }
    CHECK(built == 24, "every block builds (%d/24)", built);
    CHECK(delta_ok == 24, "Delta = min(F, R*min(dh,64)/256), first block at the cap (%d/24)", delta_ok);
    CHECK(bound_ok == 24, "debt_paid <= Delta and P = R - debt_paid (%d/24)", bound_ok);
    CHECK(no_new == 24, "0 new owed: the net booking leaves no positive row (%d/24)", no_new);
    CHECK(full == 24, "every window payee is paid its E_b(P) in full (%d/24)", full);
    CHECK(dT_ok == 24, "dT = -debt_paid at every FINALIZE (%d/24)", dT_ok);
    CHECK(f_ok == 24, "F falls strictly while positive, then stays 0 (%d/24)", f_ok);
    CHECK(p.F() == 0, "the float is drained (F=%llu)", (unsigned long long)p.F());
}

// ---------------------------------------------------------------------------
void suite_b_master_identity() {
    std::printf("== B (B2). F = 0 is master, byte for byte ==\n");
    const std::string g = golden_of_master_path();
    CHECK(g == kMasterGolden, "rule off: %d random X6 inputs (owed, dust, DEBT FIRST, caps, fold or sink) allocate exactly as "
          "master's golden (%s...)", kGoldenN, g.substr(0, 16).c_str());
    // rule on with F = 0 (no owed, no dust, no owed_left) == rule off, on 10,000 more inputs
    Rng r{0xf0f0d2a1b3c4d5e6ull};
    int same = 0, ran = 0;
    for (int i = 0; i < kGoldenN; ++i) {
        RandIn ri = random_inputs(r, false);
        x6::BuildError e0{}, e1{};
        Amounts c0, c1;
        const auto o0 = x6::allocate_exact_sum(ri.in, &e0, &c0);
        x6::CoinbaseInputs on = ri.in;
        on.paynow_first = true;
        on.drain_budget = 0;
        x6::AllocStats st;
        const auto o1 = x6::allocate_exact_sum(on, &e1, &c1, &st);
        std::vector<std::uint8_t> a, b;
        serialize_alloc(a, o0, e0, c0);
        serialize_alloc(b, o1, e1, c1);
        for (std::size_t j = 0; j < o0.size() && j < o1.size(); ++j) if (!(o0[j].pay == o1[j].pay)) b.push_back(1);
        ++ran;
        if (a == b && (e1 != x6::BuildError::None || st.split_at == ri.in.base_reward + ri.in.fees)) ++same;
    }
    CHECK(same == ran, "rule on, F = 0: outputs, roles, owed_part, credit_delta equal the rule off on %d/%d random inputs, P == R", same, ran);
    // a real source: the whole coinbase (outputs, keys, tx_extra) with the rule on and an empty ledger
    Pool on, off;
    off.drain = kMaster;
    for (std::uint16_t k = 31; k <= 34; ++k) {
        WP w; w.ref = cref(k); w.id = id_of(w.ref); w.w = ::v37::U256(static_cast<u64>(k)); on.window.push_back(w); off.window.push_back(w);
        on.learn(w.ref); off.learn(w.ref);
    }
    const auto b1 = on.build(5000, kTail + 777), b0 = off.build(5000, kTail + 777);
    CHECK(b1.ok && b0.ok && b1.src->drain_on() && !b0.src->drain_on() &&
          b1.src->built().prefix_hash == b0.src->built().prefix_hash && b1.src->extra_nonce_tail() == b0.src->extra_nonce_tail(),
          "real source, F = 0: the rule-on coinbase prefix and 0x02 tail are the rule-off bytes (Delta %llu)",
          b1.ok ? (unsigned long long)b1.src->drain_delta() : 0ull);
}

// ---------------------------------------------------------------------------
void suite_c_bound() {
    std::printf("== C (B3). debt_paid <= Delta over R x dh x F ==\n");
    const u64 Rs[] = {kTail, kTail + 1000, 2 * kTail, 3 * kTail};
    const u64 dhs[] = {1, 16, 64, 500};
    int combos = 0, good = 0;
    for (const u64 R : Rs) for (const u64 dh : dhs) {
        const u64 D = expect_delta(~u64{0}, R, dh);
        const u64 Fs[] = {0, 1, D - 1, D, D + 1, 10 * R};
        for (const u64 F : Fs) {
            Pool p;
            for (std::uint16_t k = 41; k <= 43; ++k) { WP w; w.ref = cref(k); w.id = id_of(w.ref); w.w = ::v37::U256(static_cast<u64>(k)); p.window.push_back(w); p.learn(w.ref); }
            if (F > 0) p.seed(cref(49), static_cast<long long>(F), 1);
            const u64 h = 700000;
            {   // the previous lane block of this pool, dh heights below (FOUND + FINALIZE, nothing paid)
                st::LaneFound lf; lf.height = h - dh;
                p.L.on_block_found("prev", {}, {}, std::nullopt, nullptr, &lf);
                p.L.on_block_finalized("prev", h - dh);
            }
            const auto b = p.build(h, R);
            ++combos;
            if (!b.ok) { std::printf("  R=%llu dh=%llu F=%llu: build failed: %s\n", (unsigned long long)R, (unsigned long long)dh, (unsigned long long)F, b.why.c_str()); continue; }
            u64 sum = 0; for (const auto& o : b.outs) sum += o.amount;
            const auto ebp = eb_at(b.st.split_at, p.window);
            bool no_adv = true;
            for (const auto& o : b.outs) {
                if (o.identity == id_of(cref(49))) { if (o.amount > F) no_adv = false; continue; }
                if (o.identity == fee::donation_identity(kNet)) continue;
                const auto it = ebp.find(o.identity);
                if (it == ebp.end() || o.amount > it->second) no_adv = false;
            }
            const bool ok = b.src->drain_delta() == std::min(F, D) && b.src->drain_dh() == dh &&
                            b.st.debt_paid <= b.src->drain_delta() && b.st.debt_paid == std::min(F, D) &&
                            sum == R && no_adv && b.st.split_at == R - b.st.debt_paid;
            if (ok) ++good;
            else std::printf("  R=%llu dh=%llu F=%llu: Delta=%llu debt_paid=%llu P=%llu sum=%llu no_adv=%d\n", (unsigned long long)R,
                             (unsigned long long)dh, (unsigned long long)F, (unsigned long long)b.src->drain_delta(),
                             (unsigned long long)b.st.debt_paid, (unsigned long long)b.st.split_at, (unsigned long long)sum, no_adv ? 1 : 0);
        }
    }
    CHECK(good == combos, "Delta = min(F, R*min(dh,64)/256), debt_paid = min(F, Delta) <= Delta, exact sum, no advance, "
          "split_at = R - debt_paid (%d/%d combinations)", good, combos);
    {   // D5: the dust pass draws on Delta - owed_paid only: a slice the owed pass used up leaves no dust cash
        Pool p;
        for (std::uint16_t k = 41; k <= 43; ++k) { WP w; w.ref = cref(k); w.id = id_of(w.ref); w.w = ::v37::U256(static_cast<u64>(k)); p.window.push_back(w); p.learn(w.ref); }
        const u64 R = kTail, h = 700000;
        const u64 D = expect_delta(~u64{0}, R, 1);
        p.seed(cref(49), static_cast<long long>(D), 1);   // the owed pass takes all of Delta
        for (std::uint16_t k = 0; k < 8; ++k) p.seed(cref(static_cast<std::uint16_t>(2000 + k)), 10000000ll, 2);   // sub-floor dust
        st::LaneFound lf; lf.height = h - 1;
        p.L.on_block_found("prev", {}, {}, std::nullopt, nullptr, &lf);
        p.L.on_block_finalized("prev", h - 1);
        const auto b = p.build(h, R);
        CHECK(b.ok && b.st.owed_paid == D && b.st.dust_paid == 0 && b.st.debt_paid == D,
              "D5: the owed pass spent Delta (%llu): the dust pass pays nothing more (dust %llu, debt %llu)",
              (unsigned long long)D, (unsigned long long)b.st.dust_paid, (unsigned long long)b.st.debt_paid);
    }
}

// ---------------------------------------------------------------------------
void suite_d_contested() {
    std::printf("== D (B4, B8). contested slots: 2700 debts of 2c, 3000 payees, R = 0.6 XMR ==\n");
    Pool p;
    const u64 R = kTail;
    const u64 c = x6::spend_floor(R);
    for (std::uint16_t k = 0; k < 2700; ++k) p.seed(cref(static_cast<std::uint16_t>(1000 + k)), static_cast<long long>(2 * c), 1 + k / 100);
    for (std::uint16_t k = 0; k < 3000; ++k) {
        WP w; w.ref = cref(static_cast<std::uint16_t>(5000 + k)); w.id = id_of(w.ref); w.w = ::v37::U256(u64{1});
        p.window.push_back(w); p.learn(w.ref);
    }
    const auto b = p.build(900000, R);
    CHECK(b.ok, "builds: %s", b.ok ? "ok" : b.why.c_str());
    if (!b.ok) return;
    const u64 cap_owed = 2699;
    std::size_t owed_n = 0, paynow_n = 0; u64 don = 0, sum = 0;
    for (const auto& o : b.outs) {
        sum += o.amount;
        if (o.identity == fee::donation_identity(kNet)) { don += o.amount; continue; }
        if (o.role == x6::CoinbaseOutput::Role::Owed) ++owed_n;
        if (o.role == x6::CoinbaseOutput::Role::PayNow) ++paynow_n;
    }
    const u64 k_first = std::max<u64>(1, static_cast<u64>(static_cast<unsigned __int128>(cap_owed) * b.st.owed_paid_1 / R));
    const u64 k_final = std::max<u64>(1, static_cast<u64>(static_cast<unsigned __int128>(cap_owed) * b.st.owed_paid / R));
    std::printf("  Delta=%llu first pass %llu slots %llu pico -> K_o=%llu; owed outputs %zu (%llu pico), pay-now outputs %zu, donation %llu\n",
                (unsigned long long)b.src->drain_delta(), (unsigned long long)cap_owed, (unsigned long long)b.st.owed_paid_1,
                (unsigned long long)b.st.k_o, owed_n, (unsigned long long)b.st.owed_paid, paynow_n, (unsigned long long)don);
    CHECK(b.st.contested && b.st.owed_paid_1 == cap_owed * 2 * c, "contested; the first owed pass filled all %llu slots (%llu pico)",
          (unsigned long long)cap_owed, (unsigned long long)b.st.owed_paid_1);
    CHECK(b.st.k_o == k_first, "K_o = max(1, 2699 * owed_paid_1 / R) = %llu, from the FIRST pass's cash (B5)", (unsigned long long)k_first);
    CHECK(k_final != b.st.k_o && b.st.owed_paid < b.st.owed_paid_1,
          "B8: the re-run pays less (%llu); K_o from the final cash would be %llu, not %llu", (unsigned long long)b.st.owed_paid,
          (unsigned long long)k_final, (unsigned long long)b.st.k_o);
    CHECK(owed_n <= b.st.k_o && owed_n == b.st.k_o, "the owed pass keeps exactly K_o = %llu slots (%zu owed outputs)", (unsigned long long)b.st.k_o, owed_n);
    CHECK(paynow_n >= cap_owed - b.st.k_o && paynow_n > 0, "the window keeps >= 2699 - K_o slots: %zu pay-now payees admitted (nobody admitted unreachable)", paynow_n);
    CHECK(don == 0 && sum == R, "the donation takes no spare (%llu), exact sum", (unsigned long long)don);
}

// X6 inputs by hand (fee model, spend floor, the rule on) for the two small contested cases below.
x6::CoinbaseInputs small_inputs(u64 R, std::uint32_t cap, u64 delta) {
    x6::CoinbaseInputs in;
    in.monero_major_version = 16; in.height = 4242; in.chain_id = kChain; in.base_reward = R;
    in.fixed = {fee::donation_marker(kNet)};
    in.residual_sink = fee::donation_ref(kNet); in.residual_sink_identity = fee::donation_identity(kNet);
    in.output_cap = cap; in.spend_floor = true;
    in.paynow_first = true; in.drain_budget = delta;
    return in;
}

void suite_d2_no_debt_first() {
    std::printf("== D2 (R1). DEBT FIRST is gone: a waiting payee's E_b never pays an admitted payee's old balance ==\n");
    const u64 R = kTail, delta = R / 64;
    auto in = small_inputs(R, 8, delta);   // 7 owed/pay-now slots
    x6::OwedEntry o; o.pay = cref(400); o.identity = id_of(o.pay); o.owed = delta; o.first_eligible = 0;
    in.owed.push_back(o);
    std::vector<WP> ps;
    for (std::uint16_t k = 0; k < 10; ++k) { WP w; w.ref = cref(static_cast<std::uint16_t>(410 + k)); w.id = id_of(w.ref); w.w = ::v37::U256(u64{1}); w.age = 5 + k; ps.push_back(w); }
    const ::v37::bytes32 w0 = ps[0].id;   // the oldest: admitted first, and it holds an old balance the owed pass did not take
    in.paynow_at = [ps, w0](u64 b) {
        std::vector<x6::PayNowEntry> out;
        std::map<::v37::bytes32, WP> by; for (const auto& p : ps) by[p.id] = p;
        for (const auto& [k, v] : eb_at(b, ps)) {
            x6::PayNowEntry e; e.pay = by[k].ref; e.identity = k; e.eb = v; e.age = by[k].age;
            if (k == w0) e.owed_left = 5000000000ull;
            out.push_back(e);
        }
        return out;
    };
    x6::BuildError err{}; Amounts cd; x6::AllocStats st;
    const auto outs = x6::allocate_exact_sum(in, &err, &cd, &st);
    const auto ebp = eb_at(st.split_at, ps);
    long long waiting_left = 0; std::size_t waiting = 0; u64 w0_paid = 0, admitted_sum = 0, plus_sum = 0;
    for (const auto& [k, v] : ebp) {
        u64 paid = 0; for (const auto& x : outs) if (x.identity == k) paid += x.amount;
        const long long d = cd.count(k) ? cd.at(k) : 0;
        if (paid == 0) { ++waiting; waiting_left += static_cast<long long>(v) + d; }
        else { admitted_sum += paid; plus_sum += static_cast<u64>(d > 0 ? d : 0); if (paid != v + static_cast<u64>(d > 0 ? d : 0)) admitted_sum = ~u64{0}; }
        if (k == w0) w0_paid = paid;
    }
    CHECK(err == x6::BuildError::None && st.contested && waiting > 0 && waiting_left == 0,
          "contested (%zu waiting): every waiting payee's E_b(P) is redistributed, its credit nets to 0 (left %lld)", waiting, waiting_left);
    CHECK(admitted_sum != ~u64{0} && w0_paid == ebp.at(w0) + static_cast<u64>(cd.count(w0) ? cd.at(w0) : 0),
          "the admitted payee with an old balance is paid E_b(P) + its redistribution share (%llu), never its old balance out of the spare",
          (unsigned long long)w0_paid);
}

void suite_d3_recv_fallback() {
    std::printf("== D3. the admitted payees' E_b(P) sums to 0: the moved cash goes to the owed payees, not the donation ==\n");
    const u64 R = kTail, delta = R / 64;
    auto in = small_inputs(R, 2, delta);   // one owed/pay-now slot: K_o = 1 = cap_owed, nobody is admitted
    x6::OwedEntry o; o.pay = cref(450); o.identity = id_of(o.pay); o.owed = delta;
    in.owed.push_back(o);
    std::vector<WP> ps;
    for (std::uint16_t k = 0; k < 3; ++k) { WP w; w.ref = cref(static_cast<std::uint16_t>(460 + k)); w.id = id_of(w.ref); w.w = ::v37::U256(static_cast<u64>(k + 1)); ps.push_back(w); }
    arm_weights(in, ps);
    x6::BuildError err{}; Amounts cd; x6::AllocStats st;
    const auto outs = x6::allocate_exact_sum(in, &err, &cd, &st);
    u64 don = 0, to_o = 0; for (const auto& x : outs) { if (x.identity == fee::donation_identity(kNet)) don += x.amount; if (x.identity == o.identity) to_o += x.amount; }
    long long sum_cd = 0; for (const auto& [k, d] : cd) { (void)k; sum_cd += d; }
    const auto ebp = eb_at(st.split_at, ps);
    u64 wait_sum = 0; for (const auto& [k, v] : ebp) { (void)k; wait_sum += v; }
    CHECK(err == x6::BuildError::None && don == 0 && to_o == delta + wait_sum && sum_cd == 0 && cd.count(o.identity) && cd.at(o.identity) == static_cast<long long>(wait_sum),
          "nobody admitted: the donation takes nothing (%llu); the owed payee is paid its take + the moved %llu, credited the same; credit_delta sums to 0",
          (unsigned long long)don, (unsigned long long)wait_sum);
}

// ---------------------------------------------------------------------------
void suite_e_ledger_F() {
    std::printf("== E (B5). F is the whole ledger (amendment A1) ==\n");
    const ::v37::ScriptRef K1 = cref(71), U = cref(72);
    auto run = [&](bool u_known, Pool::Built* keep) {
        auto p = std::make_unique<Pool>();
        for (std::uint16_t k = 51; k <= 53; ++k) { WP w; w.ref = cref(k); w.id = id_of(w.ref); w.w = ::v37::U256(static_cast<u64>(k)); p->window.push_back(w); p->learn(w.ref); }
        p->seed(K1, 50000000000ll, 1);                                    // 0.05 XMR, payable
        p->L.on_block_found("seed-u", Amounts{{id_of(U), 80000000000ll}}, {});   // 0.08 XMR whose ref this node cannot resolve
        p->L.on_block_finalized("seed-u", 2);
        if (u_known) p->learn(U);
        *keep = p->build(800000, kTail);
        return p;
    };
    Pool::Built bu, bk;
    auto pu = run(false, &bu);
    auto pk = run(true, &bk);
    CHECK(bu.ok && bk.ok, "both build: %s %s", bu.why.c_str(), bk.why.c_str());
    if (!bu.ok || !bk.ok) return;
    const u64 F = 130000000000ull;
    CHECK(bu.src->drain_F() == F && bk.src->drain_F() == F, "F counts the unresolvable key: %llu / %llu (expected %llu)",
          (unsigned long long)bu.src->drain_F(), (unsigned long long)bk.src->drain_F(), (unsigned long long)F);
    CHECK(bu.src->drain_delta() == bk.src->drain_delta() && bu.src->drain_delta() == expect_delta(F, kTail, 0),
          "Delta is the same whether or not the ref resolves: %llu", (unsigned long long)bu.src->drain_delta());
    u64 to_u = 0, to_k1 = 0;
    for (const auto& o : bu.outs) { if (o.identity == id_of(U)) to_u += o.amount; if (o.identity == id_of(K1)) to_k1 += o.amount; }
    CHECK(to_u == 0 && to_k1 == 50000000000ull && bu.src->carried_unpayable() >= 1,
          "unresolvable: the key is carried (paid %llu), the payable debt is paid (%llu)", (unsigned long long)to_u, (unsigned long long)to_k1);
    CHECK(bu.st.debt_paid == 50000000000ull && bu.st.split_at == kTail - bu.st.debt_paid,
          "P = R - the debt actually paid (%llu), not R - Delta", (unsigned long long)bu.st.split_at);
    u64 to_u2 = 0; for (const auto& o : bk.outs) if (o.identity == id_of(U)) to_u2 += o.amount;
    CHECK(to_u2 == 80000000000ull, "once the ref resolves the same Delta pays it (%llu)", (unsigned long long)to_u2);
}

// ---------------------------------------------------------------------------
void suite_f_per_height() {
    std::printf("== F (B6). Delta per Monero height, two cadences ==\n");
    {
        st::OwedLedger fresh(kChain, lane_rules());
        CHECK(fresh.heights_since_last_lane(123456) == 0 && fresh.prev_lane_height() == 0,
              "a ledger with no lane block: heights_since_last_lane == 0 (the drain takes the cap)");
    }
    const u64 R = kTail + 3000000;
    auto series = [&](u64 step, std::vector<u64>& deltas, std::vector<u64>& dhs) {
        Pool p;
        for (std::uint16_t k = 81; k <= 84; ++k) { WP w; w.ref = cref(k); w.id = id_of(w.ref); w.w = ::v37::U256(static_cast<u64>(k)); p.window.push_back(w); p.learn(w.ref); }
        for (std::uint16_t k = 0; k < 10; ++k) p.seed(cref(static_cast<std::uint16_t>(90 + k)), static_cast<long long>(kTail), 1 + k);   // 6 XMR float
        std::vector<u64> hs;
        for (int i = 0; i < 12; ++i) {
            const u64 h = 2000000 + step * static_cast<u64>(i);
            const auto b = p.build(h, R);
            if (!b.ok) { deltas.push_back(0); dhs.push_back(~u64{0}); continue; }
            deltas.push_back(b.src->drain_delta());
            dhs.push_back(b.src->drain_dh());
            p.book(h, R, b);
            hs.push_back(h);
            if (hs.size() > 2) p.finalize(hs[hs.size() - 3], hs[hs.size() - 3] + 2);   // two lane blocks stay pending
        }
    };
    std::vector<u64> dm, dn, hm, hn;
    series(12, dm, hm);
    series(240, dn, hn);
    int ok_m = 0, ok_n = 0;
    for (int i = 0; i < 12; ++i) {
        if (dm[i] == (i == 0 ? R * 64 / 256 : R * 12 / 256) && hm[i] == (i == 0 ? 0u : 12u)) ++ok_m;
        if (dn[i] == R * 64 / 256 && hn[i] == (i == 0 ? 0u : 240u)) ++ok_n;
    }
    std::printf("  main-like (dh 12): Delta %llu per block; mini-like (dh 240): Delta %llu per block (cap 64)\n",
                (unsigned long long)dm[1], (unsigned long long)dn[1]);
    CHECK(ok_m == 12, "every 12 heights: Delta = R*12/256 = R/16 per lane block, the first block at the cap (%d/12)", ok_m);
    CHECK(ok_n == 12, "every 240 heights: Delta = R*64/256 (H_cap binds) (%d/12)", ok_n);
    CHECK(dm[5] * 64 == dn[5] * 12, "per height the two lanes drain alike up to the cap: R/256 per Monero height");
}

// ---------------------------------------------------------------------------
void suite_g_paynow_split() {
    std::printf("== G (B9). E_b(P) > 0 with E_b(R) == 0 fails closed ==\n");
    const u64 R = kTail;
    // weights where the largest remainder gives X nothing at R and 1 piconero
    // at P = R - d (found by a deterministic search: robust to the key order)
    const ::v37::ScriptRef X = cref(61), A = cref(62), B = cref(63), O = cref(64);
    Rng r{0x0b6b6b6b6b6b6b6bull};
    std::vector<WP> ps;
    u64 d = 0;
    for (int t = 0; t < 2000000 && d == 0; ++t) {
        const u64 a = r.in(1, 1000000000000ull), bb = r.in(1, 1000000000000ull), dd = r.in(x6::spend_floor(R), R / 4);
        std::vector<WP> q(3);
        q[0].ref = X; q[0].id = id_of(X); q[0].w = ::v37::U256(u64{1});
        q[1].ref = A; q[1].id = id_of(A); q[1].w = ::v37::U256(a);
        q[2].ref = B; q[2].id = id_of(B); q[2].w = ::v37::U256(bb);
        const auto er = eb_at(R, q), ep = eb_at(R - dd, q);
        if (!er.count(id_of(X)) && ep.count(id_of(X)) && ep.at(id_of(X)) == 1) { ps = q; d = dd; }
    }
    CHECK(d != 0, "weights found: E_X(R) = 0, E_X(R - %llu) = 1", (unsigned long long)d);
    if (d == 0) return;
    x6::CoinbaseInputs in;
    in.monero_major_version = 16; in.height = 77; in.chain_id = kChain; in.base_reward = R;
    in.fixed = {fee::donation_marker(kNet)};
    in.residual_sink = fee::donation_ref(kNet); in.residual_sink_identity = fee::donation_identity(kNet);
    in.output_cap = 16; in.spend_floor = true;
    x6::OwedEntry e; e.pay = O; e.identity = id_of(O); e.owed = d; in.owed.push_back(e);
    arm_weights(in, ps);
    in.paynow_first = true; in.drain_budget = d;
    x6::BuildError err{};
    const auto outs = x6::allocate_exact_sum(in, &err);
    CHECK(outs.empty() && err == x6::BuildError::PayNowSplit, "the allocation fails closed: %s", x6::to_string(err));
    in.paynow_first = false;
    const auto outs0 = x6::allocate_exact_sum(in, &err);
    CHECK(!outs0.empty() && err == x6::BuildError::None, "the same inputs with the rule off build (the check is the rule's)");
}

// ---------------------------------------------------------------------------
void suite_h_writeoff() {
    std::printf("== H (B14). the dust write-off under the gross-set clock ==\n");
    st::OwedLedger L(kChain, lane_rules());
    const ::v37::bytes32 D = id_of(cref(65)), E = id_of(cref(66)), A = id_of(cref(67));
    const long long w = 5000000;   // below the arm floor
    L.on_block_found("sd", Amounts{{D, w}, {E, w}}, {});
    L.on_block_finalized("sd", 10);   // a seed passes nobody by
    u64 h = 1000;
    auto lane_block = [&](u64 bin) {   // nets to 0 credit; its window credits A and the active dust miner E
        st::LaneFound lf; lf.height = h; lf.gross = {A, E};
        const std::string bid = "lb-" + std::to_string(h);
        L.on_block_found(bid, {}, {}, std::nullopt, nullptr, &lf);
        L.on_block_finalized(bid, bin);
        h += 10;
    };
    lane_block(1000);   // D is passed by: gone since 1000
    lane_block(1000 + 8639);
    const long long d0 = L.finalW().count(D) ? L.finalW().at(D) : 0;
    const ::v37::bytes32 dg0 = L.owed_digest();
    const long long tot0 = L.decayed_total();
    lane_block(1000 + 8640);   // one halving due
    const long long d1 = L.finalW().count(D) ? L.finalW().at(D) : 0;
    CHECK(d0 == w && d1 == (w >> 1) && L.decayed_total() - tot0 == w - (w >> 1),
          "after 8640 heights D decays by w - (w >> 1): %lld -> %lld, decayed_total +%lld", d0, d1, L.decayed_total() - tot0);
    CHECK(!(L.owed_digest() == dg0), "the write-off FINALIZE moves owed_digest");
    lane_block(1000 + 8640 + 2160);   // the second halving
    const long long d2 = L.finalW().count(D) ? L.finalW().at(D) : 0;
    CHECK(d2 == (w >> 2), "after one more half-life: w >> 2 = %lld (got %lld)", w >> 2, d2);
    const long long e2 = L.finalW().count(E) ? L.finalW().at(E) : 0;
    CHECK(e2 == w, "the active dust miner E (in every G_b) never decays (%lld)", e2);
    CHECK(L.prev_lane_height() == h - 10 && L.last_settled_lane_height() == h - 10, "the lane height follows the finalized lane blocks (%llu)",
          (unsigned long long)L.prev_lane_height());
}
#endif  // DRAIN_KAT_GOLDEN_CAPTURE

}  // namespace

// I (F4-partial, operator ruling 2026-10-02; B-VERIFY-ADVERSARY ADV3): only a
// key whose BALANCE is below c(R) goes to the dust pass. A budget-stopped take
// below c of a balance >= c is not paid: it carries one block, balance and age
// kept, and the unspent part of Delta stays in P (the window's cash). A balance
// below c is still paid by the dust pass.
void suite_i_f4_partial() {
    std::printf("== I. F4-partial: a budget-stopped take below c(R) of a balance >= c carries ==\n");
    const u64 R = kTail, h = 700000, c = x6::spend_floor(R);
    const u64 D = expect_delta(~u64{0}, R, 64);                          // R / 4 (dh 64)
    auto pool = [&](bool with_small) {
        auto p = std::make_unique<Pool>();
        for (std::uint16_t k = 41; k <= 43; ++k) { WP w; w.ref = cref(k); w.id = id_of(w.ref); w.w = ::v37::U256(static_cast<u64>(k)); p->window.push_back(w); p->learn(w.ref); }
        p->seed(cref(49), static_cast<long long>(D - c / 2), 1);        // oldest: takes D - c/2 (>= c)
        if (with_small) p->seed(cref(47), static_cast<long long>(c / 3), 2);   // a balance below c: dust
        p->seed(cref(48), static_cast<long long>(5 * c), 3);            // balance 5c: the walk offers it the rest (< c)
        p->seed(cref(46), static_cast<long long>(2 * c), 4);            // balance 2c: untaken (the budget ran out)
        st::LaneFound lf; lf.height = h - 64;
        p->L.on_block_found("prev", {}, {}, std::nullopt, nullptr, &lf); p->L.on_block_finalized("prev", h - 64);
        return p;
    };
    auto to = [](const Pool::Built& b, std::uint16_t k) { u64 s = 0; for (const auto& q : b.outs) if (q.identity == id_of(cref(k))) s += q.amount; return s; };
    {
        auto p = pool(false);
        const long long fe48 = static_cast<long long>(p->L.first_eligible_of(id_of(cref(48))));
        const auto b = p->build(h, R);
        CHECK(b.ok, "I1 builds: %s", b.ok ? "ok" : b.why.c_str());
        if (!b.ok) return;
        u64 paid_win = 0, eb_p = 0;
        for (const auto& w : p->window) for (const auto& q : b.outs) if (q.identity == w.id) paid_win += q.amount;
        for (const auto& [k, v] : eb_at(b.st.split_at, p->window)) { (void)k; eb_p += v; }
        std::printf("  c=%llu Delta=%llu owed_paid=%llu dust_paid=%llu debt_paid=%llu split_at=%llu to48=%llu to46=%llu in.owed=%zu owed_dust=%zu\n",
                    (unsigned long long)c, (unsigned long long)D, (unsigned long long)b.st.owed_paid, (unsigned long long)b.st.dust_paid,
                    (unsigned long long)b.st.debt_paid, (unsigned long long)b.st.split_at, (unsigned long long)to(b, 48), (unsigned long long)to(b, 46),
                    b.src->inputs().owed.size(), b.src->inputs().owed_dust.size());
        CHECK(to(b, 48) == 0 && to(b, 46) == 0 && b.src->inputs().owed.size() == 1 && b.src->inputs().owed_dust.empty(),
              "I1 the c/2 take of the 5c creditor is NOT paid (no sub-c output), nor routed to the dust list; the untaken 2c balance is not "
              "in the dust list either (to48=%llu to46=%llu owed_dust=%zu)", (unsigned long long)to(b, 48), (unsigned long long)to(b, 46),
              b.src->inputs().owed_dust.size());
        CHECK(b.st.owed_paid == D - c / 2 && b.st.dust_paid == 0 && b.st.debt_paid == D - c / 2 && b.st.debt_paid < D,
              "I1 debt_paid = Delta - c/2 < Delta (allowed): owed %llu, dust %llu", (unsigned long long)b.st.owed_paid, (unsigned long long)b.st.dust_paid);
        CHECK(b.st.split_at == R - b.st.debt_paid && b.st.split_at == R - D + c / 2 && paid_win == eb_p,
              "I1 P = R - debt_paid grows by the unspent c/2 (P = %llu); the window is paid E_b(P) in full (%llu == %llu): the donation gets none of it",
              (unsigned long long)b.st.split_at, (unsigned long long)paid_win, (unsigned long long)eb_p);
        Amounts left;
        p->book(h, R, b, &left);
        bool none = true; for (const auto& [k, v] : left) if (v != 0) none = false;
        CHECK(p->L.effective_owed(id_of(cref(48))) == static_cast<long long>(5 * c) &&
              static_cast<long long>(p->L.first_eligible_of(id_of(cref(48)))) == fe48 &&
              p->L.effective_owed(id_of(cref(46))) == static_cast<long long>(2 * c) && p->L.effective_owed(id_of(cref(49))) == 0 && none,
              "I1 booked: the 5c creditor keeps balance 5c and its age (fe %lld), 2c untouched, the oldest paid in full, no window payee keeps a balance",
              fe48);
    }
    {
        auto p = pool(true);
        const auto b = p->build(h, R);
        CHECK(b.ok, "I2 builds: %s", b.ok ? "ok" : b.why.c_str());
        if (!b.ok) return;
        std::printf("  owed_paid=%llu dust_paid=%llu debt_paid=%llu to47=%llu to48=%llu owed_dust=%zu\n",
                    (unsigned long long)b.st.owed_paid, (unsigned long long)b.st.dust_paid, (unsigned long long)b.st.debt_paid,
                    (unsigned long long)to(b, 47), (unsigned long long)to(b, 48), b.src->inputs().owed_dust.size());
        CHECK(to(b, 47) == c / 3 && to(b, 48) == 0 && b.src->inputs().owed_dust.size() == 1 &&
              b.st.dust_paid == c / 3 && b.st.debt_paid == D - c / 2 + c / 3,
              "I2 a creditor whose balance is below c (c/3) is still paid by the dust pass (%llu); the 5c creditor's c/6 take carries",
              (unsigned long long)to(b, 47));
    }
}

int main() {
#ifdef DRAIN_KAT_GOLDEN_CAPTURE
    std::printf("%s\n", golden_of_master_path().c_str());
    return 0;
#else
    std::printf("v37_xmr_drain_kat\n");
    suite_a_no_new_owed();
    suite_b_master_identity();
    suite_c_bound();
    suite_d_contested();
    suite_d2_no_debt_first();
    suite_d3_recv_fallback();
    suite_e_ledger_F();
    suite_f_per_height();
    suite_g_paynow_split();
    suite_h_writeoff();
    suite_i_f4_partial();
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
#endif
}
