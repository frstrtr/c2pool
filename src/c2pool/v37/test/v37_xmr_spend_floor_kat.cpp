// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_spend_floor_kat -- the spend-cost floor c and crumbs
// (docs/xmr-lane/payout-threshold.md §2-§3).
//
//   F1  c: Monero's consensus fee per byte at the 300 kB fee-median floor
//       (Blockchain::get_dynamic_base_fee arithmetic) times one RingCT input,
//       quantized up; known values, monotone in the reward.
//   F2  with room in the block every payee, dust included, is paid its exact
//       E_b; F2b without room its cash is REDISTRIBUTED to the paid payees and
//       taken off its credit (credit delta, sum 0): never an advance.
//   F3  too few output slots: oldest first (equal ages by the salted tie),
//       the rest wait; no CapTooSmall; their cash is redistributed (F2b).
//   F4  the owed pass pays no balance below c.
//   F5  the receive side books every key NET of min(credit, paid): a crumb
//       keeps its credit, an advance stays a pending payout, and the balance
//       after FINALIZE equals the gross booking.
//   F6  flag off: master's allocation (crumbs paid, CapTooSmall on no slot).
//   F7  seniority from the floor (review 02 inverted): a parked sub-floor key
//       earns no age and does not jump the queue.
//   F8  rotation (review 04 / audit O-1): a key paid in part walks after the
//       others at once (pending) and for good after FINALIZE.
//   F9  rules off: the ledger is byte-identical to the shipped one.
//   F4b THE DRAIN RULE (R5, the F4 band): a balance in [arm floor, c(R)) is
//       proposed, routed to the dust list and paid when there is room, out of
//       Delta - owed_paid; again at a reward 8x the tail (c x 8).
//   F10b THE DRAIN RULE (R5, the decay clock): under pay-now first every
//       window row nets to 0, so the clock runs on the gross set G_b: a gone
//       key starts at the first FINALIZE whose G_b omits it, an active dust
//       miner in every G_b never decays, an empty-cut block passes nobody by.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/settle/xmr_coinbase.hpp"
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/xmr_paynow.hpp"
#include "c2pool/v37/w4_settlement.hpp"
#include "c2pool/v37/xmr/xmr_settle_store.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_source.hpp"   // THE DRAIN RULE: the real source (D0-D2)

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

constexpr std::uint64_t kTail = 600000000000ull;               // Monero tail emission: 0.6 XMR
constexpr fee::DonationNet kNet = fee::DonationNet::Regtest;

x6::CoinbaseInputs fee_on_inputs(std::uint64_t reward, bool floor) {
    x6::CoinbaseInputs in;
    in.monero_major_version = 16;
    in.height = 1234;
    in.base_reward = reward;
    in.chain_id = 7;
    in.fixed = {fee::donation_marker(kNet)};
    in.residual_sink = fee::donation_ref(kNet);
    in.residual_sink_identity = fee::donation_identity(kNet);
    in.output_cap = 16;
    in.spend_floor = floor;
    return in;
}

struct P { ::v37::ScriptRef ref; ::v37::bytes32 id; std::uint64_t eb; std::uint64_t age = 0; };
// pay-now entries with explicit E_b, identity ASC (as the provider hands them).
void arm(x6::CoinbaseInputs& in, std::vector<P> ps) {
    std::sort(ps.begin(), ps.end(), [](const P& a, const P& b) { return a.id < b.id; });
    in.paynow_at = [ps](std::uint64_t) {
        std::vector<x6::PayNowEntry> v;
        for (const auto& p : ps) { x6::PayNowEntry e; e.pay = p.ref; e.identity = p.id; e.eb = p.eb; e.age = p.age; v.push_back(e); }
        return v;
    };
    in.paynow_n = ps.size();
}
P payee(std::uint8_t k, std::uint64_t eb, std::uint64_t age = 0) { auto r = ref_of(k); return {r, id_of(r), eb, age}; }
std::uint64_t to(const std::vector<x6::CoinbaseOutput>& outs, const ::v37::bytes32& id) {
    std::uint64_t s = 0; for (const auto& o : outs) if (o.identity == id) s += o.amount; return s;
}
std::uint64_t sum_of(const std::vector<x6::CoinbaseOutput>& outs) { std::uint64_t s = 0; for (const auto& o : outs) s += o.amount; return s; }

// ---------------------------------------------------------------------------
void f1_floor() {
    std::printf("== F1. c: Monero's spend cost at the fee-median floor ==\n");
    // get_dynamic_base_fee: 600e9 * 3000 / 300000 / 300000 = 20000; minus 1/20 -> 19000.
    CHECK(x6::fee_per_byte_at_floor(kTail) == 19000, "fee per byte at the tail reward = 19000 piconero (got %llu)",
          (unsigned long long)x6::fee_per_byte_at_floor(kTail));
    CHECK(x6::kInputWeight == 659, "one ring-16 CLSAG input weighs 659 bytes");
    // 659 * 19000 = 12,521,000 -> quantized up to 10^4 -> 12,530,000.
    CHECK(x6::spend_floor(kTail) == 12530000ull, "c at the tail reward = 12,530,000 piconero, 0.00001253 XMR (got %llu)",
          (unsigned long long)x6::spend_floor(kTail));
    CHECK(x6::spend_floor(kTail) % x6::kFeeQuantizationMask == 0, "c is a multiple of Monero's fee quantization mask");
    CHECK(x6::spend_floor(kTail + 5000000000ull) >= x6::spend_floor(kTail), "monotone: fees in the total only raise c");
    CHECK(x6::spend_floor(17600000000000ull) > x6::spend_floor(kTail), "a larger (pre-tail) reward gives a larger c");
    CHECK(x6::fee_per_byte_at_floor(1) == 1, "Monero's minimum of 1 piconero per byte");
}

// ---------------------------------------------------------------------------
void f2_crumbs() {
    std::printf("== F2. dust is paid when the block has room ==\n");
    const std::uint64_t c = x6::spend_floor(kTail);
    const P a = payee(11, 361000000000ull), b = payee(12, 239000000000ull);   // reward >= the tail, so c(reward) >= c(tail)
    const P cr1 = payee(13, c - 1), cr2 = payee(14, c / 3);          // dust: below c
    const std::uint64_t reward = a.eb + b.eb + cr1.eb + cr2.eb + 1;   // the cut credits the whole reward but the marker
    auto in = fee_on_inputs(reward, true);
    arm(in, {a, b, cr1, cr2});
    x6::BuildError err{};
    const auto outs = x6::allocate_exact_sum(in, &err);
    const ::v37::bytes32 D = fee::donation_identity(kNet);
    CHECK(err == x6::BuildError::None, "builds");
    CHECK(sum_of(outs) == reward, "exact sum: %llu == %llu", (unsigned long long)sum_of(outs), (unsigned long long)reward);
    CHECK(to(outs, cr1.id) == cr1.eb && to(outs, cr2.id) == cr2.eb, "with free slots the dust is paid its exact E_b (no balance, no debt)");
    CHECK(to(outs, a.id) == a.eb && to(outs, b.id) == b.eb, "everyone gets exactly E_b: no advance is needed");
    CHECK(to(outs, D) == 1, "only the 1-piconero donation marker is left over (got %llu)", (unsigned long long)to(outs, D));
}

void f2b_no_room() {
    std::printf("== F2b. no slot: its cash is redistributed, never advanced ==\n");
    const std::uint64_t c = x6::spend_floor(kTail);
    const P a = payee(15, 361000000000ull, 1), b = payee(16, 239000000000ull, 2);   // the two oldest take the slots
    const P cr1 = payee(17, c - 1), cr2 = payee(18, c / 3);
    const std::uint64_t crumbs = cr1.eb + cr2.eb;
    const std::uint64_t reward = a.eb + b.eb + crumbs + 1;
    auto in = fee_on_inputs(reward, true);
    in.output_cap = 3;                                                // donation (folds) + 2 payee slots
    arm(in, {a, b, cr1, cr2});
    Amounts delta;
    const auto outs = x6::allocate_exact_sum(in, nullptr, &delta);
    CHECK(sum_of(outs) == reward, "exact sum");
    CHECK(to(outs, cr1.id) == 0 && to(outs, cr2.id) == 0, "no slot left: the dust gets no output");
    const std::uint64_t pa = to(outs, a.id), pb = to(outs, b.id);
    CHECK(pa - a.eb + pb - b.eb == crumbs, "the paid payees receive the dust's cash (%llu)", (unsigned long long)crumbs);
    const long double ra = static_cast<long double>(pa - a.eb) / crumbs;
    CHECK(ra > 361.0L / 600.0L - 1e-6L && ra < 361.0L / 600.0L + 1e-6L, "pro rata to E_b");
    long long dsum = 0; for (const auto& [k, d] : delta) dsum += d;
    CHECK(dsum == 0, "the credit delta sums to zero: a redistribution, the block still credits its whole reward");
    CHECK(delta[a.id] == static_cast<long long>(pa - a.eb) && delta[b.id] == static_cast<long long>(pb - b.eb),
          "the paid payees are CREDITED what they got over E_b: no advance, nothing to repay");
    CHECK(delta[cr1.id] == -static_cast<long long>(cr1.eb) && delta[cr2.id] == -static_cast<long long>(cr2.eb),
          "the waiting dust is not credited the cash that went to others this block");
    // book it: credit = E_b + delta, payout = the outputs; no balance goes negative
    Amounts credit{{a.id, (long long)a.eb}, {b.id, (long long)b.eb}, {cr1.id, (long long)cr1.eb}, {cr2.id, (long long)cr2.eb}};
    for (const auto& [k, d] : delta) { credit[k] += d; if (credit[k] == 0) credit.erase(k); }
    Amounts payout{{a.id, (long long)pa}, {b.id, (long long)pb}};
    st::OwedLedger L(7);
    L.on_block_found("b", credit, payout); L.on_block_finalized("b", 1);
    CHECK(L.effective_owed(a.id) == 0 && L.effective_owed(b.id) == 0 && L.effective_owed(cr1.id) == 0 && L.effective_owed(cr2.id) == 0,
          "ledger after FINALIZE: every balance is 0 (no debt, no advance)");
}

void f2d_debt_first() {
    std::printf("== F2d. no slot: the spare cash pays an admitted payee's old debt first ==\n");
    const std::uint64_t c = x6::spend_floor(kTail);
    P a = payee(71, kTail, 2);                                        // admitted; it also has an old balance
    const P w = payee(72, c / 2);                                     // dust without a slot
    const std::uint64_t old_debt = 3 * c;
    auto in = fee_on_inputs(a.eb + w.eb + fee::kDonationMarkerPico, true);
    in.output_cap = 2;                                                // one payee slot
    std::vector<x6::PayNowEntry> v;
    for (const P& p : {a, w}) { x6::PayNowEntry e; e.pay = p.ref; e.identity = p.id; e.eb = p.eb; e.age = p.age; v.push_back(e); }
    for (auto& e : v) if (e.identity == a.id) e.owed_left = old_debt;
    std::sort(v.begin(), v.end(), [](const x6::PayNowEntry& l, const x6::PayNowEntry& r) { return l.identity < r.identity; });
    in.paynow_at = [v](std::uint64_t) { return v; };
    in.paynow_n = 2;
    Amounts delta;
    const auto outs = x6::allocate_exact_sum(in, nullptr, &delta);
    CHECK(to(outs, a.id) == a.eb + w.eb && to(outs, w.id) == 0, "A is paid its E_b plus the dust's cash, as a payment on its old debt");
    CHECK(delta.empty(), "no credit moves: the waiting dust keeps its credit (it grows, or decays if abandoned)");
    // book it on top of A's old balance
    st::OwedLedger L(7);
    L.on_block_found("old", Amounts{{a.id, (long long)old_debt}}, {}); L.on_block_finalized("old", 1);
    L.on_block_found("b", Amounts{{a.id, (long long)a.eb}, {w.id, (long long)w.eb}}, Amounts{{a.id, (long long)(a.eb + w.eb)}});
    L.on_block_finalized("b", 2);
    CHECK(L.effective_owed(a.id) == static_cast<long long>(old_debt - w.eb) && L.effective_owed(w.id) == static_cast<long long>(w.eb),
          "ledger: A's debt shrinks by the dust's cash, the dust keeps its balance; the total is unchanged and nothing is negative");
}

void f2c_short_pool() {
    std::printf("== F2c. a short pool fills every slot and every piconero ==\n");
    const std::uint64_t c = x6::spend_floor(kTail);
    // 12 payees, one of them dust, credited 2x what the pool holds (the owed
    // pass took half of the block): nobody is dropped, everyone gets the same
    // fraction, the rest stays each one's balance.
    std::vector<P> ps;
    std::uint64_t sum = 0;
    for (int i = 0; i < 12; ++i) { ps.push_back(payee(static_cast<std::uint8_t>(60 + i), i == 0 ? c / 3 : 10000000000ull * (i + 1))); sum += ps.back().eb; }
    const std::uint64_t pool = sum / 2;
    auto in = fee_on_inputs(pool + fee::kDonationMarkerPico, true);
    arm(in, ps);
    const auto outs = x6::allocate_exact_sum(in);
    std::size_t paid = 0; bool same = true;
    for (const auto& p : ps) {
        const std::uint64_t got = to(outs, p.id);
        if (got > 0) ++paid;
        const long double f = static_cast<long double>(got) / p.eb;
        if (f < 0.4999L || f > 0.5001L) same = false;
    }
    CHECK(paid == ps.size(), "every payee with a slot is paid, dust included (%zu of %zu)", paid, ps.size());
    CHECK(same, "every payee gets the same fraction of its E_b (half: the pool holds half of what was credited)");
    CHECK(sum_of(outs) == pool + fee::kDonationMarkerPico && to(outs, fee::donation_identity(kNet)) == fee::kDonationMarkerPico, "every piconero of the pool is paid out; only the 0-amount marker is left");
}

// ---------------------------------------------------------------------------
void f3b_worth_spending_first() {
    std::printf("== F3b. with too few slots, a payout >= c goes before dust ==\n");
    const std::uint64_t c = x6::spend_floor(kTail);
    const P dust = payee(81, c / 2, 3);                              // the OLDEST, but dust
    const P big = payee(82, kTail);                                   // new, but worth spending (reward >= the tail)
    auto in = fee_on_inputs(dust.eb + big.eb + fee::kDonationMarkerPico, true);
    in.output_cap = 2;                                                // one payee slot
    arm(in, {dust, big});
    const auto outs = x6::allocate_exact_sum(in);
    CHECK(to(outs, big.id) > 0 && to(outs, dust.id) == 0, "the only slot goes to the payout >= c, although the dust is older");
}

void f3_slots() {
    std::printf("== F3. too few output slots: oldest first ==\n");
    // s is the smallest but the OLDEST (a waiting balance since bin 7); a and b
    // are new. With two slots s goes first, whatever its size.
    const P a = payee(21, 300000000000ull), b = payee(22, 200000000000ull), s = payee(23, 99000000000ull, 7);
    const std::uint64_t reward = a.eb + b.eb + s.eb + 1;
    {
        auto in = fee_on_inputs(reward, true);
        in.output_cap = 3;                                            // donation (folds) + 2 payee slots
        arm(in, {a, b, s});
        x6::BuildError err{};
        const auto outs = x6::allocate_exact_sum(in, &err);
        CHECK(err == x6::BuildError::None, "no CapTooSmall: a payee without a slot waits");
        CHECK(to(outs, s.id) >= s.eb, "the OLDEST payee gets a slot although it is the smallest");
        CHECK((to(outs, a.id) == 0) != (to(outs, b.id) == 0), "of the two new payees exactly one gets the last slot (salted tie)");
        CHECK(sum_of(outs) == reward, "exact sum");
    }
    {   // equal ages: the salted tie decides, never the size of E_b
        P x = payee(26, 5000000000ull), y = payee(27, 400000000000ull);
        auto in = fee_on_inputs(x.eb + y.eb + fee::kDonationMarkerPico, true);
        in.output_cap = 2;                                            // one payee slot
        std::vector<x6::PayNowEntry> v;
        for (const P& p : {x, y}) { x6::PayNowEntry e; e.pay = p.ref; e.identity = p.id; e.eb = p.eb; v.push_back(e); }
        v[0].tie[0] = 0x01; v[1].tie[0] = 0x02;                       // x's salted hash is lower
        std::sort(v.begin(), v.end(), [](const x6::PayNowEntry& l, const x6::PayNowEntry& r) { return l.identity < r.identity; });
        in.paynow_at = [v](std::uint64_t) { return v; };
        in.paynow_n = 2;
        const auto outs = x6::allocate_exact_sum(in);
        CHECK(to(outs, x.id) > 0 && to(outs, y.id) == 0, "the lower salted hash wins the slot, the larger E_b waits");
    }
    {   // credited work below the reward (nobody waits): nothing is moved
        const std::uint64_t c = x6::spend_floor(kTail);
        const P only = payee(24, 2 * c), dust = payee(25, c / 2);
        auto in = fee_on_inputs(kTail, true);
        arm(in, {only, dust});
        Amounts delta;
        const auto outs = x6::allocate_exact_sum(in, nullptr, &delta);
        const ::v37::bytes32 D = fee::donation_identity(kNet);
        CHECK(to(outs, dust.id) == dust.eb && to(outs, only.id) == only.eb, "both are paid exactly their E_b");
        CHECK(delta.empty(), "nobody waits, so nothing is redistributed");
        CHECK(to(outs, D) == kTail - only.eb - dust.eb, "uncredited cash stays in the residual (the donation output)");
        CHECK(sum_of(outs) == kTail, "exact sum");
    }
}

// ---------------------------------------------------------------------------
void f4_owed_floor() {
    std::printf("== F4. the owed pass pays no balance below c ==\n");
    const std::uint64_t c = x6::spend_floor(kTail);
    const auto r1 = ref_of(31), r2 = ref_of(32);
    auto in = fee_on_inputs(kTail, true);
    x6::OwedEntry e1; e1.identity = id_of(r1); e1.pay = r1; e1.owed = c - 1; e1.first_eligible = 1;
    x6::OwedEntry e2; e2.identity = id_of(r2); e2.pay = r2; e2.owed = c;     e2.first_eligible = 2;
    in.owed = {e1, e2};
    const auto outs = x6::allocate_exact_sum(in);
    CHECK(to(outs, e1.identity) == 0, "an owed balance of c-1 carries (older, still unpaid)");
    CHECK(to(outs, e2.identity) == c, "an owed balance of exactly c is paid");
    auto off = in; off.spend_floor = false;
    CHECK(to(x6::allocate_exact_sum(off), e1.identity) == c - 1, "flag off: master pays it");
}

// ---------------------------------------------------------------------------
void f5_receive() {
    std::printf("== F5. the receive side: net of min(credit, paid) ==\n");
    const auto ra = ref_of(41), rb = ref_of(42), rc = ref_of(43);
    const ::v37::bytes32 A = id_of(ra), B = id_of(rb), C = id_of(rc), D = fee::donation_identity(kNet);
    Amounts credit{{A, 1000}, {B, 600}, {C, 5}};
    Amounts payout{{A, 1003}, {B, 602}};                               // C is a crumb; A and B carry its cash
    long long before = 0;
    for (auto& [k, v] : credit) before += v;
    for (auto& [k, v] : payout) before -= v;
    const std::optional<std::uint64_t> base = 1;
    const auto r = pn::net_booking(base, 1606, credit, payout, 1, D, 1, /*spend_floor=*/true);
    long long after = 0;
    for (auto& [k, v] : credit) after += v;
    for (auto& [k, v] : payout) after -= v;
    CHECK(r.ok, "never refused: the recompute already proved the coinbase");
    CHECK(credit.size() == 1 && credit.at(C) == 5, "the crumb keeps its credit (5): paid when its balance reaches c");
    CHECK(payout.at(A) == 3 && payout.at(B) == 2, "the advances stay pending payouts (A 3, B 2): their next credits repay them");
    CHECK(after == before, "the balance after FINALIZE equals the gross booking (%lld == %lld)", after, before);

    st::OwedLedger L(7);
    L.on_block_found("b1", credit, payout);
    L.on_block_finalized("b1", 1);
    CHECK(L.effective_owed(C) == 5 && L.effective_owed(A) == -3 && L.effective_owed(B) == -2,
          "ledger: C +5, A -3, B -2 (sum 0: the crumb is exactly the advance)");
}

// ---------------------------------------------------------------------------
void f6_off() {
    std::printf("== F6. flag off: master's allocation ==\n");
    const std::uint64_t c = x6::spend_floor(kTail);
    const P a = payee(51, 300000000000ull), cr = payee(52, c / 2);
    auto in = fee_on_inputs(a.eb + cr.eb + 1, false);
    arm(in, {a, cr});
    const auto outs = x6::allocate_exact_sum(in);
    CHECK(to(outs, cr.id) == cr.eb, "without the floor a crumb is paid its own dust output");
    auto tight = fee_on_inputs(a.eb + cr.eb + 1, false);
    tight.output_cap = 2;
    arm(tight, {a, cr});
    x6::BuildError err{};
    (void)x6::allocate_exact_sum(tight, &err);
    CHECK(err == x6::BuildError::CapTooSmall, "without the floor a payee without a slot fails the build closed");
}

// ---------------------------------------------------------------------------
st::OwedLedgerRules xmr_rules(long long floor) { st::OwedLedgerRules r; r.arm_floor = floor; r.rotate_on_payment = true; return r; }
auto pay_any = [](const ::v37::bytes32&) { ::v37::ScriptRef r = ref_of(99); return r; };
auto no_hmin = [](::v37::ScriptKind) { return std::uint64_t{0}; };
::v37::bytes32 key(std::uint8_t b) { ::v37::bytes32 k{}; k[0] = b; return k; }
std::vector<::v37::bytes32> order_of(const st::OwedLedger& L, std::uint64_t budget, unsigned C) {
    std::vector<::v37::bytes32> v;
    for (const auto& o : L.propose_coinbase(budget, C, pay_any, no_hmin).outs) v.push_back(o.key);
    return v;
}

void f7_seniority() {
    std::printf("== F7. seniority from the floor (review 02 inverted) ==\n");
    const ::v37::bytes32 A = key(0x10), B = key(0x20);   // A sorts first on the raw key too
    for (int rules = 0; rules < 2; ++rules) {
        st::OwedLedger L(7, rules ? xmr_rules(1000) : st::OwedLedgerRules{});
        L.on_block_found("b1", Amounts{{A, 1}}, {});  L.on_block_finalized("b1", 1);    // A parks 1 piconero at bin 1
        L.on_block_found("b2", Amounts{{B, 5000}}, {}); L.on_block_finalized("b2", 2);  // B is payable at bin 2
        L.on_block_found("b3", Amounts{{A, 5000}}, {}); L.on_block_finalized("b3", 3);  // A becomes payable at bin 3
        const auto o = order_of(L, 1000000, 1);
        if (rules) CHECK(o.size() == 1 && o[0] == B, "floor 1000: B (payable since bin 2) is paid before A (payable only since bin 3)");
        else       CHECK(o.size() == 1 && o[0] == A, "rules off (shipped): A's parked bin-1 age wins -- the finding, reproduced");
    }
    st::OwedLedger L(7, xmr_rules(1000));
    L.on_block_found("b1", Amounts{{A, 999}}, {}); L.on_block_finalized("b1", 1);
    CHECK(order_of(L, 1000000, 0).empty(), "a balance below the floor has no age and is not paid by the owed pass");
}

void f8_rotation() {
    std::printf("== F8. rotation on payment (review 04 / audit O-1) ==\n");
    const ::v37::bytes32 A = key(0x10), B = key(0x20);
    for (int rules = 0; rules < 2; ++rules) {
        st::OwedLedger L(7, rules ? xmr_rules(50) : st::OwedLedgerRules{});
        L.on_block_found("b1", Amounts{{A, 900}}, {}); L.on_block_finalized("b1", 1);
        L.on_block_found("b2", Amounts{{B, 100}}, {}); L.on_block_finalized("b2", 2);
        const auto first = order_of(L, 500, 1);
        CHECK(first.size() == 1 && first[0] == A, "%s: the oldest key A is paid first (in part: 500 of 900)", rules ? "rules on" : "rules off");
        L.on_block_found("b3", Amounts{{A, 900}}, Amounts{{A, 500}});          // A is credited again and paid in part
        const auto pend = order_of(L, 500, 1);
        if (rules) CHECK(pend.size() == 1 && pend[0] == B, "rules on, b3 still pending: A walks after B, so B is paid next");
        else       CHECK(pend.size() == 1 && pend[0] == A, "rules off: A keeps the front and takes the block again -- O-1, reproduced");
        L.on_block_finalized("b3", 3);
        const auto fin = order_of(L, 500, 1);
        if (rules) CHECK(fin.size() == 1 && fin[0] == B, "rules on, after FINALIZE: A's age restarts at bin 3, behind B (bin 2)");
        else       CHECK(fin.size() == 1 && fin[0] == A, "rules off: A never reaches 0 and keeps its bin-1 age for ever");
    }
}

void f10_decay() {
    std::printf("== F10. dust decay: only a gone miner's dust, never active work ==\n");
    st::OwedLedgerRules r; r.arm_floor = 1000; r.rotate_on_payment = true; r.decay_horizon = 100; r.decay_half_life = 50;
    const ::v37::bytes32 A = key(0x10), D = key(0x20), S = key(0x30), N = key(0x40);
    st::OwedLedger L(7, r);
    int nb = 0;
    auto block = [&](const Amounts& credit, const Amounts& payout, std::uint64_t bin) {
        const std::string bid = "b" + std::to_string(++nb);
        L.on_block_found(bid, credit, payout); L.on_block_finalized(bid, bin);
    };
    block(Amounts{{D, 800}, {S, 3}, {N, 5000}}, {}, 1);         // D: dust that will be abandoned; S: a tiny DROPS miner
    block(Amounts{}, Amounts{{N, 5500}}, 2);                     // N pays out beyond its balance: a negative row
    block(Amounts{}, {}, 500);                                   // no lane block credits anyone for a long time
    CHECK(L.effective_owed(D) == 800, "a pool that finds no block decays nobody (D still 800 at bin 500)");
    block(Amounts{{A, 5000}, {S, 2}}, {}, 520);                  // a lane block passes D by: D is gone from bin 520
    CHECK(L.effective_owed(D) == 800, "passed by at bin 520, D keeps its balance for one more window (grace to come back)");
    block(Amounts{{A, 5000}, {S, 1}}, {}, 630);
    CHECK(L.effective_owed(D) == 400, "after the window it halves (400 at bin 630)");
    block(Amounts{{A, 5000}, {S, 1}}, {}, 680);
    CHECK(L.effective_owed(D) == 200, "and halves again each half-life (200 at bin 680)");
    CHECK(L.effective_owed(S) == 7, "the active tiny miner keeps every piconero it earned (7): every lane block credits it");
    block(Amounts{{D, 10}}, {}, 690);                            // D comes back
    block(Amounts{{A, 5000}, {S, 1}}, {}, 700);
    CHECK(L.effective_owed(D) == 210, "a returning miner stops the decay (200 + 10, untouched at bin 700)");
    CHECK(L.effective_owed(N) == -500, "a negative row never decays");
    CHECK(L.effective_owed(A) == 20000, "a balance at or above the floor never decays");
    CHECK(L.decayed_total() == 600, "the write-off is counted (600): it lowers the liability, it is paid to nobody");
    block(Amounts{{A, 1}}, {}, 2000);
    block(Amounts{{A, 1}}, {}, 20000);
    CHECK(L.effective_owed(D) == 0, "left long enough, abandoned dust decays to zero");
}

void f9_off() {
    std::printf("== F9. rules off: byte-identical ==\n");
    st::OwedLedger a(7), b(7, st::OwedLedgerRules{});
    for (auto* L : {&a, &b}) {
        L->on_block_found("b1", Amounts{{key(1), 7}, {key(2), 900}}, {}); L->on_block_finalized("b1", 1);
        L->on_block_found("b2", Amounts{{key(3), 5}}, Amounts{{key(2), 400}}); L->on_block_finalized("b2", 2);
    }
    CHECK(a.owed_digest() == b.owed_digest(), "a default ledger and an explicit rules-off ledger commit the same owed_digest");
}

void f11_anchor() {
    std::printf("== F11. the ANCHOR: the credit cut of the latest lane block finalized into the ledger ==\n");
    const ::v37::bytes32 k = payee(81, 1).id;
    auto cut = [](std::uint64_t P, std::uint8_t tag) { st::AnchorCut c; c.next_pos = P; c.spine[0] = tag; return c; };
    {   // rule off: the cut argument changes nothing (Family A and the gate-off lane stay byte-identical)
        st::OwedLedger a(7), b(7);
        a.on_block_found("x", Amounts{{k, 5}}, {});
        b.on_block_found("x", Amounts{{k, 5}}, {}, cut(100, 1));
        a.on_block_finalized("x", 1); b.on_block_finalized("x", 1);
        CHECK(a.owed_digest() == b.owed_digest() && !b.anchor_cut(), "rule off: no anchor, digest unchanged by the cut");
    }
    st::OwedLedgerRules R; R.anchor_cut = true;
    st::OwedLedger L(7, R);
    const auto d0 = L.owed_digest();
    CHECK(!L.anchor_cut(), "a fresh ledger has no anchor");
    L.on_block_found("b1", Amounts{{k, 5}}, {}, cut(100, 1));
    CHECK(!L.anchor_cut(), "FOUND does not move the anchor (pending state is outside owed_digest)");
    L.on_block_finalized("b1", 10);
    CHECK(L.anchor_cut() && *L.anchor_cut() == cut(100, 1), "FINALIZE makes the block's cut the anchor");
    const auto d1 = L.owed_digest();
    CHECK(!(d1 == d0), "the anchor is committed in owed_digest");
    L.on_block_found("b2", Amounts{{k, 5}}, {}, cut(200, 2));
    L.on_block_orphaned("b2", {});
    CHECK(L.anchor_cut() && *L.anchor_cut() == cut(100, 1), "a pre-settle orphan takes its cut with it");
    L.on_block_found("b3", Amounts{{k, 5}}, {});   // a debit-only / cutless block
    L.on_block_finalized("b3", 11);
    CHECK(L.anchor_cut() && *L.anchor_cut() == cut(100, 1), "a finalized block without a cut leaves the anchor where it is");
    {   // two ledgers that differ only in the anchor differ in owed_digest
        st::OwedLedger x(7, R), y(7, R);
        x.on_block_found("b", Amounts{{k, 5}}, {}, cut(100, 1)); x.on_block_finalized("b", 1);
        y.on_block_found("b", Amounts{{k, 5}}, {}, cut(100, 2)); y.on_block_finalized("b", 1);
        CHECK(!(x.owed_digest() == y.owed_digest()), "another anchor spine -> another owed_digest");
    }
    {   // the settle store carries the cut: a schema-2 FOUND round-trips, a schema-1 record still reads
        using c2pool::v37n::xmr::SettleEvent;
        using c2pool::v37n::xmr::SettleEvKind;
        SettleEvent e; e.kind = SettleEvKind::Found; e.bid = "b1"; e.credit = Amounts{{k, 5}};
        c2pool::v37n::xmr::set_cut(e, cut(100, 1));
        const SettleEvent back = SettleEvent::deserialize(e.serialize());
        CHECK(back.has_cut && c2pool::v37n::xmr::anchor_of(back) == std::optional<st::AnchorCut>(cut(100, 1)),
              "a FOUND event round-trips its credit cut (schema 2)");
        SettleEvent old; old.kind = SettleEvKind::Found; old.bid = "b0"; old.credit = Amounts{{k, 5}};
        const std::string raw = old.serialize();
        CHECK(static_cast<std::uint8_t>(raw[0]) == 1 && !SettleEvent::deserialize(raw).has_cut,
              "a cutless event keeps the schema-1 bytes and reads back without a cut");
        c2pool::v37n::xmr::MemSettleStore store;
        {
            auto batch = store.batch();
            batch->put(c2pool::v37n::xmr::store_codec::k_evt(7, 1), e.serialize());
            SettleEvent f; f.kind = SettleEvKind::Finalize; f.bid = "b1"; f.bin_height = 10;
            batch->put(c2pool::v37n::xmr::store_codec::k_evt(7, 2), f.serialize());
            (void)batch->commit_sync();
        }
        st::OwedLedger replay(7, R);
        bool ok = true;
        c2pool::v37n::xmr::RecoveryDriver rd(store, 7);
        (void)rd.recover(replay, ok);
        CHECK(ok && replay.anchor_cut() == std::optional<st::AnchorCut>(cut(100, 1)) && replay.owed_digest() == d1,
              "a restart replays the anchor from the event log (same owed_digest as the live ledger)");
    }
}

}  // namespace


// ---------------------------------------------------------------------------
void f12_dust_debt_when_room() {
    std::printf("== F12. a balance below c is PAID when the block has room (audit A8) ==\n");
    const std::uint64_t c = x6::spend_floor(kTail);
    const std::uint64_t reward = 600000000000ull;
    auto mk = [&](std::uint8_t k, std::uint64_t owed) { x6::OwedEntry e; auto r = ref_of(k); e.pay = r; e.identity = id_of(r); e.owed = owed; return e; };
    // (a) no pay-now, room to spare: the dust debts are paid in full, the rest
    //     of the pool stays in the donation residual.
    {
        auto in = fee_on_inputs(reward, true);
        in.owed_dust = {mk(31, c / 2), mk(32, c - 1)};
        const auto outs = x6::allocate_exact_sum(in);
        CHECK(to(outs, in.owed_dust[0].identity) == c / 2 && to(outs, in.owed_dust[1].identity) == c - 1,
              "no pay-now: both dust debts paid in full (%llu, %llu)",
              (unsigned long long)to(outs, in.owed_dust[0].identity), (unsigned long long)to(outs, in.owed_dust[1].identity));
        CHECK(sum_of(outs) == reward, "exact sum kept");
    }
    // (b) pay-now fills the pool: the dust debt is paid FIRST (debt before this
    //     block's pay-now), a pay-now payee's own dust merges into its output
    //     (no second slot), and its owed_left is not paid a second time.
    {
        const P a = payee(41, 300000000000ull), b = payee(42, 299000000000ull);
        auto in = fee_on_inputs(reward, true);
        arm(in, {a, b});
        const x6::OwedEntry da = [&] { x6::OwedEntry e; e.pay = a.ref; e.identity = a.id; e.owed = c / 4; return e; }();
        in.owed_dust = {da, mk(43, c / 5)};
        // a's pay-now entry also names the same balance as owed_left
        auto pn = in.paynow_at;
        in.paynow_at = [pn, &a, c](std::uint64_t t) { auto v = pn(t); for (auto& e : v) if (e.identity == a.id) e.owed_left = c / 4; return v; };
        const auto outs = x6::allocate_exact_sum(in);
        std::size_t outs_a = 0; for (const auto& o : outs) if (o.identity == a.id) ++outs_a;
        CHECK(outs_a == 1, "one output for the pay-now payee that also had a dust debt");
        const std::uint64_t id43 = to(outs, mk(43, 0).identity);
        CHECK(id43 == c / 5, "the other dust debt took a free slot and is paid in full (%llu)", (unsigned long long)id43);
        CHECK(sum_of(outs) == reward, "exact sum kept");
        CHECK(to(outs, a.id) + to(outs, b.id) + id43 + to(outs, fee::donation_identity(kNet)) == reward,
              "the dust debts came out of the pool, not on top of it");
        CHECK(to(outs, a.id) <= a.eb + c / 4, "a is never paid beyond its E_b plus its balance (no double pay of owed_left)");
    }
    // (c) no free slot: a dust debt whose payee has no output waits.
    {
        auto in = fee_on_inputs(reward, true);
        in.output_cap = 2;   // the donation marker + one slot
        in.owed_dust = {mk(51, c / 2), mk(52, c / 3)};
        const auto outs = x6::allocate_exact_sum(in);
        const std::uint64_t p1 = to(outs, in.owed_dust[0].identity), p2 = to(outs, in.owed_dust[1].identity);
        CHECK((p1 > 0) + (p2 > 0) == 1, "one slot: exactly one dust debt is paid, in the given (salted) order; the other waits");
        CHECK(p1 == c / 2, "the first in order took the slot");
    }
}

// ---------------------------------------------------------------------------
void f4b_band_drained() {
    std::printf("== F4b. THE DRAIN RULE: a balance in [arm floor, c(R)) is paid by the dust pass ==\n");
    namespace o2 = c2pool::v37n::xmr::o2;
    for (const std::uint64_t mult : {2ull, 8ull}) {
        const std::uint64_t R = kTail * mult;                 // fees raise c(R) above the arm floor (x8: the FCMP++-sized band)
        const std::uint64_t arm = x6::spend_floor(x6::kTailSubsidy);
        const std::uint64_t c = x6::spend_floor(R);
        const std::uint64_t w = (arm + c) / 2;              // inside the band: armed, proposed, below c(R)
        st::OwedLedgerRules r; r.arm_floor = static_cast<long long>(arm); r.rotate_on_payment = true;
        r.decay_horizon = 8640; r.decay_half_life = 2160; r.lane_height = true; r.decay_from_gross = true;
        st::OwedLedger L(7, r);
        const auto g = ref_of(41), p1 = ref_of(42), p2 = ref_of(43);
        L.on_block_found("seed", Amounts{{id_of(g), static_cast<long long>(w)}}, {});
        L.on_block_finalized("seed", 1);
        std::map<::v37::bytes32, ::v37::ScriptRef> refs{{id_of(g), g}, {id_of(p1), p1}, {id_of(p2), p2},
                                                        {fee::donation_identity(kNet), fee::donation_ref(kNet)}};
        const o2::PayOfFn pay_of = [refs](const ::v37::bytes32& k) {
            auto it = refs.find(k); if (it != refs.end()) return it->second;
            ::v37::ScriptRef raw; raw.kind = ::v37::ScriptKind::RAW; return raw;
        };
        auto build = [&](o2::DrainRule drain, std::string* why) {
            o2::XmrCoinbaseContext ctx;
            ctx.monero_major_version = 16; ctx.height = 5000; ctx.prev_id.data()[0] = 9;
            ctx.base_reward = R; ctx.chain_id = 7; ctx.lane_commitment = L.owed_digest();
            ctx.residual_sink = fee::donation_ref(kNet); ctx.residual_sink_identity = fee::donation_identity(kNet);
            ctx.fixed = {fee::donation_marker(kNet)}; ctx.output_cap = 16;
            ctx.kfair_salted_ties = true; ctx.spend_floor = true;
            ctx.has_credit_cut = true; ctx.credit_cut.next_pos = 10; ctx.has_paynow = true;
            for (const auto& p : {p1, p2}) { st::WeightedPayee wp; wp.key = id_of(p); wp.weight = ::v37::U256(std::uint64_t{1}); wp.pay = p; ctx.paynow_payees.push_back(wp); }
            ctx.drain = drain;
            return o2::XmrOwedSettlementSource::build(L, pay_of, ctx, R, why);
        };
        std::string why;
        const auto src = build(o2::DrainRule{1, 16, 64}, &why);
        CHECK(src != nullptr, "x%llu: builds: %s", (unsigned long long)mult, why.c_str());
        if (!src) continue;
        bool in_owed = false, in_dust = false;
        for (const auto& e : src->inputs().owed) if (e.identity == id_of(g)) in_owed = true;
        for (const auto& e : src->inputs().owed_dust) if (e.identity == id_of(g)) in_dust = true;
        x6::AllocStats stt;
        const auto outs = x6::allocate_exact_sum(src->inputs_at(R, {}), nullptr, nullptr, &stt);
        CHECK(!in_owed && in_dust && to(outs, id_of(g)) == w && stt.dust_paid == w && w <= src->drain_delta(),
              "x%llu: c(R)=%llu, a balance %llu in [%llu, c(R)) is routed to the dust list and paid in full by the dust pass "
              "(min(owed, Delta - owed_paid), Delta %llu)", (unsigned long long)mult, (unsigned long long)c, (unsigned long long)w,
              (unsigned long long)arm, (unsigned long long)src->drain_delta());
        const auto off = build(o2::DrainRule{}, &why);   // master: proposed, skipped by X6, absent from the dust list
        CHECK(off && to(x6::allocate_exact_sum(off->inputs_at(R, {})), id_of(g)) == 0,
              "x%llu: rule off (master): the band balance is proposed, skipped by X6 and never paid (RESULTS 13)", (unsigned long long)mult);
    }
}

// ---------------------------------------------------------------------------
void f10b_gross_clock() {
    std::printf("== F10b. THE DRAIN RULE: the dust-decay clock runs on the gross set G_b ==\n");
    st::OwedLedgerRules r; r.arm_floor = 1000; r.rotate_on_payment = true; r.decay_horizon = 100; r.decay_half_life = 50;
    r.lane_height = true; r.decay_from_gross = true;
    const ::v37::bytes32 A = key(0x11), D = key(0x21), S = key(0x31), Q = key(0x41);
    st::OwedLedger L(7, r);
    int nb = 0;
    std::uint64_t h = 100;
    // a pay-now-first lane block: every window row nets to 0 credit; G_b is the window
    auto block = [&](std::set<::v37::bytes32> gross, std::uint64_t bin) {
        const std::string bid = "g" + std::to_string(++nb);
        st::LaneFound lf; lf.height = h++; lf.gross = std::move(gross);
        L.on_block_found(bid, {}, {}, std::nullopt, nullptr, &lf); L.on_block_finalized(bid, bin);
    };
    L.on_block_found("seed", Amounts{{D, 800}, {S, 3}, {Q, 600}}, {}); L.on_block_finalized("seed", 1);
    block({}, 400);                                  // an empty cut: G_b = {} passes nobody by
    block({}, 499);
    CHECK(L.effective_owed(D) == 800 && L.effective_owed(Q) == 600, "empty-cut blocks (G_b = {}) pass nobody by: D 800, Q 600 at bin 499");
    block({A, S}, 520);                              // netted to 0, but G_b = {A, S}: D and Q are passed by
    block({A, S}, 630);
    CHECK(L.effective_owed(D) == 400 && L.effective_owed(Q) == 300, "the first FINALIZE whose G_b omits them starts the clock: halved at bin 630");
    block({A, S, Q}, 640);                           // Q's window work is back
    block({A, S, Q}, 700);
    CHECK(L.effective_owed(D) == 200 && L.effective_owed(Q) == 300, "a key in G_b stops its decay (Q 300); D keeps halving (200 at 700)");
    CHECK(L.effective_owed(S) == 3, "the active dust miner S, in every G_b, never decays (3)");
    // the gap this closes: the same blocks with the netted credit as the clock
    st::OwedLedgerRules r0 = r; r0.decay_from_gross = false;
    st::OwedLedger L0(7, r0);
    L0.on_block_found("seed", Amounts{{D, 800}}, {}); L0.on_block_finalized("seed", 1);
    for (std::uint64_t bin : {520ull, 630ull, 700ull}) {
        const std::string bid = "n" + std::to_string(bin);
        L0.on_block_found(bid, {}, {}); L0.on_block_finalized(bid, bin);
    }
    CHECK(L0.effective_owed(D) == 800, "without the gross set a netted-to-0 block passes nobody by: D never decays (800)");
}

int main() {
    std::printf("v37_xmr_spend_floor_kat\n");
    f1_floor();
    f2_crumbs();
    f2b_no_room();
    f2c_short_pool();
    f2d_debt_first();
    f3_slots();
    f3b_worth_spending_first();
    f4_owed_floor();
    f4b_band_drained();
    f5_receive();
    f6_off();
    f7_seniority();
    f8_rotation();
    f9_off();
    f10_decay();
    f10b_gross_clock();
    f11_anchor();
    f12_dust_debt_when_room();
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
