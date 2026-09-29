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
//   F3  too few output slots: the largest payees get the slots, the rest
//       wait; no CapTooSmall; the advance cap sends the excess to the residual.
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
// ---------------------------------------------------------------------------
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/settle/xmr_coinbase.hpp"
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/xmr_paynow.hpp"
#include "c2pool/v37/w4_settlement.hpp"

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

// ---------------------------------------------------------------------------
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
        auto in = fee_on_inputs(x.eb + y.eb + 1, true);
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

void f9_off() {
    std::printf("== F9. rules off: byte-identical ==\n");
    st::OwedLedger a(7), b(7, st::OwedLedgerRules{});
    for (auto* L : {&a, &b}) {
        L->on_block_found("b1", Amounts{{key(1), 7}, {key(2), 900}}, {}); L->on_block_finalized("b1", 1);
        L->on_block_found("b2", Amounts{{key(3), 5}}, Amounts{{key(2), 400}}); L->on_block_finalized("b2", 2);
    }
    CHECK(a.owed_digest() == b.owed_digest(), "a default ledger and an explicit rules-off ledger commit the same owed_digest");
}

}  // namespace

int main() {
    std::printf("v37_xmr_spend_floor_kat\n");
    f1_floor();
    f2_crumbs();
    f2b_no_room();
    f3_slots();
    f4_owed_floor();
    f5_receive();
    f6_off();
    f7_seniority();
    f8_rotation();
    f9_off();
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
