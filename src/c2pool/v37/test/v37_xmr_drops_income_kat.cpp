// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_drops_income_kat -- handoff A4b (operator ruling 2026-10-01 "Window
// price"): sub-threshold (DROPS) work is paid like a share.
//
// THE RULE (OwedLedgerRules::drops_window). A lane block's composition books
// each payee's credited sub-threshold work per bin (the Count REPLACE delta, in
// work, signed) as WINDOW WEIGHT at the bin's end position on the lane. The
// entries join the ledger's committed window at the block's FINALIZE, and every
// lane block whose cut holds them in the window splits its reward over the
// cut's share weights PLUS the window's DROPS weights,
//     (work << (62 - lz)) * rw * lambda^age,  age = N - c < W,
// the same Q62 unit and the same decay as a share of that age. The DROPS work
// is in the payee's weight AND in the SUM, so the reward is divided once.
// Nothing is priced once: the deposit / due path carries nothing.
//
// THE PREDICTION. A DROPS-only miner D with A's hashrate holds, at every cut,
// the weight of one share per bin spread over its bin's slots (A4c: the mean
// of lambda^age over the bin's n slots), A one share per bin at its slot inside
// the bin: per hash D earns what A earns, at any block rate k. The
// pool's work per bin is 13 shares (A 1, C 11, D 64 raindrops), so a share
// earns R / (13 B) per lane block of B bins.
//
// THE KAT drives the real pieces on the shipped XMR path: v37::Lane with
// xmr_lane_params_default() (Count mode, floor share_diff / 64), project and
// split_reward at the ANCHOR (the previous lane block's cut, as a booking on
// the anchor ledger does), lane_enrollment_ex with the ledger registry
// (raindrop enrolment), subthreshold_window for the entries and an OwedLedger
// with anchor_cut, drops_due, raindrop_enrol and drops_window on. A lane block
// lands at the end of every B-th bin; each bin range is harvested once.
//
//   I1  only D has window entries (A and C: a share and its 63 raindrops are
//       a zero delta), each exactly 64 * 2^26 at its bin's end (12 b + 12)
//       spanning the bin's 12 slots (A4c);
//       D is enrolled by raindrop; the window stays bounded (pruned at W).
//   I2  every block divides exactly its reward (SUM E == R), no row is ever
//       negative, and the one-shot path carries nothing (no deposit, no claim,
//       due empty): DROPS work is never paid twice.
//   I3  A earns the fair R / (13 B) per share (within 1/256).
//   I4  M1: D's income per hash / A's == 1 (within 1/4096, A4c) at k = 1, 3,
//       10, 30 and 0.33 lane blocks per window.
//   I5  the ONE-SHOT price (each raindrop priced once at its lane block's cut,
//       the A4 rule) computed alongside is m / S_eff = 2.957 / k and trips I4;
//       V37_A4_PRICE=one_shot substitutes it for the measured ratio (I4 FAILS).
//   W1  M2 withholding: A publishing its share vs the same A withholding it
//       (64 raindrops, no share) earns the same per hash (within 1/4096, A4c)
//       at k = 0.33, 1, 3, 10 and 30.
//   I6  A4c: a window entry spanning n slots weighs the mean of lambda^age over
//       them: drops_window_weights against the closed form (1e-9).
// Built without the window API (the A4 tree) the same KAT runs the one-shot
// path (deposit, due, claim) and I3/I4/W1 FAIL: that is the base measurement.
//
// TOLERANCE. I3 1/256 (vs the closed-form fair share). I4 / W1 1/4096 (A4c;
// A4b booked D at the bin end and measured 1.00193 / 1.00176, so the base trips
// it): amounts are integers floored once per payee per block (< 1e-9 of a block
// here). The only other deviation is A's FIXED slot inside its bin: the window
// entry weighs the mean over the bin's 12 slots (the weight of a share at a
// uniformly placed slot), A's share sits at slot 6 of 1..12, half a position
// older than the mean slot 6.5, so DROPS / share ~ lambda^(-1/2) - 1 ~ 1.6e-4
// (withholding: the 11-slot bin's mean vs A's slot among C's, ~1.75e-4); both
// < 1/4096 = 2.44e-4. A share whose slot is uniform in its bin weighs exactly
// the mean in expectation.
// ---------------------------------------------------------------------------
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>
#include <algorithm>

#include <sharechain/v37/v37_lane.hpp>
#include <c2pool/v37/v37_subthreshold_estimator.hpp>
#include <c2pool/v37/v37_drop_harvest.hpp>
#include <c2pool/v37/v37_drops_enrollment.hpp>
#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/xmr/xmr_node_config.hpp>
#include <c2pool/v37/xmr/xmr_drops_wiring.hpp>
#include <c2pool/v37/xmr/relay/xmr_relay_wire.hpp>   // relay::kReceiptWeight

namespace st = ::c2pool::v37::subthreshold;
namespace settle = ::c2pool::v37n::settle;
namespace dx = ::c2pool::v37n::xmr::drops;
using Amounts = settle::OwedLedger::Amounts;
using ::v37::bytes32;
using ::v37::MinerId;
using ::v37::U256;
using u64 = std::uint64_t;

static int g_pass = 0, g_fail = 0;
static void check(bool ok, const std::string& what) {
    (ok ? g_pass : g_fail)++;
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
}
static st::u256 pow2(unsigned b) { st::u256 x; x.w[b >> 6] = 1ull << (b & 63); return x; }
static bytes32 key(std::uint8_t b) { bytes32 k{}; k[0] = b; k[31] = 0xa4; return k; }

// A4c: the window key's position / payee (the A4b tree keys by (c, payee)).
#ifdef C2POOL_XMR_DROPS_WINDOW_SPAN
template <class K> static u64 kc(const K& ck) { return ck.c; }
template <class K> static bytes32 kp(const K& ck) { return ck.payee; }
template <class K> static u64 kn(const K& ck) { return ck.n; }
#else
template <class K> static u64 kc(const K& ck) { return ck.first; }
template <class K> static bytes32 kp(const K& ck) { return ck.second; }
template <class K> static u64 kn(const K&) { return 0; }
#endif

static const bytes32 KA = key(0x0a);   // share miner (1 share / bin), or withholding it (64 raindrops / bin)
static const bytes32 KC = key(0x0c);   // the rest of the pool (11 shares / bin)
static const bytes32 KD = key(0x0d);   // DROPS-only miner, A's hashrate (64 raindrops / bin)
constexpr ::v37::ChainId kChain = 0x000000A4;
constexpr u64 kReward = 600000000000ull;   // 0.6 XMR in atomic units
constexpr u64 kDropsPerShare = 64;         // 2^kXmrDropsFloorShift
constexpr u64 kWorkPerBin = 13;            // shares of work per bin: A 1 + C 11 + D 1

struct IdView {
    std::map<MinerId, ::v37::IdentityEntry> m;
    const ::v37::IdentityEntry* find(MinerId id) const {
        auto it = m.find(id);
        return it == m.end() ? nullptr : &it->second;
    }
};
struct View {
    std::map<MinerId, U256> payout;
    std::shared_ptr<const IdView> identities;
};

struct Run {
    u64 B = 0, m = 0, blocks = 0;           // bins per lane block, positions per lane block, measured blocks
    long double k = 0;                      // lane blocks per window, W / m
    long double incA = 0, incD = 0, oneshotD = 0;
    long double workA = 0, workD = 0;       // A's and D's work over the measured blocks, in shares
    long double perA = 0, perD = 0, ratio = 0, oneshot_ratio = 0, fair = 0;
    bool ac_no_entry = true, d_entry_exact = true, d_enrolled_by_raindrop = false;
    bool conserve = true, no_negative = true, never_twice = true, no_sat = true;
    std::size_t win_max = 0;                // the largest committed window seen
};

// One run: warm bins, then measured bins; a lane block closes every B-th bin.
// withhold: A keeps its share off the lane and sends it as 64 raindrops.
static Run run(u64 B, u64 warm_bins, u64 meas_bins, u64 rw, bool withhold) {
    const ::v37::LaneParams p = ::c2pool::v37n::xmr::xmr_lane_params_default();
    ::v37::Lane lane(p);
    auto idv = std::make_shared<IdView>();
    idv->m[1] = ::v37::IdentityEntry{KA, {}};
    idv->m[2] = ::v37::IdentityEntry{KC, {}};
    settle::OwedLedgerRules rules;
    rules.anchor_cut = true; rules.drops_due = true; rules.raindrop_enrol = true;
#ifdef C2POOL_XMR_DROPS_WINDOW
    rules.drops_window = settle::DropsWindowRule{p.window, p.half_life, p.epoch_len(), rw, dx::kXmrDropsLz};
#endif
    settle::OwedLedger L(kChain, rules);
    const st::u256 hT = ::c2pool::v37n::drops_detail::h_t_of_lz(dx::kXmrDropsLz);
    const st::u256 drop = pow2(228);        // h_T = 2^224 - 1 < 2^228 < floor 2^230: a raindrop
    dx::LanePrefix lp;                      // A and C have a share at bin 0 (share-rule enrolment)
    lp.base_first[KA] = 0; lp.base_first[KC] = 0;
    // The intra-bin order (as window_pulse_kat): miner i's j-th receipt at (j + 0.5) / n_i.
    std::vector<std::pair<double, int>> order;
    if (!withhold) order.push_back({0.5, 1});
    for (u64 j = 0; j < 11; ++j) order.push_back({(j + 0.5) / 11.0, 2});
    std::sort(order.begin(), order.end());
    const u64 npb = order.size();           // lane positions per bin
    Run r;
    r.B = B; r.m = B * npb; r.k = (long double)p.window / (long double)r.m;
    struct Cell { u64 S = 0, J = 0; };
    std::map<std::pair<bytes32, u64>, Cell> harvest;   // (payee, bin) since the last lane block
    std::map<bytes32, u64> first_drop;                 // first raindrop bin inside the range
    std::optional<View> anchor;                        // the view at the anchor (previous lane block's cut)
    u64 anchorN = 0, pos = 0;
    long long prev_deposit_D = 0;                      // (one-shot path only)
    for (u64 b = 0; b < warm_bins + meas_bins; ++b) {
        for (const auto& [x, i] : order) { (void)x; lane.push(MinerId(i), rw, 0); ++pos; }
        harvest[{KA, b}] = withhold ? Cell{0, kDropsPerShare} : Cell{1, 63};
        harvest[{KC, b}] = Cell{11, 11 * 63};
        harvest[{KD, b}] = Cell{0, kDropsPerShare};
        if (withhold) first_drop.try_emplace(KA, b);
        first_drop.try_emplace(KD, b);
        if ((b + 1) % B != 0) continue;
        const u64 h = b + 1;
        View now; now.payout = lane.payout_map(); now.identities = idv;
        settle::DropsCompose ctx;
        ctx.price = dx::drops_price_at(kReward, now, rw);   // the one-shot price at this cut (the A4 rule)
        const settle::DropsEnrolRegistry reg = L.drops_enrol_registry();
        const ::c2pool::v37n::EnrollmentBook book =
            dx::lane_enrollment_ex(lp, {}, dx::EnrolMode::Auto, reg, first_drop);
        ctx.enrollment = &book;
        std::vector<settle::HarvestedReceipt> hv;
        u64 J_D = 0;
        for (const auto& [pk, c] : harvest) {
            settle::HarvestedReceipt hr{pk.first, pk.second, st::ReceiptCollector(p.subthreshold.K, hT)};
            for (u64 j = 0; j < c.J; ++j) hr.collector.observe(drop);
            hr.collector.set_shares(c.S);
            if (pk.first == KD && book.enrolled(KD, pk.second)) J_D += c.J;
            hv.push_back(std::move(hr));
        }
        long long oneshot = 0;   // I5: D's raindrops of this range priced ONCE at this cut
        { st::u320 w; w.w[0] = J_D << 26; oneshot = settle::entitlement_of_work(ctx.price, w); }
        Amounts E;
        settle::DropsFound d;
#ifdef C2POOL_XMR_DROPS_WINDOW
        if (anchor) {   // the booking: shares at the anchor cut + the committed window at it
            const auto merged = L.drops_window_merge(settle::project(*anchor), anchorN);
            const auto amt = settle::split_reward(kReward, merged);
            u64 tot = 0;
            for (std::size_t i = 0; i < merged.size(); ++i) { tot += amt[i]; if (amt[i]) E[merged[i].key] += (long long)amt[i]; }
            if (tot != kReward) r.conserve = false;
        }
#ifdef C2POOL_XMR_DROPS_WINDOW_SPAN   // A4c: the bin's span (end c, its npb slots)
        d.window = settle::subthreshold_window(p, hv, ctx, [&](u64 bin) { return settle::DropsBinSpan{(bin + 1) * npb, npb}; });
#else
        d.window = settle::subthreshold_window(p, hv, ctx, [&](u64 bin) { return (bin + 1) * npb; });
#endif
        u64 d_rows = 0;
        for (const auto& [ck, v] : d.window) {
            if (kp(ck) == KC || (kp(ck) == KA && !withhold)) r.ac_no_entry = false;
            if (kp(ck) == KD) {
                ++d_rows;
                if (v != (long long)(kDropsPerShare << 26) || kc(ck) % npb != 0) r.d_entry_exact = false;
#ifdef C2POOL_XMR_DROPS_WINDOW_SPAN
                if (kn(ck) != npb) r.d_entry_exact = false;   // A4c: the entry spans the bin's slots
#endif
            }
        }
        if (d_rows != J_D / kDropsPerShare) r.d_entry_exact = false;   // one row per enrolled bin
        (void)prev_deposit_D;
#else
        for (const auto& [k2, a] : settle::settle_block(kReward, now)) E[k2] = (long long)a;
        {
            u64 tot = 0;
            for (const auto& [k2, a] : E) { (void)k2; tot += (u64)a; }
            if (tot != kReward) r.conserve = false;
        }
        bool sat = false;
        const auto delta = settle::subthreshold_credit(p, hv, ctx, &sat);
        if (sat) r.no_sat = false;
        for (const auto& [k2, x] : delta) if (x != 0) d.deposit[k2] = x;
        if (delta.count(KC) || (delta.count(KA) && !withhold)) r.ac_no_entry = false;
        prev_deposit_D = d.deposit.count(KD) ? d.deposit.at(KD) : 0;
#endif
        for (const auto& [payee, bin] : first_drop)   // RAINDROP ENROL (compose_lane)
            if (!reg.count(payee) && book.find(payee)) {
                settle::DropsEnrolRec rec; rec.eff = bin + 1;
                d.enrol_add.emplace(payee, rec);
                if (payee == KD) r.d_enrolled_by_raindrop = true;
            }
        d.claim = true;
        d.claimed = L.drops_available();
        settle::apply_drops_due(E, d.claimed, &d.writeoff);
#ifdef C2POOL_XMR_DROPS_WINDOW
        if (!d.deposit.empty() || !d.claimed.empty() || !L.drops_due().empty()) r.never_twice = false;
#endif
        for (const auto& [k2, v] : E) { (void)k2; if (v < 0) r.no_negative = false; }
        const std::string bid = "LB" + std::to_string(h);
        L.on_block_found(bid, E, {}, settle::AnchorCut{pos, {}}, &d);
        L.on_block_finalized(bid, h);
        for (const auto& [k2, v] : L.effective_owed_all()) { (void)k2; if (v < 0) r.no_negative = false; }
#ifdef C2POOL_XMR_DROPS_WINDOW
        r.win_max = std::max(r.win_max, L.drops_window().size());
#endif
        if (b >= warm_bins) {   // a measured block
            ++r.blocks;
            r.incA += (long double)(E.count(KA) ? E.at(KA) : 0);
            r.incD += (long double)(E.count(KD) ? E.at(KD) : 0);
            r.oneshotD += (long double)oneshot;
            r.workA += (long double)B; r.workD += (long double)B;   // one share of work per bin each
        }
        anchor = now; anchorN = pos;
        harvest.clear();
        first_drop.clear();
    }
    r.perA = r.incA / r.workA;
    r.perD = r.incD / r.workD;
    r.ratio = r.perD / r.perA;
    r.oneshot_ratio = (r.oneshotD / r.workD) / ((long double)kReward / (long double)r.m);   // vs a share's R / m (A4)
    r.fair = (long double)kReward / (long double)(B * kWorkPerBin);
    return r;
}

static bool within(long double x, long double want, long double tol) { return std::fabs(x / want - 1.0L) <= tol; }

static long double u256_ld(const U256& x) {
    long double r = 0;
    for (int i = 3; i >= 0; --i) r = r * 18446744073709551616.0L + (long double)x.v[static_cast<std::size_t>(i)];
    return r;
}
// I6 (A4c): one entry of work w spanning n slots up to c weighs, at a cut N,
// w * mean_{i<n} lambda^(N - c + i) (slots at or past the window weigh 0).
static void i6_span_mean(const ::v37::LaneParams& p, u64 rw, long double lambda) {
#ifdef C2POOL_XMR_DROPS_WINDOW_SPAN
    const settle::DropsWindowRule rule{p.window, p.half_life, p.epoch_len(), rw, dx::kXmrDropsLz};
    const long long work = (long long)(kDropsPerShare << 26);
    const long double unit = std::ldexp((long double)work, (int)(62 - dx::kXmrDropsLz)) * (long double)rw;
    bool ok = true, ok_point = true;
    long double worst = 0;
    for (const u64 n : std::initializer_list<u64>{1, 12, 11, 64})
        for (const u64 a0 : std::initializer_list<u64>{0, 7, 1000, (u64)p.window - 5}) {
            const u64 c = 100000, N = c + a0;
            settle::DropsWindow w; w[settle::DropsWindowKey(c, n, KD)] = work;
            const auto dw = settle::drops_window_weights(w, N, rule);
            long double want = 0;
            for (u64 i = 0; i < n; ++i) if (a0 + i < p.window) want += std::pow(lambda, (long double)(a0 + i));
            want = unit * want / (long double)n;
            const long double got = dw.count(KD) ? u256_ld(dw.at(KD).first) : 0.0L;
            const long double dev = std::fabs(got / want - 1.0L);
            worst = std::max(worst, dev);
            if (!(dev < 1e-9L)) ok = false;
            if (n == 1) {   // a one-slot span weighs exactly as the A4b point entry at c
                settle::DropsWindow pt; pt[settle::DropsWindowKey(c, KD)] = work;
                const auto dp = settle::drops_window_weights(pt, N, rule);
                if (!(dp.count(KD) && dp.at(KD).first == dw.at(KD).first)) ok_point = false;
            }
        }
    std::printf("   I6 span entries vs closed-form mean of lambda^age: worst relative deviation %.3Le\n", worst);
    check(ok, "I6 A4c: an entry spanning n slots weighs the mean of lambda^age over them (1e-9)");
    check(ok_point, "I6 A4c: a one-slot span weighs exactly as a point entry at c");
#else
    (void)p; (void)rw; (void)lambda;
    check(false, "I6 A4c: no bin span on the base (entries weigh at the bin end)");
#endif
}

// I7 (A4c, M2): under the window rule the won frame (FB_BLOCK_WON v0x02)
// carries no one-shot DROPS coin delta: the carry is the enrolment digest alone,
// identical at any price, and a receiver composing at another price agrees.
// Rule off: compose_carry byte for byte, and the frame depends on the price.
static void i7_won_frame(const ::v37::LaneParams& p, u64 rw) {
#ifdef C2POOL_XMR_DROPS_CARRY_WINDOW
    namespace relay = ::c2pool::v37n::xmr::relay;
    auto idv = std::make_shared<IdView>();
    idv->m[1] = ::v37::IdentityEntry{KA, {}};
    idv->m[2] = ::v37::IdentityEntry{KC, {}};
    const auto price_after = [&](u64 n) {
        ::v37::Lane lane(p);
        for (u64 i = 0; i < n; ++i) lane.push(MinerId(1 + i % 2), rw, 0);
        View v; v.payout = lane.payout_map(); v.identities = idv;
        return dx::drops_price_at(kReward, v, rw);
    };
    dx::LanePrefix lp; lp.base_first[KA] = 0; lp.base_first[KC] = 0;
    const std::map<bytes32, u64> first_drop{{KD, 0}};
    const ::c2pool::v37n::EnrollmentBook book = dx::lane_enrollment_ex(lp, {}, dx::EnrolMode::Auto, {}, first_drop);
    const st::u256 hT = ::c2pool::v37n::drops_detail::h_t_of_lz(dx::kXmrDropsLz);
    std::vector<settle::HarvestedReceipt> hv;
    for (u64 bin = 1; bin <= 2; ++bin)
        for (const auto& [k, S, J] : {std::tuple<bytes32, u64, u64>{KA, 1, 63}, {KD, 0, 64}}) {
            settle::HarvestedReceipt hr{k, bin, st::ReceiptCollector(p.subthreshold.K, hT)};
            for (u64 j = 0; j < J; ++j) hr.collector.observe(pow2(228));
            hr.collector.set_shares(S);
            hv.push_back(std::move(hr));
        }
    settle::DropsCompose c1, c2;
    c1.price = price_after(12); c2.price = price_after(24);
    c1.enrollment = &book; c2.enrollment = &book;
    const auto off1 = dx::compose_carry_ruled(p, hv, c1, false), off2 = dx::compose_carry_ruled(p, hv, c2, false);
    const auto on1 = dx::compose_carry_ruled(p, hv, c1, true), on2 = dx::compose_carry_ruled(p, hv, c2, true);
    const auto frame = [&](const dx::DropsCarry& c) {
        relay::BlockWon bw;
        bw.chain_id = kChain; bw.bid[0] = 0xb7; bw.h_b = 7; bw.cut_next_pos = 24; bw.reward = kReward; bw.payout_emitted = true;
        bw.drops = relay::BlockWon::Drops{c.delta, c.enrollment_digest};
        return relay::encode_block_won(bw);
    };
    const auto fo1 = frame(off1), fo2 = frame(off2), fw1 = frame(on1), fw2 = frame(on2);
    std::printf("   I7 rule off: one-shot delta rows %zu, D %lld / %lld at two prices, frames %zu / %zu B (%s)\n",
                off1.delta.size(), off1.delta.count(KD) ? off1.delta.at(KD) : 0LL, off2.delta.count(KD) ? off2.delta.at(KD) : 0LL,
                fo1.size(), fo2.size(), fo1 == fo2 ? "equal" : "differ");
    std::printf("   I7 window rule: delta rows %zu / %zu, frames %zu / %zu B (%s)\n", on1.delta.size(), on2.delta.size(),
                fw1.size(), fw2.size(), fw1 == fw2 ? "equal" : "differ");
    check(off1 == dx::compose_carry(p, hv, c1) && off1.delta.count(KD) && off1.delta != off2.delta && fo1 != fo2,
          "I7 rule off: the carry is compose_carry byte for byte and the frame depends on the one-shot price");
    check(on1.delta.empty() && on1 == on2 && fw1 == fw2 && on1.enrollment_digest == off1.enrollment_digest,
          "I7 window rule: the frame carries no one-shot delta (digest only), identical at any price");
    check(dx::verify_carry(on1, true, on2.enrollment_digest).empty() && dx::carried_delta_agrees(on1.delta, on2.delta),
          "I7 window rule: a receiver composing at another price agrees with the carried frame");
    check(!dx::carried_delta_agrees(off1.delta, on2.delta),
          "I7 window rule: a frame carrying a one-shot delta does not agree with a window receiver (one source of truth)");
#else
    (void)p; (void)rw;
    check(false, "I7 A4c: no window-ruled carry on the base (the frame carries the one-shot delta)");
#endif
}

int main() {
    std::printf("== v37_xmr_drops_income_kat: sub-threshold work is paid like a share (handoff A4b, window price)\n");
    const ::v37::LaneParams p = ::c2pool::v37n::xmr::xmr_lane_params_default();
    const u64 rw = ::c2pool::v37n::xmr::relay::kReceiptWeight;
    const long double lambda = std::pow(2.0L, -1.0L / (long double)p.half_life);
    const long double s_closed = (1.0L - std::pow(lambda, (long double)p.window)) / (1.0L - lambda);
    std::printf("   lane: window W %llu positions, half-life %llu; Count mode %u, floor shift %u; rw %llu\n",
                (unsigned long long)p.window, (unsigned long long)p.half_life, (unsigned)p.subthreshold.mode,
                (unsigned)p.subthreshold.count_floor_shift, (unsigned long long)rw);
    std::printf("   closed form S_eff = sum_{a<W} lambda^a = %.4Lf, W / S_eff = %.4Lf (the one-shot ratio is m / S_eff)\n",
                s_closed, (long double)p.window / s_closed);
#ifdef C2POOL_XMR_DROPS_WINDOW
    std::printf("   rule: DROPS WINDOW present (OwedLedgerRules::drops_window)\n");
#else
    std::printf("   rule: DROPS WINDOW ABSENT (the A4 tree): the one-shot path runs; I3/I4/W1 are expected to FAIL\n");
#endif
    check(p.subthreshold.enabled && p.subthreshold.mode == 2 && p.subthreshold.count_floor_shift == 6,
          "shipped XMR path: DROPS on, Count mode, floor share_diff / 64");
    const long double tol = 1.0L / 256.0L;
    const long double tol_eq = 1.0L / 4096.0L;   // A4c: I4 / W1 (the A4b bin-end residue 1.00193 / 1.00176 trips it)
    const char* env = std::getenv("V37_A4_PRICE");
    const bool one_shot = env && std::strcmp(env, "one_shot") == 0;
    if (one_shot) std::printf("   CONTROL MODE: the one-shot price substituted for the measured ratio (I4 must FAIL)\n");
    const u64 base_bins = p.window / 12;   // one window of bins
    std::printf("   %6s %6s %7s %6s %12s %12s %12s %9s %9s %9s\n", "B bins", "m pos", "k", "blocks",
                "A per share", "D per share", "fair", "measured", "one-shot", "m/S_eff");
    for (const u64 B : {720ull, 240ull, 72ull, 24ull, 2160ull}) {
        Run r = run(B, std::max(2 * base_bins, 2 * B), std::max(6 * base_bins, 6 * B), rw, false);
        if (one_shot) r.ratio = r.oneshot_ratio;
        const long double pred1 = (long double)r.m / s_closed;
        std::printf("   %6llu %6llu %7.3Lf %6llu %12.1Lf %12.1Lf %12.1Lf %9.5Lf %9.5Lf %9.5Lf  window<=%zu\n",
                    (unsigned long long)r.B, (unsigned long long)r.m, r.k, (unsigned long long)r.blocks,
                    r.perA, r.perD, r.fair, r.ratio, r.oneshot_ratio, pred1, r.win_max);
        char kb[32]; std::snprintf(kb, sizeof kb, "k=%.2Lf: ", r.k);
        const std::string tag = kb;
        check(r.ac_no_entry, tag + "I1 A and C (a share and its 63 raindrops) book no DROPS entry");
        check(r.d_entry_exact, tag + "I1 D books exactly 64 * 2^26 per enrolled bin, at the bin's end position");
        check(r.d_enrolled_by_raindrop, tag + "I1 D is enrolled by raindrop (A3 enrol_add)");
        check(r.win_max <= p.window / 12 + 2, tag + "I1 the committed window is bounded (pruned at W)");
        check(r.conserve && r.no_negative && r.no_sat, tag + "I2 every block divides exactly its reward; no negative row");
        check(r.never_twice, tag + "I2 the one-shot path carries nothing (no deposit, no claim, due empty)");
        check(within(r.perA, r.fair, tol), tag + "I3 A earns the fair R / (13 B) per share (1/256)");
        std::printf("   I3 k=%.2Lf D per share / fair = %.9Lf (A4c: DROPS work weighs a share at the mean slot of its bin)\n", r.k,
                    r.perD / r.fair);
        check(within(r.perD, r.fair, 1e-6L), tag + "I3 A4c: DROPS-only D earns exactly the fair R / (13 B) per share (1e-6)");
        std::printf("   I4 k=%.2Lf DROPS/share per hash = %.6Lf (deviation %+.3Le, bound 1/4096 = %.3Le)\n", r.k, r.ratio,
                    r.ratio - 1.0L, tol_eq);
        check(within(r.ratio, 1.0L, tol_eq), tag + "I4 M1 DROPS-only / share-only income per hash == 1 (1/4096)");
        check(within(r.oneshot_ratio, pred1, tol), tag + "I5 the one-shot price is m / S_eff (the A4 measurement)");
        check(!within(r.oneshot_ratio, 1.0L, tol), tag + "I5 the one-shot price trips I4");
    }
    std::printf("   W1 (M2) withholding: A publishing its share vs A withholding it (64 raindrops, no share)\n");
    std::printf("   %6s %7s %14s %14s %9s\n", "B bins", "k", "A publishes", "A withholds", "ratio");
    for (const u64 B : {2160ull, 720ull, 240ull, 72ull, 24ull}) {
        const Run pub = run(B, std::max(2 * base_bins, 2 * B), std::max(6 * base_bins, 6 * B), rw, false);
        const Run wh = run(B, std::max(2 * base_bins, 2 * B), std::max(6 * base_bins, 6 * B), rw, true);
        const long double w = wh.perA / pub.perA;
        std::printf("   %6llu %7.3Lf %14.1Lf %14.1Lf %9.6Lf (deviation %+.3Le)\n", (unsigned long long)B, pub.k, pub.perA, wh.perA, w,
                    w - 1.0L);
        char kb[32]; std::snprintf(kb, sizeof kb, "k=%.2Lf: ", pub.k);
        check(wh.conserve && wh.no_negative && wh.never_twice, std::string(kb) + "W1 withholding run: exact division, no negative row, never twice");
        check(within(w, 1.0L, tol_eq), std::string(kb) + "W1 M2 withholding a share changes A's income per hash by < 1/4096");
        check(within(wh.perA, wh.fair, 1e-6L), std::string(kb) + "W1 A4c: withholding A earns exactly the fair R / (13 B) per share (1e-6)");
    }
    i6_span_mean(p, rw, lambda);
    i7_won_frame(p, rw);
    std::printf("== v37_xmr_drops_income_kat: %d passed, %d failed -> %s\n", g_pass, g_fail, g_fail ? "FAIL" : "OK");
    return g_fail ? 1 : 0;
}
