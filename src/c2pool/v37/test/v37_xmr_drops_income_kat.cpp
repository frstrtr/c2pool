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
// the weight of one share per bin at its bin's end, A one share per bin at its
// slot inside the bin: per hash D earns what A earns, at any block rate k. The
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
//       a zero delta), each exactly 64 * 2^26 at its bin's end (12 b + 12);
//       D is enrolled by raindrop; the window stays bounded (pruned at W).
//   I2  every block divides exactly its reward (SUM E == R), no row is ever
//       negative, and the one-shot path carries nothing (no deposit, no claim,
//       due empty): DROPS work is never paid twice.
//   I3  A earns the fair R / (13 B) per share (within 1/256).
//   I4  M1: D's income per hash / A's == 1 (within 1/256) at k = 1, 3, 10, 30
//       and 0.33 lane blocks per window.
//   I5  the ONE-SHOT price (each raindrop priced once at its lane block's cut,
//       the A4 rule) computed alongside is m / S_eff = 2.957 / k and trips I4;
//       V37_A4_PRICE=one_shot substitutes it for the measured ratio (I4 FAILS).
//   W1  M2 withholding: A publishing its share vs the same A withholding it
//       (64 raindrops, no share) earns the same per hash (within 1/256) at
//       k = 0.33, 1 and 10.
// Built without the window API (the A4 tree) the same KAT runs the one-shot
// path (deposit, due, claim) and I3/I4/W1 FAIL: that is the base measurement.
//
// TOLERANCE 1/256, justified: amounts are integers floored once per payee per
// block (< 1e-9 of a block here). The only other deviation is A's slot inside
// its bin: D's work sits at the bin end, A's share 6 positions earlier on
// average, so their weights differ by lambda^(+-6), |lambda^6 - 1| < 0.00193.
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
        d.window = settle::subthreshold_window(p, hv, ctx, [&](u64 bin) { return (bin + 1) * npb; });
        u64 d_rows = 0;
        for (const auto& [ck, v] : d.window) {
            if (ck.second == KC || (ck.second == KA && !withhold)) r.ac_no_entry = false;
            if (ck.second == KD) {
                ++d_rows;
                if (v != (long long)(kDropsPerShare << 26) || ck.first % npb != 0) r.d_entry_exact = false;
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
        check(within(r.ratio, 1.0L, tol), tag + "I4 M1 DROPS-only / share-only income per hash == 1 (1/256)");
        check(within(r.oneshot_ratio, pred1, tol), tag + "I5 the one-shot price is m / S_eff (the A4 measurement)");
        check(!within(r.oneshot_ratio, 1.0L, tol), tag + "I5 the one-shot price trips I4");
    }
    std::printf("   W1 (M2) withholding: A publishing its share vs A withholding it (64 raindrops, no share)\n");
    std::printf("   %6s %7s %14s %14s %9s\n", "B bins", "k", "A publishes", "A withholds", "ratio");
    for (const u64 B : {2160ull, 720ull, 72ull}) {
        const Run pub = run(B, std::max(2 * base_bins, 2 * B), std::max(6 * base_bins, 6 * B), rw, false);
        const Run wh = run(B, std::max(2 * base_bins, 2 * B), std::max(6 * base_bins, 6 * B), rw, true);
        const long double w = wh.perA / pub.perA;
        std::printf("   %6llu %7.3Lf %14.1Lf %14.1Lf %9.5Lf\n", (unsigned long long)B, pub.k, pub.perA, wh.perA, w);
        char kb[32]; std::snprintf(kb, sizeof kb, "k=%.2Lf: ", pub.k);
        check(wh.conserve && wh.no_negative && wh.never_twice, std::string(kb) + "W1 withholding run: exact division, no negative row, never twice");
        check(within(w, 1.0L, tol), std::string(kb) + "W1 M2 withholding a share changes A's income per hash by < 1/256");
    }
    std::printf("== v37_xmr_drops_income_kat: %d passed, %d failed -> %s\n", g_pass, g_fail, g_fail ? "FAIL" : "OK");
    return g_fail ? 1 : 0;
}
