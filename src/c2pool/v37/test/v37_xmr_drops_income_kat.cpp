// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_drops_income_kat -- handoff A4 (ruling 2026-09-30: keep the one-shot
// price of sub-threshold work). Measurement only: no consensus path changes.
//
// A share takes a lane position and earns in EVERY lane block while it is in
// the window (decayed). A raindrop never takes a position: the lane block that
// books it prices its work ONCE, at that block's cut, as fresh share work
// (entitlement_of_work over drops_price_at), and it is never paid again.
//
// THE PREDICTION, from the code. Let every receipt have lane weight rw, let
// SUM be the projected weight sum at a cut (Q62), and m the mean number of
// lane positions between two lane blocks (k = W / m lane blocks per window).
//   share   earns R * w / SUM in each block while in the window; summed over
//           its life that is R / m per share (the fair price, window_pulse_kat).
//   raindrop  2^lz / 2^6 of a share's work, priced once at
//           R * (work << 62) / sum', sum' = (SUM << lz) / rw
//           => R * rw * 2^62 / SUM per share of work.
// So, per hash, DROPS-only / share-only = m * rw * 2^62 / SUM = m / S_eff,
// where S_eff = SUM / (rw * 2^62) = sum_{a < W} lambda^a is the lane's
// decay-weighted window in positions (lambda = 2^(-1/half_life)):
//     ratio = m / S_eff = (W / S_eff) / k
// With the shipped geometry (W 8640, half-life 2160) S_eff = 2921.93 and
// W / S_eff = 2.957: the ratio is about 2.96 / k, NOT 1 / k. The handoff's 1 / k
// holds only for an undecayed window. k_eff = k * S_eff / W is the mean number of
// lane blocks per DECAY-WEIGHTED window; the ratio is exactly 1 / k_eff.
//
// THE KAT drives the real pieces on the shipped XMR path: the real v37::Lane
// with xmr_lane_params_default() (Count mode, floor share_diff / 64),
// settle_block for E_b, drops_price_at for the price, lane_enrollment_ex with
// the ledger registry (raindrop enrolment, A3) under EnrolMode::Auto,
// subthreshold_credit for the delta, and an OwedLedger with anchor_cut,
// drops_due (A5: the delta is a deposit, claimed by the next lane block) and
// raindrop_enrol on. The pool: 12 receipts per Monero block (bin); miner A has
// 1 share per bin (and its 63 raindrops: Count makes its delta exactly 0),
// the rest of the pool C has 11 (and 693 raindrops); miner D has A's hashrate
// but its work enters only as raindrops: 64 per bin, no share. A lane block
// lands at the end of every B-th bin, deterministically, so every quantity is
// exact; each bin range [prev block, this block) is harvested by exactly one
// lane block (the ranges tile the chain, as ChainOrderedHarvest's do).
//
//   I1  every booking: A and C have no delta row; D's deposit is exactly
//       SUM over its bins of entitlement_of_work(price, J_bin * 2^26) (one
//       floor per (payee, interval) row); the next block's E' pays D
//       exactly that deposit (claimed once); no write-off, no saturation.
//   I2  SUM is steady over the measured blocks, and S_eff = SUM / (rw 2^62)
//       equals the closed form sum_{a<W} lambda^a (to 1e-6).
//   I3  A's income per share is the fair R / m (within 1/256).
//   I4  M1: measured DROPS-only / share-only ratio == m / S_eff (within
//       1/256), for k = 1, 3, 10 and 30 lane blocks per window.
//   I5  M2 sensitivity: a control that credits each raindrop in EVERY lane
//       block of its window (decayed exactly like a share of its age) gives
//       ~1.0 and trips the I4 assertion; the handoff's 1/k trips it as well.
//
// TOLERANCE 1/256, justified: all amounts are integers floored once per payee
// per block (an error below 1e-9 of a block's credit here). The only other
// deviation is A's slot inside its bin: a block at a bin end sees A at a fixed
// age c in [0, 12), so A holds lambda^(c - 5.5) of its 1/12 average weight
// share. |lambda^(+-6) - 1| < 1 - 2^(-12/2160) = 0.00384 < 1/256.
// ---------------------------------------------------------------------------
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
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
static long double ld(const U256& x) {
    long double r = 0;
    for (int i = 3; i >= 0; --i) r = r * 18446744073709551616.0L + (long double)x.v[i];
    return r;
}
static st::u256 pow2(unsigned b) { st::u256 x; x.w[b >> 6] = 1ull << (b & 63); return x; }
static bytes32 key(std::uint8_t b) { bytes32 k{}; k[0] = b; k[31] = 0xa4; return k; }

static const bytes32 KA = key(0x0a);   // share-only miner (1 share / bin)
static const bytes32 KC = key(0x0c);   // the rest of the pool (11 shares / bin)
static const bytes32 KD = key(0x0d);   // DROPS-only miner, A's hashrate (64 raindrops / bin)
constexpr ::v37::ChainId kChain = 0x000000A4;
constexpr u64 kReward = 600000000000ull;   // 0.6 XMR in atomic units
constexpr u64 kPerBin = 12;                // receipts per bin (A 1 + C 11)
constexpr u64 kDropsPerShare = 64;         // 2^kXmrDropsFloorShift

// The view settle_block / drops_price_at read (the SettlementView shape).
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
    long double incA = 0, incD = 0, ctrlD = 0;
    long double sharesA = 0, dropsD = 0;    // A's shares, D's credited raindrops over the measured blocks
    long double sum_min = 0, sum_max = 0;   // SUM weight at the measured cuts
    long double s_eff = 0, pred = 0;        // S_eff = SUM / (rw 2^62), pred = m / S_eff
    long double perA = 0, perD = 0, ratio = 0, ctrl_ratio = 0;
    bool ac_no_delta = true, d_deposit_exact = true, d_claim_exact = true, no_writeoff = true, no_sat = true;
    bool d_enrolled_by_raindrop = false;
};

// One run: warm bins (the window fills and every enrolment settles), then the
// measured bins. A lane block closes every B-th bin.
static Run run(u64 B, u64 warm_bins, u64 meas_bins, u64 rw) {
    const ::v37::LaneParams p = ::c2pool::v37n::xmr::xmr_lane_params_default();
    ::v37::Lane lane(p);
    auto idv = std::make_shared<IdView>();
    idv->m[1] = ::v37::IdentityEntry{KA, {}};
    idv->m[2] = ::v37::IdentityEntry{KC, {}};
    settle::OwedLedgerRules rules;
    rules.anchor_cut = true; rules.drops_due = true; rules.raindrop_enrol = true;
    settle::OwedLedger L(kChain, rules);
    const st::u256 hT = ::c2pool::v37n::drops_detail::h_t_of_lz(dx::kXmrDropsLz);
    const st::u256 drop = pow2(228);        // h_T = 2^224 - 1 < 2^228 < floor 2^230: a raindrop

    // The folded lane prefix: A and C have a share at bin 0 (share-rule enrolment).
    dx::LanePrefix lp;
    lp.base_first[KA] = 0; lp.base_first[KC] = 0;

    // The intra-bin order (as window_pulse_kat): miner i's j-th receipt at (j + 0.5) / n_i.
    std::vector<std::pair<double, int>> order;
    order.push_back({0.5, 1});
    for (u64 j = 0; j < 11; ++j) order.push_back({(j + 0.5) / 11.0, 2});
    std::sort(order.begin(), order.end());

    Run r;
    r.B = B; r.m = B * kPerBin; r.k = (long double)p.window / (long double)r.m;
    const long double lambda = std::pow(2.0L, -1.0L / (long double)p.half_life);
    std::vector<long double> d_pos;         // CONTROL: D's raindrop work per lane position (fractional)
    struct Cell { u64 S = 0, J = 0; };
    std::map<std::pair<bytes32, u64>, Cell> harvest;   // (payee, bin) since the last lane block
    std::map<bytes32, u64> first_drop;                 // first raindrop bin inside the range
    long long prev_deposit_D = 0; u64 prev_J_D = 0;
    first_drop.clear();
    for (u64 b = 0; b < warm_bins + meas_bins; ++b) {
        for (const auto& [x, i] : order) { (void)x; lane.push(MinerId(i), rw, 0); d_pos.push_back(64.0L / 12.0L); }
        harvest[{KA, b}] = Cell{1, 63};
        harvest[{KC, b}] = Cell{11, 11 * 63};
        harvest[{KD, b}] = Cell{0, kDropsPerShare};
        first_drop.try_emplace(KD, b);
        if ((b + 1) % B != 0) continue;

        // ── lane block at height h = b + 1, harvest range [h - B, h) ──
        const u64 h = b + 1;
        View v; v.payout = lane.payout_map(); v.identities = idv;
        Amounts E;
        for (const auto& [k, a] : settle::settle_block(kReward, v)) E[k] = (long long)a;
        const settle::WorkPrice raw = settle::work_price_at(kReward, v);
        settle::DropsCompose ctx;
        ctx.price = dx::drops_price_at(kReward, v, rw);
        const settle::DropsEnrolRegistry reg = L.drops_enrol_registry();
        const ::c2pool::v37n::EnrollmentBook book =
            dx::lane_enrollment_ex(lp, {}, dx::EnrolMode::Auto, reg, first_drop);
        ctx.enrollment = &book;
        std::vector<settle::HarvestedReceipt> hv;
        u64 J_D = 0;
        long long want_D = 0;   // I1: priced per (payee, interval) row, each floored once
        for (const auto& [pk, c] : harvest) {
            settle::HarvestedReceipt hr{pk.first, pk.second, st::ReceiptCollector(p.subthreshold.K, hT)};
            for (u64 j = 0; j < c.J; ++j) hr.collector.observe(drop);
            hr.collector.set_shares(c.S);
            if (pk.first == KD && book.enrolled(KD, pk.second)) {
                J_D += c.J;
                st::u320 w; w.w[0] = c.J << 26;
                want_D += settle::entitlement_of_work(ctx.price, w);
            }
            hv.push_back(std::move(hr));
        }
        bool sat = false;
        const auto delta = settle::subthreshold_credit(p, hv, ctx, &sat);
        if (sat) r.no_sat = false;
        if (delta.count(KA) || delta.count(KC)) r.ac_no_delta = false;
        settle::DropsFound d;
        for (const auto& [k2, x] : delta) if (x != 0) d.deposit[k2] = x;
        // I1: D's deposit is its raindrop work priced ONCE at this cut.
        {
            const long long got = d.deposit.count(KD) ? d.deposit.at(KD) : 0;
            if (got != want_D) r.d_deposit_exact = false;
        }
        // RAINDROP ENROL (compose_lane): payees enrolled by raindrop, not yet in the registry.
        for (const auto& [payee, bin] : first_drop)
            if (!reg.count(payee) && book.find(payee)) {
                settle::DropsEnrolRec rec; rec.eff = bin + 1;
                d.enrol_add.emplace(payee, rec);
                r.d_enrolled_by_raindrop = true;
            }
        d.claim = true;
        d.claimed = L.drops_available();
        settle::apply_drops_due(E, d.claimed, &d.writeoff);
        if (!d.writeoff.empty()) r.no_writeoff = false;
        const long long paid_D = E.count(KD) ? E.at(KD) : 0;
        if (paid_D != prev_deposit_D) r.d_claim_exact = false;   // claimed once, exactly the deposit
        const std::string bid = "LB" + std::to_string(h);
        L.on_block_found(bid, E, {}, std::nullopt, &d);
        L.on_block_finalized(bid, h);

        // CONTROL (M2): the same raindrops credited in EVERY lane block of their
        // window, each decayed like a share of its age (no one-shot price).
        long double ctrl_work = 0;
        {
            const u64 n = d_pos.size();
            long double f = 1.0L;
            for (u64 a = 0; a < p.window && a < n; ++a) { ctrl_work += d_pos[n - 1 - a] * f; f *= lambda; }
        }
        st::u320 cw; cw.w[0] = (u64)std::floor(ctrl_work * 67108864.0L);   // * 2^26
        const long long ctrl_paid = settle::entitlement_of_work(ctx.price, cw);

        if (b >= warm_bins) {   // a measured block
            ++r.blocks;
            r.incA += (long double)(E.count(KA) ? E.at(KA) : 0);
            r.incD += (long double)paid_D;
            r.ctrlD += (long double)ctrl_paid;
            r.sharesA += (long double)B;                  // A: one share per bin
            r.dropsD += (long double)prev_J_D;            // the raindrops of the deposit this block paid
            const long double s = ld(raw.sum_weight);
            if (r.blocks == 1 || s < r.sum_min) r.sum_min = s;
            if (r.blocks == 1 || s > r.sum_max) r.sum_max = s;
        }
        prev_deposit_D = d.deposit.count(KD) ? d.deposit.at(KD) : 0;
        prev_J_D = J_D;
        harvest.clear();
        first_drop.clear();
    }
    // Per share of work: A's shares; D's raindrops / 64; the control's D work
    // is every measured bin's 64 raindrops (all of them in its window).
    r.perA = r.incA / r.sharesA;
    r.perD = r.incD / (r.dropsD / (long double)kDropsPerShare);
    r.ratio = r.perD / r.perA;
    r.ctrl_ratio = (r.ctrlD / (long double)(r.blocks * B)) / r.perA;
    r.s_eff = r.sum_max / ((long double)rw * 4611686018427387904.0L);   // SUM / (rw * 2^62)
    r.pred = (long double)r.m / r.s_eff;
    return r;
}

static bool within(long double x, long double want, long double tol) { return std::fabs(x / want - 1.0L) <= tol; }

int main() {
    std::printf("== v37_xmr_drops_income_kat: the one-shot price of sub-threshold work (handoff A4)\n");
    const ::v37::LaneParams p = ::c2pool::v37n::xmr::xmr_lane_params_default();
    const u64 rw = ::c2pool::v37n::xmr::relay::kReceiptWeight;
    const long double lambda = std::pow(2.0L, -1.0L / (long double)p.half_life);
    const long double s_closed = (1.0L - std::pow(lambda, (long double)p.window)) / (1.0L - lambda);
    std::printf("   lane: window W %llu positions, half-life %llu; Count mode %u, floor shift %u; rw %llu\n",
                (unsigned long long)p.window, (unsigned long long)p.half_life, (unsigned)p.subthreshold.mode,
                (unsigned)p.subthreshold.count_floor_shift, (unsigned long long)rw);
    std::printf("   closed form S_eff = sum_{a<W} lambda^a = %.4Lf, W / S_eff = %.4Lf\n", s_closed,
                (long double)p.window / s_closed);
    check(p.subthreshold.enabled && p.subthreshold.mode == 2 && p.subthreshold.count_floor_shift == 6,
          "shipped XMR path: DROPS on, Count mode, floor share_diff / 64");
    const long double tol = 1.0L / 256.0L;
    const u64 warm = 2 * (p.window / kPerBin);   // two windows of bins
    const u64 meas = 6 * (p.window / kPerBin);   // six windows of bins
    std::printf("   %6s %6s %7s %6s %12s %12s %9s %9s %9s %9s\n", "B bins", "m pos", "k", "blocks",
                "A per share", "D per share", "measured", "m/S_eff", "1/k", "control");
    // SENSITIVITY DEMO (M2): V37_A4_PRICE=every_block substitutes the control
    // (each raindrop paid in every lane block of its window) for the measured
    // D income, i.e. the one-shot price removed; the I4 assertions must FAIL.
    const char* env = std::getenv("V37_A4_PRICE");
    const bool every_block = env && std::strcmp(env, "every_block") == 0;
    if (every_block) std::printf("   CONTROL MODE: D paid in every window block (one-shot price removed)\n");
    for (const u64 B : {720ull, 240ull, 72ull, 24ull}) {
        Run r = run(B, warm, meas, rw);
        if (every_block) r.ratio = r.ctrl_ratio;
        std::printf("   %6llu %6llu %7.3Lf %6llu %12.1Lf %12.1Lf %9.5Lf %9.5Lf %9.5Lf %9.5Lf\n",
                    (unsigned long long)r.B, (unsigned long long)r.m, r.k, (unsigned long long)r.blocks,
                    r.perA, r.perD, r.ratio, r.pred, 1.0L / r.k, r.ctrl_ratio);
        const std::string tag = "k=" + std::to_string((int)std::lround((double)r.k)) + ": ";
        check(r.ac_no_delta, tag + "I1 A and C (a share and its 63 raindrops) have no DROPS delta row");
        check(r.d_deposit_exact, tag + "I1 D's deposit == SUM over its bins of entitlement_of_work(price, J_bin * 2^26)");
        check(r.d_claim_exact, tag + "I1 the next lane block pays D exactly that deposit, once");
        check(r.no_writeoff && r.no_sat, tag + "I1 no write-off, no saturation");
        check(r.d_enrolled_by_raindrop, tag + "I1 D is enrolled by raindrop (A3 enrol_add)");
        check(r.sum_max - r.sum_min <= r.sum_max * 1e-12L, tag + "I2 SUM weight is steady over the measured cuts");
        check(within(r.s_eff, s_closed, 1e-6L), tag + "I2 S_eff = SUM / (rw 2^62) matches the closed form");
        check(within(r.perA, (long double)kReward / (long double)r.m, tol), tag + "I3 A earns the fair R / m per share");
        check(within(r.ratio, r.pred, tol), tag + "I4 measured DROPS-only / share-only == m / S_eff (1/256)");
        check(!within(r.ctrl_ratio, r.pred, tol), tag + "I5 control (raindrop paid in every window block) trips I4");
        check(within(r.ctrl_ratio, 1.0L, tol), tag + "I5 control pays D like a share miner (ratio 1)");
        check(!within(1.0L / r.k, r.ratio, tol), tag + "I5 the handoff's 1/k is not the measured ratio");
        check(within(r.ratio * r.k, (long double)p.window / s_closed, tol), tag + "I4 ratio * k == W / S_eff");
    }
    std::printf("== v37_xmr_drops_income_kat: %d passed, %d failed -> %s\n", g_pass, g_fail, g_fail ? "FAIL" : "OK");
    return g_fail ? 1 : 0;
}
