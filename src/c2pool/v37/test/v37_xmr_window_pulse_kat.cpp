// SPDX-License-Identifier: AGPL-3.0-or-later
// v37_xmr_window_pulse_kat.cpp -- the XMR lane window cannot be gamed by
// pulsing hashrate (external review, "window deflation").
//
// The XMR lane runs the shipped positional window (LaneParams{}: 8640
// positions, half-life 2160 positions, every V37.1 gate OFF). Every receipt is
// admitted at the one lane share difficulty, so every position is the same
// work and every position is equally likely to be a block. A receipt's
// expected pay is then the same whenever it was mined: a pulse shortens the
// window in wall-clock time, and blocks come just as much faster.
//
// The KAT drives the REAL v37::Lane with a deterministic schedule and computes
// each miner's EXPECTED income exactly: every push is a block with the same
// probability q, so income_i = q * sum over pushes of (weight_i / total) at
// that push, against the fair (pay-per-share) q * receipts_i. It pins:
//
//   P1  steady pool: every miner gets 1.00;
//   P2  a miner at 10x the pool for 2 h a day (the pulser) and the small
//       steady miners it "deflates" all get 1.00 (within 1%);
//   P3  a hopper who knows the pulse schedule gets 1.00 mining 2 h before
//       the pulse, during it, or 2 h after it;
//   P4  a weekly pulse (10x for a day) and a hopper a day before it: 1.00.
//
// The contrast (a V37.1-style time window pays the pre-pulse hopper up to
// +23%, the pulser -10%) is a model, not code, and lives with the simulation
// in docs/research/window-pulse/.

#include <cstdio>
#include <cstdint>
#include <cmath>
#include <functional>
#include <vector>
#include <algorithm>

#include "sharechain/v37/v37_lane.hpp"

using namespace v37;

static long g_checks = 0, g_fail = 0;
static void check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) { ++g_fail; std::printf("  FAIL: %s\n", what); }
}
static long double ld(const U256& x) {
    long double r = 0;
    for (int i = 3; i >= 0; --i) r = r * 18446744073709551616.0L + (long double)x.v[i];
    return r;
}

constexpr int NM = 4;   // 0 A pulser, 1 B small steady, 2 C rest steady, 3 D hopper
constexpr u64 DAY = 720; // bins (one Monero block each)
using Sched = std::function<void(u64 bin, unsigned n[NM])>;

struct Result { double ratio[NM]; u64 receipts[NM]; };

// Deterministic interleave inside a bin: miner i's k-th receipt sits at
// (k + 0.5) / n_i, ties by miner id.
static Result run(const Sched& s, u64 days, u64 warm_days) {
    ::v37::Lane lane(LaneParams{});
    long double inc[NM] = {}, fair[NM] = {};
    u64 rc[NM] = {};
    for (u64 b = 0; b < days * DAY; ++b) {
        unsigned n[NM] = {};
        s(b, n);
        std::vector<std::pair<double, int>> order;
        for (int i = 0; i < NM; ++i)
            for (unsigned k = 0; k < n[i]; ++k) order.push_back({(k + 0.5) / n[i], i});
        std::sort(order.begin(), order.end());
        const bool count = b >= warm_days * DAY;
        for (const auto& [x, i] : order) {
            (void)x;
            lane.push(MinerId(i + 1), 1, 0);
            if (!count) continue;
            long double tot = 0, w[NM] = {};
            for (const auto& [m, v] : lane.payout_map()) { const long double y = ld(v); tot += y; w[m - 1] = y; }
            for (int j = 0; j < NM; ++j) inc[j] += w[j] / tot;
            fair[i] += 1;
            ++rc[i];
        }
    }
    Result r{};
    for (int i = 0; i < NM; ++i) { r.ratio[i] = fair[i] > 0 ? (double)(inc[i] / fair[i]) : 1.0; r.receipts[i] = rc[i]; }
    return r;
}

static void report(const char* name, const Result& r, double tol) {
    static const char* nm[NM] = {"A pulser", "B small", "C steady", "D hopper"};
    std::printf("   %-40s", name);
    for (int i = 0; i < NM; ++i)
        if (r.receipts[i]) std::printf(" %s %.4f", nm[i], r.ratio[i]);
    std::printf("\n");
    for (int i = 0; i < NM; ++i)
        if (r.receipts[i]) check(std::fabs(r.ratio[i] - 1.0) < tol, name);
}

int main() {
    std::printf("== v37_xmr_window_pulse_kat: the positional window under a pulsing miner\n");
    const LaneParams p{};
    std::printf("   lane: window %llu positions, half-life %llu, 12 receipts/bin steady (~24 h window)\n",
                (unsigned long long)p.window, (unsigned long long)p.half_life);
    auto steady = [](unsigned n[NM]) { n[1] = 1; n[2] = 11; };
    const double tol = 0.01;

    std::printf("-- P1 steady --\n");
    report("steady", run([&](u64, unsigned n[NM]) { steady(n); }, 6, 2), 0.002);

    std::printf("-- P2 pulse 10x for 2 h a day --\n");
    report("pulse", run([&](u64 b, unsigned n[NM]) { steady(n); n[0] = (b % DAY) < 60 ? 120 : 0; }, 14, 2), tol);

    std::printf("-- P3 hopper who knows the schedule --\n");
    report("hopper 2 h before", run([&](u64 b, unsigned n[NM]) {
        steady(n); const u64 m = b % DAY; n[0] = m < 60 ? 120 : 0; n[3] = m >= DAY - 60 ? 2 : 0; }, 14, 2), tol);
    report("hopper during", run([&](u64 b, unsigned n[NM]) {
        steady(n); const u64 m = b % DAY; n[0] = m < 60 ? 120 : 0; n[3] = m < 60 ? 2 : 0; }, 14, 2), tol);
    report("hopper 2 h after", run([&](u64 b, unsigned n[NM]) {
        steady(n); const u64 m = b % DAY; n[0] = m < 60 ? 120 : 0; n[3] = (m >= 60 && m < 120) ? 2 : 0; }, 14, 2), tol);

    std::printf("-- P4 weekly pulse 10x for a day, hopper the day before --\n");
    report("weekly", run([&](u64 b, unsigned n[NM]) {
        steady(n); const u64 m = b % (7 * DAY); n[0] = m < DAY ? 120 : 0; n[3] = m >= 6 * DAY ? 2 : 0; }, 29, 1), tol);

    std::printf("\n%ld checks, %ld failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
