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
#include "sharechain/v37/v37_descriptor_xmr.hpp"   // A2: xmr_ga_split

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


// ---------------------------------------------------------------------------
// A2: the fee model (give_author d) on the positional window. A receipt with
// d > 0 either takes ONE position as a composite identity whose weight is
// split floor(W*d/65535) to the donation at settlement (OnePosition, A2), or
// the old rule: TWO positions, (miner, 65535-d) then (donation, d) (TwoPush).
// Fair share per receipt: the miner (65535-d)/65535, the donation d/65535.
// ---------------------------------------------------------------------------
constexpr int FM = 3;                       // 0 B (d = 655), 1 C (d = 0), 2 E (d = 6554, 10%)
constexpr std::uint16_t FD[FM] = {655, 0, 6554};
struct FeeResult { double ratio[FM + 1]; u64 receipts; u64 next_pos; };
static FeeResult run_fee(bool one_position, const std::function<void(u64, unsigned[FM])>& s, u64 days, u64 warm_days) {
    ::v37::Lane lane(LaneParams{});
    long double inc[FM + 1] = {}, fair[FM + 1] = {};
    u64 rc = 0;
    const MinerId DON = 99;
    auto comp = [](int i) { return MinerId(100 + i); };          // composite lane identity of miner i
    for (u64 b = 0; b < days * DAY; ++b) {
        unsigned n[FM] = {};
        s(b, n);
        std::vector<std::pair<double, int>> order;
        for (int i = 0; i < FM; ++i)
            for (unsigned k = 0; k < n[i]; ++k) order.push_back({(k + 0.5) / n[i], i});
        std::sort(order.begin(), order.end());
        const bool count = b >= warm_days * DAY;
        for (const auto& [x, i] : order) {
            (void)x;
            const std::uint16_t d = FD[i];
            if (d == 0) lane.push(MinerId(i + 1), 65535, 0);
            else if (one_position) lane.push(comp(i), 65535, 0);
            else { lane.push(MinerId(i + 1), 65535 - d, 0); lane.push(DON, d, 0); }
            ++rc;
            if (!count) continue;
            long double tot = 0, w[FM + 1] = {};
            for (const auto& [m, v] : lane.payout_map()) {
                long double y = ld(v); tot += y;
                if (m == DON) { w[FM] += y; continue; }
                if (m >= 100) {                                   // split the composite as settle::project does
                    const int j = static_cast<int>(m - 100);
                    const auto sp = ::v37::xmr::xmr_ga_split(v, FD[j]);
                    w[j] += ld(sp.payee); w[FM] += ld(sp.donation);
                } else w[m - 1] += y;
            }
            for (int j = 0; j <= FM; ++j) inc[j] += w[j] / tot;
            fair[i] += (long double)(65535 - d) / 65535.0L;
            fair[FM] += (long double)d / 65535.0L;
        }
    }
    FeeResult r{};
    for (int j = 0; j <= FM; ++j) r.ratio[j] = fair[j] > 0 ? (double)(inc[j] / fair[j]) : 1.0;
    r.receipts = rc; r.next_pos = lane.next_pos();
    return r;
}
static void report_fee(const char* name, const FeeResult& r) {
    std::printf("   %-40s B(1%%) %.4f C(0%%) %.4f E(10%%) %.4f donation %.4f  next_pos %llu / %llu receipts\n", name,
                r.ratio[0], r.ratio[1], r.ratio[2], r.ratio[3], (unsigned long long)r.next_pos, (unsigned long long)r.receipts);
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

    std::printf("-- A2 fee model on (give_author 1%% / 0%% / 10%%) --\n");
    auto fsteady = [](u64, unsigned n[FM]) { n[0] = 1; n[1] = 10; n[2] = 1; };
    auto fpulse = [](u64 b, unsigned n[FM]) { n[0] = 1; n[1] = 10; n[2] = (b % DAY) < 60 ? 12 : 1; };
    const FeeResult one = run_fee(true, fsteady, 6, 2), two = run_fee(false, fsteady, 6, 2);
    report_fee("OnePosition (A2) steady", one);
    report_fee("TwoPush (pre-A2) steady", two);
    for (int j = 0; j <= FM; ++j) check(std::fabs(one.ratio[j] - 1.0) < 0.002, "A2 OnePosition: every miner and the donation get their fair share");
    check(one.next_pos == one.receipts, "A2 OnePosition: next_pos == receipts (one lane position per receipt)");
    check(two.next_pos > two.receipts, "control: TwoPush takes more positions than receipts");
    // The TwoPush defect is window capacity, not the steady split: a d > 0 receipt
    // spends two of the window's positions, so the same window spans fewer receipts
    // (here 1/1.1667 of them), i.e. less time, for everyone.
    check(two.next_pos * 100 >= two.receipts * 115, "control: TwoPush spends >= 15% more positions than receipts (a shorter window for everyone)");
    std::printf("   TwoPush window span: %.4f of OnePosition's, in receipts\n", (double)two.receipts / (double)two.next_pos);
    const FeeResult onep = run_fee(true, fpulse, 14, 2);
    report_fee("OnePosition (A2) pulse", onep);
    for (int j = 0; j <= FM; ++j) check(std::fabs(onep.ratio[j] - 1.0) < 0.01, "A2 OnePosition under a pulse: every share within 1%");

    std::printf("\n%ld checks, %ld failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
