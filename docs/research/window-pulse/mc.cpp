// SPDX-License-Identifier: AGPL-3.0-or-later
// Research simulation (docs/research/window-pulse/README.md). Monte Carlo on the REAL v37::Lane vs a fixed 720-bin time window: variance, empty blocks.
// Build: g++ -O2 -std=c++20 -I../../../src/sharechain/v37 -I../../../src mc.cpp -o mc && ./mc 200 0.001 30   (runs, B share, pulse x)
// Monte Carlo on the REAL shipped lane (v37::Lane, LaneParams{} = the XMR lane, gates OFF)
// vs a V37.1-shaped fixed time window. Receipts Poisson per bin, each receipt a block w.p. q.
#include "v37_lane.hpp"
#include <cstdio>
#include <random>
#include <cmath>
#include <vector>
#include <deque>
#include <algorithm>
using namespace v37;
static long double ld(const U256& x) { long double r = 0; for (int i = 3; i >= 0; --i) r = r * 18446744073709551616.0L + x.v[i]; return r; }
int main(int argc, char** argv) {
  const int runs = argc > 1 ? atoi(argv[1]) : 20; const long days = 30, bins = 720 * days;
  const double r0 = 12, q = 2.0 / 8640; const double kB = argc > 2 ? atof(argv[2]) : 0.01;
  const double kA = argc > 3 ? atof(argv[3]) : 10;   // pulse multiplier, 2h per day
  std::vector<double> incB_pos, incB_time, fairB; long zeroB_pos = 0, zeroB_time = 0, nblk = 0; double maxdiff = 0;
  for (int run = 0; run < runs; ++run) {
    std::mt19937_64 rng(1000 + run);
    Lane lane(LaneParams{});
    std::deque<std::pair<long, int>> pos_model;  // (pos, miner): double reference of the positional rule
    std::vector<std::array<double, 3>> tw;        // per-bin receipts per miner (time window)
    long P = 0; double iBp = 0, iBt = 0, fB = 0;
    for (long b = 0; b < bins; ++b) {
      double rate[3] = {(b % 720) < 60 ? kA * r0 : 0, kB * r0, (1 - kB) * r0};
      tw.push_back({0, 0, 0});
      std::vector<int> recs;
      for (int m = 0; m < 3; ++m) { std::poisson_distribution<int> d(rate[m]); int n = d(rng); for (int k = 0; k < n; ++k) recs.push_back(m); }
      std::shuffle(recs.begin(), recs.end(), rng);
      for (int m : recs) {
        lane.push((MinerId)m, 1, 0); pos_model.push_back({P++, m}); tw[b][m] += 1;
        while (pos_model.size() > 8640) pos_model.pop_front();
        if (m == 1) fB += q;
        if (std::uniform_real_distribution<double>(0, 1)(rng) < q) {   // this receipt is a block
          ++nblk;
          auto mp = lane.payout_map(); long double tot = 0, wb = 0;
          for (auto& [k, v] : mp) { tot += ld(v); if (k == 1) wb = ld(v); }
          iBp += (double)(wb / tot); if (wb == 0) ++zeroB_pos;
          // double reference of the same rule (window 8640, hl 2160 positions); lane evicts whole buckets of 8
          double t2 = 0, b2 = 0; for (auto& [p, mm] : pos_model) { double w = std::pow(2.0, -(double)(P - 1 - p) / 2160); t2 += w; if (mm == 1) b2 += w; }
          maxdiff = std::max(maxdiff, std::fabs(b2 / t2 - (double)(wb / tot)));
          // time window, 720 bins, hl 2160 bins
          double tt = 0, tb = 0; for (long x = std::max(0L, b - 719); x <= b; ++x) { double w = std::pow(2.0, -(double)(b - x) / 2160); for (int k = 0; k < 3; ++k) tt += tw[x][k] * w; tb += tw[x][1] * w; }
          iBt += tb / tt; if (tb == 0) ++zeroB_time;
        }
      }
    }
    incB_pos.push_back(iBp); incB_time.push_back(iBt); fairB.push_back(fB);
  }
  auto stat = [&](std::vector<double>& v, const char* n) { double m = 0, s = 0; for (double x : v) m += x; m /= v.size(); for (double x : v) s += (x - m) * (x - m); s = std::sqrt(s / (v.size() - 1));
    printf("  %-12s mean %.4f blocks  sd %.4f  CV %.3f\n", n, m, s, s / m); };
  printf("B = %.2f%% of steady, A = %gx for 2h/day, %d runs x %ld days, %ld blocks\n", kB * 100, kA, runs, days, nblk);
  stat(fairB, "fair(PPS)"); stat(incB_pos, "pos(now)"); stat(incB_time, "time720");
  printf("  blocks where B has ZERO weight: pos %ld, time %ld (of %ld)\n", zeroB_pos, zeroB_time, nblk);
  printf("  real Lane vs double reference, max |share diff| = %.2e\n", maxdiff);
}
