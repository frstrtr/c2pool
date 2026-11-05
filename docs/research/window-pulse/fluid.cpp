// SPDX-License-Identifier: AGPL-3.0-or-later
// Research simulation (docs/research/window-pulse/README.md). Expected-value (fluid) model: shipped positional window vs a V37.1-shaped time window.
// Build: g++ -O2 -std=c++20 fluid.cpp -o fluid   (about 4 min)
// Expected-value (fluid) model of the XMR lane credit window under a pulsing miner.
// POS  = the shipped lane: window 8640 positions, decay hl 2160 positions (gates OFF).
// TIME = V37.1 shape: weight by bin age (hl 2160 bins), window W bins, width law
//        W = C*D*W/raw_prev (prev full window), damp x4, clamp, floor to 8, every 8 bins.
#include <cstdio>
#include <cmath>
#include <vector>
#include <deque>
#include <string>
#include <functional>
using namespace std;
constexpr int NM = 4;                        // A pulser, B small steady, C rest steady, D hopper
struct Seg { double lo, hi; double f[NM]; long bin; };
struct Cfg {
  double r0 = 12;          // steady receipts per bin (C+B) -> 8640 positions ~= 720 bins = 24h
  double q = 2.0 / 8640;   // P(receipt is a block): 2 pool blocks/day at steady
  int sub = 8;             // sub-steps per bin
  long bins = 720 * 120;   // 120 days
  // time window
  double C = 2;            // coverage_blocks (OWED) -> steady W = C/(q*r0) = 720 bins
  long wmin = 72, wdef = 720, wmax = 5760;
  bool law = true;
};
using RateFn = function<void(long bin, double sub, double r[NM])>;
struct Out { double inc[NM]{}, fair[NM]{}; };

double lam_int(double a, double b, double hl) { // ∫_a^b 2^(-x/hl) dx, age a..b
  double k = log(2.0) / hl; return (exp(-k * a) - exp(-k * b)) / k;
}
Out run_pos(const Cfg& c, RateFn rate) {
  deque<Seg> segs; double P = 0; Out o;
  for (long b = 0; b < c.bins; ++b) for (int s = 0; s < c.sub; ++s) {
    double r[NM]; rate(b, (s + 0.5) / c.sub, r); double rt = 0; for (double x : r) rt += x;
    double len = rt / c.sub; if (len <= 0) continue;
    Seg g{P, P + len, {}, b}; for (int i = 0; i < NM; ++i) g.f[i] = r[i] / rt; segs.push_back(g); P += len;
    while (!segs.empty() && segs.front().hi <= P - 8640) segs.pop_front();
    double w[NM]{}, wt = 0;
    for (auto& z : segs) { double lo = max(z.lo, P - 8640); double v = lam_int(P - z.hi, P - lo, 2160);
      for (int i = 0; i < NM; ++i) w[i] += z.f[i] * v; wt += v; }
    double blocks = c.q * len;
    if (b >= 10080) for (int i = 0; i < NM; ++i) { o.inc[i] += blocks * w[i] / wt; o.fair[i] += c.q * r[i] / c.sub; }
  }
  return o;
}
Out run_time(const Cfg& c, RateFn rate, vector<long>* wtrace = nullptr) {
  // per-bin work per miner; weight at bin t of work in bin b: 2^-(t-b)/2160, live if t-b < W
  vector<array<double, NM>> work; long W = c.wdef; Out o; double raw_prev = 0;
  for (long b = 0; b < c.bins; ++b) {
    if (b > 0 && b % 8 == 0) {           // retarget on raw work of the prior full window (lag)
      double raw = 0; for (long x = max(0L, b - W); x < b; ++x) for (int i = 0; i < NM; ++i) raw += work[x][i];
      if (c.law && raw > 0) {
        double tgt = c.C * (1.0 / c.q) * W / raw;
        tgt = min(max(tgt, W / 4.0), W * 4.0); tgt = min(max(tgt, (double)c.wmin), (double)c.wmax);
        W = (long)(tgt / 8) * 8;
      }
      if (wtrace) wtrace->push_back(W);
    }
    work.push_back({});
    for (int s = 0; s < c.sub; ++s) {
      double r[NM]; rate(b, (s + 0.5) / c.sub, r); double rt = 0;
      for (int i = 0; i < NM; ++i) { work[b][i] += r[i] / c.sub; rt += r[i]; }
      double w[NM]{}, wt = 0;
      for (long x = max(0L, b - W + 1); x <= b; ++x) { double d = pow(2.0, -(double)(b - x) / 2160);
        for (int i = 0; i < NM; ++i) { w[i] += work[x][i] * d; wt += work[x][i] * d; } }
      double blocks = c.q * rt / c.sub;
      if (b >= 10080) { if (wt > 0) for (int i = 0; i < NM; ++i) o.inc[i] += blocks * w[i] / wt;
      for (int i = 0; i < NM; ++i) o.fair[i] += c.q * r[i] / c.sub; }
    }
  }
  return o;
}
void show(const char* name, const Out& p, const Out& t) {
  const char* nm[NM] = {"A", "B", "C", "D"};
  printf("%-44s", name);
  for (int i = 0; i < NM; ++i) if (p.fair[i] > 0) printf(" %s pos %.4f time %.4f |", nm[i], p.inc[i] / p.fair[i], t.inc[i] / t.fair[i]);
  printf("\n");
}
int main() {
  Cfg c; const double r0 = c.r0;
  auto steady = [&](double r[NM]) { r[1] = 0.01 * r0; r[2] = 0.99 * r0; };
  RateFn S1 = [&](long b, double, double r[NM]) { r[3] = 0; steady(r); r[0] = (b % 720) < 60 ? 10 * r0 : 0; };
  RateFn S4 = [&](long b, double, double r[NM]) { steady(r); long m = b % 720; r[0] = m < 60 ? 10 * r0 : 0; r[3] = m >= 660 ? 0.1 * r0 : 0; };
  RateFn S6 = [&](long b, double, double r[NM]) { steady(r); long m = b % 720; r[0] = m < 60 ? 10 * r0 : 0; r[3] = (m >= 60 && m < 120) ? 0.1 * r0 : 0; };
  RateFn S7 = [&](long b, double, double r[NM]) { r[3] = 0; steady(r); r[0] = (b % 5040) < 720 ? 10 * r0 : 0; };
  RateFn S8 = [&](long b, double, double r[NM]) { steady(r); long m = b % 5040; r[0] = m < 720 ? 10 * r0 : 0; r[3] = m >= 4320 ? 0.1 * r0 : 0; };
  RateFn S0 = [&](long, double, double r[NM]) { r[0] = r[3] = 0; steady(r); };
  Cfg law = c; Cfg fix = c; fix.law = false;
  show("LAW S1 A 10x 2h/24h", run_pos(law, S1), run_time(law, S1));
  show("LAW S4 +D 2h before pulse", run_pos(law, S4), run_time(law, S4));
  show("LAW S6 +D 2h after pulse", run_pos(law, S6), run_time(law, S6));
  show("FIX S7 A 10x 1d/7d", run_pos(fix, S7), run_time(fix, S7));
  show("FIX S8 S7 + D 1d before pulse", run_pos(fix, S8), run_time(fix, S8));
  show("LAW S8 S7 + D 1d before pulse", run_pos(law, S8), run_time(law, S8));
  vector<long> tr; run_time(law, S0, &tr); printf("S0 steady width, bins 8..: "); for (int i = 0; i < 40; ++i) printf("%ld ", tr[i]); printf("... last %ld\n", tr.back());
}
