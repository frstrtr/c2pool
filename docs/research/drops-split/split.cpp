// SPDX-License-Identifier: AGPL-3.0-or-later
// Research simulation (docs/research/drops-split/README.md).
// Build: g++ -O2 -std=c++20 split.cpp -o split && ./split
//
// Does splitting one miner's hashrate over N identities change its credit?
// Hashes are a Poisson process on the floor-normalised value u in [0, 1): u < 1
// is a raindrop (the XMR drops floor, share_diff / 64), u < 1/64 is a share.
// A miner of rate lambda has lambda hashes below the floor per interval; its
// true work is lambda (floor units). Three credit rules for one interval:
//
//   E1  shipped COMBINED K-min per (payee, interval), REPLACE composition:
//       J < K raindrops -> the shares only (S * 64); else (S + K - 1) / u_(S+K).
//   E2  count: every hash below the floor is one floor unit: S + J.
//   E3  pool-wide bottom-k: tau = the (k+1)-th smallest u of the whole pool in
//       the interval; each hash below tau is worth 1 / tau (rank-conditioned
//       Horvitz-Thompson, priority sampling); if the pool has <= k hashes, E2.
#include <cstdio>
#include <cmath>
#include <random>
#include <vector>
#include <algorithm>

static std::mt19937_64 rng(20260930);
static double U() { return std::uniform_real_distribution<double>(0, 1)(rng); }
static int P(double l) { return std::poisson_distribution<int>(l)(rng); }

struct Stat { double s = 0, q = 0; long n = 0; void add(double x) { s += x; q += x * x; ++n; }
  double mean() const { return s / n; } double cv() const { double m = mean(); return std::sqrt(q / n - m * m) / m; } };

constexpr double SHARE = 1.0 / 64;

// E1 for one identity's hashes (sorted ascending).
static double e1(const std::vector<double>& h, int K) {
  int S = 0; while (S < (int)h.size() && h[S] < SHARE) ++S;
  const int J = (int)h.size() - S;
  if (J < K) return S * 64.0;
  return (S + K - 1) / h[S + K - 1];
}

int main() {
  const double pool = 6400;   // the rest of the pool: 100 shares per interval
  const long IV = 200000;
  const int K = 4;
  std::printf("rest of pool %.0f raindrops/interval (100 shares); %ld intervals; K = %d\n", pool, IV, K);
  std::printf("%-8s %-3s | %-17s | %-17s | %-17s | %-17s\n", "lambda", "N", "E1 K-min mean/cv", "E2 count mean/cv",
              "E3 k=64 mean/cv", "E3 k=512 mean/cv");
  for (double lam : {1.0, 4.0, 16.0, 64.0, 256.0}) {
    for (int N : {1, 4, 16}) {
      Stat s1, s2, s3a, s3b;
      for (long it = 0; it < IV; ++it) {
        // the pool's own bottom 513 values, as successive Poisson arrivals on [0, 1)
        std::vector<double> rest; double t = 0;
        while ((int)rest.size() < 513) { t += std::exponential_distribution<double>(pool)(rng); if (t >= 1) break; rest.push_back(t); }
        std::vector<std::vector<double>> sh(N);
        std::vector<double> all_b;
        for (int i = 0; i < N; ++i) { const int n = P(lam / N); for (int j = 0; j < n; ++j) { double u = U(); sh[i].push_back(u); all_b.push_back(u); }
          std::sort(sh[i].begin(), sh[i].end()); }
        double c1 = 0, c2 = 0;
        for (auto& v : sh) { c1 += e1(v, K); c2 += v.size(); }
        auto e3 = [&](int k) {
          std::vector<double> m = rest; m.insert(m.end(), all_b.begin(), all_b.end()); std::sort(m.begin(), m.end());
          if ((int)m.size() <= k) return (double)all_b.size();
          const double tau = m[k]; double c = 0; for (double u : all_b) if (u < tau) c += 1 / tau; return c; };
        s1.add(c1 / lam); s2.add(c2 / lam); s3a.add(e3(64) / lam); s3b.add(e3(512) / lam);
      }
      std::printf("%-8.0f %-3d | %6.3f  %8.3f | %6.3f  %8.3f | %6.3f  %8.3f | %6.3f  %8.3f\n", lam, N,
                  s1.mean(), s1.cv(), s2.mean(), s2.cv(), s3a.mean(), s3a.cv(), s3b.mean(), s3b.cv());
    }
  }
}
