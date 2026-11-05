// SPDX-License-Identifier: AGPL-3.0-or-later
// Research check (docs/research/drops-split/README.md): the SHIPPED estimator
// module (ReceiptCollector + estimate_combined, K = 4, the DROPS-JK rule and the
// REPLACE composition) on the same Poisson hash stream as split.cpp.
// Build: g++ -O2 -std=c++20 -I../../../src module_check.cpp -o module_check
#include <cstdio>
#include <cmath>
#include <random>
#include <vector>
#include "c2pool/v37/v37_subthreshold_estimator.hpp"
namespace st = c2pool::v37::subthreshold;

// floor-normalised u in [0, 1) -> the 256-bit hash u * 2^230 (lz = 32: h_T = 2^224 - 1,
// the drops floor = share_diff / 64 = 2^230).
static st::u256 hash_of(double u) {
  const unsigned long long m = (unsigned long long)std::ldexp(u, 63);   // u * 2^63
  std::array<std::uint8_t, 32> b{};
  // value = m << 167 ; byte i (big-endian) holds bits [8*(31-i), 8*(31-i)+8)
  for (int bit = 0; bit < 64; ++bit) if (m >> bit & 1ull) { const int p = bit + 167; b[31 - p / 8] |= (std::uint8_t)(1u << (p % 8)); }
  return st::u256::from_be_bytes(b);
}
int main() {
  std::mt19937_64 rng(7);
  const st::u256 hT = hash_of(1.0 / 64);
  const int K = 4; const long IV = 100000;
  std::printf("shipped module, K = %d: mean credit / true work (floor units)\n", K);
  for (double lam : {4.0, 16.0, 64.0, 256.0}) {
    std::printf("lambda %4.0f:", lam);
    for (int N : {1, 4, 16}) {
      double sum = 0;
      for (long it = 0; it < IV; ++it)
        for (int s = 0; s < N; ++s) {
          st::ReceiptCollector rc(K, hT);
          const int n = std::poisson_distribution<int>(lam / N)(rng);
          for (int j = 0; j < n; ++j) rc.observe(hash_of(std::uniform_real_distribution<double>(0, 1)(rng)));
          double c;
          if (!rc.has_K()) c = rc.shares() * 64.0;                        // DROPS-JK: shares only
          else c = (double)st::fold63(st::estimate_combined(rc.shares(), K, rc.h_K())) / std::ldexp(1.0, 26);
          sum += c;
        }
      std::printf("  N=%-2d %.3f", N, sum / IV / lam);
    }
    std::printf("\n");
  }
}
