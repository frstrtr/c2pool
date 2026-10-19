// SPDX-License-Identifier: AGPL-3.0-or-later
// Research simulation (docs/research/window-pulse/README.md). The width law's fixed point, positional divisor vs the pre-fix native-ridge divisor.
// Build: g++ -O2 -std=c++20 -I../../../src/sharechain/v37 -I../../../src nrlaw.cpp -o nrlaw
#include "v37_lane.hpp"
#include <cstdio>
using namespace v37;
int main() {
  WinGate g = winlaw::for_version(1, LaneKind::LTC);   // W 528/576/4608, C pinned = 576
  printf("LTC gate: wmin %llu wdef %llu wmax %llu C %llu R %llu\n", (unsigned long long)g.w_min_bins,
         (unsigned long long)g.w_default_bins, (unsigned long long)g.w_max_bins, (unsigned long long)g.coverage_blocks, (unsigned long long)g.retarget_bins);
  // Constant pool: D_net = 1e6 work/block, pool rate chosen so the INTENDED fixed point
  // W* = C*D/rate is 1000 bins (inside [528,4608]) -> rate = 576*1e6/1000 = 576000 work/bin.
  const u64 D = 1000000, rate = 576000;
  for (int mode = 0; mode < 3; ++mode) {
    u64 W = g.w_default_bins;
    static const char* nm[3] = {"WIN divisor = raw of prior full window", "NR (pre-fix) one 8-bin period as a window", "NR (fixed) retarget_width_over(span = 8)"};
    printf("%s: ", nm[mode]);
    for (int k = 0; k < 12; ++k) {
      u128 raw = mode ? (u128)rate * 8 : (u128)rate * W;
      W = mode == 2 ? winlaw::retarget_width_over(U256(D), W, raw, 8, g) : winlaw::retarget_width(U256(D), W, raw, g);
      printf("%llu ", (unsigned long long)W);
    }
    printf("\n");
  }
}
