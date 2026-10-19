// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_coinbase_reserve_kat (pathb_emission.hpp, K10 / K25, ruling 25 K-5):
//   N(B) = max(1, floor((Z - 2 OVH) / (2 OUT))) at the frozen Z/2 reserve;
//   the N(B) vectors recompute to the byte; the two written forms are equal for
//   every integer Z (Z 300,000 / 300,001 -> 3,747, Z 300,079 -> 3,748); a
//   non-positive numerator -> 1; the hf 17 cap 10,000; N(B) reads Z, hf and S_A
//   only (signature).
// ---------------------------------------------------------------------------
#include <cstdint>
#include <type_traits>

#include "impl/xmr/pathb/pathb_emission.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

int main() {
    const std::uint64_t s6e11 = 600000000000ull;      // S_A = B = 6e11, V(S) = 6
    const std::uint64_t s2p42 = std::uint64_t{1} << 42;  // S_A = 2^42, V(S) = 7

    // OVH / OUT per hf (K24a / K24b).
    check(pb::ovh(16) == 89 && pb::ovh(17) == 61, "OVH 89 (hf16) / 61 (hf17)");
    check(pb::out_size(16, s6e11) == 40 && pb::out_size(17, s6e11) == 90, "OUT 40 (hf16) / 90 (hf17) at 6e11");
    check(pb::out_size(16, s2p42) == 41 && pb::out_size(17, s2p42) == 91, "OUT 41 / 91 at S_A >= 2^42");

    // N(B) vectors (S3.6, verified independently).
    check(pb::n_rule(300000, 16, s6e11) == 3747, "N(B) = 3747 at Z 300000 hf16");
    check(pb::n_rule(625000, 17, s6e11) == 3471, "N(B) = 3471 at Z 625000 hf17");
    check(pb::n_rule(300000, 17, s6e11) == 1665, "N(B) = 1665 at Z 300000 hf17");
    check(pb::n_rule(300000, 16, s2p42) == 3656, "N(B) = 3656 at Z 300000 hf16 V=7");
    check(pb::n_rule(300000, 17, s2p42) == 1647, "N(B) = 1647 at Z 300000 hf17 V=7");

    // the hf 17 cap 10,000 binds at Z >= 1,800,122 (and not at 1,800,121).
    check(pb::n_rule(1800122, 17, s6e11) == 10000, "hf17 cap 10000 binds at Z 1800122");
    check(pb::n_rule(1800121, 17, s6e11) == 9999, "hf17 N = 9999 at Z 1800121");

    // non-positive numerator -> N = 1 (Z < 2 OVH).
    check(pb::n_rule(100, 16, s6e11) == 1, "non-positive numerator -> N = 1");
    check(pb::n_rule(178, 16, s6e11) == 1, "Z == 2 OVH -> N = 1");

    // the two written forms are equal for every integer Z (reserve KAT invariant).
    check(pb::n_rule(300000, 16, s6e11) == 3747 && pb::n_rule(300001, 16, s6e11) == 3747
                  && pb::n_rule(300079, 16, s6e11) == 3748,
          "N(B) at Z 300000 / 300001 -> 3747, Z 300079 -> 3748");
    check(pb::n_rule_half_form(300000, 16, s6e11) == 3747 && pb::n_rule_half_form(300001, 16, s6e11) == 3747
                  && pb::n_rule_half_form(300079, 16, s6e11) == 3748,
          "half form at Z 300000 / 300001 -> 3747, Z 300079 -> 3748");
    Rng rng(0xC01DF00D);
    bool forms_equal = true;
    for (int i = 0; i < 200000 && forms_equal; ++i) {
        const std::uint64_t z = rng.below(4000000);
        const std::uint8_t hf = (i & 1) ? 17 : 16;
        const std::uint64_t s = (i & 2) ? s6e11 : s2p42;
        forms_equal = pb::n_rule(z, hf, s) == pb::n_rule_half_form(z, hf, s);
    }
    check(forms_equal, "two written N(B) forms equal over 200000 random Z");

    // N(B) does not move with mempool spam: its only inputs are Z(A), hf and S_A.
    static_assert(std::is_same_v<decltype(&pb::n_rule), std::uint64_t (*)(std::uint64_t, std::uint8_t, std::uint64_t) noexcept>,
                  "n_rule reads Z, hf and S_A only");

    return finish("v37_xmr_coinbase_reserve_kat");
}
