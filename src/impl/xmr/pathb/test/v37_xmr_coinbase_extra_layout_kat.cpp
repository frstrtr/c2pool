// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_coinbase_extra_layout_kat (pathb_pbx1.hpp / pathb_emission.hpp, K24,
// PBX1): the hf 16 extra == 01 R[32] 02 04 nonce[4] 03 21 00 root[32] (74 B);
// the hf 17 additional-pubkeys form for n >= 2; the coinbase weight bound OVH +
// n x OUT for n in {1, 127, 128, 511, 3747, 10000} at both hf; out_size(16,6e11)
// = 40, out_size(17,6e11) = 90, out_size(16,2^42) = 41.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <vector>

#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/pathb_emission.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

int main() {
    pb::Hash32 r_tx = seq32(0x11), mm = seq32(0x22);
    std::array<std::uint8_t, pb::kExtraNonceBytes> nonce{0xDE, 0xAD, 0xBE, 0xEF};
    const std::vector<std::uint8_t> extra = pb::canonical_tx_extra_hf16(r_tx, nonce, mm);

    // exact hf 16 byte form (74 B).
    check(extra.size() == 74, "hf16 PBX1 extra == 74 bytes");
    check(extra[0] == 0x01, "tag 0x01 TX_EXTRA_TAG_PUBKEY");
    bool rok = true;
    for (int i = 0; i < 32; ++i) rok = rok && extra[1 + i] == r_tx[i];
    check(rok, "R_tx[32] follows 0x01");
    check(extra[33] == 0x02 && extra[34] == 0x04, "0x02 TX_EXTRA_NONCE, length 4");
    bool nok = true;
    for (int i = 0; i < 4; ++i) nok = nok && extra[35 + i] == nonce[i];
    check(nok, "nonce[4] follows 02 04");
    check(extra[39] == 0x03 && extra[40] == 0x21 && extra[41] == 0x00, "0x03 MM tag, len 0x21, depth 0");
    bool mok = true;
    for (int i = 0; i < 32; ++i) mok = mok && extra[42 + i] == mm[i];
    check(mok, "mm_root[32] closes the extra");

    // out_size per hf / S_A (ruling 17 H-3 / 20 Q-G).
    const std::uint64_t s6e11 = 600000000000ull;
    const std::uint64_t s2p42 = std::uint64_t{1} << 42;
    check(pb::out_size(16, s6e11) == 40, "out_size(16, 6e11) == 40");
    check(pb::out_size(17, s6e11) == 90, "out_size(17, 6e11) == 90");
    check(pb::out_size(16, s2p42) == 41, "out_size(16, 2^42) == 41");

    // coinbase weight bound OVH + n x OUT for the output counts (K24).
    for (std::uint64_t n : {std::uint64_t{1}, std::uint64_t{127}, std::uint64_t{128}, std::uint64_t{511},
                            std::uint64_t{3747}, std::uint64_t{10000}}) {
        const std::uint64_t w16 = pb::ovh(16) + n * pb::out_size(16, s6e11);
        const std::uint64_t w17 = pb::ovh(17) + n * pb::out_size(17, s6e11);
        check(w16 == 89 + n * 40, "hf16 coinbase weight bound OVH + n x OUT");
        check(w17 == 61 + n * 90, "hf17 coinbase weight bound OVH + n x OUT");
    }

    return finish("v37_xmr_coinbase_extra_layout_kat");
}
