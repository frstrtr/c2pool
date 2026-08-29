// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::u256_be_display_hex -- SSOT for rendering a u256 as the
// GBT-conventional big-endian block-hash display hex (most-significant limb
// first, 64 lowercase hex digits, no 0x prefix; mirrors uint256::GetHex()
// ordering for a hash stored with limb[0] least-significant).
//
// Header-only u256 (coin/dgb_arith256.hpp) has no GetHex(), and the consuming
// TUs must not depend on btclibs' uint256, so the limbs are formatted directly.
//
// SSOT rationale: the stratum work source (stratum/work_source.cpp,
// previousblockhash + get_current_gbt_prevhash) and the embedded work path
// (coin/embedded_coin_node.hpp) both render the tip hash for the GBT template.
// Drawing both from ONE formatter means the two callers of build_work_template
// can never emit a previousblockhash in a divergent byte-encoding -- the same
// "cannot diverge" intent build_work_template itself enforces for the template
// body.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <string>

#include "dgb_arith256.hpp"  // dgb::coin::u256

namespace dgb::coin
{

inline std::string u256_be_display_hex(const u256& v)
{
    static constexpr char H[] = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (int li = 3; li >= 0; --li) {
        const uint64_t w = v.limb[li];
        for (int sh = 60; sh >= 0; sh -= 4)
            out.push_back(H[(w >> sh) & 0xF]);
    }
    return out;
}

} // namespace dgb::coin