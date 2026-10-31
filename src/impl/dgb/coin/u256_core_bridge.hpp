// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// dgb::coin::to_core_uint256 -- lossless bridge from the DGB-local 256-bit
// arithmetic type (dgb_arith256.hpp u256: four uint64 limbs, limb[0] least
// significant) to the shared core uint256 (base_uint<256>: eight uint32 words,
// filled little-endian by its vector ctor, uint256.cpp ReadLE32).
//
// DC (DGB-as-DOGE-parent): the per-accepted-share merged submit hands the
// scrypt PoW hash to MergedMiningManager::try_submit_merged_blocks as
// parent_hash, which gates on `parent_hash <= aux_target` (merged_mining.cpp).
// A byte-order slip here would silently mis-gate every DOGE aux block, so the
// conversion lives in one named place with its own KAT
// (work_source_test.cpp DgbWorkSource.U256ToCoreUint256*).

#include <impl/dgb/coin/dgb_arith256.hpp>
#include <core/uint256.hpp>

#include <vector>

namespace dgb::coin {

inline uint256 to_core_uint256(const u256& v)
{
    std::vector<unsigned char> le(32, 0);
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 8; ++j)
            le[i * 8 + j] = static_cast<unsigned char>((v.limb[i] >> (8 * j)) & 0xff);
    return uint256(le);
}

} // namespace dgb::coin
