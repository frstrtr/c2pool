// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// The block flag of a share reloaded from the sharechain store.
//
// A share that solved a block has its index flag (is_block_solution) set
// when it is first verified (share_init_verify: its PoW hash at or below the
// block target its header carries), and the found-block event fires then.
// A share reloaded as verified is added to the verified chain without being
// verified again, so the flag was never set for it: the share view and the
// explorer showed a found block as an ordinary share after a restart.
//
// restore_block_flag sets the flag from the share's PoW hash and the block
// target of its header, the same test share_init_verify makes. It fires no
// event: the block was recorded when the share was first verified (the
// found-block store survives the restart). A null PoW hash (not cached and
// not recomputable) leaves the flag clear.

#include <core/target_utils.hpp>
#include <core/uint256.hpp>

namespace core {

/// True when `pow_hash` meets the block target of `header_bits` (the
/// share's m_min_header.m_bits).
inline bool meets_block_target(const uint256& pow_hash, uint32_t header_bits)
{
    if (pow_hash.IsNull())
        return false;
    const uint256 target = chain::bits_to_target(header_bits);
    return !target.IsNull() && pow_hash <= target;
}

/// Sets `idx.is_block_solution` for a reloaded share `share` whose PoW hash
/// is `pow_hash`; returns it. Never clears a flag already set.
template <typename IndexT, typename ShareT>
inline bool restore_block_flag(IndexT& idx, const ShareT& share, const uint256& pow_hash)
{
    if (meets_block_target(pow_hash, share.m_min_header.m_bits))
        idx.is_block_solution = true;
    return idx.is_block_solution;
}

} // namespace core
