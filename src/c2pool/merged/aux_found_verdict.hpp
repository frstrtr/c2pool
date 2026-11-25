// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Found-block verdict for a merged chain that has no embedded header chain:
/// the same rule as ltc::coin::found_block::aux_verdict (confirmed once our
/// block is the best chain's block at its height kDepth deep, orphaned once
/// another block is there kDepth deep, pending otherwise), read from the aux
/// daemon's best chain (getblockcount, getblockhash, getblockheader). A
/// daemon that answers is not a confirmation: until it shows our block on its
/// best chain the verdict is pending (0), and a daemon that cannot tell
/// (down, or a backend without these calls) leaves it pending too.

#include <c2pool/merged/merged_mining.hpp>
#include <impl/ltc/coin/found_block_verify.hpp>

#include <optional>

namespace c2pool {
namespace merged {

/// A ChainView over the backend's best chain; the tip is read once per view.
inline ltc::coin::found_block::ChainView backend_chain_view(IAuxChainBackend& backend)
{
    auto tip = std::make_shared<std::optional<std::optional<uint32_t>>>();
    auto read_tip = [&backend, tip]() -> std::optional<uint32_t> {
        if (!tip->has_value())
            *tip = backend.get_block_count();
        return **tip;
    };
    ltc::coin::found_block::ChainView v;
    v.height_of = [&backend](const uint256& h) { return backend.get_block_height(h); };
    v.hash_at = [&backend](uint32_t h) { return backend.get_block_hash_at(h); };
    v.tip_height = [read_tip]() { return read_tip().value_or(0); };
    v.has_tip = [read_tip]() { return read_tip().has_value(); };
    return v;
}

/// >0 confirmed (confirmations), <0 orphaned, 0 pending.
inline int aux_backend_verdict(IAuxChainBackend& backend, const uint256& hash,
                               std::optional<uint32_t> found_height)
{
    return ltc::coin::found_block::aux_verdict(backend_chain_view(backend), hash, found_height);
}

} // namespace merged
} // namespace c2pool
