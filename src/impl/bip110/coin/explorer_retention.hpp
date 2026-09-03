// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110 explorer raw-block RETENTION seam.
//
// The bip110 node downloads every full block over coin-p2p (for its M3 own-UTXO
// view). This seam persists EACH received full block into the bounded explorer
// raw-block store so /api/explorer getblock can serve full bodies for the last
// EXPLORER_DEPTH heights. It is deliberately factored OUT of the UTXO-connect
// leg — DASH/LTC parity (main_dash.cpp:2976, main_ltc.cpp:2588): retention must
// fire for EVERY received body, independent of connect contiguity / reorg state.
//
// CRITICAL correctness detail (the live-failure root cause): the header chain is
// keyed by the BIP-110 block IDENTITY — bip110::coin::block_hash(header), which
// is BLAKE2b at/after the v2 fork and SHA256d below it — NOT by SHA256d(header).
// The retention lookup therefore MUST use block_hash(), not Hash(packed_header):
// past the fork every received block is v2, so a SHA256d key never matches the
// BLAKE2b-keyed chain and the height is never resolved (which is exactly why
// retention never fired live and getblock stayed header-partial for every
// height including the tip).
//
// STORAGE / SERVE ONLY. No consensus / share / reward / coinbase / gentx / wire
// path is touched here. A regression is a display-surface regression only.

#pragma once

#include <impl/bip110/coin/block.hpp>
#include <impl/bip110/coin/header_chain.hpp>   // bip110::coin::block_hash

#include <core/coin/utxo_view_db.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace bip110::coin {

// Resolve a block identity hash to its chain height, or std::nullopt if the
// header is not yet known (header sync lagging the body). In production this is
// backed by HeaderChain::get_header; the KAT backs it with an identity->height
// map so it drives THIS function, not a re-derivation.
using HeightResolver = std::function<std::optional<uint32_t>(const uint256&)>;

// Persist one received full block into the bounded raw-block store. Returns the
// stored height on success, std::nullopt when the header is unknown or height 0
// (genesis is never retained). Storage/serve only.
inline std::optional<uint32_t> retain_full_block(
    const HeightResolver&      height_of_identity,
    core::coin::UTXOViewDB&    udb,
    const BlockType&           block,
    uint32_t                   explorer_depth)
{
    // Identity == BLAKE2b at/after the fork, SHA256d below — the SAME key the
    // header chain is indexed by. Using Hash(packed_header) (SHA256d) here would
    // silently miss every post-fork block.
    const uint256 ident = block_hash(static_cast<const BlockHeaderType&>(block));
    const auto height = height_of_identity(ident);
    if (!height || *height == 0)
        return std::nullopt;

    PackStream ps;
    ps << block;
    auto span = ps.get_span();
    std::vector<uint8_t> raw(
        reinterpret_cast<const uint8_t*>(span.data()),
        reinterpret_cast<const uint8_t*>(span.data()) + span.size());

    udb.put_raw_block(*height, raw);
    udb.prune_raw_blocks(*height, explorer_depth);
    return *height;
}

} // namespace bip110::coin
