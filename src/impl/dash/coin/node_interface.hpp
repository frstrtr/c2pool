// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include "block.hpp"
#include "transaction.hpp"

#include <core/uint256.hpp>
#include <core/events.hpp>

#include <cstdint>
#include <map>
#include <vector>

namespace dash
{
namespace interfaces
{

/// Header/think path payload: the active chain tip advanced. Carries the exact
/// inputs build_embedded_workdata() needs that a bare best_block_hash cannot --
/// the height/hash to build the next block ON, the next-block work target
/// (bits), the tip median-time-past for time bounds, and the coin address
/// versions for coinbase-payee encoding. curtime/version default to 0 so the
/// shaper applies its own SAFE-ADDITIVE defaults.
struct TipAdvance
{
    uint32_t prev_height{0};
    uint256  prev_hash;
    uint32_t bits_for_next{0};
    uint32_t mtp_at_tip{0};
    uint8_t  address_version{0};
    uint8_t  address_p2sh_version{0};
    uint32_t curtime{0};
    uint32_t version{0};
};

/// Header/think path payload: a block was connected to the active chain. The
/// bare full_block carries the block body but NOT the height CoinStateMaintainer
/// ::on_block_connected needs to drive MnStateMachine::apply_block (the DIP3
/// special-tx height is a chain-position input apply_block cannot recover from
/// the block alone). block_connected pairs the two so the reception wire feeds
/// apply_block the exact (block, height) apply_block expects -- purely additive,
/// dash interface only (leg 2's new_tip added TipAdvance for the same reason a
/// bare best_block_hash was insufficient).
struct BlockConnected
{
    coin::BlockType block;
    uint32_t        height{0};
};

struct Node
{
    Variable<uint256> best_block_hash;
    Event<uint256> new_block;
    Event<coin::Transaction> new_tx;
    Event<std::vector<coin::BlockHeaderType>> new_headers;
    Event<coin::BlockType> full_block;

    // Header/think path: fires when the active chain tip advances, carrying the
    // embedded-template params (see TipAdvance). The reception wire subscribes
    // CoinStateMaintainer::on_new_tip to this so the node-held bundle arms its
    // tip-readiness prerequisite without a direct poke.
    Event<TipAdvance> new_tip;

    // Header/think path: fires when a block is connected to the active chain,
    // carrying (block, height) (see BlockConnected). The reception wire
    // subscribes CoinStateMaintainer::on_block_connected to this so the DMN set
    // the embedded coinbase pays auto-maintains incrementally between full
    // mnlistdiff snapshots -- a block that empties the set demotes to the dashd
    // fallback rather than backing a template with a phantom payee.
    Event<BlockConnected> block_connected;

    // SPV A1 (parity audit): fires when dashd announces a ChainLock has
    // been aggregated for a block. Carries {block_hash, height}.
    // Consumers (e.g. block-find submit handler) can consult
    // m_chainlocked_blocks to know whether a found block is now
    // irreversible.
    Event<std::pair<uint256, int32_t>> new_chainlock;
    std::map<uint256, int32_t> chainlocked_blocks; // block_hash -> height

    std::map<uint256, coin::Transaction> known_txs;
};

} // namespace interfaces
} // namespace dash
