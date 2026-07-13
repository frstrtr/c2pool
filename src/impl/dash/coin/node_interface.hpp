// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include "block.hpp"
#include "transaction.hpp"
#include "mn_state_machine.hpp"

#include <core/uint256.hpp>
#include <core/events.hpp>

#include <cstdint>
#include <map>
#include <utility>
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
/// dash interface only (leg 2s new_tip added TipAdvance for the same reason a
/// bare best_block_hash was insufficient).
struct BlockConnected
{
    coin::BlockType block;
    uint32_t        height{0};
};

/// Reception path payload (mnlistdiff): the AUTHORITATIVE masternode-set
/// snapshot the embedded coinbase pays. dashd (protx diff / the qdata
/// mnlistdiff message) yields the full projected DMN set as
/// (proTxHash -> MNState) pairs; CoinStateMaintainer::on_mn_list_update()
/// takes exactly that vector. This is the bulk RESYNC feed -- distinct from
/// leg 3s block_connected, which folds per-block special txs INCREMENTALLY
/// between snapshots. An empty vector is a set-gap signal (see on_mn_list_
/// update): it cannot back a payee, so it demotes the bundle to the dashd
/// fallback rather than publishing a template with a phantom payment. Purely
/// additive, dash interface only -- carries dash::coin::MNState, so this
/// header now pulls mn_state_machine.hpp (dash-coin scoped, no cross-coin
/// reach), matching the codec weight it already takes from block.hpp.
struct MnListUpdate
{
    std::vector<std::pair<uint256, coin::MNState>> mnstates;
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

    // Reception path: fires when dashd delivers a full mnlistdiff snapshot,
    // carrying the authoritative projected DMN set (see MnListUpdate). The
    // reception wire subscribes CoinStateMaintainer::on_mn_list_update to this
    // so the masternode set the embedded coinbase pays is bulk-RESYNCED off the
    // real feed (block_connected only folds per-block deltas between snapshots);
    // an empty snapshot demotes the bundle to the dashd fallback.
    Event<MnListUpdate> mn_list_update;

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
