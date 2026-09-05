/*
 * This file is part of c2pool <https://github.com/frstrtr/c2pool>
 * Copyright (c) 2024-2026 The c2pool developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

// ===========================================================================
// src/impl/xmr/node/xmr_node_observer.hpp
//
// AUTHORED for c2pool (not ported). The callback contract the transport layer
// (RPC parse + ZMQ reader) pushes into, and which MoneroNodeAdapter implements.
//
// PATTERN PROVENANCE (interface shape only, clean reimpl):
//   SChernykh/p2pool v4.18 @ 128643114f9bea55bfdb95462eaeffa2e3f666bd
//     src/util.h  struct MinerCallbackHandler { handle_tx / handle_miner_data /
//                 handle_chain_main / handle_monero_block_broadcast }.
//   We keep the first three (they are pure Monero plumbing) and DROP
//   handle_monero_block_broadcast — that pushes a found block back onto the
//   p2p network for the p2pool pool-model; v37 submits via submit_block RPC and
//   does not gossip Monero blocks. Signatures are simplified: no `const char*
//   extra` / tree-hash out-params (that binding lives in the W3/W5 XMR legs),
//   and prev_id is added to the chain_main payload so the index can detect a
//   reorg by parent mismatch (p2pool defers reorg handling to its SideChain,
//   which is exactly the pool-model we do not port).
// ===========================================================================
#pragma once

#include "xmr_node_types.hpp"

namespace c2pool::xmr::node {

// Implemented by MoneroNodeAdapter. Called on the adapter's event thread by the
// ZMQ reader and by the RPC parse callbacks. Implementations must be cheap and
// non-blocking (they run on the transport thread); heavy work is posted to the
// engine loop.
class IMoneroNodeObserver {
public:
    virtual ~IMoneroNodeObserver() = default;

    // A new txpool entry (ZMQ json-minimal-txpool_add, one per array element).
    // Mirrors p2pool MinerCallbackHandler::handle_tx.
    virtual void on_txpool_add(const TxBacklogEntry& tx) = 0;

    // A fresh miner_data snapshot (get_miner_data RPC result OR ZMQ
    // json-full-miner_data). Mirrors handle_miner_data. Carries the whole
    // tx_backlog and the seed_hash for `height`.
    virtual void on_miner_data(const MinerData& data) = 0;

    // A block was accepted onto monerod's best chain (ZMQ json-full-chain_main,
    // or a get_block_header_by_height / get_block_headers_range backfill row).
    // Mirrors handle_chain_main. The adapter feeds this to MainchainIndex, which
    // decides Extend vs Reorg vs Orphan. monerod is the fork-choice oracle; the
    // index only mirrors its best chain and surfaces the delta to W4.
    virtual void on_chain_main(const ChainMainBlock& block) = 0;
};

} // namespace c2pool::xmr::node
