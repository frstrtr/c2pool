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
// src/impl/xmr/node/monero_node_adapter.hpp
//
// AUTHORED for c2pool (not ported). The top-level DAEMON-FUL monerod adapter: it
// owns the RPC client, the ZMQ reader and the MainchainIndex, implements the
// observer callbacks, and exposes the seam the XMR V37Engine / W4 / W5 consume.
// This is the whole `src/impl/xmr/node/` surface above the transport seam.
//
// ------------------------------------------------------------------ DEPLOYMENT
// DAEMON-FUL (this design; the p2pool model, RECOMMENDED):
//   c2pool talks to an EXTERNAL monerod (>= v0.18.0.0) over JSON-RPC + ZMQ. The
//   daemon does all Monero consensus (Levin p2p, RingCT/CLSAG/FCMP proof
//   verification, tx relay, fork choice). c2pool consumes get_miner_data + the
//   ZMQ stream, assembles whole blocks, and submits via submit_block. This adds
//   ~256 MiB (light RandomX for our own share/receipt verify) on top of the
//   operator's monerod, never a second consensus implementation.
//
// EMBEDDED (DO NOT — scoping §4 item 9 / §23):
//   An in-process Monero node would have to fully validate every RELAYED tx
//   (RingCT range proofs, ring signatures, and post-hard-fork FCMP++ membership
//   proofs). That is DASH-embedded class x3: a second consensus-grade codebase
//   with chain-split liability and no reuse below the sharechain seam. v37 never
//   needs it — we only need block templates + a settlement/confirmation view,
//   both of which the daemon-ful path supplies. This class is intentionally the
//   ONLY node backend; there is no embedded fallback.
//
// ------------------------------------------------------------- CARROT/FCMP FENCE
// This adapter does NOT derive any coinbase output. It only forwards
// MinerData.major_version to the RandomX-verify leg (algorithm select) and to
// the W5 coinbase builder (which owns the pre-CARROT-fenced derivation). The
// fence lives at the derivation site; here we add a tripwire: if the daemon
// reports a major_version beyond XMR_MAX_KNOWN_HF_MAJOR the adapter raises
// hardfork_beyond_known() so the lane HALTS template building rather than
// building against an unvalidated coinbase/PoW rule. Bump the constant only
// together with the fenced derivation + a KAT on the new fork's blocks.
//
// PATTERN PROVENANCE (orchestration; clean reimpl, NO lines copied):
//   SChernykh/p2pool v4.18 @ 128643114f9bea55bfdb95462eaeffa2e3f666bd
//     src/p2pool.cpp  handle_miner_data() (upsert c0 at height, c1=prev_id at
//                     height-1, swap tx_backlog into the mempool); handle_
//                     chain_main() (remove mined txs, upsert the settled row);
//                     get_seed()/download of the seed anchors; the get_miner_
//                     data() bootstrap + ZMQ liveness watchdog.
//   NOT PORTED: SideChain / PPLNS / PoolBlock share-consensus / uncles / the
//   found-block gossip — v37's RDWR work-receipts model replaces all of it.
// ===========================================================================
#pragma once

#include "mainchain_index.hpp"
#include "monero_rpc.hpp"
#include "monero_zmq.hpp"
#include "xmr_node_observer.hpp"
#include "xmr_node_types.hpp"

#include <functional>
#include <optional>
#include <string>

namespace c2pool::xmr::node {

// Highest Monero hard-fork major_version whose coinbase/PoW rules this lane has
// a validated (fenced + KAT'd) implementation for. Monero master tops at v16
// (height 2689608) as read 2026-09-05; FCMP++/CARROT will introduce a new major
// version whose coinbase-output derivation differs (scoping §15 / P2 OQ-X10).
inline constexpr uint8_t XMR_MAX_KNOWN_HF_MAJOR = 16;

class MoneroNodeAdapter final : public IMoneroNodeObserver {
public:
    // Callbacks INTO the engine (posted to the engine loop by the impl). Kept as
    // std::function so the node leg does not depend on the engine's headers.
    struct EngineHooks {
        // Fresh miner_data ready -> W5 can (re)build a template. Carries the full
        // snapshot incl. tx_backlog and seed_hash.
        std::function<void(const MinerData&)> on_miner_data;
        // Best-chain delta -> W4 settlement (Extend/Reorg/Orphan).
        std::function<void(const MainchainEvent&)> on_mainchain_event;
    };

    MoneroNodeAdapter(DaemonEndpoint endpoint,
                      IJsonRpcTransport& rpc_transport,
                      IZmqSubscriber& zmq_subscriber,
                      EngineHooks hooks);

    // Bootstrap: prime with one get_miner_data (so we have a tip + seed_hash
    // before the first ZMQ push) then start the ZMQ reader. Idempotent.
    void start();
    void stop();

    // ---- IMoneroNodeObserver (called on the transport thread) -------------
    void on_txpool_add(const TxBacklogEntry& tx) override;
    void on_miner_data(const MinerData& data) override;
    void on_chain_main(const ChainMainBlock& block) override;

    // ---- W5 template inputs ----------------------------------------------
    std::optional<MinerData> latest_miner_data() const { return latest_; }
    const std::vector<TxBacklogEntry>& tx_backlog() const { return index_.backlog(); }
    std::optional<FeeEstimate> latest_fee_estimate() const { return fee_; }

    // Publish a v37-assembled whole block. Passthrough to submit_block RPC.
    void submit_block(const std::string& block_blob_hex, ResultCb<SubmitBlockResult> cb);

    // ---- W4 settlement view (NO address monitoring; scoping O5.3) ---------
    // Confirmation depth of the settlement (coinbase-carrying) block on the
    // current best chain, or 0 if unknown/orphaned. W4 compares against D_conf=60.
    uint64_t confirmation_depth(const Hash& settlement_block_id) const {
        return index_.confirmation_depth(settlement_block_id);
    }
    const MainchainIndex& index() const { return index_; }

    // ---- health / fences --------------------------------------------------
    bool zmq_connected() const { return zmq_.is_connected(); }
    // Every RandomX seed anchor for the retained window is resident -> any share
    // in-window can be light-verified locally without a daemon round-trip.
    bool seed_reach_satisfied() const { return index_.seed_reach_satisfied(); }
    // CARROT/FCMP tripwire (see header banner). True => halt template building.
    bool hardfork_beyond_known() const { return hardfork_beyond_known_; }

private:
    // After a miner_data, ensure every required seed anchor is resident: fire a
    // get_block_header_by_height for each MainchainIndex::missing_seed_heights().
    void ensure_seed_reach(uint64_t tip_height);
    // After a ZMQ gap (index_.resync_needed()), pull the missing headers.
    void resync_headers(uint64_t from_height, uint64_t to_height);
    // Refresh k_live(XMR) input.
    void refresh_fee_estimate();

    DaemonEndpoint      endpoint_;
    MoneroDaemonRpc     rpc_;
    MoneroZmqReader     zmq_;
    MainchainIndex      index_;
    EngineHooks         hooks_;

    std::optional<MinerData>   latest_;
    std::optional<FeeEstimate> fee_;
    bool                       started_ = false;
    bool                       hardfork_beyond_known_ = false;
};

} // namespace c2pool::xmr::node
