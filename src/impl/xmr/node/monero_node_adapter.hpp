/*
 * This file is part of c2pool <https://github.com/frstrtr/c2pool>
 * Copyright (c) 2024-2026 The c2pool developers
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See COPYING in the repository root.
 */

// ===========================================================================
// src/impl/xmr/node/monero_node_adapter.hpp   (Track X / Family B: XMR lane, X2)
//
// AUTHORED for c2pool (not ported). The daemon-ful monerod adapter facade: binds
// the JSON-RPC client (monero_rpc) and the ZMQ subscriber (monero_zmq) to the
// MainchainIndex, and exposes to the XMR lane exactly:
//   * the current best chain + >= 2112-block RandomX seed reach;
//   * an Extend / Reorg / Orphan event stream (for W4 confirmation depth);
//   * the latest miner_data + fee estimate + tx backlog (for W5 template build);
//   * submit_block (to publish a v37-assembled whole block).
//
// DAEMON-FUL vs EMBEDDED (scoping §4 item 9, recommendation): this adapter is the
// DAEMON-FUL (p2pool) model -- it talks to an external monerod over RPC+ZMQ and
// never validates a Monero tx body. An EMBEDDED Monero node (validating RingCT /
// FCMP proofs in-process) is the DASH-embedded class x3 and is explicitly NOT
// recommended; nothing here pulls monerod's tx-validation stack.
//
// INDEX-DRIVE POLICY (documented, see monero_zmq.hpp): the AUTHORITATIVE tip feed
// is json-full-miner_data, which unambiguously gives (tip_id = prev_id,
// tip_height = height - 1) with no coin-leg hashing. Reorgs are classified by
// height (a miner_data at height <= best rolls back). json-full-chain_main only
// annotates the tip's plaintext coinbase reward (CONS-2). A future coin-leg block
// -id hook lets chain_main drive the tip with a true prev_id for exact same-height
// reorg detection; that is X-later, out of X2 scope.
//
// FCMP-FENCE: this leg reads NO coinbase-output derivation. Stealth-output key
// re-derivation (deterministic r, one-time keys, view tags) is W5/X6 and is fenced
// out of the adapter entirely (scoping OQ-X10 / X6).
// ===========================================================================
#pragma once

#include "mainchain_index.hpp"
#include "monero_rpc.hpp"
#include "monero_zmq.hpp"
#include "monerod_transport.hpp"
#include "xmr_node_types.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <unordered_set>

namespace c2pool::xmr::node {

class MonerodAdapter {
public:
    MonerodAdapter(IMonerodTransport& transport, DaemonEndpoint endpoint = {},
                   std::uint64_t retain_recent = 720)
        : endpoint_(std::move(endpoint)),
          rpc_(transport),
          zmq_(transport),
          index_(retain_recent) {}

    // Subscribe to the ZMQ topics and wire decode -> index. Does not itself do the
    // initial RPC sync; call initial_sync() (or drive on_miner_data) after start().
    void start() {
        zmq_.on_miner_data  = [this](const MinerData& md)            { on_miner_data(md); };
        zmq_.on_txpool_add  = [this](std::vector<TxBacklogEntry> t)  { on_txpool_add(std::move(t)); };
        zmq_.on_chain_main  = [this](const ChainMainZmq& c)          { on_chain_main(c); };
        zmq_.start();
    }

    // One-shot RPC pull of miner_data (e.g. at boot, before ZMQ warms up).
    void initial_sync() {
        rpc_.get_miner_data([this](std::optional<MinerData> md, const std::string&) {
            if (md) on_miner_data(*md);
        });
    }

    // Route the index's Extend/Reorg/Orphan stream to the lane (W4).
    void set_event_sink(MainchainIndex::EventSink sink) { index_.set_sink(std::move(sink)); }

    // --- feed entry points (called by ZMQ decode, or directly in tests) ----------

    // PRIMARY tip driver. Refreshes the backlog, registers the epoch seed anchor
    // from md.seed_hash (sparing an RPC), derives+applies the tip, then backfills
    // any still-missing seed anchors via RPC to keep >= 2112 reach.
    void on_miner_data(const MinerData& md) {
        latest_miner_data_ = md;

        // (a) tx backlog snapshot for W5.
        index_.set_backlog(md.tx_backlog);

        // (b) seed anchor handed to us directly: seed_hash keys the RandomX cache
        //     for md.height, whose anchor is rx_seed_height(md.height).
        index_.note_seed_anchor(rx_seed_height(md.height), md.seed_hash);

        // (c) derive the tip. miner_data.height is the block being mined (tip+1),
        //     miner_data.prev_id is the tip's id. The tip's own parent id is not in
        //     miner_data, so prev_id is left zero and the index classifies by
        //     height (a miner_data at height <= best is a reorg).
        if (md.height >= 1) {
            ChainMainBlock tip;
            tip.height  = md.height - 1;
            tip.id      = md.prev_id;
            // prev_id intentionally zero (unknown parent on this feed).
            index_.apply(tip);
        }

        // (d) keep seed reach satisfied.
        ensure_seed_reach();
    }

    void on_txpool_add(std::vector<TxBacklogEntry> txs) {
        for (auto& t : txs) index_.add_backlog_tx(t);
    }

    // Annotate the tip's plaintext coinbase reward/timestamp (W4 CONS-2). Matched
    // by height against the row miner_data already placed.
    void on_chain_main(const ChainMainZmq& c) {
        index_.annotate(c.height, c.reward, c.timestamp);
    }

    // Ensure every required RandomX seed anchor is resident; RPC-backfill the gaps
    // via get_block_header_by_height (deduped against in-flight requests).
    void ensure_seed_reach() {
        for (std::uint64_t h : index_.missing_seed_heights()) {
            if (!seed_reqs_inflight_.insert(h).second) continue; // already requested
            rpc_.get_block_header_by_height(h, [this, h](std::optional<ChainMainBlock> b, const std::string&) {
                seed_reqs_inflight_.erase(h);
                if (b) index_.backfill(*b);
            });
        }
    }

    // Publish a v37-assembled whole block (W5 output). Thin pass-through.
    void submit_block(const std::string& block_blob_hex, ResultCb<SubmitBlockResult> cb) {
        rpc_.submit_block(block_blob_hex, std::move(cb));
    }

    // Refresh k_live(XMR) from the daemon's dynamic base fee (W4/W5).
    void refresh_fee_estimate(std::uint64_t grace_blocks, ResultCb<FeeEstimate> cb) {
        rpc_.get_fee_estimate(grace_blocks, std::move(cb));
    }

    // --- accessors ---------------------------------------------------------------
    MainchainIndex&       index()       noexcept { return index_; }
    const MainchainIndex& index() const noexcept { return index_; }
    MoneroDaemonRpc&      rpc()         noexcept { return rpc_; }
    const std::optional<MinerData>& latest_miner_data() const noexcept { return latest_miner_data_; }
    const DaemonEndpoint& endpoint()   const noexcept { return endpoint_; }

private:
    DaemonEndpoint  endpoint_;
    MoneroDaemonRpc rpc_;
    ZmqSubscriber   zmq_;
    MainchainIndex  index_;
    std::optional<MinerData> latest_miner_data_;
    std::unordered_set<std::uint64_t> seed_reqs_inflight_;
};

} // namespace c2pool::xmr::node
