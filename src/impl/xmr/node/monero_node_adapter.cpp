/*
 * This file is part of c2pool <https://github.com/frstrtr/c2pool>
 * Copyright (c) 2024-2026 The c2pool developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.  (Full header: monero_node_adapter.hpp)
 */

// ===========================================================================
// src/impl/xmr/node/monero_node_adapter.cpp
//
// Orchestration is concrete: index upserts, seed backfill, reorg forwarding,
// backlog maintenance, the HF fence. The only stubbed code reachable from here
// is the transport parse (monero_rpc.cpp / monero_zmq.cpp X2 stubs).
//
// EVENT SOURCING: MainchainIndex::apply() is driven ONLY from on_chain_main (the
// settled-block ZMQ stream + RPC backfill), so Extend/Reorg/Orphan is emitted
// exactly once per real block. on_miner_data only backfills the current tip id
// (from prev_id), refreshes the template inputs, and ensures seed reach — it
// never emits a mainchain event. This avoids the double-counting that using both
// streams as event sources would cause.
// ===========================================================================
#include "monero_node_adapter.hpp"

#include <chrono>
#include <sstream>

namespace c2pool::xmr::node {
namespace {
uint64_t now_ns() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}
std::string zmq_endpoint_of(const DaemonEndpoint& e) {
    std::ostringstream s;
    s << "tcp://" << e.rpc_host << ':' << e.zmq_port;
    return s.str();
}
} // namespace

MoneroNodeAdapter::MoneroNodeAdapter(DaemonEndpoint endpoint,
                                     IJsonRpcTransport& rpc_transport,
                                     IZmqSubscriber& zmq_subscriber,
                                     EngineHooks hooks)
    : endpoint_(std::move(endpoint)),
      rpc_(rpc_transport),
      zmq_(zmq_subscriber, *this),
      index_(720),
      hooks_(std::move(hooks)) {
    // The index forwards every classified best-chain delta to W4.
    index_.set_sink([this](const MainchainEvent& ev) {
        if (hooks_.on_mainchain_event) hooks_.on_mainchain_event(ev);
    });
}

void MoneroNodeAdapter::start() {
    if (started_) return;
    started_ = true;
    // Prime with one get_miner_data so a tip + seed_hash exist before ZMQ pushes.
    rpc_.get_miner_data([this](std::optional<MinerData> md, const std::string& /*err*/) {
        if (md) on_miner_data(*md);
        // (Transport auto-retries on error; the ZMQ json-full-miner_data stream
        //  will also deliver miner_data going forward.)
    });
    refresh_fee_estimate();
    zmq_.start(zmq_endpoint_of(endpoint_));
}

void MoneroNodeAdapter::stop() {
    if (!started_) return;
    zmq_.stop();
    started_ = false;
}

// --- observer callbacks -----------------------------------------------------

void MoneroNodeAdapter::on_txpool_add(const TxBacklogEntry& tx) {
    index_.add_backlog_tx(tx); // keep the W5 candidate set fresh between snapshots
}

void MoneroNodeAdapter::on_miner_data(const MinerData& data) {
    // CARROT/FCMP tripwire: never build against an unvalidated fork's rules.
    hardfork_beyond_known_ = (data.major_version > XMR_MAX_KNOWN_HF_MAJOR);

    // Learn the current tip id immediately: the block being mined has
    // prev_id == id(height-1). Backfill it WITHOUT emitting an event (the event
    // for that block already arrived via on_chain_main, or will).
    if (data.height >= 1 && !is_zero(data.prev_id)) {
        ChainMainBlock tip;
        tip.height = data.height - 1;
        tip.id     = data.prev_id;
        index_.backfill(tip);
    }

    // Refresh the W5 template inputs.
    MinerData md = data;
    md.local_recv_ns = now_ns();
    index_.set_backlog(md.tx_backlog);
    latest_ = md;

    // Make sure every RandomX seed anchor for the window is resident.
    ensure_seed_reach(data.height);
    if (index_.resync_needed()) {
        const uint64_t lo = (data.height > 720) ? data.height - 720 : 1;
        resync_headers(lo, data.height ? data.height - 1 : 0);
    }

    if (hooks_.on_miner_data) hooks_.on_miner_data(md);
}

void MoneroNodeAdapter::on_chain_main(const ChainMainBlock& block) {
    // Single event source: classify + emit Extend/Reorg/Orphan to W4.
    index_.apply(block);
    // (Mined-tx pruning from the backlog is driven by the tx-hash list the ZMQ
    //  chain_main parse collects; the parse calls index_.remove_backlog_txs on
    //  that list before this returns. See monero_zmq.cpp parse_chain_main.)
}

// --- RPC-driven maintenance -------------------------------------------------

void MoneroNodeAdapter::ensure_seed_reach(uint64_t /*tip_height*/) {
    for (uint64_t h : index_.missing_seed_heights()) {
        rpc_.get_block_header_by_height(h, [this](std::optional<ChainMainBlock> hdr,
                                                  const std::string& /*err*/) {
            if (hdr) index_.backfill(*hdr); // no event; below-tip anchor
        });
    }
}

void MoneroNodeAdapter::resync_headers(uint64_t from_height, uint64_t to_height) {
    if (to_height < from_height) { index_.clear_resync(); return; }
    rpc_.get_block_headers_range(from_height, to_height,
        [this](std::optional<std::vector<ChainMainBlock>> hdrs, const std::string& /*err*/) {
            if (hdrs) for (const auto& h : *hdrs) index_.backfill(h);
            index_.clear_resync();
        });
}

void MoneroNodeAdapter::refresh_fee_estimate() {
    rpc_.get_fee_estimate(/*grace_blocks*/ 10,
        [this](std::optional<FeeEstimate> fe, const std::string& /*err*/) {
            if (fe) fee_ = *fe;
        });
}

void MoneroNodeAdapter::submit_block(const std::string& block_blob_hex,
                                     ResultCb<SubmitBlockResult> cb) {
    rpc_.submit_block(block_blob_hex, std::move(cb));
}

} // namespace c2pool::xmr::node
