/*
 * This file is part of c2pool <https://github.com/frstrtr/c2pool>
 * Copyright (c) 2024-2026 The c2pool developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.  (Full header: monero_zmq.hpp)
 */

// ===========================================================================
// src/impl/xmr/node/monero_zmq.cpp  --  subscribe + dispatch; per-topic parse is
// the X2 rapidjson stub (documented field paths).
// ===========================================================================
#include "monero_zmq.hpp"

#include <cstring>

namespace c2pool::xmr::node {
namespace {

// PARSE STUBS (X2). Documented payload shapes; replace with rapidjson parse.
// Each returns whether the parse succeeded so a malformed frame is skipped (as
// p2pool logs and skips a bad frame rather than aborting).

// json-minimal-txpool_add : JSON array of objects, one per newly-added tx.
//   [{"id":hex32,"blob_size":u64,"weight":u64,"fee":u64}, ...]
bool parse_txpool_add(const char* /*body*/, std::size_t /*len*/,
                      IMoneroNodeObserver& /*obs*/) {
    // for each element -> TxBacklogEntry{id,blob_size,weight,fee,
    //   time_received=now}; obs.on_txpool_add(e);
    return false; // TODO(X2): rapidjson array walk
}

// json-full-miner_data : JSON object identical to get_miner_data's result.
//   {"major_version","height","prev_id","seed_hash","difficulty",
//    "difficulty_top64","median_weight","already_generated_coins",
//    "median_timestamp","tx_backlog":[{"id","weight","fee","blob_size"}]}
bool parse_miner_data(const char* /*body*/, std::size_t /*len*/,
                      IMoneroNodeObserver& /*obs*/) {
    // fill MinerData (see monero_rpc.cpp parse_miner_data field paths);
    // md.local_recv_ns = monotonic_now(); obs.on_miner_data(md);
    return false; // TODO(X2)
}

// json-full-chain_main : JSON array of just-accepted main-chain blocks. Each
// carries block CONTENT (miner_tx, extra, inputs[gen->height], outputs,
// timestamp, tx-hash list) but NOT the canonical block id. The id is computed by
// the coin leg's block-id hasher (Keccak tree hash over the 76-B hashing blob
// header) OR correlated with the next miner_data.prev_id (p2pool's approach).
// `reward` = sum(miner_tx.vout amounts). The mined tx-hash list is returned so
// the adapter can prune them from the backlog (p2pool: m_mempool->remove(...)).
bool parse_chain_main(const char* /*body*/, std::size_t /*len*/,
                      IMoneroNodeObserver& /*obs*/,
                      std::vector<Hash>& /*mined_tx_hashes_out*/) {
    // for each block -> ChainMainBlock{height (from gen input),
    //   timestamp, reward (sum vout), prev_id (from header or correlation),
    //   id (coin-leg hasher)}; obs.on_chain_main(cmb);
    // collect its tx hashes into mined_tx_hashes_out.
    return false; // TODO(X2)
}

} // namespace

bool MoneroZmqReader::start(const std::string& zmq_endpoint) {
    sub_.set_frame_handler([this](const std::string& topic, const char* body, std::size_t len) {
        on_frame(topic, body, len);
    });
    const bool ok = sub_.connect(zmq_endpoint);
    sub_.subscribe(ZMQ_TOPIC_CHAIN_MAIN);
    sub_.subscribe(ZMQ_TOPIC_MINER_DATA);
    sub_.subscribe(ZMQ_TOPIC_TXPOOL_ADD);
    sub_.start();
    return ok;
}

void MoneroZmqReader::stop() { sub_.stop(); }

void MoneroZmqReader::on_frame(const std::string& topic, const char* body, std::size_t len) {
    if (topic == ZMQ_TOPIC_TXPOOL_ADD) {
        parse_txpool_add(body, len, observer_);
    } else if (topic == ZMQ_TOPIC_MINER_DATA) {
        parse_miner_data(body, len, observer_);
    } else if (topic == ZMQ_TOPIC_CHAIN_MAIN) {
        std::vector<Hash> mined;              // pruned from the backlog by the adapter
        parse_chain_main(body, len, observer_, mined);
        // The adapter, as the observer, prunes `mined` from MainchainIndex's
        // backlog inside on_chain_main using the block's tx-hash list; we keep
        // the collection local here to mirror p2pool's remove-on-mined step.
    }
    // Any other topic: ignore (we subscribed to exactly three).
}

} // namespace c2pool::xmr::node
