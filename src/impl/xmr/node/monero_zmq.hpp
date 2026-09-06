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
// src/impl/xmr/node/monero_zmq.hpp   (Track X / Family B: XMR lane, X2)
//
// AUTHORED for c2pool (not ported). Decodes the three monerod --zmq-pub topics
// the daemon-ful lane subscribes to, behind the same IMonerodTransport seam:
//   json-full-miner_data   -> MinerData        (primary tip/template trigger)
//   json-minimal-txpool_add -> [TxBacklogEntry] (backlog deltas)
//   json-full-chain_main   -> ChainMainZmq     (a block was added: reward/height)
//
// PATTERN PROVENANCE (topics + decode intent; clean reimpl, NO lines copied):
//   SChernykh/p2pool (GPL-3.0; portable to AGPL-3.0 via AGPLv3 §13)
//     src/zmq_reader.cpp  ZMQReader subscribing to exactly these three topics and
//                         dispatching one decoded message per callback; p2pool
//                         treats json-full-miner_data as the primary new-block
//                         trigger (get_miner_data pushed on each block).
//
// WIRE-SCHEMA NOTE: json-full-chain_main carries the newly added cryptonote block
// object(s) (monero-project src/serialization/json_object.cpp keys: "miner_tx",
// "vin"/"gen"/"height", "vout"/"amount", "tx_hashes", header "prev_id"/"timestamp").
// The block *id* is NOT in that payload -- it is Keccak(hashing_blob), computed by
// the X1 coin leg. So this decoder returns ChainMainZmq (the directly-available
// fields incl. plaintext coinbase reward), and the adapter uses it to annotate the
// tip's reward for W4's CONS-2 audit; the authoritative tip is driven by the
// unambiguous json-full-miner_data (prev_id = new tip id, height = tip+1).
// ===========================================================================
#pragma once

#include "monerod_transport.hpp"
#include "xmr_node_types.hpp"

#include <functional>
#include <optional>
#include <vector>

namespace c2pool::xmr::node {

// The directly-decodable content of a json-full-chain_main block. `id` is left
// for the coin leg to fill (Keccak of the hashing blob); `reward` is the summed
// plaintext coinbase amount (Monero coinbase amounts are not RingCT-masked).
struct ChainMainZmq {
    std::uint8_t  major_version = 0;
    std::uint8_t  minor_version = 0;
    std::uint64_t height    = 0;    // miner_tx.vin[0].gen.height
    std::uint64_t timestamp = 0;
    Hash          prev_id{};        // header prev_id
    std::uint64_t reward    = 0;    // sum of miner_tx.vout[].amount (piconero)
    std::uint64_t n_tx      = 0;    // tx_hashes.size()
    bool          valid     = false;
};

class ZmqSubscriber {
public:
    explicit ZmqSubscriber(IMonerodTransport& transport) : tx_(transport) {}

    // Callbacks the adapter wires. Any may be left null.
    std::function<void(const MinerData&)>              on_miner_data;
    std::function<void(std::vector<TxBacklogEntry>)>   on_txpool_add;
    std::function<void(const ChainMainZmq&)>           on_chain_main;

    // Subscribe to all three topics through the transport seam.
    void start() {
        tx_.zmq_subscribe(ZMQ_TOPIC_MINER_DATA, [this](const ZmqFrame& f) {
            if (auto md = parse_miner_data_payload(f.payload); md && on_miner_data) on_miner_data(*md);
        });
        tx_.zmq_subscribe(ZMQ_TOPIC_TXPOOL_ADD, [this](const ZmqFrame& f) {
            auto txs = parse_txpool_add_payload(f.payload);
            if (on_txpool_add) on_txpool_add(std::move(txs));
        });
        tx_.zmq_subscribe(ZMQ_TOPIC_CHAIN_MAIN, [this](const ZmqFrame& f) {
            if (auto c = parse_chain_main_payload(f.payload); c && c->valid && on_chain_main) on_chain_main(*c);
        });
    }

    // --- static payload decoders (public so the KAT drives them directly) --------
    // json-full-miner_data payload is the miner_data object at TOP LEVEL (no
    // JSON-RPC {"result":...} wrapper, unlike the get_miner_data RPC response).
    static std::optional<MinerData> parse_miner_data_payload(const std::vector<char>& payload);
    // json-minimal-txpool_add payload is a JSON array of {id, blob_size, weight, fee}.
    static std::vector<TxBacklogEntry> parse_txpool_add_payload(const std::vector<char>& payload);
    // json-full-chain_main payload is a JSON array of added cryptonote blocks
    // (newest last); returns the newest decoded (the one that moved the tip).
    static std::optional<ChainMainZmq> parse_chain_main_payload(const std::vector<char>& payload);

private:
    IMonerodTransport& tx_;
};

} // namespace c2pool::xmr::node
