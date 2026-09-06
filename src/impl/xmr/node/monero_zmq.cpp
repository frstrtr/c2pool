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
// src/impl/xmr/node/monero_zmq.cpp   (Track X / Family B: XMR lane, X2)
//
// AUTHORED for c2pool (not ported). minijson decoders for the three monerod ZMQ
// topics. Field keys follow monero-project src/serialization/json_object.cpp.
// Production swaps in the vetted rapidjson path; this exists so the topic->struct
// MAPPING is testable single-TU on an OOM host.
// ===========================================================================
#include "monero_zmq.hpp"

#include "minijson.hpp"

namespace c2pool::xmr::node {

namespace mj = minijson;

namespace {

Difficulty128 read_difficulty(const mj::Value& obj) {
    Difficulty128 d;
    d.lo = obj["difficulty"].as_u64();
    d.hi = obj["difficulty_top64"].as_u64();
    return d;
}

// Read a MinerData from a minijson object (the miner_data body, no RPC wrapper).
std::optional<MinerData> read_miner_data_obj(const mj::Value& r) {
    if (!r.is_object()) return std::nullopt;
    MinerData md;
    md.major_version           = static_cast<std::uint8_t>(r["major_version"].as_u32());
    md.height                  = r["height"].as_u64();
    md.difficulty              = read_difficulty(r);
    md.median_weight           = r["median_weight"].as_u64();
    md.already_generated_coins = r["already_generated_coins"].as_u64();
    md.median_timestamp        = r["median_timestamp"].as_u64();
    if (!mj::hex_to_hash(r["prev_id"].as_string(), md.prev_id)) return std::nullopt;
    mj::hex_to_hash(r["seed_hash"].as_string(), md.seed_hash);

    const mj::Value& tb = r["tx_backlog"];
    if (tb.is_array()) {
        md.tx_backlog.reserve(tb.arr.size());
        for (const auto& e : tb.arr) {
            TxBacklogEntry t;
            mj::hex_to_hash(e["id"].as_string(), t.id);
            t.weight    = e["weight"].as_u64();
            t.fee       = e["fee"].as_u64();
            t.blob_size = e["blob_size"].as_u64();
            md.tx_backlog.push_back(t);
        }
    }
    if (!md.valid()) return std::nullopt;
    return md;
}

// Decode one cryptonote block object into ChainMainZmq (directly-present fields).
std::optional<ChainMainZmq> read_chain_block_obj(const mj::Value& b) {
    if (!b.is_object()) return std::nullopt;
    ChainMainZmq c;
    c.major_version = static_cast<std::uint8_t>(b["major_version"].as_u32());
    c.minor_version = static_cast<std::uint8_t>(b["minor_version"].as_u32());
    c.timestamp     = b["timestamp"].as_u64();
    mj::hex_to_hash(b["prev_id"].as_string(), c.prev_id);

    const mj::Value& miner = b["miner_tx"];
    // height from txin_gen: miner_tx.vin[0].gen.height
    const mj::Value& vin = miner["vin"];
    if (vin.is_array() && !vin.arr.empty()) {
        const mj::Value& gen = vin.arr[0]["gen"];
        c.height = gen["height"].as_u64();
    }
    // plaintext reward = sum of miner_tx.vout[].amount
    const mj::Value& vout = miner["vout"];
    if (vout.is_array()) {
        std::uint64_t sum = 0;
        for (const auto& o : vout.arr) sum += o["amount"].as_u64();
        c.reward = sum;
    }
    const mj::Value& txh = b["tx_hashes"];
    if (txh.is_array()) c.n_tx = txh.arr.size();

    // Minimally valid if we recovered a height and a parent id.
    c.valid = (c.height != 0) && !is_zero(c.prev_id);
    return c;
}

} // namespace

std::optional<MinerData> ZmqSubscriber::parse_miner_data_payload(const std::vector<char>& payload) {
    mj::Value root;
    if (!mj::parse(payload.data(), payload.size(), root)) return std::nullopt;
    // ZMQ payload is the object at top level; tolerate a {"result":...} wrapper too.
    if (root["result"].is_object()) return read_miner_data_obj(root["result"]);
    return read_miner_data_obj(root);
}

std::vector<TxBacklogEntry> ZmqSubscriber::parse_txpool_add_payload(const std::vector<char>& payload) {
    std::vector<TxBacklogEntry> out;
    mj::Value root;
    if (!mj::parse(payload.data(), payload.size(), root)) return out;
    if (!root.is_array()) return out;
    out.reserve(root.arr.size());
    for (const auto& e : root.arr) {
        TxBacklogEntry t;
        mj::hex_to_hash(e["id"].as_string(), t.id);
        t.blob_size     = e["blob_size"].as_u64();
        t.weight        = e["weight"].as_u64();
        t.fee           = e["fee"].as_u64();
        t.time_received = e["receive_time"].as_u64();
        if (t.weight == 0) t.weight = t.blob_size; // some builds omit weight
        out.push_back(t);
    }
    return out;
}

std::optional<ChainMainZmq> ZmqSubscriber::parse_chain_main_payload(const std::vector<char>& payload) {
    mj::Value root;
    if (!mj::parse(payload.data(), payload.size(), root)) return std::nullopt;
    // Array of added blocks (newest last); or a single block object.
    if (root.is_array()) {
        if (root.arr.empty()) return std::nullopt;
        return read_chain_block_obj(root.arr.back());
    }
    return read_chain_block_obj(root);
}

} // namespace c2pool::xmr::node
