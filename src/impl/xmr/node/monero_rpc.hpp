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
// src/impl/xmr/node/monero_rpc.hpp   (Track X / Family B: XMR lane, X2)
//
// AUTHORED for c2pool (not ported). The daemon-ful monerod JSON-RPC client for
// the XMR lane. Real method signatures, real request bodies, real field paths.
// All I/O is behind IMonerodTransport; parsing goes through minijson in the .cpp,
// so no libuv / cpp-httplib / rapidjson dependency lives in this leg.
//
// The five methods the scoping note names (§14.3 / §4 item 9 / X2 WBS):
//   get_miner_data, submit_block, get_block[_header_by_height],
//   calc_pow, get_fee_estimate.  (+ get_block_headers_range for gap backfill.)
//
// PATTERN PROVENANCE (request shapes + call flow; clean reimpl, NO lines copied):
//   SChernykh/p2pool (GPL-3.0; portable to AGPL-3.0 via AGPLv3 §13)
//     src/p2pool.cpp   get_miner_data() body ("method":"get_miner_data");
//                      submit_block() body ("method":"submit_block",
//                      "params":["<blob hex>"]); get_seed()/update_block_template()
//                      bodies ("get_block_header_by_height",
//                      "get_block_headers_range").
//   v37 ADDS calc_pow and get_fee_estimate wrappers (p2pool calls neither: it
//   verifies PoW with its own RandomX and derives reward from median_weight).
//   v37 uses get_fee_estimate for k_live(XMR) and calc_pow only as an optional
//   daemon cross-check of the local light-mode RandomX verify during bring-up.
// NOT PORTED: p2pool's host-failover list, TLS SPKI pinning, api_*/stats plumbing.
// ===========================================================================
#pragma once

#include "monerod_transport.hpp"
#include "xmr_node_types.hpp"

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace c2pool::xmr::node {

// --- typed results ----------------------------------------------------------
struct SubmitBlockResult {
    bool        accepted = false;
    std::string status;      // monerod "status" ("OK" on success)
    std::string error;       // JSON-RPC error message, if any
};

template <typename T>
using ResultCb = std::function<void(std::optional<T> /*value*/, const std::string& /*err*/)>;

// ===========================================================================
// MoneroDaemonRpc -- the daemon calls the lane needs. monerod >= v0.18.0.0.
// ===========================================================================
class MoneroDaemonRpc {
public:
    explicit MoneroDaemonRpc(IMonerodTransport& transport) : tx_(transport) {}

    // get_miner_data: everything to build a block template except tx bodies.
    // Parses result.{major_version,height,prev_id,seed_hash,difficulty(+
    // difficulty_top64),median_weight,already_generated_coins,median_timestamp,
    // tx_backlog[{id,weight,fee,blob_size}]}. (No params.)
    void get_miner_data(ResultCb<MinerData> cb);

    // submit_block: params = ["<hex of the full block blob>"]. On the daemon this
    // is the only way to publish a v37-assembled whole block (get_block_template's
    // single-output coinbase is unusable -- scoping §14.3).
    void submit_block(const std::string& block_blob_hex, ResultCb<SubmitBlockResult> cb);

    // get_block_header_by_height: one settled header. Backfills a RandomX seed
    // anchor named by MainchainIndex::missing_seed_heights(). Parses
    // result.block_header.{hash,prev_hash,height,timestamp,reward,difficulty,
    // difficulty_top64}.
    void get_block_header_by_height(std::uint64_t height, ResultCb<ChainMainBlock> cb);

    // get_block_headers_range: [start,end] inclusive (monerod caps span at 1000).
    // Backfills the interior after a ZMQ gap (MainchainIndex::resync_needed()).
    void get_block_headers_range(std::uint64_t start_height, std::uint64_t end_height,
                                 ResultCb<std::vector<ChainMainBlock>> cb);

    // get_block: full block (by height or by hash) incl. the miner_tx blob and tx
    // id list. Used to re-derive/byte-compare a won coinbase and to read tx bodies
    // selected by id. `hash_hex` empty => query by height. Returns the raw JSON
    // result object (the CryptoNote block deserializer lives in the coin leg).
    void get_block(std::uint64_t height, const std::string& hash_hex, ResultCb<std::string> cb);

    // calc_pow: OPTIONAL daemon-side RandomX evaluation, for cross-checking the
    // local light verify during bring-up. params = {major_version, height,
    // block_blob(hex), seed_hash(hex)}. NOT on the hot path.
    void calc_pow(std::uint8_t major_version, std::uint64_t height,
                  const std::string& block_blob_hex, const std::string& seed_hash_hex,
                  ResultCb<Hash> cb);

    // get_fee_estimate: dynamic base fee for k_live(XMR). Optional grace_blocks.
    // Parses result.{fee, fees[4], quantization_mask}.
    void get_fee_estimate(std::uint64_t grace_blocks, ResultCb<FeeEstimate> cb);

    // --- request-body builders (pure strings; public so the KAT can assert them) -
    static std::string body_get_miner_data();
    static std::string body_submit_block(const std::string& block_blob_hex);
    static std::string body_get_block_header_by_height(std::uint64_t height);
    static std::string body_get_block_headers_range(std::uint64_t s, std::uint64_t e);
    static std::string body_get_block(std::uint64_t height, const std::string& hash_hex);
    static std::string body_calc_pow(std::uint8_t major_version, std::uint64_t height,
                                     const std::string& block_blob_hex,
                                     const std::string& seed_hash_hex);
    static std::string body_get_fee_estimate(std::uint64_t grace_blocks);

    // --- response parsers (public + static so the KAT can drive them directly) ---
    static std::optional<MinerData>       parse_miner_data(const std::vector<char>& body);
    static SubmitBlockResult              parse_submit_block(const std::vector<char>& body);
    static std::optional<ChainMainBlock>  parse_block_header(const std::vector<char>& body);
    static std::optional<std::vector<ChainMainBlock>> parse_block_headers_range(const std::vector<char>& body);
    static std::optional<FeeEstimate>     parse_fee_estimate(const std::vector<char>& body);
    static std::optional<Hash>            parse_calc_pow(const std::vector<char>& body);

private:
    IMonerodTransport& tx_;
};

} // namespace c2pool::xmr::node
