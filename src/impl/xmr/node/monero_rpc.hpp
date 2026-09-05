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
// src/impl/xmr/node/monero_rpc.hpp
//
// AUTHORED for c2pool (not ported). The daemon-ful monerod JSON-RPC client for
// the XMR lane. Real method signatures + real request bodies; the HTTP transport
// and the rapidjson parse are behind interfaces so this header/impl carries no
// libuv / cpp-httplib / rapidjson dependency and is syntax-checkable in isolation.
//
// The five methods the scoping note (§14.3 / §4 item 9 / X2) names:
//   get_miner_data, submit_block, get_block[_header_by_height],
//   calc_pow, get_fee_estimate.
//
// PATTERN PROVENANCE (request shapes + call flow; clean reimpl, NO lines copied):
//   SChernykh/p2pool v4.18 @ 128643114f9bea55bfdb95462eaeffa2e3f666bd
//     src/json_rpc_request.h  JSONRPCRequest::Call(address,port,req,auth,proxy,
//                             ssl,fingerprint, cb, close_cb, loop)
//     src/p2pool.cpp          get_miner_data() body ("method":"get_miner_data");
//                             submit_block() body ("method":"submit_block",
//                             "params":["<blob hex>"]); get_seed()/update_block_
//                             template() bodies ("method":"get_block_header_by_
//                             height" and "get_block_headers_range").
//   v37 ADDS calc_pow and get_fee_estimate wrappers (p2pool does not call
//   these: it verifies PoW with its own RandomX and derives reward from
//   median_weight). v37 uses get_fee_estimate for k_live(XMR) and calc_pow only
//   as an optional daemon cross-check of the local RandomX verify.
//
// NOT PORTED: p2pool's host-failover list, TLS SPKI pinning, and its api_*/
// stats plumbing — those are operational, not consensus, and v37 has its own.
// ===========================================================================
#pragma once

#include "xmr_node_types.hpp"

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace c2pool::xmr::node {

// --- transport seam ---------------------------------------------------------
// The real build backs this with an async HTTP/1.1 client on the engine's
// libuv loop (or cpp-httplib for the blocking test peer). Decoupled so the RPC
// method layer is testable with a mock and carries no network dependency here.
struct RpcResponse {
    std::vector<char> body;   // raw response bytes (JSON)
    std::string       error;  // non-empty on transport failure
    double            ping_ms = 0.0;
};

class IJsonRpcTransport {
public:
    virtual ~IJsonRpcTransport() = default;
    // `json_body` is a complete JSON-RPC 2.0 request. Result is delivered async.
    virtual void post(const std::string& json_body,
                      std::function<void(const RpcResponse&)> on_done) = 0;
};

// --- typed results ----------------------------------------------------------
struct SubmitBlockResult {
    bool        accepted = false;
    std::string status;      // monerod "status" ("OK" on success)
    std::string error;       // JSON-RPC error message, if any
};

template <typename T>
using ResultCb = std::function<void(std::optional<T> /*value*/, const std::string& /*err*/)>;

// ===========================================================================
// MoneroDaemonRpc — the five daemon calls the lane needs. Endpoints hit the
// monerod JSON-RPC path (http://host:port/json_rpc) except where noted.
// monerod >= v0.18.0.0 required (get_miner_data was added then).
// ===========================================================================
class MoneroDaemonRpc {
public:
    explicit MoneroDaemonRpc(IJsonRpcTransport& transport) : tx_(transport) {}

    // get_miner_data: everything to build a block template except tx bodies.
    // Parses: result.{major_version,height,prev_id,seed_hash,difficulty(+
    // difficulty_top64),median_weight,already_generated_coins,median_timestamp,
    // tx_backlog[{id,weight,fee,blob_size}]}. (No params.)
    void get_miner_data(ResultCb<MinerData> cb);

    // submit_block: params = ["<hex of the full block blob>"]. On the daemon this
    // is the only way to publish a v37-assembled whole block (get_block_template's
    // single-output coinbase is unusable — scoping §14.3).
    void submit_block(const std::string& block_blob_hex, ResultCb<SubmitBlockResult> cb);

    // get_block_header_by_height: one settled header. Used to backfill a RandomX
    // seed anchor named by MainchainIndex::missing_seed_heights().
    // Parses result.block_header.{hash,prev_hash,height,timestamp,reward,
    // difficulty,difficulty_top64}.
    void get_block_header_by_height(uint64_t height, ResultCb<ChainMainBlock> cb);

    // get_block_headers_range: [start,end] inclusive (monerod caps the span at
    // 1000). Used to backfill after a ZMQ gap (MainchainIndex::resync_needed()).
    void get_block_headers_range(uint64_t start_height, uint64_t end_height,
                                 ResultCb<std::vector<ChainMainBlock>> cb);

    // get_block: full block (by height or by hash) incl. the miner_tx blob and
    // tx id list. v37 uses it to re-derive/byte-compare a won coinbase and to
    // read tx bodies it selected by id. `hash_hex` empty => query by height.
    void get_block(uint64_t height, const std::string& hash_hex, ResultCb<std::string> cb);

    // calc_pow: OPTIONAL daemon-side RandomX evaluation, for cross-checking the
    // local light-verify during bring-up. params = {major_version, height,
    // block_blob(hex), seed_hash(hex)}. NOT on the hot path (we verify locally).
    void calc_pow(uint8_t major_version, uint64_t height,
                  const std::string& block_blob_hex, const std::string& seed_hash_hex,
                  ResultCb<Hash> cb);

    // get_fee_estimate: dynamic base fee for k_live(XMR). Optional `grace_blocks`.
    // Parses result.{fee, fees[4], quantization_mask}. Endpoint is
    // /json_rpc method "get_fee_estimate".
    void get_fee_estimate(uint64_t grace_blocks, ResultCb<FeeEstimate> cb);

private:
    // Request-body builders are pure/string-only (defined in the .cpp). Parsers
    // are the only rapidjson-touching code in the real build; declared here,
    // stubbed in the skeleton .cpp with the exact field paths documented.
    IJsonRpcTransport& tx_;
};

} // namespace c2pool::xmr::node
