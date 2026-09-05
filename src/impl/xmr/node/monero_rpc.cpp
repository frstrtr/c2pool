/*
 * This file is part of c2pool <https://github.com/frstrtr/c2pool>
 * Copyright (c) 2024-2026 The c2pool developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.  (Full header: monero_rpc.hpp)
 */

// ===========================================================================
// src/impl/xmr/node/monero_rpc.cpp  --  request builders concrete; rapidjson
// parse is the one wire-touching piece left as a documented X2 stub.
//
// The request strings below are byte-for-byte the JSON-RPC 2.0 bodies monerod
// expects and are the exact shapes p2pool sends (provenance in monero_rpc.hpp).
// ===========================================================================
#include "monero_rpc.hpp"

#include <sstream>

namespace c2pool::xmr::node {
namespace {

// The five request bodies. Pure string construction — no dependency.
std::string req_get_miner_data() {
    return R"({"jsonrpc":"2.0","id":"0","method":"get_miner_data"})";
}
std::string req_submit_block(const std::string& blob_hex) {
    std::ostringstream s;
    s << R"({"jsonrpc":"2.0","id":"0","method":"submit_block","params":[")"
      << blob_hex << R"("]})";
    return s.str();
}
std::string req_get_block_header_by_height(uint64_t h) {
    std::ostringstream s;
    s << R"({"jsonrpc":"2.0","id":"0","method":"get_block_header_by_height","params":{"height":)"
      << h << R"(}})";
    return s.str();
}
std::string req_get_block_headers_range(uint64_t start_h, uint64_t end_h) {
    std::ostringstream s;
    s << R"({"jsonrpc":"2.0","id":"0","method":"get_block_headers_range","params":{"start_height":)"
      << start_h << R"(,"end_height":)" << end_h << R"(}})";
    return s.str();
}
std::string req_get_block_by_height(uint64_t h) {
    std::ostringstream s;
    s << R"({"jsonrpc":"2.0","id":"0","method":"get_block","params":{"height":)"
      << h << R"(}})";
    return s.str();
}
std::string req_get_block_by_hash(const std::string& hash_hex) {
    std::ostringstream s;
    s << R"({"jsonrpc":"2.0","id":"0","method":"get_block","params":{"hash":")"
      << hash_hex << R"("}})";
    return s.str();
}
std::string req_calc_pow(uint8_t mv, uint64_t h, const std::string& blob_hex,
                         const std::string& seed_hex) {
    std::ostringstream s;
    s << R"({"jsonrpc":"2.0","id":"0","method":"calc_pow","params":{"major_version":)"
      << static_cast<unsigned>(mv) << R"(,"height":)" << h
      << R"(,"block_blob":")" << blob_hex << R"(","seed_hash":")" << seed_hex << R"("}})";
    return s.str();
}
std::string req_get_fee_estimate(uint64_t grace_blocks) {
    std::ostringstream s;
    s << R"({"jsonrpc":"2.0","id":"0","method":"get_fee_estimate","params":{"grace_blocks":)"
      << grace_blocks << R"(}})";
    return s.str();
}

// ---------------------------------------------------------------------------
// PARSE STUBS (X2). The ONLY rapidjson-touching code in the real build lives
// here. Each documents the exact result field path it must read into the typed
// struct. Kept as stubs so the skeleton carries no rapidjson dependency and the
// caller contract (optional<T> + err) is exercisable with a mock transport.
// Replace each body with a rapidjson::Document parse in the X2 implementation.
// ---------------------------------------------------------------------------
constexpr const char* kStub = "TODO(X2): rapidjson parse not wired in skeleton";

std::optional<MinerData> parse_miner_data(const RpcResponse&, std::string& err) {
    // result.major_version (u8), result.height (u64), result.prev_id (hex32),
    // result.seed_hash (hex32), result.difficulty (u64 lo) + result.
    // difficulty_top64 (u64 hi), result.median_weight (u64), result.
    // already_generated_coins (u64), result.median_timestamp (u64),
    // result.tx_backlog[i].{id(hex32), weight(u64), fee(u64), blob_size(u64)}.
    err = kStub;
    return std::nullopt;
}
std::optional<SubmitBlockResult> parse_submit(const RpcResponse&, std::string& err) {
    // On success: result.status == "OK". On failure: top-level error.{code,message}
    // (e.g. -7 "Block not accepted"). p2pool logs "BLOCK ACCEPTED" on OK.
    err = kStub;
    return std::nullopt;
}
std::optional<ChainMainBlock> parse_block_header(const RpcResponse&, std::string& err) {
    // result.block_header.{hash(hex32)->id, prev_hash(hex32)->prev_id,
    // height(u64), timestamp(u64), reward(u64), difficulty(u64 lo)+
    // difficulty_top64(u64 hi)}.
    err = kStub;
    return std::nullopt;
}
std::optional<std::vector<ChainMainBlock>> parse_headers_range(const RpcResponse&, std::string& err) {
    // result.headers[i] with the same block_header fields as above.
    err = kStub;
    return std::nullopt;
}
std::optional<std::string> parse_block(const RpcResponse&, std::string& err) {
    // result.blob (hex of the full block: header || miner_tx || tx hashes) plus
    // result.json (parsed) if needed. Returned raw for the W3/W5 legs to decode.
    err = kStub;
    return std::nullopt;
}
std::optional<Hash> parse_calc_pow(const RpcResponse&, std::string& err) {
    // result is the 32-byte PoW hash as a hex string.
    err = kStub;
    return std::nullopt;
}
std::optional<FeeEstimate> parse_fee_estimate(const RpcResponse&, std::string& err) {
    // result.{fee(u64), fees[4](u64), quantization_mask(u64)}.
    err = kStub;
    return std::nullopt;
}

} // namespace

// ---------------------------------------------------------------------------
// Method layer: build request -> post -> parse -> deliver typed result. The
// transport-error path short-circuits before parse (matches p2pool's data.
// m_error check).
// ---------------------------------------------------------------------------
void MoneroDaemonRpc::get_miner_data(ResultCb<MinerData> cb) {
    tx_.post(req_get_miner_data(), [cb = std::move(cb)](const RpcResponse& r) {
        if (!r.error.empty()) { cb(std::nullopt, r.error); return; }
        std::string err; auto v = parse_miner_data(r, err); cb(std::move(v), err);
    });
}

void MoneroDaemonRpc::submit_block(const std::string& blob_hex, ResultCb<SubmitBlockResult> cb) {
    tx_.post(req_submit_block(blob_hex), [cb = std::move(cb)](const RpcResponse& r) {
        if (!r.error.empty()) { cb(std::nullopt, r.error); return; }
        std::string err; auto v = parse_submit(r, err); cb(std::move(v), err);
    });
}

void MoneroDaemonRpc::get_block_header_by_height(uint64_t height, ResultCb<ChainMainBlock> cb) {
    tx_.post(req_get_block_header_by_height(height), [cb = std::move(cb)](const RpcResponse& r) {
        if (!r.error.empty()) { cb(std::nullopt, r.error); return; }
        std::string err; auto v = parse_block_header(r, err); cb(std::move(v), err);
    });
}

void MoneroDaemonRpc::get_block_headers_range(uint64_t start_height, uint64_t end_height,
                                              ResultCb<std::vector<ChainMainBlock>> cb) {
    tx_.post(req_get_block_headers_range(start_height, end_height),
             [cb = std::move(cb)](const RpcResponse& r) {
        if (!r.error.empty()) { cb(std::nullopt, r.error); return; }
        std::string err; auto v = parse_headers_range(r, err); cb(std::move(v), err);
    });
}

void MoneroDaemonRpc::get_block(uint64_t height, const std::string& hash_hex, ResultCb<std::string> cb) {
    const std::string body = hash_hex.empty() ? req_get_block_by_height(height)
                                              : req_get_block_by_hash(hash_hex);
    tx_.post(body, [cb = std::move(cb)](const RpcResponse& r) {
        if (!r.error.empty()) { cb(std::nullopt, r.error); return; }
        std::string err; auto v = parse_block(r, err); cb(std::move(v), err);
    });
}

void MoneroDaemonRpc::calc_pow(uint8_t major_version, uint64_t height,
                               const std::string& block_blob_hex, const std::string& seed_hash_hex,
                               ResultCb<Hash> cb) {
    tx_.post(req_calc_pow(major_version, height, block_blob_hex, seed_hash_hex),
             [cb = std::move(cb)](const RpcResponse& r) {
        if (!r.error.empty()) { cb(std::nullopt, r.error); return; }
        std::string err; auto v = parse_calc_pow(r, err); cb(std::move(v), err);
    });
}

void MoneroDaemonRpc::get_fee_estimate(uint64_t grace_blocks, ResultCb<FeeEstimate> cb) {
    tx_.post(req_get_fee_estimate(grace_blocks), [cb = std::move(cb)](const RpcResponse& r) {
        if (!r.error.empty()) { cb(std::nullopt, r.error); return; }
        std::string err; auto v = parse_fee_estimate(r, err); cb(std::move(v), err);
    });
}

} // namespace c2pool::xmr::node
