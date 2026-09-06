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
// src/impl/xmr/node/monero_rpc.cpp   (Track X / Family B: XMR lane, X2)
//
// AUTHORED for c2pool (not ported). Request-body builders (fully real; pure
// strings) and response parsers (via minijson; the production build swaps in the
// vetted rapidjson path) for the seven monerod JSON-RPC calls. Field paths match
// the monerod v0.18 /json_rpc schema (docs.getmonero.org daemon-rpc) and p2pool's
// usage of get_miner_data / get_block_header* (pattern provenance in the header).
// ===========================================================================
#include "monero_rpc.hpp"

#include "minijson.hpp"

namespace c2pool::xmr::node {

namespace mj = minijson;

// ---------------------------------------------------------------------------
// Request-body builders. Exact JSON-RPC 2.0 bodies monerod expects.
// ---------------------------------------------------------------------------
std::string MoneroDaemonRpc::body_get_miner_data() {
    return R"({"jsonrpc":"2.0","id":"0","method":"get_miner_data"})";
}

std::string MoneroDaemonRpc::body_submit_block(const std::string& block_blob_hex) {
    return R"({"jsonrpc":"2.0","id":"0","method":"submit_block","params":[")" +
           block_blob_hex + R"("]})";
}

std::string MoneroDaemonRpc::body_get_block_header_by_height(std::uint64_t height) {
    return R"({"jsonrpc":"2.0","id":"0","method":"get_block_header_by_height","params":{"height":)" +
           std::to_string(height) + R"(}})";
}

std::string MoneroDaemonRpc::body_get_block_headers_range(std::uint64_t s, std::uint64_t e) {
    return R"({"jsonrpc":"2.0","id":"0","method":"get_block_headers_range","params":{"start_height":)" +
           std::to_string(s) + R"(,"end_height":)" + std::to_string(e) + R"(}})";
}

std::string MoneroDaemonRpc::body_get_block(std::uint64_t height, const std::string& hash_hex) {
    if (!hash_hex.empty()) {
        return R"({"jsonrpc":"2.0","id":"0","method":"get_block","params":{"hash":")" +
               hash_hex + R"("}})";
    }
    return R"({"jsonrpc":"2.0","id":"0","method":"get_block","params":{"height":)" +
           std::to_string(height) + R"(}})";
}

std::string MoneroDaemonRpc::body_calc_pow(std::uint8_t major_version, std::uint64_t height,
                                           const std::string& block_blob_hex,
                                           const std::string& seed_hash_hex) {
    return R"({"jsonrpc":"2.0","id":"0","method":"calc_pow","params":{"major_version":)" +
           std::to_string(static_cast<unsigned>(major_version)) +
           R"(,"height":)" + std::to_string(height) +
           R"(,"block_blob":")" + block_blob_hex +
           R"(","seed_hash":")" + seed_hash_hex + R"("}})";
}

std::string MoneroDaemonRpc::body_get_fee_estimate(std::uint64_t grace_blocks) {
    return R"({"jsonrpc":"2.0","id":"0","method":"get_fee_estimate","params":{"grace_blocks":)" +
           std::to_string(grace_blocks) + R"(}})";
}

// ---------------------------------------------------------------------------
// Parse helpers.
// ---------------------------------------------------------------------------
namespace {

bool root_result(const std::vector<char>& body, mj::Value& root, const mj::Value*& result,
                 std::string& err) {
    if (!mj::parse(body.data(), body.size(), root)) { err = "json: parse failed"; return false; }
    const mj::Value& r = root["result"];
    if (!r.is_object()) {
        // surface a JSON-RPC error object if present
        const mj::Value& e = root["error"];
        err = e.is_object() ? ("rpc: " + e["message"].as_string()) : "json: no result";
        return false;
    }
    result = &r;
    return true;
}

Difficulty128 read_difficulty(const mj::Value& obj) {
    Difficulty128 d;
    d.lo = obj["difficulty"].as_u64();
    d.hi = obj["difficulty_top64"].as_u64(); // absent => 0 (fits u64 today)
    return d;
}

// Read a block_header object (get_block_header_by_height / _range).
std::optional<ChainMainBlock> read_block_header(const mj::Value& bh) {
    if (!bh.is_object()) return std::nullopt;
    ChainMainBlock b;
    b.height     = bh["height"].as_u64();
    b.timestamp  = bh["timestamp"].as_u64();
    b.reward     = bh["reward"].as_u64();
    b.difficulty = read_difficulty(bh);
    if (!mj::hex_to_hash(bh["hash"].as_string(), b.id)) return std::nullopt;
    mj::hex_to_hash(bh["prev_hash"].as_string(), b.prev_id); // may be all-zero at genesis
    return b;
}

} // namespace

std::optional<MinerData> MoneroDaemonRpc::parse_miner_data(const std::vector<char>& body) {
    mj::Value root; const mj::Value* result = nullptr; std::string err;
    if (!root_result(body, root, result, err)) return std::nullopt;
    const mj::Value& r = *result;

    MinerData md;
    md.major_version           = static_cast<std::uint8_t>(r["major_version"].as_u32());
    md.height                  = r["height"].as_u64();
    md.difficulty              = read_difficulty(r);
    md.median_weight           = r["median_weight"].as_u64();
    md.already_generated_coins = r["already_generated_coins"].as_u64();
    md.median_timestamp        = r["median_timestamp"].as_u64();
    if (!mj::hex_to_hash(r["prev_id"].as_string(), md.prev_id)) return std::nullopt;
    mj::hex_to_hash(r["seed_hash"].as_string(), md.seed_hash); // may be zero pre-RandomX heights

    const mj::Value& tb = r["tx_backlog"];
    if (tb.is_array()) {
        md.tx_backlog.reserve(tb.arr.size());
        for (const auto& e : tb.arr) {
            TxBacklogEntry t;
            mj::hex_to_hash(e["id"].as_string(), t.id);
            t.weight    = e["weight"].as_u64();
            t.fee       = e["fee"].as_u64();
            t.blob_size = e["blob_size"].as_u64(); // absent in some monerod builds
            md.tx_backlog.push_back(t);
        }
    }
    if (!md.valid()) return std::nullopt;
    return md;
}

SubmitBlockResult MoneroDaemonRpc::parse_submit_block(const std::vector<char>& body) {
    SubmitBlockResult out;
    mj::Value root;
    if (!mj::parse(body.data(), body.size(), root)) { out.error = "json: parse failed"; return out; }
    const mj::Value& r = root["result"];
    if (r.is_object()) {
        out.status   = r["status"].as_string();
        out.accepted = (out.status == "OK");
        return out;
    }
    const mj::Value& e = root["error"];
    out.error = e.is_object() ? ("rpc: " + e["message"].as_string()) : "json: no result";
    return out;
}

std::optional<ChainMainBlock> MoneroDaemonRpc::parse_block_header(const std::vector<char>& body) {
    mj::Value root; const mj::Value* result = nullptr; std::string err;
    if (!root_result(body, root, result, err)) return std::nullopt;
    return read_block_header((*result)["block_header"]);
}

std::optional<std::vector<ChainMainBlock>>
MoneroDaemonRpc::parse_block_headers_range(const std::vector<char>& body) {
    mj::Value root; const mj::Value* result = nullptr; std::string err;
    if (!root_result(body, root, result, err)) return std::nullopt;
    const mj::Value& hs = (*result)["headers"];
    if (!hs.is_array()) return std::nullopt;
    std::vector<ChainMainBlock> out;
    out.reserve(hs.arr.size());
    for (const auto& bh : hs.arr) {
        if (auto b = read_block_header(bh)) out.push_back(*b);
        else return std::nullopt;
    }
    return out;
}

std::optional<FeeEstimate> MoneroDaemonRpc::parse_fee_estimate(const std::vector<char>& body) {
    mj::Value root; const mj::Value* result = nullptr; std::string err;
    if (!root_result(body, root, result, err)) return std::nullopt;
    const mj::Value& r = *result;
    FeeEstimate fe;
    fe.fee_per_byte      = r["fee"].as_u64();
    fe.quantization_mask = r["quantization_mask"].as_u64(1);
    const mj::Value& fees = r["fees"];
    if (fees.is_array()) {
        for (std::size_t i = 0; i < fees.arr.size() && i < 4; ++i)
            fe.fees[i] = fees.arr[i].as_u64();
    }
    return fe;
}

std::optional<Hash> MoneroDaemonRpc::parse_calc_pow(const std::vector<char>& body) {
    // calc_pow returns the pow hash as a bare hex string in "result".
    mj::Value root;
    if (!mj::parse(body.data(), body.size(), root)) return std::nullopt;
    const mj::Value& r = root["result"];
    Hash h{};
    if (r.is_string()) { if (!mj::hex_to_hash(r.as_string(), h)) return std::nullopt; return h; }
    if (r.is_object()) { if (!mj::hex_to_hash(r["pow_hash"].as_string(), h)) return std::nullopt; return h; }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Call methods: build body -> post via the seam -> parse -> deliver typed result.
// ---------------------------------------------------------------------------
void MoneroDaemonRpc::get_miner_data(ResultCb<MinerData> cb) {
    tx_.rpc_post(body_get_miner_data(), [cb = std::move(cb)](const RpcResponse& resp) {
        if (!resp.ok()) { cb(std::nullopt, resp.error); return; }
        auto md = parse_miner_data(resp.body);
        if (!md) { cb(std::nullopt, "get_miner_data: parse/validate failed"); return; }
        md->local_recv_ns = 0; // stamped by the adapter, not here
        cb(md, {});
    });
}

void MoneroDaemonRpc::submit_block(const std::string& block_blob_hex,
                                   ResultCb<SubmitBlockResult> cb) {
    tx_.rpc_post(body_submit_block(block_blob_hex), [cb = std::move(cb)](const RpcResponse& resp) {
        if (!resp.ok()) { cb(std::nullopt, resp.error); return; }
        SubmitBlockResult r = parse_submit_block(resp.body);
        cb(r, r.error);
    });
}

void MoneroDaemonRpc::get_block_header_by_height(std::uint64_t height, ResultCb<ChainMainBlock> cb) {
    tx_.rpc_post(body_get_block_header_by_height(height), [cb = std::move(cb)](const RpcResponse& resp) {
        if (!resp.ok()) { cb(std::nullopt, resp.error); return; }
        auto b = parse_block_header(resp.body);
        if (!b) { cb(std::nullopt, "get_block_header_by_height: parse failed"); return; }
        cb(b, {});
    });
}

void MoneroDaemonRpc::get_block_headers_range(std::uint64_t s, std::uint64_t e,
                                              ResultCb<std::vector<ChainMainBlock>> cb) {
    tx_.rpc_post(body_get_block_headers_range(s, e), [cb = std::move(cb)](const RpcResponse& resp) {
        if (!resp.ok()) { cb(std::nullopt, resp.error); return; }
        auto v = parse_block_headers_range(resp.body);
        if (!v) { cb(std::nullopt, "get_block_headers_range: parse failed"); return; }
        cb(v, {});
    });
}

void MoneroDaemonRpc::get_block(std::uint64_t height, const std::string& hash_hex,
                                ResultCb<std::string> cb) {
    tx_.rpc_post(body_get_block(height, hash_hex), [cb = std::move(cb)](const RpcResponse& resp) {
        if (!resp.ok()) { cb(std::nullopt, resp.error); return; }
        cb(std::string(resp.body.begin(), resp.body.end()), {});
    });
}

void MoneroDaemonRpc::calc_pow(std::uint8_t major_version, std::uint64_t height,
                               const std::string& block_blob_hex, const std::string& seed_hash_hex,
                               ResultCb<Hash> cb) {
    tx_.rpc_post(body_calc_pow(major_version, height, block_blob_hex, seed_hash_hex),
                 [cb = std::move(cb)](const RpcResponse& resp) {
        if (!resp.ok()) { cb(std::nullopt, resp.error); return; }
        auto h = parse_calc_pow(resp.body);
        if (!h) { cb(std::nullopt, "calc_pow: parse failed"); return; }
        cb(h, {});
    });
}

void MoneroDaemonRpc::get_fee_estimate(std::uint64_t grace_blocks, ResultCb<FeeEstimate> cb) {
    tx_.rpc_post(body_get_fee_estimate(grace_blocks), [cb = std::move(cb)](const RpcResponse& resp) {
        if (!resp.ok()) { cb(std::nullopt, resp.error); return; }
        auto fe = parse_fee_estimate(resp.body);
        if (!fe) { cb(std::nullopt, "get_fee_estimate: parse failed"); return; }
        cb(fe, {});
    });
}

} // namespace c2pool::xmr::node
