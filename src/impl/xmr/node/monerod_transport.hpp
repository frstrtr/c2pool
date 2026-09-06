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
// src/impl/xmr/node/monerod_transport.hpp   (Track X / Family B: XMR lane, X2)
//
// AUTHORED for c2pool (not ported). THE I/O SEAM. Every byte in/out of monerod --
// JSON-RPC over HTTP and the ZMQ SUB stream -- goes through IMonerodTransport, so
// the RPC method layer (monero_rpc), the ZMQ decode layer (monero_zmq) and the
// MainchainIndex carry NO network dependency and are driven by MockMonerodTransport
// in tests. The production build backs this with an async HTTP/1.1 client + a
// libzmq SUB socket on the engine's event loop (X5/engine work, out of X2 scope).
//
// PATTERN PROVENANCE (structure only; clean reimpl, NO source lines copied):
//   SChernykh/p2pool (GPL-3.0; portable to AGPL-3.0 via AGPLv3 §13)
//     src/json_rpc_request.h  JSONRPCRequest::Call(addr,port,req,auth,proxy,ssl,
//                             fingerprint, cb, close_cb, loop)  -- the async
//                             "post a body, get a callback" shape.
//     src/zmq_reader.cpp      ZMQReader: a SUB socket subscribing to the three
//                             topics, one callback per decoded message.
//   v37 UNIFIES both behind ONE seam (IMonerodTransport) so a single mock backs
//   the whole adapter, and DROPS p2pool's host-failover list / TLS SPKI pinning
//   (operational, not consensus; the engine supplies its own).
// ===========================================================================
#pragma once

#include "xmr_node_types.hpp"

#include <deque>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace c2pool::xmr::node {

// --- RPC response envelope ---------------------------------------------------
struct RpcResponse {
    std::vector<char> body;    // raw response bytes (JSON)
    std::string       error;   // non-empty on transport failure (no HTTP 2xx)
    double            ping_ms = 0.0;
    bool ok() const noexcept { return error.empty(); }
};

// --- one decoded ZMQ frame (topic + payload) --------------------------------
// monerod --zmq-pub sends "<topic>:<json-payload>"; the transport splits on the
// first ':' and hands the JSON payload here. Topic is one of ZMQ_TOPIC_*.
struct ZmqFrame {
    std::string       topic;
    std::vector<char> payload;  // JSON bytes after the "topic:" prefix
};

// ===========================================================================
// IMonerodTransport -- the single I/O seam the whole node leg is written against.
// ===========================================================================
class IMonerodTransport {
public:
    virtual ~IMonerodTransport() = default;

    // POST a complete JSON-RPC 2.0 request body to monerod's /json_rpc (or a
    // direct /<method> endpoint for the non-json_rpc calls). Result is delivered
    // to `on_done` (async in production; may be synchronous in the mock).
    virtual void rpc_post(const std::string& json_body,
                          std::function<void(const RpcResponse&)> on_done) = 0;

    // Subscribe to one monerod --zmq-pub topic. Each decoded frame is delivered
    // to `on_frame`. Multiple subscriptions to distinct topics are expected
    // (chain_main / miner_data / txpool_add). Idempotent per topic.
    virtual void zmq_subscribe(const std::string& topic,
                               std::function<void(const ZmqFrame&)> on_frame) = 0;
};

// ===========================================================================
// MockMonerodTransport -- deterministic, in-process, no sockets. Tests:
//   * set an rpc responder (by method name, or a catch-all) to return canned
//     JSON bodies -- so the RPC parse layer runs end-to-end;
//   * push ZMQ frames on demand -- so the decode + index layers run end-to-end;
//   * inspect every RPC body that was posted (last_bodies()).
// ===========================================================================
class MockMonerodTransport final : public IMonerodTransport {
public:
    // Responder invoked for each rpc_post. Return the JSON body monerod would
    // send. `method` is extracted from the request body ("method":"<name>") for
    // convenience; the full request body is also passed.
    using Responder = std::function<RpcResponse(const std::string& method,
                                                const std::string& request_body)>;

    void set_responder(Responder r) { responder_ = std::move(r); }

    // Register a canned success body for a specific JSON-RPC method.
    void set_method_body(const std::string& method, std::string json_body) {
        method_bodies_[method] = std::move(json_body);
    }

    // Force the next N rpc_post calls to fail at the transport level.
    void fail_next(int n, std::string err = "transport: connection refused") {
        fail_remaining_ = n; fail_err_ = std::move(err);
    }

    void rpc_post(const std::string& json_body,
                  std::function<void(const RpcResponse&)> on_done) override {
        posted_.push_back(json_body);
        RpcResponse resp;
        if (fail_remaining_ > 0) {
            --fail_remaining_;
            resp.error = fail_err_;
            on_done(resp);
            return;
        }
        const std::string method = extract_method(json_body);
        if (auto it = method_bodies_.find(method); it != method_bodies_.end()) {
            resp.body.assign(it->second.begin(), it->second.end());
            resp.ping_ms = 0.1;
            on_done(resp);
            return;
        }
        if (responder_) {
            resp = responder_(method, json_body);
            on_done(resp);
            return;
        }
        resp.error = "mock: no responder / no canned body for method '" + method + "'";
        on_done(resp);
    }

    void zmq_subscribe(const std::string& topic,
                       std::function<void(const ZmqFrame&)> on_frame) override {
        subs_[topic].push_back(std::move(on_frame));
    }

    // Test driver: deliver a JSON payload on `topic` to every subscriber.
    void push_zmq(const std::string& topic, const std::string& json_payload) {
        auto it = subs_.find(topic);
        if (it == subs_.end()) return;
        ZmqFrame f;
        f.topic = topic;
        f.payload.assign(json_payload.begin(), json_payload.end());
        for (auto& cb : it->second) cb(f);
    }

    const std::vector<std::string>& posted_bodies() const noexcept { return posted_; }
    bool subscribed(const std::string& topic) const { return subs_.count(topic) != 0; }

    // Extract the "method" string field from a JSON-RPC request body (mock-only).
    static std::string extract_method(const std::string& body) {
        const std::string key = "\"method\"";
        auto p = body.find(key);
        if (p == std::string::npos) return {};
        p = body.find(':', p + key.size());
        if (p == std::string::npos) return {};
        p = body.find('"', p);
        if (p == std::string::npos) return {};
        auto q = body.find('"', p + 1);
        if (q == std::string::npos) return {};
        return body.substr(p + 1, q - p - 1);
    }

private:
    Responder responder_;
    std::unordered_map<std::string, std::string> method_bodies_;
    std::unordered_map<std::string, std::vector<std::function<void(const ZmqFrame&)>>> subs_;
    std::vector<std::string> posted_;
    int fail_remaining_ = 0;
    std::string fail_err_;
};

} // namespace c2pool::xmr::node
