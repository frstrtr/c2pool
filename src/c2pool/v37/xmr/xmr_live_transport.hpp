// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_live_transport.hpp   (Track A2 / Milestone A — X2 I/O)
//
// The PRODUCTION IMonerodTransport the merged X2 adapter is written against.
// The X2 leg (monero_rpc / monero_zmq / MonerodAdapter) is transport-agnostic
// and, in-tree, only MockMonerodTransport backs it — the note in
// impl/xmr/node/monerod_transport.hpp defers the live backend to "X5/engine
// work". This is that live backend, kept dependency-light so a fresh master
// build can talk to a real stagenet monerod:
//
//   * rpc_post()  — a self-contained blocking HTTP/1.1 JSON POST to monerod's
//                   /json_rpc (and /<method> direct endpoints) over a raw POSIX
//                   socket. NO libcurl / boost::beast dependency. Digest auth
//                   (--rpc-login) is NOT implemented here (stagenet is run
//                   unrestricted / no-login for the demo); a login string is
//                   rejected loudly rather than sent in cleartext.
//   * zmq_subscribe() — TWO modes:
//       (a) XMR_NODE_HAVE_ZMQ defined: a real libzmq SUB socket (the monerod
//           --zmq-pub feed). Requires cppzmq at build time.
//       (b) default (no libzmq): a POLL FALLBACK — the transport periodically
//           re-issues get_miner_data over RPC and synthesises a json-full-
//           miner_data frame for the ZMQ_TOPIC_MINER_DATA subscriber, so the
//           MainchainIndex still tracks the tip + seed reach from RPC alone.
//           (chain_main annotation + txpool deltas are skipped in this mode;
//           the tip/seed/backlog the miner needs all ride on miner_data.)
//
// SINGLE-THREAD/BLOCKING: this is the single-node demo transport. rpc_post
// blocks and invokes on_done synchronously, which matches how the merged
// MonerodAdapter drives it (it posts and consumes the callback inline). The poll
// pump is driven by the XmrNode's own loop calling pump_poll() on a timer.
// ===========================================================================
#pragma once

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "impl/xmr/node/monerod_transport.hpp"
#include "impl/xmr/node/xmr_node_types.hpp"

namespace c2pool::v37n::xmr {

class LiveMonerodTransport final : public c2pool::xmr::node::IMonerodTransport {
public:
    using RpcResponse = c2pool::xmr::node::RpcResponse;
    using ZmqFrame    = c2pool::xmr::node::ZmqFrame;

    explicit LiveMonerodTransport(c2pool::xmr::node::DaemonEndpoint ep)
        : ep_(std::move(ep)) {}

    // Blocking HTTP/1.1 POST to monerod. `json_body` carries "method"; json_rpc
    // methods go to /json_rpc, the few direct endpoints to /<method>. on_done is
    // invoked synchronously with the raw response body (or an error).
    void rpc_post(const std::string& json_body,
                  std::function<void(const RpcResponse&)> on_done) override {
        RpcResponse resp;
        if (!ep_.rpc_login.empty()) {
            resp.error = "live-transport: --rpc-login (digest auth) not supported; "
                         "run stagenet monerod unrestricted for the demo";
            on_done(resp);
            return;
        }
        const std::string method = c2pool::xmr::node::MockMonerodTransport::extract_method(json_body);
        const std::string path = json_rpc_method(method) ? "/json_rpc" : ("/" + method);
        std::string body;
        std::string err = http_post(path, json_body, body);
        if (!err.empty()) { resp.error = std::move(err); on_done(resp); return; }
        resp.body.assign(body.begin(), body.end());
        on_done(resp);
    }

    // Register a subscriber. With libzmq it would open a SUB socket; without it,
    // the miner_data subscriber is served by the RPC poll pump (pump_poll()).
    void zmq_subscribe(const std::string& topic,
                       std::function<void(const ZmqFrame&)> on_frame) override {
        subs_[topic].push_back(std::move(on_frame));
#if defined(XMR_NODE_HAVE_ZMQ)
        open_zmq_sub(topic);   // real SUB socket (cppzmq); defined in the .cpp guard
#endif
    }

    // POLL FALLBACK pump: called by the node loop on a timer. Re-fetches
    // get_miner_data over RPC and pushes a synthesized json-full-miner_data
    // frame to the ZMQ_TOPIC_MINER_DATA subscribers. No-op under XMR_NODE_HAVE_ZMQ.
    void pump_poll() {
#if !defined(XMR_NODE_HAVE_ZMQ)
        auto it = subs_.find(c2pool::xmr::node::ZMQ_TOPIC_MINER_DATA);
        if (it == subs_.end()) return;
        std::string body;
        std::string rpc = R"({"jsonrpc":"2.0","id":"0","method":"get_miner_data"})";
        if (!http_post("/json_rpc", rpc, body).empty()) return;
        ZmqFrame f;
        f.topic = c2pool::xmr::node::ZMQ_TOPIC_MINER_DATA;
        // monerod's get_miner_data returns {result:{...}}; the merged
        // monero_zmq decoder accepts the same field shape as the ZMQ payload, so
        // we forward the JSON result object. (Both are parsed by minijson.)
        f.payload.assign(body.begin(), body.end());
        for (auto& cb : it->second) cb(f);
#endif
    }

    const c2pool::xmr::node::DaemonEndpoint& endpoint() const { return ep_; }

private:
    static bool json_rpc_method(const std::string& m) {
        // The direct (non-json_rpc) monerod endpoints the adapter may use.
        return !(m == "submitblock" || m == "sendrawtransaction" || m == "get_info");
    }

    // Minimal blocking HTTP/1.1 POST. Returns "" on success (body in out), else
    // an error string. Connects, sends, reads until the socket closes / content
    // length is met, strips the header, returns the body.
    std::string http_post(const std::string& path, const std::string& body, std::string& out) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return "live-transport: socket() failed";
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = ::htons(ep_.rpc_port);
        if (::inet_pton(AF_INET, ep_.rpc_host.c_str(), &a.sin_addr) != 1) {
            // resolve a hostname
            addrinfo hints{}, *res = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (::getaddrinfo(ep_.rpc_host.c_str(), nullptr, &hints, &res) != 0 || !res) {
                ::close(fd);
                return "live-transport: cannot resolve " + ep_.rpc_host;
            }
            a.sin_addr = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
            ::freeaddrinfo(res);
        }
        if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) {
            ::close(fd);
            return "live-transport: connect " + ep_.rpc_host + ":" + std::to_string(ep_.rpc_port) +
                   " failed (is monerod running with restricted RPC on this port?)";
        }
        std::string req = "POST " + path + " HTTP/1.1\r\n"
                          "Host: " + ep_.rpc_host + "\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: " + std::to_string(body.size()) + "\r\n"
                          "Connection: close\r\n\r\n" + body;
        if (send_all(fd, req) != 0) { ::close(fd); return "live-transport: send failed"; }
        std::string raw;
        char buf[4096];
        for (;;) {
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            raw.append(buf, static_cast<std::size_t>(n));
        }
        ::close(fd);
        auto hdr_end = raw.find("\r\n\r\n");
        if (hdr_end == std::string::npos) return "live-transport: malformed HTTP response";
        std::string head = raw.substr(0, hdr_end);
        std::string payload = raw.substr(hdr_end + 4);
        if (head.find(" 200") == std::string::npos)
            return "live-transport: monerod HTTP status: " + head.substr(0, head.find("\r\n"));
        // De-chunk if Transfer-Encoding: chunked (monerod restricted RPC uses it).
        if (head.find("chunked") != std::string::npos) payload = dechunk(payload);
        out = std::move(payload);
        return "";
    }

    static int send_all(int fd, const std::string& s) {
        std::size_t off = 0;
        while (off < s.size()) {
            ssize_t n = ::send(fd, s.data() + off, s.size() - off, 0);
            if (n <= 0) return -1;
            off += static_cast<std::size_t>(n);
        }
        return 0;
    }
    static std::string dechunk(const std::string& in) {
        std::string out;
        std::size_t p = 0;
        while (p < in.size()) {
            std::size_t nl = in.find("\r\n", p);
            if (nl == std::string::npos) break;
            std::size_t len = std::strtoul(in.substr(p, nl - p).c_str(), nullptr, 16);
            if (len == 0) break;
            p = nl + 2;
            if (p + len > in.size()) break;
            out.append(in, p, len);
            p += len + 2;
        }
        return out;
    }

    c2pool::xmr::node::DaemonEndpoint ep_;
    std::unordered_map<std::string, std::vector<std::function<void(const ZmqFrame&)>>> subs_;
#if defined(XMR_NODE_HAVE_ZMQ)
    void open_zmq_sub(const std::string& topic);   // real SUB socket; separate TU
#endif
};

} // namespace c2pool::v37n::xmr
