// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/node/xmr_monerod_http.hpp
//
// The PARITY ARM's transport, and nothing else's.
//
// WHAT IT IS FOR. C6's MonerodTipObserver and C4's MonerodMinerDataSource both
// take a `node::IMonerodTransport`. The native node needs one for exactly two
// jobs, and both of them are OFF the tip-follow path by construction:
//
//   * the parity oracle's monerod arm -- the judge the native chain is measured
//     against while the daemon is still armed (plan M0..M4);
//   * the monerod template arm, when one is configured.
//
// It is NEVER reached by anything that follows the chain. The node's levin path
// -- peer pool, chain index, txpool -- includes this header nowhere, and the
// status line reports `rpc_calls` beside `blocks_in` so that "the tip moved
// without an RPC" is a pair of numbers rather than a claim.
//
// WHY NOT REUSE c2pool/v37/xmr/xmr_live_transport.hpp, which already does this.
// Because that file lives in the CONSUMER tree and this one lives in the
// component tree: `src/impl/xmr/**` is included by `src/c2pool/**` and must not
// include it back. A transport is ~150 lines of POSIX sockets; an inverted
// dependency is a layering rule that stops being true. The two are deliberately
// not shared and neither is the "production" one -- the pool proper keeps using
// the consumer-tree transport it always did.
//
// DELIBERATELY SMALL. Blocking HTTP/1.1 POST, no keep-alive, no TLS, no digest
// auth (a login string is refused loudly rather than sent in the clear), no
// chunked-transfer support beyond what monerod actually emits (it sends
// Content-Length for JSON-RPC). `zmq_subscribe` is a refusal, not a stub: the
// native node takes its tip from levin, so a ZMQ subscriber here would be a
// second source of truth for the one fact this whole track exists to own.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/.
//
// Header-only, POSIX. STL plus <sys/socket.h>.
// ---------------------------------------------------------------------------
#pragma once

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "impl/xmr/node/monerod_transport.hpp"

namespace c2pool::xmr::native::rt {

class MonerodHttp final : public ::c2pool::xmr::node::IMonerodTransport {
public:
    using RpcResponse = ::c2pool::xmr::node::RpcResponse;
    using ZmqFrame    = ::c2pool::xmr::node::ZmqFrame;

    MonerodHttp(std::string host, std::uint16_t port, std::uint32_t timeout_ms = 5000)
        : host_(std::move(host)), port_(port), timeout_ms_(timeout_ms) {}

    std::uint64_t calls()    const noexcept { return calls_.load(); }
    std::uint64_t failures() const noexcept { return failures_.load(); }
    std::string   endpoint() const { return host_ + ":" + std::to_string(port_); }

    void rpc_post(const std::string& json_body,
                  std::function<void(const RpcResponse&)> on_done) override {
        RpcResponse resp;
        ++calls_;
        const std::string method = extract_method_(json_body);
        const std::string path   = json_rpc_method_(method) ? "/json_rpc" : ("/" + method);
        std::string body;
        const std::string err = post_(path, json_body, body);
        if (!err.empty()) {
            ++failures_;
            resp.error = err;
            on_done(resp);
            return;
        }
        resp.body.assign(body.begin(), body.end());
        on_done(resp);
    }

    // See the banner: the native node's tip comes from levin, and a second live
    // source of the same fact is a bug waiting for a disagreement.
    void zmq_subscribe(const std::string&, std::function<void(const ZmqFrame&)>) override {}

private:
    static bool json_rpc_method_(const std::string& m) {
        // The handful of monerod endpoints that are NOT under /json_rpc.
        return !(m == "get_transactions" || m == "get_transaction_pool" ||
                 m == "send_raw_transaction" || m == "get_o_indexes" ||
                 m == "get_outs" || m == "is_key_image_spent" || m == "get_height" ||
                 m == "get_peer_list" || m == "start_mining" || m == "stop_mining");
    }

    // The method name out of a JSON-RPC body, without a JSON parser: the bodies
    // are ours, one line each, and pulling in a parser to read back what we just
    // wrote would be the wrong kind of thorough.
    static std::string extract_method_(const std::string& body) {
        const std::string key = "\"method\"";
        const std::size_t k = body.find(key);
        if (k == std::string::npos) return {};
        std::size_t i = body.find(':', k + key.size());
        if (i == std::string::npos) return {};
        i = body.find('"', i);
        if (i == std::string::npos) return {};
        const std::size_t j = body.find('"', i + 1);
        if (j == std::string::npos) return {};
        return body.substr(i + 1, j - i - 1);
    }

    std::string post_(const std::string& path, const std::string& body, std::string& out) {
        out.clear();

        addrinfo hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        const std::string port_s = std::to_string(port_);
        if (::getaddrinfo(host_.c_str(), port_s.c_str(), &hints, &res) != 0 || !res)
            return "resolve failed for " + endpoint();

        const int fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0) { ::freeaddrinfo(res); return "socket() failed"; }

        timeval tv{};
        tv.tv_sec  = static_cast<time_t>(timeout_ms_ / 1000);
        tv.tv_usec = static_cast<suseconds_t>((timeout_ms_ % 1000) * 1000);
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        int one = 1;
        ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        if (::connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
            ::freeaddrinfo(res);
            ::close(fd);
            return "connect failed to " + endpoint();
        }
        ::freeaddrinfo(res);

        std::string req = "POST " + path + " HTTP/1.1\r\nHost: " + host_ + ":" + port_s +
                          "\r\nContent-Type: application/json\r\nConnection: close"
                          "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
        std::size_t sent = 0;
        while (sent < req.size()) {
            const ssize_t n = ::send(fd, req.data() + sent, req.size() - sent, 0);
            if (n <= 0) { ::close(fd); return "send failed"; }
            sent += static_cast<std::size_t>(n);
        }

        std::string raw;
        char        buf[8192];
        for (;;) {
            const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n < 0) { ::close(fd); return "recv failed/timed out"; }
            if (n == 0) break;
            raw.append(buf, static_cast<std::size_t>(n));
            if (raw.size() > 64u * 1024 * 1024) { ::close(fd); return "response too large"; }
        }
        ::close(fd);

        const std::size_t hdr_end = raw.find("\r\n\r\n");
        if (hdr_end == std::string::npos) return "malformed HTTP response";
        out = raw.substr(hdr_end + 4);
        if (raw.compare(0, 9, "HTTP/1.1 ") == 0 && raw.compare(9, 3, "200") != 0)
            return "HTTP " + raw.substr(9, 3);
        return {};
    }

    std::string                host_;
    std::uint16_t              port_;
    std::uint32_t              timeout_ms_;
    std::atomic<std::uint64_t> calls_{0};
    std::atomic<std::uint64_t> failures_{0};
};

} // namespace c2pool::xmr::native::rt
