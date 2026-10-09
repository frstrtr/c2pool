// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_live_transport_bounds_kat.cpp
//
// LiveMonerodTransport's chunked-transfer decoder, driven through the public
// rpc_post() against a loopback stand-in daemon. The stand-in answers with a
// Transfer-Encoding: chunked body whose second chunk declares a length near
// SIZE_MAX; a decoder that tests "p + len > size" wraps past the guard and
// folds trailing bytes into the result, while "len > size - p" refuses the
// chunk and stops at the valid prefix.
//   LT1  chunk_size_wrap : the decoded body is exactly the valid prefix.
//   LT2  valid_chunks     : an ordinary chunked body decodes unchanged.
// Nonzero exit on any failure.
// ===========================================================================
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

#include "c2pool/v37/xmr/xmr_live_transport.hpp"

namespace xn = ::c2pool::xmr::node;
namespace v37n = ::c2pool::v37n::xmr;

namespace {

// A one-shot loopback server: binds 127.0.0.1:0, accepts one connection, reads
// the request, writes `response`, closes. port() is valid before run().
struct StandinHttp {
    int listen_fd = -1;
    std::uint16_t port_ = 0;
    std::string response;
    std::thread th;

    bool bind_listen() {
        listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) return false;
        int one = 1; ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
        if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) return false;
        if (::listen(listen_fd, 1) != 0) return false;
        socklen_t sl = sizeof a;
        if (::getsockname(listen_fd, reinterpret_cast<sockaddr*>(&a), &sl) != 0) return false;
        port_ = ntohs(a.sin_port);
        return true;
    }
    void serve() {
        th = std::thread([this] {
            const int fd = ::accept(listen_fd, nullptr, nullptr);
            if (fd < 0) return;
            char buf[4096];
            (void)!::recv(fd, buf, sizeof buf, 0);   // drain the request line(s)
            (void)!::write(fd, response.data(), response.size());
            ::close(fd);
        });
    }
    void join() { if (th.joinable()) th.join(); if (listen_fd >= 0) ::close(listen_fd); }
};

std::string chunked_response(const std::string& chunk_body) {
    return "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + chunk_body;
}

std::string body_of(const xn::RpcResponse& r) { return std::string(r.body.begin(), r.body.end()); }

} // namespace

int main() {
    int fails = 0;
    auto check = [&](const char* name, bool ok, const std::string& d = {}) {
        if (!ok) ++fails;
        std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name, d.empty() ? "" : "  -- ", d.c_str());
        std::fflush(stdout);
    };
    std::printf("== v37_xmr_live_transport_bounds_kat ==\n");

    const std::string rpc = R"({"jsonrpc":"2.0","id":"0","method":"get_miner_data"})";

    // ── LT1 chunk_size_wrap ─────────────────────────────────────────────────
    {
        // A valid 5-byte chunk, then a chunk whose size is SIZE_MAX-1.
        const std::string body = "5\r\nHELLO\r\nfffffffffffffffe\r\nZZ";
        StandinHttp s; check("LT1 server binds", s.bind_listen());
        s.response = chunked_response(body);
        s.serve();
        xn::DaemonEndpoint ep; ep.rpc_host = "127.0.0.1"; ep.rpc_port = s.port_;
        v37n::LiveMonerodTransport t(ep);
        std::string got; bool called = false;
        t.rpc_post(rpc, [&](const xn::RpcResponse& r) { got = body_of(r); called = called || r.error.empty(); });
        s.join();
        check("LT1 wrapping chunk decodes to just the valid prefix", got == "HELLO", "body='" + got + "'");
    }

    // ── LT2 valid_chunks ────────────────────────────────────────────────────
    {
        const std::string body = "5\r\nHELLO\r\n6\r\n WORLD\r\n0\r\n\r\n";
        StandinHttp s; check("LT2 server binds", s.bind_listen());
        s.response = chunked_response(body);
        s.serve();
        xn::DaemonEndpoint ep; ep.rpc_host = "127.0.0.1"; ep.rpc_port = s.port_;
        v37n::LiveMonerodTransport t(ep);
        std::string got;
        t.rpc_post(rpc, [&](const xn::RpcResponse& r) { got = body_of(r); });
        s.join();
        check("LT2 an ordinary chunked body decodes unchanged", got == "HELLO WORLD", "body='" + got + "'");
    }

    std::printf("%s: %d failures\n", fails ? "FAILED" : "OK", fails);
    return fails ? 1 : 0;
}
