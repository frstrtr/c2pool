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
// LiveMonerodTransport through the public rpc_post() against a loopback
// stand-in daemon, and its chunked decoder (detail::dechunk_chunked) directly.
//   LT1  chunk_past_end      : a chunk length past the end of the body is an
//        error; no byte after the valid chunks is returned.
//   LT2  valid_chunks        : an ordinary chunked body decodes unchanged.
//   LT3  strict_chunk_size   : a size field with a sign, a space, a "0x"
//        prefix or an extension, or a missing CRLF after the chunk data, is
//        refused; upper- and lower-case hex sizes decode.
//   LT4  partial_then_silent : a reply that stops arriving before it is
//        complete is an error at the call deadline, not a truncated body.
//   LT5  call_deadline       : a reply that keeps arriving past the call
//        deadline is an error at the deadline.
// Nonzero exit on any failure.
// ===========================================================================
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <functional>
#include <string>
#include <thread>

#include "c2pool/v37/xmr/xmr_live_transport.hpp"

namespace xn = ::c2pool::xmr::node;
namespace v37n = ::c2pool::v37n::xmr;
using Clock = std::chrono::steady_clock;

namespace {

// A one-shot loopback server: binds 127.0.0.1:0, accepts one connection, reads
// the request headers, runs `script` on the connection, closes.
struct StandinHttp {
    int listen_fd = -1;
    std::uint16_t port_ = 0;
    std::function<void(int)> script;
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
            std::string req;
            char buf[4096];
            while (req.find("\r\n\r\n") == std::string::npos) {
                const ssize_t n = ::recv(fd, buf, sizeof buf, 0);
                if (n <= 0) break;
                req.append(buf, static_cast<std::size_t>(n));
            }
            script(fd);
            ::close(fd);
        });
    }
    void join() { if (th.joinable()) th.join(); if (listen_fd >= 0) ::close(listen_fd); }
};

void write_all(int fd, const std::string& s) {
    std::size_t off = 0;
    while (off < s.size()) {
        const ssize_t n = ::send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL);
        if (n <= 0) return;
        off += static_cast<std::size_t>(n);
    }
}

const std::string kChunkedHead = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
const std::string kPlainHead   = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";

struct Result { std::string body, error; long long ms = 0; };

// One rpc_post() against a stand-in that runs `script` after reading the request.
Result post(std::function<void(int)> script, std::uint32_t deadline_ms = v37n::kLiveCallDeadlineMs) {
    Result res;
    StandinHttp s;
    if (!s.bind_listen()) { res.error = "stand-in bind failed"; return res; }
    s.script = std::move(script);
    s.serve();
    xn::DaemonEndpoint ep; ep.rpc_host = "127.0.0.1"; ep.rpc_port = s.port_;
    v37n::LiveMonerodTransport t(ep, deadline_ms);
    const auto t0 = Clock::now();
    t.rpc_post(R"({"jsonrpc":"2.0","id":"0","method":"get_miner_data"})", [&](const xn::RpcResponse& r) {
        res.body.assign(r.body.begin(), r.body.end());
        res.error = r.error;
    });
    res.ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
    s.join();
    return res;
}

bool dechunk(const std::string& in, std::string& out) { return v37n::detail::dechunk_chunked(in, out); }

} // namespace

int main() {
    int fails = 0;
    auto check = [&](const char* name, bool ok, const std::string& d = {}) {
        if (!ok) ++fails;
        std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name, d.empty() ? "" : "  -- ", d.c_str());
        std::fflush(stdout);
    };
    std::printf("== v37_xmr_live_transport_bounds_kat ==\n");

    // ── LT1 chunk_past_end ──────────────────────────────────────────────────
    {
        // A valid 5-byte chunk, then a chunk whose size is SIZE_MAX-1.
        const Result r = post([](int fd) { write_all(fd, kChunkedHead + "5\r\nHELLO\r\nfffffffffffffffe\r\nZZ"); });
        check("LT1 a chunk length past the end of the body is an error", !r.error.empty(), "error='" + r.error + "'");
        check("LT1 no byte after the valid chunks is returned", r.body.find("ZZ") == std::string::npos,
              "body='" + r.body + "'");
    }

    // ── LT2 valid_chunks ────────────────────────────────────────────────────
    {
        const Result r = post([](int fd) { write_all(fd, kChunkedHead + "5\r\nHELLO\r\n6\r\n WORLD\r\n0\r\n\r\n"); });
        check("LT2 an ordinary chunked body decodes unchanged", r.error.empty() && r.body == "HELLO WORLD",
              "error='" + r.error + "' body='" + r.body + "'");
    }

    // ── LT3 strict_chunk_size ───────────────────────────────────────────────
    {
        std::string out;
        check("LT3 '+5' refused", !dechunk("+5\r\nHELLO\r\n0\r\n\r\n", out));
        check("LT3 ' 5' refused", !dechunk(" 5\r\nHELLO\r\n0\r\n\r\n", out));
        check("LT3 '0x5' refused", !dechunk("0x5\r\nHELLO\r\n0\r\n\r\n", out));
        check("LT3 '5;ext=1' refused", !dechunk("5;ext=1\r\nHELLO\r\n0\r\n\r\n", out));
        check("LT3 '-1' refused", !dechunk("-1\r\nHELLO\r\n0\r\n\r\n", out));
        check("LT3 empty size field refused", !dechunk("\r\nHELLO\r\n0\r\n\r\n", out));
        check("LT3 missing CRLF after the chunk data refused", !dechunk("5\r\nHELLOXX0\r\n\r\n", out));
        check("LT3 body without the last chunk refused", !dechunk("5\r\nHELLO\r\n", out));
        const bool ok = dechunk("a\r\n0123456789\r\nB\r\nABCDEFGHIJK\r\n0\r\n\r\n", out);
        check("LT3 upper- and lower-case hex sizes decode", ok && out == "0123456789ABCDEFGHIJK", "out='" + out + "'");
        const Result r = post([](int fd) { write_all(fd, kChunkedHead + "+5\r\nHELLO\r\n0\r\n\r\n"); });
        check("LT3 rpc_post reports a refused chunk size as an error", !r.error.empty(), "error='" + r.error + "'");
    }

    // ── LT4 partial_then_silent ─────────────────────────────────────────────
    {
        const Result r = post([](int fd) {
            write_all(fd, kPlainHead + R"({"id":"0","jsonrpc":"2.0","result":{"blob":"abcd)");
            std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        }, 300);
        check("LT4 a reply that stops before it is complete is an error", !r.error.empty(),
              "error='" + r.error + "' body='" + r.body + "'");
        check("LT4 ... returned at the call deadline", r.ms < 1200, "elapsed=" + std::to_string(r.ms) + " ms");
    }

    // ── LT5 call_deadline ───────────────────────────────────────────────────
    {
        const Result r = post([](int fd) {
            write_all(fd, kPlainHead);
            for (int i = 0; i < 20; ++i) {
                write_all(fd, "x");
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }, 300);
        check("LT5 a reply still arriving at the call deadline is an error", !r.error.empty(),
              "error='" + r.error + "'");
        check("LT5 ... returned at the call deadline", r.ms < 1200, "elapsed=" + std::to_string(r.ms) + " ms");
    }

    std::printf("%s: %d failures\n", fails ? "FAILED" : "OK", fails);
    return fails ? 1 : 0;
}
