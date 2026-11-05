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
//
// IT COUNTS ITSELF, AND THAT IS NOT BOOKKEEPING. The native-template milestone
// makes a claim about RPC traffic -- "the template path made no daemon call" --
// and prints a number beside it. The number it used to print came from the
// embedded node's OWN transport (impl/xmr/native/node/xmr_monerod_http.hpp) and
// counted only the parity and submit round trips. This transport is a second,
// independent socket to the same daemon, and in the no-libzmq build its
// pump_poll() issues a get_miner_data on a timer for the whole life of the
// process -- an order of magnitude more requests than the headline reported.
//
// An auditor with tcpdump would therefore have seen ten times the traffic the
// status line claimed, and the true claim (zero of them are on the TEMPLATE
// path) would have been buried under an apparent discrepancy that looked like a
// lie. So every POST through this transport is counted, split by what drove it,
// and the status line adds the two transports together and shows the split. The
// headline number is now the one an auditor can reconcile at the wire.
// ===========================================================================
#pragma once

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "impl/xmr/node/monerod_transport.hpp"
#include "impl/xmr/node/xmr_node_types.hpp"

namespace c2pool::v37n::xmr {

// Node-local caps for the blocking monerod client. kLiveMaxResponseBytes and
// kLiveSocketTimeoutMs equal the parity-arm transport's (xmr_monerod_http.hpp).
// kLiveCallDeadlineMs bounds one whole request: connect + send + receive.
inline constexpr std::size_t   kLiveMaxResponseBytes = 64u * 1024u * 1024u;
inline constexpr std::uint32_t kLiveSocketTimeoutMs  = 5000;
inline constexpr std::uint32_t kLiveCallDeadlineMs   = kLiveSocketTimeoutMs;
inline constexpr std::size_t   kLiveMaxChunks        = 1u << 20;

namespace detail {

// One chunk-size field, in[b, e): hex digits only (no sign, space, "0x" or
// chunk extension), value at most SIZE_MAX. Returns false otherwise.
inline bool parse_chunk_size(const std::string& in, std::size_t b, std::size_t e, std::size_t& len) {
    if (b >= e) return false;
    std::size_t v = 0;
    for (std::size_t i = b; i < e; ++i) {
        const char h = in[i];
        unsigned d;
        if (h >= '0' && h <= '9')      d = static_cast<unsigned>(h - '0');
        else if (h >= 'a' && h <= 'f') d = static_cast<unsigned>(h - 'a' + 10);
        else if (h >= 'A' && h <= 'F') d = static_cast<unsigned>(h - 'A' + 10);
        else return false;
        if (v > (SIZE_MAX >> 4)) return false;
        v = (v << 4) | d;
    }
    len = v;
    return true;
}

// De-chunk an HTTP/1.1 Transfer-Encoding: chunked body into `out`. Returns
// true when the zero-length last chunk is reached. Returns false on a size
// field that parse_chunk_size refuses, a chunk length past the end of the
// input, a chunk not followed by CRLF, input that ends before the last chunk,
// or more than max_chunks chunks; `out` then holds the chunks decoded so far.
inline bool dechunk_chunked(const std::string& in, std::string& out,
                            std::size_t max_chunks = kLiveMaxChunks) {
    out.clear();
    std::size_t p = 0, chunks = 0;
    for (;;) {
        const std::size_t nl = in.find("\r\n", p);
        if (nl == std::string::npos) return false;
        std::size_t len = 0;
        if (!parse_chunk_size(in, p, nl, len)) return false;
        p = nl + 2;
        if (len == 0) return true;
        if (len > in.size() - p) return false;
        out.append(in, p, len);
        p += len;
        if (in.size() - p < 2 || in.compare(p, 2, "\r\n") != 0) return false;
        p += 2;
        if (++chunks > max_chunks) return false;
    }
}

} // namespace detail

class LiveMonerodTransport final : public c2pool::xmr::node::IMonerodTransport {
public:
    using RpcResponse = c2pool::xmr::node::RpcResponse;
    using ZmqFrame    = c2pool::xmr::node::ZmqFrame;

    explicit LiveMonerodTransport(c2pool::xmr::node::DaemonEndpoint ep,
                                  std::uint32_t call_deadline_ms = kLiveCallDeadlineMs)
        : ep_(std::move(ep)), call_deadline_ms_(call_deadline_ms) {}

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
        ++poll_calls_;   // counted here, not in http_post, so the split is by DRIVER
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

    // --- the wire counters (see the header note) -----------------------------
    // Every HTTP POST this transport puts on the socket, whatever drove it.
    std::uint64_t rpc_calls()      const noexcept { return calls_.load(); }
    // ...of which: the ZMQ-substitute tip poll, which is the bulk of them in a
    // build without libzmq and is on nobody's template path.
    std::uint64_t tip_poll_calls() const noexcept { return poll_calls_.load(); }
    // ...and everything else the pool asked for: submit_block, the adapter's own
    // reads, sendrawtransaction.
    std::uint64_t other_calls()    const noexcept {
        const std::uint64_t a = calls_.load(), p = poll_calls_.load();
        return a > p ? (a - p) : 0;
    }
    std::uint64_t rpc_failures()   const noexcept { return failures_.load(); }

private:
    static bool json_rpc_method(const std::string& m) {
        // The direct (non-json_rpc) monerod endpoints the adapter may use.
        return !(m == "submitblock" || m == "sendrawtransaction" || m == "get_info");
    }

    // Minimal blocking HTTP/1.1 POST. Returns "" on success (body in out), else
    // an error string. Connects, sends, reads until the socket closes / content
    // length is met, strips the header, returns the body.
    std::string http_post(const std::string& path, const std::string& body, std::string& out) {
        ++calls_;
        const std::string err = http_post_(path, body, out);
        if (!err.empty()) ++failures_;
        return err;
    }

    std::string http_post_(const std::string& path, const std::string& body, std::string& out) {
        out.clear();
        const Clock::time_point deadline = Clock::now() + std::chrono::milliseconds(call_deadline_ms_);
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
        // Non-blocking socket for the whole request: every wait is a poll()
        // bounded by min(time to the deadline, kLiveSocketTimeoutMs).
        if (connect_until(fd, a, deadline) != 0) {
            ::close(fd);
            return "live-transport: connect " + ep_.rpc_host + ":" + std::to_string(ep_.rpc_port) +
                   " failed (is monerod running with restricted RPC on this port?)";
        }
        std::string req = "POST " + path + " HTTP/1.1\r\n"
                          "Host: " + ep_.rpc_host + "\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: " + std::to_string(body.size()) + "\r\n"
                          "Connection: close\r\n\r\n" + body;
        if (send_until(fd, req, deadline) != 0) { ::close(fd); return "live-transport: send failed/timed out"; }
        std::string raw;
        char buf[4096];
        for (;;) {
            if (wait_io(fd, POLLIN, deadline) <= 0) { ::close(fd); return "live-transport: recv failed/timed out"; }
            const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n == 0) break;                                   // reply complete (Connection: close)
            if (n < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                ::close(fd);
                return "live-transport: recv failed/timed out";
            }
            raw.append(buf, static_cast<std::size_t>(n));
            if (raw.size() > kLiveMaxResponseBytes) { ::close(fd); return "live-transport: response too large"; }
        }
        ::close(fd);
        auto hdr_end = raw.find("\r\n\r\n");
        if (hdr_end == std::string::npos) return "live-transport: malformed HTTP response";
        std::string head = raw.substr(0, hdr_end);
        std::string content = raw.substr(hdr_end + 4);
        if (head.find(" 200") == std::string::npos)
            return "live-transport: monerod HTTP status: " + head.substr(0, head.find("\r\n"));
        // De-chunk if Transfer-Encoding: chunked (monerod restricted RPC uses it).
        if (head.find("chunked") != std::string::npos) {
            std::string decoded;
            if (!detail::dechunk_chunked(content, decoded)) return "live-transport: malformed chunked body";
            content = std::move(decoded);
        }
        out = std::move(content);
        return "";
    }

    using Clock = std::chrono::steady_clock;

    // Waits for `events` on fd until the deadline, each poll() at most
    // kLiveSocketTimeoutMs. Returns 1 when ready, 0 at the deadline or on a
    // poll() timeout, -1 on a poll() error.
    static int wait_io(int fd, short events, Clock::time_point deadline) {
        for (;;) {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
            if (left <= 0) return 0;
            const int ms = static_cast<int>(left < static_cast<long long>(kLiveSocketTimeoutMs) ? left : kLiveSocketTimeoutMs);
            pollfd pfd{fd, events, 0};
            const int r = ::poll(&pfd, 1, ms);
            if (r < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
            return r == 0 ? 0 : 1;
        }
    }

    // Non-blocking connect completed within the deadline. 0 on success.
    static int connect_until(int fd, const sockaddr_in& a, Clock::time_point deadline) {
        const int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags < 0) return -1;
        if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
        if (::connect(fd, reinterpret_cast<const sockaddr*>(&a), sizeof(a)) == 0) return 0;
        if (errno != EINPROGRESS) return -1;
        if (wait_io(fd, POLLOUT, deadline) <= 0) return -1;
        int err = 0; socklen_t el = sizeof(err);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) return -1;
        return 0;
    }

    // All of `s` written within the deadline. 0 on success.
    static int send_until(int fd, const std::string& s, Clock::time_point deadline) {
#if defined(MSG_NOSIGNAL)
        constexpr int kSendFlags = MSG_NOSIGNAL;
#else
        constexpr int kSendFlags = 0;
#endif
        std::size_t off = 0;
        while (off < s.size()) {
            if (wait_io(fd, POLLOUT, deadline) <= 0) return -1;
            const ssize_t n = ::send(fd, s.data() + off, s.size() - off, kSendFlags);
            if (n < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                return -1;
            }
            if (n == 0) return -1;
            off += static_cast<std::size_t>(n);
        }
        return 0;
    }

    c2pool::xmr::node::DaemonEndpoint ep_;
    std::uint32_t call_deadline_ms_ = kLiveCallDeadlineMs;
    std::unordered_map<std::string, std::vector<std::function<void(const ZmqFrame&)>>> subs_;
    // Atomic because the found-block submitter posts from its own thread while
    // the node loop is pumping; the counters are read on the status cadence.
    std::atomic<std::uint64_t> calls_{0};
    std::atomic<std::uint64_t> poll_calls_{0};
    std::atomic<std::uint64_t> failures_{0};
#if defined(XMR_NODE_HAVE_ZMQ)
    void open_zmq_sub(const std::string& topic);   // real SUB socket; separate TU
#endif
};

} // namespace c2pool::v37n::xmr
