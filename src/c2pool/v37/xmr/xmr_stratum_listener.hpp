// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_stratum_listener.hpp   (Track A2 / X9 O-2 — wire 1)
//
// STRATUM LISTENER — the host / TCP layer that the X5 stratum front-end
// (impl/xmr/stratum/xmr_stratum.hpp, PR #1507) deliberately left to the host:
// it BINDS the XMR stratum port, ACCEPTS RandomX miners (xmrig), newline-frames
// and tokenises their CryptoNote/xmrig JSON dialect, and DRIVES the merged
// XmrStratumServer (login / job / submit). It IS the server's ITransport seam.
//
// What it owns:
//   * one POSIX poll() event loop on ONE background thread ("the listener
//     thread"): listen fd + a self-pipe wake fd + every client fd;
//   * one XmrStratumSession per connection (the X5 4-deep job ring);
//   * the XmrStratumServer itself, constructed over the three X5 seams the
//     assembler passes in (ITemplateSource / IPowVerifier / IShareSink) and
//     over `*this` as the transport;
//   * per-client read/write buffers (non-blocking sockets; a slow reader is
//     buffered up to max_write_backlog, then dropped — never blocks the loop).
//
// What it delivers:
//   * RandomX WORK: the first job in the login reply (X5 handle_login) and a
//     `job` push to EVERY logged-in session whenever the main loop signals a
//     new template via notify_new_template() — the NEW-TEMPLATE PUSH that X5's
//     broadcast_job() existed for but nothing called. Before the push it runs
//     the assembler's TemplateHook on the listener thread with a peek of the
//     new template, which is where the RandomX seed epoch gets prefetched (so
//     the ~seconds Argon2d cache init never lands inside a miner's submit and
//     the verifier — not thread-safe — is only ever touched from this thread).
//   * SHARES: every "submit" is handed to XmrStratumServer::handle_submit,
//     which rebuilds the blob, re-hashes it with the IPowVerifier, and calls
//     the assembler's IShareSink (on_accepted_share / submit_network_block) —
//     ON THE LISTENER THREAD. The sink must do its own submit and hand results
//     to the main thread through a queue (nothing here touches XmrNode).
//   * OBSERVABILITY: counters (stats()) and a bounded log the main loop drains
//     (drain_log()) — the listener never prints; all stdout stays on main.
//
// Startup race handled: a miner that logs in BEFORE the daemon has its first
// template is PARKED (no reply) and answered with a real login_ok the moment
// notify_new_template() delivers one (bounded by parked_login_ttl_ms, then it
// gets "No job available" and xmrig's own retry takes over).
//
// THREADING CONTRACT (see the O-2 survey §E):
//   listener thread: sockets, sessions, XmrStratumServer, ITemplateSource reads
//                    (get_job/rebuild_blob — the source must be safe for a
//                    concurrent reader), IPowVerifier, IShareSink callbacks.
//   any thread:      notify_new_template(), request_stop(), stats(),
//                    drain_log(), bound_port().
//   main thread:     bind(), start(), stop() (joins), destructor.
//
// CONSUMER-TREE ONLY: defines no consensus digest; calls only the merged X5
// front-end. Linux/POSIX sockets (the daemon is Linux-only; CI = ubuntu).
// ===========================================================================
#pragma once

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include "impl/xmr/node/minijson.hpp"          // xmrig JSON tokeniser (header-only)
#include "impl/xmr/stratum/xmr_stratum.hpp"    // X5 seams + XmrStratumServer

namespace c2pool::v37n::xmr::o2 {

namespace strat = ::v37::xmr::stratum;
namespace mj    = ::c2pool::xmr::node::minijson;

// ---------------------------------------------------------------------------
// Tunables. Defaults suit a single-rig regtest/stagenet demo.
// ---------------------------------------------------------------------------
struct StratumListenerOptions {
    std::string   bind_host = "127.0.0.1";   // cfg.stratum_bind_host (dotted quad or resolvable name)
    std::uint16_t bind_port = 3333;          // cfg.stratum_bind_port (0 = ephemeral; see bound_port())
    int           backlog = 16;
    std::size_t   max_clients = 256;         // beyond this, accept() + close immediately
    std::size_t   max_line_bytes = 64 * 1024;      // one JSON request line
    std::size_t   max_write_backlog = 1u << 20;    // pending bytes per slow client before drop
    int           poll_timeout_ms = 250;     // idle tick (parked-login expiry granularity)
    int           parked_login_ttl_ms = 15000;     // xmrig's login response timeout is 20 s
    int           max_json_depth = 8;        // login/submit are depth-3 objects; guards the recursive parser
    std::size_t   max_log_lines = 2048;      // bounded log (oldest dropped)
};

// Point-in-time counters (all monotone since start(), except `active`).
struct StratumListenerStats {
    std::uint64_t connections = 0;       // accepted
    std::uint64_t active = 0;            // open right now
    std::uint64_t closed = 0;            // closed for any reason (peer or server)
    std::uint64_t logins = 0;            // successful (session logged in)
    std::uint64_t parked_logins = 0;     // logins that waited for the first template
    std::uint64_t submits = 0;           // "submit" requests seen
    std::uint64_t accepted_shares = 0;   // IShareSink::on_accepted_share calls
    std::uint64_t network_blocks = 0;    // IShareSink::submit_network_block calls
    std::uint64_t rejected_submits = 0;  // submit answered with an error (stale/low-diff/…)
    std::uint64_t job_pushes = 0;        // `job` notifications pushed (broadcast)
    std::uint64_t template_signals = 0;  // notify_new_template() calls
    std::uint64_t malformed = 0;         // unparseable / too-deep request lines
};

// ---------------------------------------------------------------------------
// StratumListener
// ---------------------------------------------------------------------------
class StratumListener final : public strat::ITransport {
public:
    // Runs on the listener thread, BEFORE jobs are pushed, with a peek of the
    // current template (extra_nonce 0). Use it to prefetch the RandomX seed
    // epoch: verifier.prefetch(peek.seed_hash, peek.next_seed_hash).
    using TemplateHook = std::function<void(const strat::TemplateJob& peek)>;

    StratumListener(strat::ITemplateSource& templates,
                    strat::IPowVerifier& verifier,
                    strat::IShareSink& sink,
                    StratumListenerOptions opts = {})
        : m_opts(std::move(opts)),
          m_templates(templates),
          m_tap(*this, sink),
          m_server(templates, verifier, m_tap, *this) {}

    ~StratumListener() override { stop(); }

    StratumListener(const StratumListener&) = delete;
    StratumListener& operator=(const StratumListener&) = delete;

    // Install the seed-prefetch hook. Call before start().
    void set_template_hook(TemplateHook h) { m_hook = std::move(h); }

    // Create the wake pipe, resolve + bind + listen. Returns "" on success,
    // else a human-readable reason (port busy, bad host, …). Does NOT spawn
    // the thread — so a bind failure is reported synchronously to main.
    std::string bind() {
        if (m_listen_fd >= 0) return "";
        if (m_wake[0] < 0) {
            int p[2];
            if (::pipe(p) != 0)
                return std::string("stratum: pipe() failed: ") + std::strerror(errno);
            set_nonblock_cloexec(p[0]);
            set_nonblock_cloexec(p[1]);
            m_wake[0] = p[0];
            m_wake[1] = p[1];
        }
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port   = ::htons(m_opts.bind_port);
        if (!resolve_ipv4(m_opts.bind_host, a.sin_addr))
            return "stratum: cannot resolve bind host '" + m_opts.bind_host + "'";

        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return std::string("stratum: socket() failed: ") + std::strerror(errno);
        int on = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) {
            std::string e = "stratum: bind " + m_opts.bind_host + ":" +
                            std::to_string(m_opts.bind_port) + " failed: " + std::strerror(errno);
            ::close(fd);
            return e;
        }
        if (::listen(fd, m_opts.backlog) < 0) {
            std::string e = std::string("stratum: listen() failed: ") + std::strerror(errno);
            ::close(fd);
            return e;
        }
        set_nonblock_cloexec(fd);
        sockaddr_in got{};
        socklen_t gl = sizeof(got);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&got), &gl) == 0)
            m_bound_port.store(::ntohs(got.sin_port), std::memory_order_release);
        else
            m_bound_port.store(m_opts.bind_port, std::memory_order_release);
        m_listen_fd = fd;
        log("listening on " + m_opts.bind_host + ":" + std::to_string(bound_port()));
        return "";
    }

    // Spawn the listener thread. Requires a successful bind(). False if not
    // bound or already running.
    bool start() {
        if (m_listen_fd < 0 || m_thread.joinable()) return false;
        m_stop.store(false, std::memory_order_release);
        m_running.store(true, std::memory_order_release);
        m_thread = std::thread([this] {
            loop();
            m_running.store(false, std::memory_order_release);
        });
        return true;
    }

    // Ask the loop to exit (non-blocking; any thread).
    void request_stop() {
        m_stop.store(true, std::memory_order_release);
        wake();
    }

    // Stop + join, then close every socket. Safe to call repeatedly and when
    // never started. Call BEFORE XmrNode::stop() (donor order: network first).
    void stop() {
        request_stop();
        if (m_thread.joinable()) m_thread.join();
        // Single-threaded from here.
        for (auto& [cid, c] : m_clients) {
            (void)cid;
            if (c.fd >= 0) ::close(c.fd);
            c.fd = -1;
        }
        m_clients.clear();
        m_stats.active.store(0, std::memory_order_relaxed);
        if (m_listen_fd >= 0) { ::close(m_listen_fd); m_listen_fd = -1; }
        if (m_wake[0] >= 0)   { ::close(m_wake[0]);   m_wake[0] = -1; }
        if (m_wake[1] >= 0)   { ::close(m_wake[1]);   m_wake[1] = -1; }
    }

    bool running() const { return m_running.load(std::memory_order_acquire); }

    // The port actually bound (differs from options only when 0 was asked for).
    std::uint16_t bound_port() const { return m_bound_port.load(std::memory_order_acquire); }
    const StratumListenerOptions& options() const { return m_opts; }

    // NEW-TEMPLATE PUSH (any thread; the main loop calls this whenever the
    // template source's template_id changed). On the listener thread this
    // runs: peek template -> TemplateHook (seed prefetch) -> answer parked
    // logins -> broadcast_job() to every already-logged-in session.
    void notify_new_template() {
        m_stats.template_signals.fetch_add(1, std::memory_order_relaxed);
        m_template_dirty.store(true, std::memory_order_release);
        wake();
    }

    StratumListenerStats stats() const {
        StratumListenerStats s;
        s.connections      = m_stats.connections.load(std::memory_order_relaxed);
        s.active           = m_stats.active.load(std::memory_order_relaxed);
        s.closed           = m_stats.closed.load(std::memory_order_relaxed);
        s.logins           = m_stats.logins.load(std::memory_order_relaxed);
        s.parked_logins    = m_stats.parked_logins.load(std::memory_order_relaxed);
        s.submits          = m_stats.submits.load(std::memory_order_relaxed);
        s.accepted_shares  = m_stats.accepted_shares.load(std::memory_order_relaxed);
        s.network_blocks   = m_stats.network_blocks.load(std::memory_order_relaxed);
        s.rejected_submits = m_stats.rejected_submits.load(std::memory_order_relaxed);
        s.job_pushes       = m_stats.job_pushes.load(std::memory_order_relaxed);
        s.template_signals = m_stats.template_signals.load(std::memory_order_relaxed);
        s.malformed        = m_stats.malformed.load(std::memory_order_relaxed);
        return s;
    }

    // Take every pending log line (oldest first). Any thread. The main loop
    // prints these (prefix them as it likes); the listener itself never prints.
    std::vector<std::string> drain_log() {
        std::vector<std::string> out;
        std::lock_guard<std::mutex> lk(m_log_mtx);
        out.assign(m_log.begin(), m_log.end());
        m_log.clear();
        return out;
    }

    // ── ITransport (called by XmrStratumServer on the listener thread) ─────
    bool send_line(std::uint64_t client_id, std::string_view line) override {
        Client* c = live(client_id);
        if (!c) return false;
        classify_reply(*c, line);
        if (c->wbuf.empty()) {
            // Fast path: write straight to the socket; buffer only the rest.
            for (;;) {
                const ssize_t n = ::send(c->fd, line.data(), line.size(), MSG_NOSIGNAL);
                if (n >= 0) {
                    line.remove_prefix(static_cast<std::size_t>(n));
                    break;
                }
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                close_client(client_id, std::string("send failed: ") + std::strerror(errno));
                return false;
            }
            if (line.empty()) return true;
        }
        if (c->wbuf.size() + line.size() > m_opts.max_write_backlog) {
            close_client(client_id, "write backlog exceeded (slow reader)");
            return false;
        }
        c->wbuf.append(line.data(), line.size());
        return true;
    }

    void close(std::uint64_t client_id) override {
        close_client(client_id, "closed by server");
    }

private:
    // ── per-connection state ───────────────────────────────────────────────
    struct ParkedLogin {
        std::uint32_t req_id = 0;
        std::string   login;
        std::string   agent;
        std::chrono::steady_clock::time_point since;
    };

    struct Client {
        int         fd = -1;
        bool        dead = false;          // fd closed; erased by reap() after the current pass
        std::string peer;                  // "ip:port" for the log
        std::string rbuf;                  // unframed inbound bytes
        std::string wbuf;                  // unsent outbound bytes (slow reader)
        std::optional<ParkedLogin> parked; // login waiting for the first template
        std::unique_ptr<strat::XmrStratumSession> session;
        bool        last_reply_error = false;
        std::string last_reply_msg;
    };

    struct AtomicStats {
        std::atomic<std::uint64_t> connections{0}, active{0}, closed{0}, logins{0},
            parked_logins{0}, submits{0}, accepted_shares{0}, network_blocks{0},
            rejected_submits{0}, job_pushes{0}, template_signals{0}, malformed{0};
    };

    // Forwarding IShareSink: counts + logs, then hands everything to the
    // assembler's sink unchanged (same thread, same order as X5 calls them:
    // submit_network_block BEFORE on_accepted_share).
    class SinkTap final : public strat::IShareSink {
    public:
        SinkTap(StratumListener& owner, strat::IShareSink& inner)
            : m_owner(owner), m_inner(inner) {}
        void on_accepted_share(const strat::AcceptedShare& s) override {
            m_owner.m_stats.accepted_shares.fetch_add(1, std::memory_order_relaxed);
            m_owner.log("share ACCEPTED height=" + std::to_string(s.height) +
                        " template=" + std::to_string(s.template_id) +
                        " nonce=" + hex_u32(s.nonce) +
                        " worker='" + s.worker + "'" +
                        (s.is_network_block ? " NETWORK-BLOCK" : ""));
            m_inner.on_accepted_share(s);
        }
        void submit_network_block(std::uint32_t template_id, std::uint32_t nonce,
                                  std::uint32_t extra_nonce) override {
            m_owner.m_stats.network_blocks.fetch_add(1, std::memory_order_relaxed);
            m_owner.log("NETWORK BLOCK candidate: template=" + std::to_string(template_id) +
                        " nonce=" + hex_u32(nonce) + " extra_nonce=" + std::to_string(extra_nonce) +
                        " -> sink.submit_network_block");
            m_inner.submit_network_block(template_id, nonce, extra_nonce);
        }
    private:
        StratumListener&  m_owner;
        strat::IShareSink& m_inner;
    };

    // ── small helpers ──────────────────────────────────────────────────────
    static void set_nonblock_cloexec(int fd) {
        int fl = ::fcntl(fd, F_GETFL, 0);
        if (fl >= 0) ::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        int fd_fl = ::fcntl(fd, F_GETFD, 0);
        if (fd_fl >= 0) ::fcntl(fd, F_SETFD, fd_fl | FD_CLOEXEC);
    }

    static bool resolve_ipv4(const std::string& host, in_addr& out) {
        if (host.empty()) { out.s_addr = ::htonl(INADDR_LOOPBACK); return true; }
        if (::inet_pton(AF_INET, host.c_str(), &out) == 1) return true;
        addrinfo hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return false;
        bool ok = false;
        for (addrinfo* p = res; p; p = p->ai_next) {
            if (p->ai_family == AF_INET && p->ai_addrlen >= sizeof(sockaddr_in)) {
                out = reinterpret_cast<sockaddr_in*>(p->ai_addr)->sin_addr;
                ok = true;
                break;
            }
        }
        ::freeaddrinfo(res);
        return ok;
    }

    static std::string peer_string(const sockaddr_in& sa) {
        char buf[INET_ADDRSTRLEN] = {0};
        if (!::inet_ntop(AF_INET, &sa.sin_addr, buf, sizeof(buf))) return "?";
        return std::string(buf) + ":" + std::to_string(::ntohs(sa.sin_port));
    }

    static std::string hex_u32(std::uint32_t v) {
        char b[16];
        std::snprintf(b, sizeof(b), "0x%08x", static_cast<unsigned>(v));
        return b;
    }

    // Request id: xmrig sends a JSON number; tolerate a numeric string.
    static std::uint32_t req_id_of(const mj::Value& v) {
        if (v.is_number()) return v.as_u32();
        if (v.is_string()) return static_cast<std::uint32_t>(std::strtoul(v.text.c_str(), nullptr, 10));
        return 0;
    }

    // Reject pathologically nested input before it reaches the recursive
    // minijson parser (which is KAT-grade, not adversarial-hardened).
    static bool depth_ok(std::string_view s, int max_depth) {
        int depth = 0;
        bool in_str = false, esc = false;
        for (char c : s) {
            if (in_str) {
                if (esc) esc = false;
                else if (c == '\\') esc = true;
                else if (c == '"') in_str = false;
                continue;
            }
            if (c == '"') in_str = true;
            else if (c == '{' || c == '[') { if (++depth > max_depth) return false; }
            else if (c == '}' || c == ']') { if (depth > 0) --depth; }
        }
        return true;
    }

    // Remember whether the line we are about to send is a dialect error reply
    // ({"id":N,"jsonrpc":"2.0","error":{"message":"…"}}) so a submit can be
    // logged as rejected without wrapping the server.
    static void classify_reply(Client& c, std::string_view line) {
        static constexpr std::string_view kErr = "\"error\":{";
        static constexpr std::string_view kMsg = "\"message\":\"";
        const std::size_t e = line.find(kErr);
        c.last_reply_error = (e != std::string_view::npos);
        c.last_reply_msg.clear();
        if (!c.last_reply_error) return;
        const std::size_t m = line.find(kMsg, e);
        if (m == std::string_view::npos) return;
        const std::size_t b = m + kMsg.size();
        const std::size_t q = line.find('"', b);
        c.last_reply_msg.assign(line.substr(b, q == std::string_view::npos ? std::string_view::npos : q - b));
    }

    void log(std::string line) {
        std::lock_guard<std::mutex> lk(m_log_mtx);
        if (m_log.size() >= m_opts.max_log_lines) m_log.pop_front();
        m_log.push_back(std::move(line));
    }

    void wake() {
        const int fd = m_wake[1];
        if (fd < 0) return;
        const char b = 1;
        (void)!::write(fd, &b, 1);   // EAGAIN == a wake is already pending; fine
    }

    void drain_wake() {
        char buf[64];
        while (::read(m_wake[0], buf, sizeof(buf)) > 0) {}
    }

    Client* live(std::uint64_t cid) {
        auto it = m_clients.find(cid);
        if (it == m_clients.end() || it->second.dead || it->second.fd < 0) return nullptr;
        return &it->second;
    }

    // Deferred close: shut the fd now, erase the entry in reap() so callers
    // iterating m_clients (broadcast, expiry) never see an invalidated iterator.
    void close_client(std::uint64_t cid, const std::string& why) {
        auto it = m_clients.find(cid);
        if (it == m_clients.end() || it->second.dead) return;
        Client& c = it->second;
        if (c.fd >= 0) { ::close(c.fd); c.fd = -1; }
        c.dead = true;
        c.parked.reset();
        m_stats.active.fetch_sub(1, std::memory_order_relaxed);
        m_stats.closed.fetch_add(1, std::memory_order_relaxed);
        log("client " + std::to_string(cid) + " (" + c.peer + ") closed: " + why);
    }

    void reap() {
        for (auto it = m_clients.begin(); it != m_clients.end();) {
            if (it->second.dead) it = m_clients.erase(it);
            else ++it;
        }
    }

    // ── the event loop (listener thread) ───────────────────────────────────
    void loop() {
        std::vector<pollfd> pfds;
        std::vector<std::uint64_t> ids;
        while (!m_stop.load(std::memory_order_acquire)) {
            if (m_template_dirty.exchange(false, std::memory_order_acq_rel))
                on_template_changed();

            pfds.clear();
            ids.clear();
            pfds.push_back(pollfd{m_listen_fd, POLLIN, 0});
            pfds.push_back(pollfd{m_wake[0], POLLIN, 0});
            for (auto& [cid, c] : m_clients) {
                if (c.dead || c.fd < 0) continue;
                short ev = POLLIN;
                if (!c.wbuf.empty()) ev |= POLLOUT;
                pfds.push_back(pollfd{c.fd, ev, 0});
                ids.push_back(cid);
            }

            const int rc = ::poll(pfds.data(), pfds.size(), m_opts.poll_timeout_ms);
            if (rc < 0) {
                if (errno == EINTR) continue;
                log(std::string("poll() failed, listener exiting: ") + std::strerror(errno));
                break;
            }
            if (rc > 0) {
                if (pfds[1].revents & POLLIN) drain_wake();
                if (pfds[0].revents & POLLIN) do_accept();
                for (std::size_t i = 2; i < pfds.size(); ++i) {
                    const short re = pfds[i].revents;
                    if (!re) continue;
                    const std::uint64_t cid = ids[i - 2];
                    if (re & POLLOUT) flush(cid);
                    if (re & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) do_read(cid);
                }
            }
            expire_parked();
            reap();
        }
    }

    void do_accept() {
        for (;;) {
            sockaddr_in sa{};
            socklen_t sl = sizeof(sa);
            const int fd = ::accept(m_listen_fd, reinterpret_cast<sockaddr*>(&sa), &sl);
            if (fd < 0) {
                if (errno == EINTR) continue;
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    log(std::string("accept() failed: ") + std::strerror(errno));
                break;
            }
            set_nonblock_cloexec(fd);
            int one = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            const std::string peer = peer_string(sa);
            if (m_stats.active.load(std::memory_order_relaxed) >= m_opts.max_clients) {
                log("refused " + peer + ": client cap (" + std::to_string(m_opts.max_clients) + ")");
                ::close(fd);
                continue;
            }
            const std::uint64_t cid = ++m_next_cid;
            Client c;
            c.fd = fd;
            c.peer = peer;
            c.session = std::make_unique<strat::XmrStratumSession>(cid);
            m_clients.emplace(cid, std::move(c));
            m_stats.connections.fetch_add(1, std::memory_order_relaxed);
            m_stats.active.fetch_add(1, std::memory_order_relaxed);
            log("client " + std::to_string(cid) + " connected from " + peer);
        }
    }

    void flush(std::uint64_t cid) {
        Client* c = live(cid);
        if (!c || c->wbuf.empty()) return;
        for (;;) {
            const ssize_t n = ::send(c->fd, c->wbuf.data(), c->wbuf.size(), MSG_NOSIGNAL);
            if (n >= 0) { c->wbuf.erase(0, static_cast<std::size_t>(n)); return; }
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            close_client(cid, std::string("send failed: ") + std::strerror(errno));
            return;
        }
    }

    void do_read(std::uint64_t cid) {
        Client* c = live(cid);
        if (!c) return;
        char buf[8192];
        for (;;) {
            const ssize_t n = ::recv(c->fd, buf, sizeof(buf), 0);
            if (n > 0) {
                c->rbuf.append(buf, static_cast<std::size_t>(n));
                if (c->rbuf.size() > 4 * m_opts.max_line_bytes) {
                    close_client(cid, "inbound backlog too large");
                    return;
                }
                continue;
            }
            if (n == 0) { close_client(cid, "peer closed"); return; }
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            close_client(cid, std::string("recv failed: ") + std::strerror(errno));
            return;
        }
        // Drain complete newline-framed requests.
        for (;;) {
            c = live(cid);
            if (!c) return;                          // dispatch closed us
            const std::size_t nl = c->rbuf.find('\n');
            if (nl == std::string::npos) {
                if (c->rbuf.size() > m_opts.max_line_bytes)
                    close_client(cid, "request line too long");
                break;
            }
            std::string line = c->rbuf.substr(0, nl);
            c->rbuf.erase(0, nl + 1);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            dispatch(cid, line);
        }
    }

    // ── the xmrig dialect → X5 server ─────────────────────────────────────
    void dispatch(std::uint64_t cid, const std::string& line) {
        Client* c = live(cid);
        if (!c) return;
        if (!depth_ok(line, m_opts.max_json_depth)) {
            m_stats.malformed.fetch_add(1, std::memory_order_relaxed);
            close_client(cid, "request nested too deep");
            return;
        }
        mj::Value req;
        if (!mj::parse(line, req) || !req.is_object()) {
            m_stats.malformed.fetch_add(1, std::memory_order_relaxed);
            send_line(cid, strat::StratumDialect::build_error(0, "Malformed request"));
            close_client(cid, "malformed JSON");
            return;
        }
        const std::uint32_t req_id = req_id_of(req["id"]);
        const std::string   method = req["method"].as_string();
        const mj::Value&    params = req["params"];
        strat::XmrStratumSession& s = *c->session;

        if (method == "login") {
            const std::string login = params["login"].as_string();
            const std::string agent = params["agent"].as_string();
            if (s.logged_in()) { close_client(cid, "duplicate login"); return; }   // p2pool semantics
            if (c->parked)     { close_client(cid, "login while a login is pending"); return; }
            if (login.empty()) {
                send_line(cid, strat::StratumDialect::build_error(req_id, "Missing login"));
                close_client(cid, "empty login");
                return;
            }
            strat::TemplateJob peek;
            if (!m_templates.get_job(0, peek)) {
                // No template yet: park, answer when notify_new_template() lands.
                c->parked = ParkedLogin{req_id, login, agent, std::chrono::steady_clock::now()};
                m_stats.parked_logins.fetch_add(1, std::memory_order_relaxed);
                log("client " + std::to_string(cid) + " login PARKED (no template yet) agent='" +
                    agent + "'");
                return;
            }
            do_login(cid, req_id, login, agent);
            return;
        }

        if (method == "submit") {
            m_stats.submits.fetch_add(1, std::memory_order_relaxed);
            if (!s.logged_in()) {
                send_line(cid, strat::StratumDialect::build_error(req_id, "Unauthenticated"));
                return;
            }
            strat::SubmitFields f;
            f.rpc_id = params["id"].as_string();
            f.job_id = params["job_id"].as_string();
            f.nonce  = params["nonce"].as_string();
            f.result = params["result"].as_string();
            c->last_reply_error = false;
            c->last_reply_msg.clear();
            if (!m_server.handle_submit(s, req_id, f)) {
                close_client(cid, "submit rejected at parse level (malformed fields)");
                return;
            }
            c = live(cid);
            if (c && c->last_reply_error) {
                m_stats.rejected_submits.fetch_add(1, std::memory_order_relaxed);
                log("client " + std::to_string(cid) + " submit REJECTED: " + c->last_reply_msg +
                    " (job_id=" + f.job_id + " nonce=" + f.nonce + ")");
            }
            return;
        }

        if (method == "keepalived") {
            send_line(cid, strat::StratumDialect::build_status_ok(req_id));
            return;
        }

        if (method == "getjob") {
            // Legacy CryptoNote-stratum request: acknowledge, then push a job.
            if (!s.logged_in()) {
                send_line(cid, strat::StratumDialect::build_error(req_id, "Unauthenticated"));
                return;
            }
            send_line(cid, strat::StratumDialect::build_status_ok(req_id));
            m_server.broadcast_job(s);
            m_stats.job_pushes.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        send_line(cid, strat::StratumDialect::build_error(req_id, "Unknown method"));
    }

    void do_login(std::uint64_t cid, std::uint32_t req_id, const std::string& login,
                  const std::string& agent) {
        Client* c = live(cid);
        if (!c) return;
        strat::XmrStratumSession& s = *c->session;
        if (!m_server.handle_login(s, req_id, login)) {
            close_client(cid, "login refused by server");
            return;
        }
        if (s.logged_in()) {
            m_stats.logins.fetch_add(1, std::memory_order_relaxed);
            const strat::LoginString& ls = s.login();
            log("client " + std::to_string(cid) + " LOGIN OK address=" + ls.address +
                " worker='" + ls.worker + "'" +
                (ls.custom_diff ? " custom_diff=" + std::to_string(*ls.custom_diff) : "") +
                " agent='" + agent + "' -> first job sent");
        } else {
            // Race: template vanished between the peek and handle_login; the
            // server already answered "No job available" and xmrig will retry.
            log("client " + std::to_string(cid) + " login answered 'No job available'");
        }
    }

    // Answer every parked login now that a template exists.
    void flush_parked() {
        std::vector<std::tuple<std::uint64_t, std::uint32_t, std::string, std::string>> todo;
        for (auto& [cid, c] : m_clients) {
            if (c.dead || !c.parked) continue;
            todo.emplace_back(cid, c.parked->req_id, c.parked->login, c.parked->agent);
            c.parked.reset();
        }
        for (auto& [cid, rid, login, agent] : todo) do_login(cid, rid, login, agent);
    }

    void expire_parked() {
        const auto now = std::chrono::steady_clock::now();
        const auto ttl = std::chrono::milliseconds(m_opts.parked_login_ttl_ms);
        for (auto& [cid, c] : m_clients) {
            if (c.dead || !c.parked) continue;
            if (now - c.parked->since < ttl) continue;
            const std::uint32_t rid = c.parked->req_id;
            c.parked.reset();
            send_line(cid, strat::StratumDialect::build_error(rid, "No job available"));
            log("client " + std::to_string(cid) + " parked login EXPIRED (no template within " +
                std::to_string(m_opts.parked_login_ttl_ms) + " ms)");
        }
    }

    // The NEW-TEMPLATE PUSH, on the listener thread.
    void on_template_changed() {
        strat::TemplateJob peek;
        if (!m_templates.get_job(0, peek)) {
            log("template signal received but the template source has no job");
            return;
        }
        if (m_hook) m_hook(peek);   // seed prefetch (may take seconds; miners idle meanwhile)

        // Sessions already logged in get a `job` push; parked logins get their
        // login_ok (which carries the new job) — never both.
        std::vector<std::uint64_t> already;
        for (auto& [cid, c] : m_clients)
            if (!c.dead && c.session && c.session->logged_in()) already.push_back(cid);

        flush_parked();

        std::size_t pushed = 0;
        for (std::uint64_t cid : already) {
            Client* c = live(cid);
            if (!c) continue;
            m_server.broadcast_job(*c->session);
            ++pushed;
        }
        m_stats.job_pushes.fetch_add(pushed, std::memory_order_relaxed);
        log("template " + std::to_string(peek.template_id) + " height=" + std::to_string(peek.height) +
            " -> job pushed to " + std::to_string(pushed) + " session(s)");
    }

    // ── members (declaration order == construction order; m_tap before m_server)
    StratumListenerOptions   m_opts;
    strat::ITemplateSource&  m_templates;
    SinkTap                  m_tap;
    strat::XmrStratumServer  m_server;
    TemplateHook             m_hook;

    int                      m_listen_fd = -1;
    int                      m_wake[2] = {-1, -1};
    std::atomic<std::uint16_t> m_bound_port{0};
    std::atomic<bool>        m_stop{false};
    std::atomic<bool>        m_running{false};
    std::atomic<bool>        m_template_dirty{false};
    std::thread              m_thread;

    std::map<std::uint64_t, Client> m_clients;   // listener thread only
    std::uint64_t            m_next_cid = 0;

    AtomicStats              m_stats;
    mutable std::mutex       m_log_mtx;
    std::deque<std::string>  m_log;
};

} // namespace c2pool::v37n::xmr::o2
