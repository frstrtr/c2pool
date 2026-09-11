// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/p2pool_observer.hpp
//
// THE OBSERVER: a handful of outbound TCP connections to real P2Pool peers,
// driven by one poll() loop, feeding the read model.
//
// ---------------------------------------------------------------------------
// WHY IT PULLS INSTEAD OF LISTENING
// ---------------------------------------------------------------------------
// The natural way to watch a gossip network is to be gossiped at. Doing that on
// P2Pool costs one message -- LISTEN_PORT -- and that message is exactly the
// one this observer will not send, because it is what puts an address into
// every peer's list and onward into the network's own directory. So the
// observer pulls: it asks each peer for its tip with BLOCK_REQUEST, notices
// when the answer is a block it has not seen, and walks parents backwards to
// fill the gap. Nothing it sends can add, replace or advertise anything.
//
// That choice has a timing consequence which has to be got right, and the rule
// comes straight out of upstream's own idle logic (P2PServer::update_peer_list
// and the connection sweep in p2p_server.cpp):
//
//   * A peer disconnects a handshaken connection that has sent NOTHING for 300
//     seconds. Polling satisfies this easily.
//   * A peer BANS a connection that has not broadcast a block in 900 seconds --
//     but only when `cur_time >= max(last_sidechain_update, last_block_request)
//     + 10`. A peer that is requesting blocks reads as syncing, not as silent,
//     and is exempt. So the tip poll must stay UNDER ten seconds.
//
// kTipPollSeconds is therefore 5, and the comment above is the reason it is not
// a tunable knob. A 30-second poll would look harmless in review, work fine for
// a quarter of an hour, and then get the observer banned by every peer at once.
//
// ---------------------------------------------------------------------------
// FIFO REPLY MATCHING
// ---------------------------------------------------------------------------
// BLOCK_RESPONSE carries no request id -- the same shape of problem as levin in
// the native lane, and the same answer: replies arrive in request order, so
// each session keeps a deque of the ids it asked for and pops the front on each
// response. A response with an empty deque is a protocol violation and closes
// the connection rather than being absorbed.
//
// ---------------------------------------------------------------------------
// WHAT IT NEVER DOES
// ---------------------------------------------------------------------------
// It never accepts an inbound connection (there is no listening socket in this
// file, and no bind() anywhere in the tree). It never answers a peer's
// BLOCK_REQUEST -- there is no encoder that could. It never announces a port,
// never broadcasts, never submits. `OutboundLedger` counts every byte it does
// send, bucketed by control message, and the tool prints the buckets so that
// the claim is auditable from a run rather than from a comment.
//
// POSIX sockets, no asio, no threads: one blocking-free poll() loop. That is
// deliberate -- this is a telemetry harness, and keeping it dependency-free
// keeps it honest about what observing actually requires.
// ---------------------------------------------------------------------------
#pragma once

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/consensus/xmr_block_id.hpp"
#include "impl/xmr/p2pool/p2pool_block.hpp"
#include "impl/xmr/p2pool/p2pool_consensus.hpp"
#include "impl/xmr/p2pool/p2pool_handshake.hpp"
#include "impl/xmr/p2pool/p2pool_read_model.hpp"
#include "impl/xmr/p2pool/p2pool_wire.hpp"

namespace c2pool::xmr::p2pool {

inline std::uint64_t now_ms() {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
            duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

// Every byte this process puts on a P2Pool socket, bucketed. Four buckets, one
// per ControlMessage; there is no fifth because there is no fifth encoder.
struct OutboundLedger {
    std::uint64_t messages[kControlMessageCount] = {0, 0, 0, 0};
    std::uint64_t bytes[kControlMessageCount]    = {0, 0, 0, 0};

    void record(ControlMessage c, std::size_t n) {
        const std::size_t i = static_cast<std::size_t>(c);
        if (i < kControlMessageCount) { ++messages[i]; bytes[i] += n; }
    }
    std::uint64_t total_bytes() const {
        std::uint64_t t = 0;
        for (std::size_t i = 0; i < kControlMessageCount; ++i) t += bytes[i];
        return t;
    }
    std::string to_string() const {
        return std::string("challenge=") + std::to_string(messages[0])
             + " solution="    + std::to_string(messages[1])
             + " block_req="   + std::to_string(messages[2])
             + " peerlist_req="+ std::to_string(messages[3])
             + " bytes="       + std::to_string(total_bytes());
    }
};

struct ObserverConfig {
    Sidechain     chain            = Sidechain::Mini;
    std::size_t   max_peers        = 4;
    std::uint64_t tip_poll_ms      = 5000;    // see the header note: MUST be < 10 s
    std::uint64_t peer_list_ms     = 90000;   // upstream rate-limits to 60 s
    std::uint64_t connect_timeout_ms = 15000;
    std::size_t   backfill_budget  = 64;      // parent walks per session
    std::size_t   max_inflight     = 4;       // block requests outstanding per peer
    std::uint64_t run_ms           = 300000;
    std::uint64_t seed             = 0;       // 0 => clock-seeded
    bool          verbose          = false;
    // Directory to write any blob that failed to parse. A parser that cannot
    // be shown its own counter-example is a parser nobody can fix, and these
    // bytes came off a live network that will not reproduce them on request.
    std::string   dump_failed_dir;
};

// A parsed block plus the endpoint it came from; the tool turns this into an
// ObservedBlock (and, when it can, re-parses the embedded Monero block).
using BlockSink = std::function<void(const PoolBlock&, const std::vector<std::uint8_t>& body,
                                     MessageId wire_id, const std::string& endpoint)>;
using LogSink   = std::function<void(const std::string&)>;

class PeerSession {
public:
    enum class State : std::uint8_t { Connecting, Handshaking, Established, Closed };

    PeerSession(std::string host, std::uint16_t port, const ObserverConfig& cfg,
                const ConsensusId& consensus, std::uint64_t rng_seed)
        : host_(std::move(host)), port_(port), cfg_(cfg), consensus_(consensus), rng_(rng_seed) {}

    ~PeerSession() { close_fd(); }

    PeerSession(const PeerSession&) = delete;
    PeerSession& operator=(const PeerSession&) = delete;

    const std::string& endpoint() const noexcept { return endpoint_; }
    State state() const noexcept { return state_; }
    bool closed() const noexcept { return state_ == State::Closed; }
    int fd() const noexcept { return fd_; }
    const std::string& close_reason() const noexcept { return close_reason_; }
    std::uint32_t peer_protocol_version() const noexcept { return peer_protocol_; }
    std::uint32_t peer_software_version() const noexcept { return peer_software_; }
    std::uint64_t blocks_received() const noexcept { return blocks_received_; }

    bool start(OutboundLedger& ledger, const LogSink& log) {
        endpoint_ = host_ + ":" + std::to_string(port_);

        addrinfo hints{};
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        const std::string portstr = std::to_string(port_);
        if (::getaddrinfo(host_.c_str(), portstr.c_str(), &hints, &res) != 0 || !res)
            return fail("dns", log);

        for (addrinfo* ai = res; ai; ai = ai->ai_next) {
            fd_ = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (fd_ < 0) continue;
            set_nonblocking(fd_);
            int one = 1;
            ::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            const int rc = ::connect(fd_, ai->ai_addr, ai->ai_addrlen);
            if (rc == 0 || errno == EINPROGRESS) break;
            close_fd();
        }
        ::freeaddrinfo(res);
        if (fd_ < 0) return fail("connect", log);

        state_        = State::Connecting;
        deadline_ms_  = now_ms() + cfg_.connect_timeout_ms;
        (void)ledger;
        return true;
    }

    short poll_events() const noexcept {
        short ev = POLLIN;
        if (state_ == State::Connecting) ev = POLLOUT;
        else if (!txbuf_.empty()) ev |= POLLOUT;
        return ev;
    }

    // Drive the session. Returns false when the session has closed.
    bool step(short revents, OutboundLedger& ledger, const BlockSink& on_block,
              const LogSink& log, ReadModel& model) {
        if (state_ == State::Closed) return false;
        const std::uint64_t t = now_ms();

        if (state_ == State::Connecting) {
            if (t > deadline_ms_) return fail("connect timeout", log);
            if (!(revents & (POLLOUT | POLLERR | POLLHUP))) return true;
            int err = 0; socklen_t len = sizeof(err);
            if (::getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0)
                return fail("connect refused", log);
            state_ = State::Handshaking;
            // Both ends send a challenge the instant the connection is up.
            for (std::size_t i = 0; i < kChallengeSize; ++i)
                my_challenge_[i] = static_cast<std::uint8_t>(rng_() & 0xFFu);
            ControlArgs a{};
            a.challenge = my_challenge_;
            a.peer_id   = (static_cast<std::uint64_t>(rng_()) << 32) ^ rng_();
            if (a.peer_id == 0) a.peer_id = 1;   // upstream rejects peer id 0
            send_control(ControlMessage::HandshakeChallenge, a, ledger);
            deadline_ms_ = t + cfg_.connect_timeout_ms;
        }

        if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
            // Drain first: a peer can queue a frame and hang up in the same
            // breath, and dropping that frame would lose a real observation.
            if (!drain(ledger, on_block, log, model)) return false;
            return fail("peer closed", log);
        }

        if ((revents & POLLOUT) && !txbuf_.empty()) {
            const ssize_t n = ::send(fd_, txbuf_.data(), txbuf_.size(), MSG_NOSIGNAL);
            if (n > 0) txbuf_.erase(txbuf_.begin(), txbuf_.begin() + n);
            else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return fail("send", log);
        }

        if (revents & POLLIN) {
            if (!drain(ledger, on_block, log, model)) return false;
        }

        if (state_ == State::Handshaking && t > deadline_ms_)
            return fail("handshake timeout", log);

        if (state_ == State::Established) {
            if (t >= next_tip_poll_ms_) {
                request_block(Hash{}, ledger);          // all-zero id == "your tip"
                next_tip_poll_ms_ = t + cfg_.tip_poll_ms;
            }
            if (t >= next_peer_list_ms_) {
                ControlArgs a{};
                send_control(ControlMessage::PeerListRequest, a, ledger);
                next_peer_list_ms_ = t + cfg_.peer_list_ms;
            }
            pump_backfill(ledger);
        }
        return true;
    }

    // Queue a parent walk. Bounded by the session's backfill budget, so a peer
    // that answers with an endless ancestor chain cannot make us loop.
    void want_block(const Hash& id) {
        if (backfill_used_ >= cfg_.backfill_budget) return;
        if (requested_.count(id)) return;
        backfill_.push_back(id);
    }

    void close_now(const std::string& why, const LogSink& log) { (void)fail(why, log); }

private:
    static void set_nonblocking(int fd) {
        const int fl = ::fcntl(fd, F_GETFL, 0);
        if (fl >= 0) ::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    }

    void close_fd() { if (fd_ >= 0) { ::close(fd_); fd_ = -1; } }

    bool fail(const std::string& why, const LogSink& log) {
        if (state_ != State::Closed) {
            close_reason_ = why;
            state_ = State::Closed;
            close_fd();
            if (log) log("peer " + endpoint_ + " closed: " + why);
        }
        return false;
    }

    void send_control(ControlMessage c, const ControlArgs& a, OutboundLedger& ledger) {
        const std::size_t before = txbuf_.size();
        encode(c, a, txbuf_);
        ledger.record(c, txbuf_.size() - before);
        flush();
    }

    void flush() {
        while (!txbuf_.empty()) {
            const ssize_t n = ::send(fd_, txbuf_.data(), txbuf_.size(), MSG_NOSIGNAL);
            if (n <= 0) break;
            txbuf_.erase(txbuf_.begin(), txbuf_.begin() + n);
        }
    }

    void request_block(const Hash& id, OutboundLedger& ledger) {
        if (pending_.size() >= cfg_.max_inflight) return;
        ControlArgs a{};
        a.block_id = id;
        send_control(ControlMessage::BlockRequest, a, ledger);
        pending_.push_back(id);
    }

    void pump_backfill(OutboundLedger& ledger) {
        while (!backfill_.empty() && pending_.size() < cfg_.max_inflight
               && backfill_used_ < cfg_.backfill_budget) {
            const Hash id = backfill_.front();
            backfill_.pop_front();
            if (requested_.count(id)) continue;
            requested_.insert(id);
            ++backfill_used_;
            request_block(id, ledger);
        }
    }

    bool drain(OutboundLedger& ledger, const BlockSink& on_block, const LogSink& log,
               ReadModel& model) {
        for (;;) {
            std::uint8_t tmp[65536];
            const ssize_t n = ::recv(fd_, tmp, sizeof(tmp), 0);
            if (n == 0) return fail("eof", log);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR) continue;
                return fail("recv", log);
            }
            rxbuf_.insert(rxbuf_.end(), tmp, tmp + n);
            if (rxbuf_.size() > 2u * 1024u * 1024u) return fail("read buffer overflow", log);
            if (!consume(ledger, on_block, log, model)) return false;
            if (static_cast<std::size_t>(n) < sizeof(tmp)) break;
        }
        return true;
    }

    bool consume(OutboundLedger& ledger, const BlockSink& on_block, const LogSink& log,
                 ReadModel& model) {
        std::size_t off = 0;
        for (;;) {
            const std::size_t avail = rxbuf_.size() - off;
            if (avail == 0) break;
            std::size_t flen = 0;
            const FrameStatus st = frame_size(rxbuf_.data() + off, avail, flen);
            if (st == FrameStatus::Incomplete) break;
            if (st == FrameStatus::BadId)  { compact(off); return fail("bad message id", log); }
            if (st == FrameStatus::TooBig) { compact(off); return fail("oversized frame", log); }

            const std::uint8_t* f = rxbuf_.data() + off;
            if (!handle_frame(f, flen, ledger, on_block, log, model)) { compact(off + flen); return false; }
            off += flen;
        }
        compact(off);
        return true;
    }

    void compact(std::size_t off) {
        if (off == 0) return;
        rxbuf_.erase(rxbuf_.begin(), rxbuf_.begin() + static_cast<std::ptrdiff_t>(off));
    }

    bool handle_frame(const std::uint8_t* f, std::size_t flen, OutboundLedger& ledger,
                      const BlockSink& on_block, const LogSink& log, ReadModel& model) {
        const MessageId id = static_cast<MessageId>(f[0]);

        // Until the handshake has completed, exactly one message is legal --
        // the same fail-closed rule upstream applies to us.
        if (state_ == State::Handshaking
            && id != MessageId::HandshakeChallenge && id != MessageId::HandshakeSolution)
            return fail("message before handshake", log);

        switch (id) {
            case MessageId::HandshakeChallenge: {
                if (got_peer_challenge_) return fail("duplicate challenge", log);
                got_peer_challenge_ = true;
                Challenge peer_challenge{};
                std::memcpy(peer_challenge.data(), f + 1, kChallengeSize);
                std::memcpy(&peer_id_, f + 1 + kChallengeSize, sizeof(peer_id_));

                // We dialled, so we owe the proof of work. ~10^4 keccaks.
                const HandshakeSolution sol =
                        solve_handshake(peer_challenge, consensus_,
                                        (static_cast<std::uint64_t>(rng_()) << 32) ^ rng_());
                if (sol.iterations == 0) return fail("handshake pow exhausted", log);
                ControlArgs a{};
                a.solution = sol.solution;
                a.salt     = sol.salt;
                send_control(ControlMessage::HandshakeSolution, a, ledger);
                pow_iterations_ = sol.iterations;
                return true;
            }
            case MessageId::HandshakeSolution: {
                Hash32 sol{};
                Challenge salt{};
                std::memcpy(sol.data(), f + 1, kHashSize);
                std::memcpy(salt.data(), f + 1 + kHashSize, kChallengeSize);
                if (!verify_handshake(my_challenge_, consensus_, sol, salt))
                    return fail("consensus mismatch (wrong sidechain)", log);
                state_ = State::Established;
                model.note_connected(endpoint_);
                if (log) log("peer " + endpoint_ + " handshake ok (pow "
                             + std::to_string(pow_iterations_) + " iters, peer_id "
                             + std::to_string(peer_id_) + ")");
                // First tip request immediately; the poll cadence takes over.
                request_block(Hash{}, ledger);
                const std::uint64_t t = now_ms();
                next_tip_poll_ms_  = t + cfg_.tip_poll_ms;
                next_peer_list_ms_ = t + 1000;
                return true;
            }
            case MessageId::BlockResponse: {
                if (pending_.empty()) return fail("unsolicited BLOCK_RESPONSE", log);
                pending_.pop_front();
                const std::uint32_t len = frame_body_length(f, flen);
                if (len == 0) return true;      // "I do not have it"
                return parse_and_emit(f + 5, len, BlobShape::Full, id, on_block, log, model);
            }
            case MessageId::BlockBroadcast:
            case MessageId::BlockBroadcastCompact: {
                // Not expected -- a peer only broadcasts to nodes that announced
                // a listen port -- but legal, so it is parsed rather than dropped.
                model.note_broadcast_seen();
                const std::uint32_t len = frame_body_length(f, flen);
                if (len == 0) return true;
                const BlobShape shape = (id == MessageId::BlockBroadcastCompact)
                                      ? BlobShape::Compact : BlobShape::Pruned;
                return parse_and_emit(f + 5, len, shape, id, on_block, log, model);
            }
            case MessageId::PeerListResponse: {
                std::vector<PeerEntry> peers;
                if (!decode_peer_list(f, flen, peers)) return fail("bad peer list", log);
                std::size_t addrs = 0;
                for (const PeerEntry& p : peers) {
                    if (p.is_version_announcement()) {
                        peer_protocol_ = p.announced_protocol_version();
                        peer_software_ = p.announced_software_version();
                        continue;
                    }
                    ++addrs;
                    model.note_peer(format_peer(p));
                    discovered_.push_back(p);
                }
                model.note_peer_gossip(addrs);
                return true;
            }
            case MessageId::BlockNotify:
                // A hash we could ask for. The parent walk already covers the
                // ancestry we care about, so this is recorded and not chased:
                // chasing it would multiply requests without adding coverage.
                ++notifies_;
                return true;
            case MessageId::BlockRequest:
                // A peer asking US for a block. There is no encoder in this
                // tree that could answer, and that is the point. Upstream
                // tolerates silence here (it simply never resolves its own
                // pending entry), so the connection continues.
                ++requests_ignored_;
                return true;
            case MessageId::ListenPort:
                // The peer telling us where it listens. We record nothing from
                // it: the peer list already carries reachable addresses, and
                // this observer keeps no directory of its own.
                return true;
            case MessageId::PeerListRequest:
                // The peer asking for OUR peer list. Silence is the answer; we
                // have no encoder for PEER_LIST_RESPONSE and no list to share.
                ++requests_ignored_;
                return true;
            case MessageId::AuxJobDonation:
            case MessageId::MoneroBlockBroadcast:
                // Merge-mining jobs and relayed Monero blocks. Out of scope for
                // a sidechain observer; counted, framed correctly (frame_size
                // has already bounded them) and skipped.
                ++off_scope_frames_;
                return true;
        }
        return true;
    }

    bool parse_and_emit(const std::uint8_t* body, std::uint32_t len, BlobShape shape,
                        MessageId wire_id, const BlockSink& on_block, const LogSink& log,
                        ReadModel& model) {
        PoolBlock pb;
        const BlockStatus st = deserialize(body, len, consensus_, shape, pb);
        if (st != BlockStatus::Ok) {
            model.note_parse_failure();
            if (log) log("peer " + endpoint_ + " block parse failed: "
                         + std::string(to_string(st)) + " (" + to_string(shape) + ", "
                         + std::to_string(len) + " bytes)");
            if (!cfg_.dump_failed_dir.empty()) {
                const std::string path = cfg_.dump_failed_dir + "/failed-"
                                       + std::string(to_string(st)) + "-"
                                       + std::to_string(now_ms()) + ".bin";
                if (FILE* f = std::fopen(path.c_str(), "wb")) {
                    std::fwrite(body, 1, len, f);
                    std::fclose(f);
                    if (log) log("  dumped to " + path);
                }
            }
            return true;    // a bad block is not a bad peer; keep observing
        }
        ++blocks_received_;
        if (on_block) on_block(pb, std::vector<std::uint8_t>(body, body + len), wire_id, endpoint_);
        return true;
    }

    static std::string format_peer(const PeerEntry& p) {
        char buf[INET6_ADDRSTRLEN] = {0};
        if (!p.is_v6 || p.is_ipv4_mapped()) {
            ::inet_ntop(AF_INET, p.addr.data() + 12, buf, sizeof(buf));
            return std::string(buf) + ":" + std::to_string(p.port);
        }
        ::inet_ntop(AF_INET6, p.addr.data(), buf, sizeof(buf));
        return std::string("[") + buf + "]:" + std::to_string(p.port);
    }

public:
    std::vector<PeerEntry> take_discovered() {
        std::vector<PeerEntry> out;
        out.swap(discovered_);
        return out;
    }
    std::uint64_t notifies() const noexcept { return notifies_; }
    std::uint64_t requests_ignored() const noexcept { return requests_ignored_; }
    std::uint64_t off_scope_frames() const noexcept { return off_scope_frames_; }

private:
    std::string    host_;
    std::uint16_t  port_ = 0;
    std::string    endpoint_;
    ObserverConfig cfg_;
    ConsensusId    consensus_{};
    std::mt19937   rng_;

    int    fd_ = -1;
    State  state_ = State::Closed;
    std::string close_reason_;

    std::vector<std::uint8_t> rxbuf_;
    std::vector<std::uint8_t> txbuf_;

    Challenge     my_challenge_{};
    bool          got_peer_challenge_ = false;
    std::uint64_t peer_id_ = 0;
    std::uint64_t pow_iterations_ = 0;

    std::deque<Hash> pending_;        // FIFO: BLOCK_RESPONSE carries no id
    std::deque<Hash> backfill_;
    std::set<Hash>   requested_;
    std::size_t      backfill_used_ = 0;

    std::vector<PeerEntry> discovered_;
    std::uint32_t peer_protocol_ = 0;
    std::uint32_t peer_software_ = 0;
    std::uint64_t blocks_received_ = 0;
    std::uint64_t notifies_ = 0;
    std::uint64_t requests_ignored_ = 0;
    std::uint64_t off_scope_frames_ = 0;

    std::uint64_t deadline_ms_       = 0;
    std::uint64_t next_tip_poll_ms_  = 0;
    std::uint64_t next_peer_list_ms_ = 0;
};

// ---------------------------------------------------------------------------
// The driver: a few sessions, one poll loop, one read model.
//
// Peer supply is two-stage, exactly as upstream bootstraps: the sidechain's DNS
// seeds first, then addresses learned through PEER_LIST_RESPONSE. The seeds
// are a starting point and nothing more -- every address is authenticated by
// the handshake before a single block is believed, so a hostile seed can waste
// a connection and nothing else.
// ---------------------------------------------------------------------------
class Observer {
public:
    explicit Observer(const ObserverConfig& cfg)
        : cfg_(cfg), model_(cfg.chain), consensus_(consensus_id(cfg.chain)),
          rng_(cfg.seed ? cfg.seed : now_ms()) {}

    ReadModel&            model()  noexcept { return model_; }
    const ReadModel&      model()  const noexcept { return model_; }
    const OutboundLedger& ledger() const noexcept { return ledger_; }

    void set_log(LogSink s) { log_ = std::move(s); }
    void set_block_sink(BlockSink s) { on_block_ = std::move(s); }

    // Seed the dial queue. Host names are resolved lazily, inside the session.
    void add_seed(const std::string& host, std::uint16_t port) {
        queue_.push_back({host, port});
    }
    void add_default_seeds() {
        const std::uint16_t port = default_port(cfg_.chain);
        for (const std::string& h : seed_hosts(cfg_.chain)) queue_.push_back({h, port});
    }

    // Blocking run for cfg_.run_ms. Returns the number of poll iterations.
    std::uint64_t run() {
        const std::uint64_t t_end = now_ms() + cfg_.run_ms;
        std::uint64_t iterations = 0;
        while (now_ms() < t_end) {
            ++iterations;
            open_sessions();
            std::vector<pollfd> pfds;
            std::vector<PeerSession*> live;
            pfds.reserve(sessions_.size());
            for (auto& s : sessions_) {
                if (s->closed()) continue;
                pollfd p{};
                p.fd = s->fd();
                p.events = s->poll_events();
                pfds.push_back(p);
                live.push_back(s.get());
            }
            if (pfds.empty()) {
                if (queue_.empty()) break;          // nothing left to dial
                ::poll(nullptr, 0, 200);
                continue;
            }
            const int rc = ::poll(pfds.data(), pfds.size(), 500);
            if (rc < 0 && errno != EINTR) break;
            for (std::size_t i = 0; i < live.size(); ++i)
                live[i]->step(pfds[i].revents, ledger_, sink(), log_, model_);
            harvest();
        }
        for (auto& s : sessions_) if (!s->closed()) s->close_now("run finished", log_);
        return iterations;
    }

    std::size_t live_sessions() const {
        std::size_t n = 0;
        for (const auto& s : sessions_) if (!s->closed()) ++n;
        return n;
    }

private:
    struct Dial { std::string host; std::uint16_t port; };

    BlockSink sink() {
        return [this](const PoolBlock& pb, const std::vector<std::uint8_t>& body,
                      MessageId wire_id, const std::string& endpoint) {
            ingest(pb, body, endpoint);
            if (on_block_) on_block_(pb, body, wire_id, endpoint);
        };
    }

    void ingest(const PoolBlock& pb, const std::vector<std::uint8_t>& blob,
                const std::string& endpoint);

    void open_sessions() {
        while (live_sessions() < cfg_.max_peers && !queue_.empty()) {
            const Dial d = queue_.front();
            queue_.pop_front();
            const std::string ep = d.host + ":" + std::to_string(d.port);
            if (dialled_.count(ep)) continue;
            dialled_.insert(ep);
            auto s = std::make_unique<PeerSession>(d.host, d.port, cfg_, consensus_,
                                                   static_cast<std::uint64_t>(rng_()));
            if (s->start(ledger_, log_)) sessions_.push_back(std::move(s));
        }
        // Reap closed sessions so the vector cannot grow without bound on a
        // long run against a churning network.
        sessions_.erase(std::remove_if(sessions_.begin(), sessions_.end(),
                                       [this](const std::unique_ptr<PeerSession>& s) {
                                           if (!s->closed()) return false;
                                           model_.note_disconnected(s->endpoint());
                                           return true;
                                       }),
                        sessions_.end());
    }

    void harvest() {
        for (auto& s : sessions_) {
            for (const PeerEntry& p : s->take_discovered()) {
                if (p.port == 0 || p.port == 0xFFFF) continue;
                if (p.is_v6 && !p.is_ipv4_mapped()) continue;   // no IPv6 route on the run host
                char buf[INET6_ADDRSTRLEN] = {0};
                ::inet_ntop(AF_INET, p.addr.data() + 12, buf, sizeof(buf));
                const std::string ep = std::string(buf) + ":" + std::to_string(p.port);
                if (dialled_.count(ep)) continue;
                queue_.push_back({std::string(buf), p.port});
            }
        }
    }

    ObserverConfig cfg_;
    ReadModel      model_;
    ConsensusId    consensus_{};
    OutboundLedger ledger_;
    std::mt19937   rng_;
    LogSink        log_;
    BlockSink      on_block_;

    std::vector<std::unique_ptr<PeerSession>> sessions_;
    std::deque<Dial>      queue_;
    std::set<std::string> dialled_;
};

// ---------------------------------------------------------------------------
// Turning a parsed sidechain block into an observation -- and the one place the
// M3 native Monero lane is actually used.
//
// The Monero half of a Full sidechain blob is bytes [0, sidechain_offset): a
// complete, well-formed Monero block blob. Handing it to
// native::parse_and_identify() means the embedded template is read by the SAME
// code the native node runs against monerod -- the same coinbase parse, the
// same tree hash, the same length-prefixed block id -- rather than by a second
// implementation written for this component. If that parse disagrees with our
// own reading of the shared prefix (prev_id, timestamp, coinbase height), the
// disagreement shows up as a mismatch here instead of as a subtly wrong number
// in a report.
//
// The block id it produces is the id of the template AS TEMPLATED. A sidechain
// block is not a Monero block unless its PoW also cleared the Monero network
// target, so this id is a handle for cross-checking the template against a
// public Monero source (prev_id must be the id of monero height-1), never a
// claim that P2Pool found a mainnet block.
// ---------------------------------------------------------------------------
inline void Observer::ingest(const PoolBlock& pb, const std::vector<std::uint8_t>& blob,
                             const std::string& endpoint) {
    ObservedBlock ob;
    ob.sidechain_id          = pb.sidechain_id;
    ob.sidechain_height      = pb.sidechain_height;
    ob.difficulty            = pb.difficulty;
    ob.cumulative_difficulty = pb.cumulative_difficulty;
    ob.parent                = pb.parent;
    ob.uncles                = pb.uncles;
    ob.monero_height         = pb.txin_gen_height;
    ob.monero_prev_id        = pb.prev_id;
    ob.monero_timestamp      = pb.timestamp;
    ob.share_outputs         = pb.outputs.size();
    ob.total_reward          = pb.total_reward;
    ob.tx_count              = pb.tx_hashes.size();
    ob.shape                 = pb.shape;
    ob.id_verified           = pb.sidechain_id_verified;
    ob.first_seen_ms         = now_ms();
    ob.from_peer             = endpoint;

    if (pb.monero_blob_contiguous() && pb.sidechain_offset > 0
        && pb.sidechain_offset <= blob.size()) {
        const std::vector<std::uint8_t> mblob(blob.begin(),
                                              blob.begin() + static_cast<std::ptrdiff_t>(pb.sidechain_offset));
        native::ParsedBlock  mpb;
        native::BlockIdentity mid;
        if (native::parse_and_identify(mblob, mpb, mid) == native::BlockParseStatus::Ok) {
            ob.monero_parsed    = true;
            ob.monero_blob_size = mblob.size();
            std::memcpy(ob.monero_block_id.data(), mid.id.data(), 32);
            // Cross-check the two readings of the shared prefix. A mismatch is
            // a real defect in one of the two parsers, so it is loud.
            if (mpb.header.timestamp != pb.timestamp
                || std::memcmp(mpb.header.prev_id.data(), pb.prev_id.data(), 32) != 0
                || mpb.header.nonce != pb.nonce) {
                if (log_) log_("NATIVE/P2POOL HEADER DISAGREEMENT on "
                               + hex(pb.sidechain_id));
                ob.monero_parsed = false;
            }
        } else if (log_) {
            log_("embedded monero block did not parse for " + hex(pb.sidechain_id));
        }
    }

    if (model_.observe(ob)) {
        // Walk the ancestry we do not have yet, so a run reports a chain rather
        // than a scatter of tips. Bounded per session by the backfill budget.
        if (!model_.find(pb.parent)) {
            for (auto& s : sessions_) if (!s->closed()) { s->want_block(pb.parent); break; }
        }
        for (const Hash& u : pb.uncles)
            if (!model_.find(u))
                for (auto& s : sessions_) if (!s->closed()) { s->want_block(u); break; }
    }
}

} // namespace c2pool::xmr::p2pool
