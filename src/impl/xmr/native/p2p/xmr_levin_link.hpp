// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/p2p/xmr_levin_link.hpp
//
// Wave 1, component C1b: ONE PEER CONNECTION, driven. This is the object that
// binds the four pieces C1b owns into a live link:
//
//   LevinSocket      -- the framed transport (levin_socket.hpp)
//   HandshakeMachine -- the 1001 exchange and its refusals (xmr_handshake.hpp)
//   InvokeQueue      -- the FIFO reply matcher (levin_invoke_queue.hpp)
//   ExpectResponse   -- the 2003/2006 notify-answered legs
//   InboundLiveness  -- the TIMED_SYNC-driven deadline
//
// and runs the two exchanges that keep a monerod peer talking to us:
//
//   COMMAND_HANDSHAKE  (1001) once, at connect, 5 s deadline;
//   COMMAND_TIMED_SYNC (1002) every 60 s (jittered), both directions.
//
// WHY TIMED_SYNC IS THE HEARTBEAT AND PING IS NOT. monerod's
// peer_sync_idle_maker fires every P2P_DEFAULT_HANDSHAKE_INTERVAL (60 s) and
// INVOKES 1002 on every handshaked peer, carrying its CORE_SYNC_DATA; the
// answer carries ours back plus any peers it has not yet sent on this
// connection. COMMAND_PING (1003) is only the port-reachability call-back for
// nodes that advertise my_port != 0 -- we advertise 0, so we are never pinged
// and could not use it as liveness even if we wanted to. So 1002 is
// simultaneously our keepalive, our peer-height gauge, our reorg tripwire and
// the peerlist source; failing to answer one, or answering with sync data the
// peer's process_payload_sync_data rejects, gets us dropped.
//
// THE THREE C1-LENS CORRECTIONS, live-monerod-confirmed during the C1a verify,
// are folded into the codec (C1a) and are ASSERTED from this layer's KAT so a
// later edit cannot quietly undo them:
//
//   (a) epee sections serialize in SORTED KEY ORDER. monerod's section is a
//       std::map<std::string, storage_entry>, so its encoder emits keys sorted,
//       and byte parity is impossible without sorting. epee_storage.hpp's
//       write_storage() sorts.
//   (b) SIGNATURE_B is 0x01020101, which little-endian puts on the wire as the
//       bytes 01 01 02 01 -- not 01 02 01 01. The storage header is
//       01 11 01 01 | 01 01 02 01 | 01.
//   (c) COMMAND_TIMED_SYNC::response carries payload_data and
//       local_peerlist_new ONLY. There is no local_time and no legacy
//       local_peerlist field in the deployed daemon, and an ABSENT OR EMPTY
//       local_peerlist_new is a perfectly normal answer -- monerod writes no
//       key for an empty container -- so treating it as a drop would blackhole
//       healthy peers that have simply already sent us everything they have.
//       Our own answer to an inbound 1002 is built the same way, which is why
//       an empty peerlist here emits exactly one key.
//
// SUCCESS ON THE WIRE IS `return_code >= 0`, NOT `== LEVIN_OK`. epee copies the
// handler's own return value into the response header and every monerod handler
// ends in `return 1`, so a real HANDSHAKE answer carries 1. A matcher that
// insisted on 0 would refuse every honest daemon -- which is precisely what the
// first live run of this component against a stagenet daemon did. Our own
// answers carry 1 too, so a C6 byte-parity capture matches. See rc_is_error and
// RC_HANDLER_OK in levin_invoke_queue.hpp.
//
// AN UNKNOWN INVOKE STILL GETS AN ANSWER. If a peer invokes a command we do not
// serve, we reply with LEVIN_ERROR_CONNECTION_HANDLER_NOT_DEFINED rather than
// staying silent. Silence would stall the PEER'S FIFO -- the same
// arrival-order matcher we run -- and it would drop us for non-response. An
// error answer keeps both matchers in step and costs 33 bytes.
//
// RANDOMX NEVER RUNS ON THE IO THREAD. Everything this file does on a frame is
// codec work: decode a section, compare a network id, restart a timer. Block
// bodies go out through on_frame to C2's bounded queue, and C2 owns the verify
// thread (contracts note in levin_socket.hpp). The KAT asserts every callback
// lands on the io thread, so the boundary is measured, not promised.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record;
// nothing here activates v37 consensus and src/sharechain/v37 is not touched.
//
// Header-only. STL plus boost::asio.
// ---------------------------------------------------------------------------
#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>

#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/p2p/levin_codec.hpp"
#include "impl/xmr/native/p2p/levin_invoke_queue.hpp"
#include "impl/xmr/native/p2p/levin_messages.hpp"
#include "impl/xmr/native/p2p/levin_socket.hpp"
#include "impl/xmr/native/p2p/xmr_handshake.hpp"

namespace c2pool::xmr::native::levin {

// Why a link ended. HandshakeFailure covers the admission refusals; these cover
// everything after admission.
enum class LinkClose : std::uint8_t {
    None = 0,
    Requested,          // our own stop()
    TransportError,     // socket read/write error, peer closed
    HandshakeRefused,   // see HandshakeMachine::failure()
    ReplyMismatch,      // FIFO matcher refused the answer
    Unsolicited,        // a response or a 2004/2007 nobody asked for
    InvokeTimeout,      // the peer never answered inside the deadline
    PeerUnresponsive,   // peer_timeout_ms of total inbound silence
    BadSyncData,        // a TIMED_SYNC carrying data no honest daemon sends
    BadMessage,         // an undecodable body on a command we own
    WriteRefused,       // the outbound queue is full: the peer stopped reading
    TooManyInvokes,     // our own bug: MAX_OUTSTANDING questions already in the air
};

inline const char* to_string(LinkClose c) noexcept {
    switch (c) {
        case LinkClose::None:             return "None";
        case LinkClose::Requested:        return "Requested";
        case LinkClose::TransportError:   return "TransportError";
        case LinkClose::HandshakeRefused: return "HandshakeRefused";
        case LinkClose::ReplyMismatch:    return "ReplyMismatch";
        case LinkClose::Unsolicited:      return "Unsolicited";
        case LinkClose::InvokeTimeout:    return "InvokeTimeout";
        case LinkClose::PeerUnresponsive: return "PeerUnresponsive";
        case LinkClose::BadSyncData:      return "BadSyncData";
        case LinkClose::BadMessage:       return "BadMessage";
        case LinkClose::WriteRefused:     return "WriteRefused";
        case LinkClose::TooManyInvokes:   return "TooManyInvokes";
    }
    return "?";
}

struct LinkConfig {
    HandshakeConfig handshake{};

    // Deadlines. The defaults are monerod's; the KAT compresses them so the
    // cadence and the timeouts are exercised in milliseconds, not minutes.
    Millis handshake_timeout_ms    = P2P_DEFAULT_CONNECTION_TIMEOUT_MS;
    Millis invoke_timeout_ms       = P2P_DEFAULT_INVOKE_TIMEOUT_MS;
    Millis timed_sync_interval_ms  = P2P_DEFAULT_HANDSHAKE_INTERVAL_MS;
    Millis timed_sync_jitter_ms    = TIMED_SYNC_JITTER_MS;
    Millis peer_timeout_ms         = PEER_TIMEOUT_MS;

    // How often deadlines are scanned. Everything here is measured in tens of
    // seconds, so a one-second tick costs nothing and keeps the timer logic to
    // a single periodic timer instead of one timer per deadline.
    Millis tick_ms = 1'000;

    // Answer an inbound TIMED_SYNC even before our own handshake has landed.
    // monerod will not do this to us (it invokes 1002 only on handshaked
    // connections), so the default is the strict one.
    bool answer_timed_sync_before_handshake = false;

    LevinSocket::Options socket{};
};

// Everything the link reports upward. C1c installs the demux; C2 gets sync data
// through it. `our_sync_data` is the only REQUIRED one: without it we cannot
// even open the handshake.
struct LinkCallbacks {
    std::function<PeerSyncData()>                          our_sync_data;
    std::function<void(const PeerRef&, const PeerSyncData&)> on_peer_sync_data;
    std::function<void(const PeerRef&, const std::vector<PeerlistEntry>&)> on_peerlist;
    std::function<void(const PeerRef&)>                    on_handshaked;
    // Everything this layer does not own: 2001..2010 for C1c/C2/C3/C5. The body
    // pointer is valid only for the duration of the call.
    std::function<void(const PeerRef&, const BucketHead&,
                       const std::uint8_t*, std::size_t)>  on_frame;
    std::function<void(const PeerRef&, LinkClose, const std::string& why)> on_closed;
};

class LevinLink : public std::enable_shared_from_this<LevinLink> {
public:
    using tcp = boost::asio::ip::tcp;

    static std::shared_ptr<LevinLink> create(tcp::socket   sock,
                                             LinkConfig    cfg,
                                             LinkCallbacks cb) {
        return std::shared_ptr<LevinLink>(
            new LevinLink(std::move(sock), std::move(cfg), std::move(cb)));
    }

    LevinLink(const LevinLink&)            = delete;
    LevinLink& operator=(const LevinLink&) = delete;

    // Arms the transport, then sends the handshake. Both are posted to the io
    // thread in that order, so the read loop is live before the first byte
    // goes out and an instant answer cannot be missed.
    void start() {
        auto self = shared_from_this();

        // OWNERSHIP, and why the handlers below capture a RAW pointer.
        //
        // The link owns the socket (shared_ptr member). If the socket's
        // handlers captured a shared_ptr back to the link, the two would keep
        // each other alive forever -- a cycle neither the io_context nor the
        // pool can break, and on a node that churns peers it grows without
        // bound. ASan's leak checker catches it on the sanitizer CI leg, which
        // is how this one was found.
        //
        // So the handlers hold a raw LevinLink* and the socket holds a WEAK
        // pointer to the same object, which it locks at the top of every async
        // callback and before every handler call. That is exactly
        // core::Socket's m_node / m_node_lifetime pair: raw for access, weak
        // for liveness. Whoever owns the link (C1c's peer pool) is the only
        // strong reference, and dropping it mid-flight aborts the transport
        // instead of dereferencing freed memory.
        socket_->set_owner_lifetime(std::weak_ptr<void>(self));
        LevinLink* raw = this;
        socket_->set_frame_handler(
            [raw](const BucketHead& h, const std::uint8_t* b, std::size_t n) {
                raw->on_frame(h, b, n);
            });
        socket_->set_close_handler(
            [raw](const std::string& why) { raw->on_socket_closed(why); });
        socket_->start();
        // This post DOES hold a strong reference, deliberately and briefly: it
        // keeps the link alive until the handshake is on the wire, and releases
        // it when the lambda is destroyed.
        boost::asio::post(socket_->executor(), [self]() { self->begin_handshake(); });
    }

    void stop(const std::string& why) { fail(LinkClose::Requested, why); }

    // --- outbound ------------------------------------------------------------
    // A one-way notification. No FIFO record: nothing is owed back.
    bool send_notify(std::uint32_t cmd, const std::vector<std::uint8_t>& body) {
        if (!socket_->send(make_notify(cmd, body))) {
            fail(LinkClose::WriteRefused, "outbound queue full sending a notification");
            return false;
        }
        return true;
    }

    // A question. Registers a FIFO record FIRST, because a peer that answers
    // instantly must find the record already there.
    bool send_invoke(std::uint32_t cmd, const std::vector<std::uint8_t>& body,
                     Millis timeout_ms = 0) {
        const Millis now = now_ms();
        const Millis to  = timeout_ms ? timeout_ms : cfg_.invoke_timeout_ms;
        if (!invokes_.push(cmd, now, to)) {
            fail(LinkClose::TooManyInvokes, "too many outstanding invokes on one connection");
            return false;
        }
        if (!socket_->send(make_invoke(cmd, body))) {
            fail(LinkClose::WriteRefused, "outbound queue full sending an invoke");
            return false;
        }
        return true;
    }

    // The 2003/2006 legs, whose answers come back as NOTIFICATIONS. Exactly one
    // may be in flight; false means one already is.
    bool send_notify_answered_request(std::uint32_t cmd,
                                      const std::vector<std::uint8_t>& body) {
        if (!expect_.arm(cmd, now_ms())) return false;
        if (!socket_->send(make_notify(cmd, body))) {
            expect_.disarm();
            fail(LinkClose::WriteRefused, "outbound queue full sending a chain request");
            return false;
        }
        return true;
    }

    // --- observation ----------------------------------------------------------
    const PeerRef&        peer()      const noexcept { return peer_; }
    HandshakeState        state()     const noexcept { return hs_.state(); }
    HandshakeFailure      hs_failure()const noexcept { return hs_.failure(); }
    bool                  handshaked()const noexcept { return hs_.handshaked(); }
    const PeerSyncData&   peer_sync() const noexcept { return peer_sync_; }
    const InvokeQueue&    invokes()   const noexcept { return invokes_; }
    const ExpectResponse& expect()    const noexcept { return expect_; }
    const InboundLiveness& liveness() const noexcept { return live_; }
    std::uint64_t timed_syncs_sent()     const noexcept { return timed_syncs_sent_; }
    std::uint64_t timed_syncs_answered() const noexcept { return timed_syncs_answered_; }
    LinkClose     close_reason()  const noexcept { return close_reason_; }
    const std::string& close_why() const noexcept { return close_why_; }
    std::shared_ptr<LevinSocket> socket() const noexcept { return socket_; }

    // Monotonic milliseconds since this link was constructed. Deadlines only
    // ever compare differences, so the origin is arbitrary -- but making it
    // per-link keeps the numbers small and readable in logs.
    Millis now_ms() const {
        using namespace std::chrono;
        return static_cast<Millis>(
            duration_cast<milliseconds>(steady_clock::now() - epoch_).count());
    }

private:
    LevinLink(tcp::socket sock, LinkConfig cfg, LinkCallbacks cb)
        : cfg_(std::move(cfg))
        , cb_(std::move(cb))
        , hs_(cfg_.handshake)
        , tick_(sock.get_executor())
        , epoch_(std::chrono::steady_clock::now()) {
        // Pre-handshake caps and strictness come from C1a's defaults; the link
        // flips `handshaked` once, on success.
        cfg_.socket.policy.handshaked = false;
        socket_ = LevinSocket::create(std::move(sock), cfg_.socket);
        peer_.addr = socket_->remote();
        // Seed the cadence jitter from OUR peer id and the remote endpoint, so
        // two connections of the same process to different peers beat out of
        // phase while a single connection stays reproducible in a KAT.
        jitter_state_ = cfg_.handshake.our_peer_id * 0x9E3779B97F4A7C15ull;
        for (char c : peer_.addr)
            jitter_state_ = jitter_state_ * 1099511628211ull ^ static_cast<std::uint8_t>(c);
    }

    // --- handshake ------------------------------------------------------------
    void begin_handshake() {
        if (closed_) return;
        if (!cb_.our_sync_data) {
            fail(LinkClose::BadSyncData, "no sync-data source installed on the link");
            return;
        }
        live_.start(now_ms());
        hs_.on_dialed();

        std::vector<std::uint8_t> body;
        if (!hs_.build_request(cb_.our_sync_data(), body)) {
            fail(LinkClose::HandshakeRefused, hs_.why());
            return;
        }
        if (!send_invoke(CMD_HANDSHAKE, body, cfg_.handshake_timeout_ms)) return;
        arm_tick();
    }

    void on_handshake_response(const std::uint8_t* body, std::size_t n, std::int32_t rc) {
        if (!hs_.on_response(body, n, rc)) {
            fail(LinkClose::HandshakeRefused,
                 std::string(to_string(hs_.failure())) + ": " + hs_.why());
            return;
        }
        // The cap flip. Before this line a frame above 256 KiB, or any command
        // other than 1001/1007, closes the connection; after it the per-command
        // table applies.
        socket_->set_handshaked(true);

        peer_.peer_id = hs_.outcome().node_data.peer_id;
        peer_sync_    = hs_.outcome().payload_data;

        if (cb_.on_handshaked)      cb_.on_handshaked(peer_);
        if (cb_.on_peer_sync_data)  cb_.on_peer_sync_data(peer_, peer_sync_);
        if (cb_.on_peerlist && !hs_.outcome().local_peerlist_new.empty())
            cb_.on_peerlist(peer_, hs_.outcome().local_peerlist_new);

        schedule_next_timed_sync(now_ms());
    }

    // --- TIMED_SYNC, our side -------------------------------------------------
    void send_timed_sync() {
        if (closed_ || !hs_.handshaked()) return;
        TimedSyncRequest req;
        req.payload_data = cb_.our_sync_data();
        std::vector<std::uint8_t> body;
        MessageError merr = MessageError::None;
        if (!encode_timed_sync_request(req, body, merr)) {
            fail(LinkClose::BadMessage,
                 std::string("cannot encode our TIMED_SYNC: ") + to_string(merr));
            return;
        }
        if (!send_invoke(CMD_TIMED_SYNC, body, cfg_.invoke_timeout_ms)) return;
        ++timed_syncs_sent_;
        schedule_next_timed_sync(now_ms());
    }

    void on_timed_sync_response(const std::uint8_t* body, std::size_t n) {
        TimedSyncResponse resp;
        MessageError merr = MessageError::None;
        // CORRECTION (c): the deployed response is payload_data plus
        // local_peerlist_new, and nothing else. An absent or empty
        // local_peerlist_new decodes to an empty vector and is NOT a fault --
        // it is what a peer sends once it has already given us everything it
        // has for this connection.
        if (!decode_timed_sync_response(body, n, resp, merr, cfg_.handshake.limits)) {
            fail(merr == MessageError::TooManyElements ? LinkClose::BadSyncData
                                                       : LinkClose::BadMessage,
                 std::string("undecodable TIMED_SYNC response: ") + to_string(merr));
            return;
        }
        std::string why;
        if (!HandshakeMachine::validate_sync_data(resp.payload_data, why)) {
            fail(LinkClose::BadSyncData, "TIMED_SYNC response: " + why);
            return;
        }
        ++timed_syncs_answered_;
        peer_sync_ = resp.payload_data;
        peer_sync_.support_flags = hs_.outcome().node_data.support_flags;
        if (cb_.on_peer_sync_data) cb_.on_peer_sync_data(peer_, peer_sync_);
        if (cb_.on_peerlist && !resp.local_peerlist_new.empty())
            cb_.on_peerlist(peer_, resp.local_peerlist_new);
    }

    // --- TIMED_SYNC, the peer's side -----------------------------------------
    void answer_timed_sync(const std::uint8_t* body, std::size_t n) {
        TimedSyncRequest req;
        MessageError merr = MessageError::None;
        if (decode_timed_sync_request(body, n, req, merr)) {
            std::string why;
            if (HandshakeMachine::validate_sync_data(req.payload_data, why)) {
                peer_sync_ = req.payload_data;
                peer_sync_.support_flags = hs_.outcome().node_data.support_flags;
                if (cb_.on_peer_sync_data) cb_.on_peer_sync_data(peer_, peer_sync_);
            }
        }
        // Answer regardless of what we made of the peer's half: silence would
        // stall its matcher and get us dropped, and what it told us about
        // ITSELF has no bearing on what we owe it about US.
        TimedSyncResponse resp;
        resp.payload_data = cb_.our_sync_data();
        // CORRECTION (c) again, from the writing side: payload_data and
        // local_peerlist_new only. We are outbound-only and run no peer store
        // of our own to gossip from, so the list is empty -- and an empty
        // container emits NO key at all, which is exactly what monerod does and
        // what its reader expects.
        std::vector<std::uint8_t> out;
        MessageError eerr = MessageError::None;
        if (!encode_timed_sync_response(resp, out, eerr)) {
            fail(LinkClose::BadMessage,
                 std::string("cannot encode our TIMED_SYNC answer: ") + to_string(eerr));
            return;
        }
        if (!socket_->send(make_response(CMD_TIMED_SYNC, out, RC_HANDLER_OK)))
            fail(LinkClose::WriteRefused, "outbound queue full answering TIMED_SYNC");
    }

    void answer_support_flags() {
        SupportFlagsResponse r;
        r.support_flags = cfg_.handshake.support_flags;
        std::vector<std::uint8_t> out;
        MessageError err = MessageError::None;
        if (!encode_support_flags_response(r, out, err)) return;
        if (!socket_->send(make_response(CMD_REQUEST_SUPPORT_FLAGS, out, RC_HANDLER_OK)))
            fail(LinkClose::WriteRefused, "outbound queue full answering support flags");
    }

    void answer_ping() {
        PingResponse r;
        r.status  = PING_OK_RESPONSE_STATUS_TEXT;
        r.peer_id = cfg_.handshake.our_peer_id;
        std::vector<std::uint8_t> out;
        MessageError err = MessageError::None;
        if (!encode_ping_response(r, out, err)) return;
        if (!socket_->send(make_response(CMD_PING, out, RC_HANDLER_OK)))
            fail(LinkClose::WriteRefused, "outbound queue full answering PING");
    }

    void decline_invoke(std::uint32_t cmd) {
        // Keeps the peer's own arrival-order matcher in step. Costs one bare
        // header; staying silent costs the connection.
        socket_->send(make_response(cmd, {}, RC_ERROR_HANDLER_NOT_DEFINED));
    }

    // --- the demux ------------------------------------------------------------
    void on_frame(const BucketHead& h, const std::uint8_t* body, std::size_t n) {
        if (closed_) return;
        const Millis now = now_ms();
        live_.on_inbound_bytes(now);

        switch (classify(h)) {
            case FrameClass::Response: on_response_frame(h, body, n, now); return;
            case FrameClass::Invoke:   on_invoke_frame(h, body, n);        return;
            case FrameClass::Notify:   on_notify_frame(h, body, n, now);   return;
            default:
                // C1a's header policy refuses fragments on clearnet before the
                // body is ever read, so reaching here means the policy was
                // relaxed without teaching this demux about it.
                fail(LinkClose::BadMessage, "fragmented frame on a clearnet link");
                return;
        }
    }

    void on_response_frame(const BucketHead& h, const std::uint8_t* body,
                           std::size_t n, Millis now) {
        InvokeRecord rec;
        InvokeError  err = InvokeError::None;
        if (!invokes_.match_response(h.command, h.return_code, now, rec, err)) {
            if (err == InvokeError::PeerError) {
                // The record WAS consumed: the peer answered, with a refusal.
                if (rec.command == CMD_HANDSHAKE) {
                    hs_.on_response(body, n, h.return_code);
                    fail(LinkClose::HandshakeRefused, hs_.why());
                } else {
                    fail(LinkClose::ReplyMismatch,
                         std::string("peer refused ") + command_name(rec.command)
                         + ": " + return_code_name(h.return_code));
                }
                return;
            }
            fail(err == InvokeError::Unsolicited ? LinkClose::Unsolicited
                                                 : LinkClose::ReplyMismatch,
                 std::string("response to ") + command_name(h.command) + ": "
                 + to_string(err));
            return;
        }

        switch (rec.command) {
            case CMD_HANDSHAKE:             on_handshake_response(body, n, h.return_code); return;
            case CMD_TIMED_SYNC:            on_timed_sync_response(body, n);               return;
            case CMD_REQUEST_SUPPORT_FLAGS: {
                SupportFlagsResponse r;
                MessageError merr = MessageError::None;
                if (decode_support_flags_response(body, n, r, merr))
                    peer_sync_.support_flags = r.support_flags;
                return;
            }
            case CMD_PING: return;   // nothing downstream needs a pong
            default:
                if (cb_.on_frame) cb_.on_frame(peer_, h, body, n);
                return;
        }
    }

    void on_invoke_frame(const BucketHead& h, const std::uint8_t* body, std::size_t n) {
        switch (h.command) {
            case CMD_TIMED_SYNC:
                if (!hs_.handshaked() && !cfg_.answer_timed_sync_before_handshake) {
                    decline_invoke(h.command);
                    return;
                }
                answer_timed_sync(body, n);
                return;
            case CMD_REQUEST_SUPPORT_FLAGS: answer_support_flags(); return;
            case CMD_PING:                  answer_ping();          return;
            default:
                // 2003 / 2006 serving belongs to C1c through IChainServing. If
                // nobody claimed the frame, decline it rather than hang.
                if (cb_.on_frame) { cb_.on_frame(peer_, h, body, n); return; }
                decline_invoke(h.command);
                return;
        }
    }

    void on_notify_frame(const BucketHead& h, const std::uint8_t* body,
                         std::size_t n, Millis now) {
        if (h.command == CMD_RESPONSE_GET_OBJECTS || h.command == CMD_RESPONSE_CHAIN_ENTRY) {
            if (!expect_.accept(h.command, now)) {
                fail(LinkClose::Unsolicited,
                     std::string("unrequested ") + command_name(h.command));
                return;
            }
        } else {
            // Push traffic: a block or transactions arriving unasked is the
            // signal that the peer holds us in state_normal. That is exactly
            // what the silent-starvation tripwire measures.
            live_.on_relay_frame(now);
        }
        if (cb_.on_frame) cb_.on_frame(peer_, h, body, n);
    }

    // --- timers ---------------------------------------------------------------
    void schedule_next_timed_sync(Millis now) {
        next_timed_sync_at_ = now + jittered_interval();
    }

    // Deterministic jitter. A per-connection splitmix64 seeded from the two
    // peer ids, not a global RNG: the spread across a pool is what matters, and
    // a fixed seed makes the cadence reproducible in a KAT.
    Millis jittered_interval() {
        const Millis base = cfg_.timed_sync_interval_ms;
        const Millis j    = cfg_.timed_sync_jitter_ms;
        if (j == 0) return base;
        std::uint64_t z = (jitter_state_ += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        z ^= (z >> 31);
        const std::uint64_t span = 2ull * j + 1ull;
        const Millis offset = static_cast<Millis>(z % span);   // 0 .. 2j
        const Millis low    = (base > j) ? (base - j) : 0;
        return low + offset;
    }

    void arm_tick() {
        if (closed_) return;
        auto self = shared_from_this();
        tick_.expires_after(std::chrono::milliseconds(cfg_.tick_ms));
        tick_.async_wait([self](const boost::system::error_code& ec) {
            if (ec) return;              // cancelled by close
            self->on_tick();
        });
    }

    void on_tick() {
        if (closed_) return;
        const Millis now = now_ms();

        if (const auto exp = invokes_.expired(now)) {
            fail(LinkClose::InvokeTimeout,
                 std::string("no answer to ") + command_name(exp->command)
                 + " within its deadline");
            return;
        }
        if (hs_.handshaked() && live_.timed_out(now, cfg_.peer_timeout_ms)) {
            // Only INBOUND bytes push this deadline, so a peer we keep writing
            // to but never hear from still dies here.
            fail(LinkClose::PeerUnresponsive, "no inbound bytes inside the peer timeout");
            return;
        }
        if (expect_.idle_drop_due(now)) {
            fail(LinkClose::PeerUnresponsive,
                 std::string("no ") + command_name(expect_.expected())
                 + " inside IDLE_PEER_KICK_TIME");
            return;
        }
        if (hs_.handshaked() && next_timed_sync_at_ != 0 && now >= next_timed_sync_at_)
            send_timed_sync();

        arm_tick();
    }

    // --- teardown -------------------------------------------------------------
    void on_socket_closed(const std::string& why) {
        if (closed_) return;
        // The transport ended under us. If the handshake was still owed, that
        // is the more informative reason to report.
        if (!hs_.handshaked()) hs_.on_transport_closed(why);
        finish(LinkClose::TransportError, why);
    }

    void fail(LinkClose reason, const std::string& why) {
        if (closed_) return;
        finish(reason, why);
        socket_->close(why);
    }

    void finish(LinkClose reason, const std::string& why) {
        if (closed_) return;
        closed_       = true;
        close_reason_ = reason;
        close_why_    = why;
        invokes_.clear();
        expect_.disarm();
        tick_.cancel();   // Boost 1.90 dropped the error_code overload
        if (cb_.on_closed) cb_.on_closed(peer_, reason, why);
    }

    LinkConfig    cfg_;
    LinkCallbacks cb_;

    std::shared_ptr<LevinSocket> socket_;
    HandshakeMachine             hs_;
    InvokeQueue                  invokes_;
    ExpectResponse               expect_;
    InboundLiveness              live_;

    boost::asio::steady_timer                          tick_;
    std::chrono::steady_clock::time_point              epoch_;

    PeerRef      peer_{};
    PeerSyncData peer_sync_{};

    Millis        next_timed_sync_at_   = 0;
    std::uint64_t jitter_state_         = 0x243F6A8885A308D3ull;
    std::uint64_t timed_syncs_sent_     = 0;
    std::uint64_t timed_syncs_answered_ = 0;

    bool        closed_       = false;
    LinkClose   close_reason_ = LinkClose::None;
    std::string close_why_;
};

} // namespace c2pool::xmr::native::levin
