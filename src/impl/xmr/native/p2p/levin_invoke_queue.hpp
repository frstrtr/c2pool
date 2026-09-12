// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/p2p/levin_invoke_queue.hpp
//
// Wave 1, component C1b: the per-connection REPLY MATCHER.
//
// THE LOAD-BEARING FACT: levin has no request id. A bucket header carries a
// command, a flags word and a return code -- and nothing that ties an answer to
// the question that provoked it. monerod's own async protocol handler
// (contrib/epee/include/net/levin_protocol_handler_async.h) resolves this by
// running one handler chain per connection and completing invokes in ARRIVAL
// ORDER: `m_invoke_response_handlers` is a std::list, a response pops the
// FRONT, and the connection is dropped when the front's command does not match
// the response's command. This file is that discipline, made explicit:
//
//   * one FIFO of outstanding invokes per connection;
//   * a response pops the front, never a keyed lookup;
//   * front command mismatch  -> WrongCommand -> close (never "search the
//     queue for a better fit": that is exactly how a peer would desynchronise
//     our matcher and steer one answer onto another question);
//   * a response with an empty FIFO -> Unsolicited -> close;
//   * per-record deadlines, because a peer that simply never answers must not
//     pin the slot forever.
//
// The 2003/2006 legs are DIFFERENT and get their own tracker below. Their
// answers (2004 RESPONSE_GET_OBJECTS, 2007 RESPONSE_CHAIN_ENTRY) come back as
// NOTIFICATIONS, not as levin responses, so they never enter this FIFO.
// monerod's connection context keeps `m_state`, `m_last_request_time` and
// `m_expect_response` for exactly that reason (cryptonote_protocol_handler.inl)
// and drops a peer that pushes a 2004/2007 nobody asked for. ExpectResponse
// mirrors those three fields.
//
// PURE: no socket, no timer, no thread. Time enters as a monotonic
// milliseconds argument, so every deadline in here is exercised by a KAT
// without waiting for a wall clock.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record;
// nothing here activates v37 consensus and src/sharechain/v37 is not touched.
//
// STL only. Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <deque>
#include <optional>

#include "impl/xmr/native/p2p/levin_codec.hpp"

namespace c2pool::xmr::native::levin {

// Monotonic milliseconds. Which epoch it counts from is the caller's business;
// only differences are ever used.
using Millis = std::uint64_t;

// --- timeouts ----------------------------------------------------------------
// monerod's own constants (src/p2p/p2p_protocol_defs.h,
// src/cryptonote_config.h, src/cryptonote_protocol/cryptonote_protocol_defs.h).
// Named here so a reader can check them against the daemon without guessing
// which number came from where.
inline constexpr Millis P2P_DEFAULT_CONNECTION_TIMEOUT_MS = 5'000;    // TCP connect + handshake
inline constexpr Millis P2P_DEFAULT_INVOKE_TIMEOUT_MS     = 120'000;  // 60 * 2, every other invoke
inline constexpr Millis P2P_DEFAULT_HANDSHAKE_INTERVAL_MS = 60'000;   // TIMED_SYNC cadence
inline constexpr Millis NON_RESPONSIVE_PEER_KICK_MS       = 20'000;   // 2003/2006 kick
inline constexpr Millis IDLE_PEER_KICK_MS                 = 240'000;  // hard idle ceiling

// Two unanswered TIMED_SYNCs, or four minutes of total silence, is a dead peer.
// Note it is 2x the INVOKE timeout, not 2x the 60 s cadence: a peer whose
// answer is merely slow must not be dropped while its answer is still legal.
inline constexpr Millis PEER_TIMEOUT_MS = 2 * P2P_DEFAULT_INVOKE_TIMEOUT_MS;

// The cadence is jittered so a pool of connections does not fire every
// TIMED_SYNC in the same millisecond (and so a passive observer cannot use the
// beat as a fingerprint). +/- 5 s around 60 s.
inline constexpr Millis TIMED_SYNC_JITTER_MS = 5'000;

// --- return codes: what "success" actually looks like on the wire ------------
// SUCCESS IS NOT `== LEVIN_OK`. This one cost a live run to learn, and it is
// worth spelling out because a codec-only reading of levin_base.h suggests
// otherwise.
//
// epee's async handler does not synthesise a return code for a response: it
// copies THE HANDLER'S OWN RETURN VALUE into the bucket header
// (`head.m_return_code = SWAP32LE(res)` in levin_protocol_handler_async.h,
// where `res` is what m_pcommands_handler.invoke returned). Every monerod admin
// and protocol handler -- handle_handshake, handle_timed_sync, handle_ping,
// handle_get_support_flags -- ends in `return 1;`. So a real HANDSHAKE answer
// from a deployed daemon carries return_code == 1.
//
// The error codes are the negative ones (LEVIN_ERROR_* run -1 .. -7), and
// monerod's own response handlers test exactly that: `if (code < 0) { ... }`.
// We use the same rule, in both directions.
inline constexpr bool rc_is_error(std::int32_t rc) noexcept { return rc < 0; }

// What we put in OUR answers. LEVIN_OK would also be accepted by every peer
// (nothing tests for zero), but 1 is what monerod's handlers actually write, so
// it is what a C6 byte-parity capture expects to see from us.
inline constexpr std::int32_t RC_HANDLER_OK = 1;

// --- outcomes ----------------------------------------------------------------
enum class InvokeError : std::uint8_t {
    None = 0,
    Unsolicited,   // a response arrived with nothing outstanding
    WrongCommand,  // the response answers a command that is not at the front
    Timeout,       // the peer never answered inside the record's deadline
    PeerError,     // the peer answered with a negative levin return code
    Overflow,      // too many invokes already outstanding on this connection
};

inline const char* to_string(InvokeError e) noexcept {
    switch (e) {
        case InvokeError::None:         return "None";
        case InvokeError::Unsolicited:  return "Unsolicited";
        case InvokeError::WrongCommand: return "WrongCommand";
        case InvokeError::Timeout:      return "Timeout";
        case InvokeError::PeerError:    return "PeerError";
        case InvokeError::Overflow:     return "Overflow";
    }
    return "?";
}

// One outstanding question. `seq` is the per-connection sequence number: levin
// gives us no id, so this is the closest thing to one and it is what the
// liveness gauge uses as a "nonce" (design section 2.2) -- purely local, never
// on the wire.
struct InvokeRecord {
    std::uint32_t command     = 0;
    std::uint64_t seq         = 0;
    Millis        sent_at     = 0;
    Millis        deadline_at = 0;
};

// --- the FIFO ----------------------------------------------------------------
class InvokeQueue {
public:
    // A pool-minimal node has at most a handshake plus a TIMED_SYNC plus a
    // support-flags probe in flight. Eight is generous; beyond it we are the
    // ones misbehaving, and saying so loudly beats growing a deque.
    static constexpr std::size_t MAX_OUTSTANDING = 8;

    // Registers an invoke we have just written. Returns the record's sequence
    // number, or nullopt when the connection already has MAX_OUTSTANDING
    // questions in the air (the caller must not send the frame in that case).
    std::optional<std::uint64_t> push(std::uint32_t command, Millis now, Millis timeout_ms) {
        if (q_.size() >= MAX_OUTSTANDING) return std::nullopt;
        InvokeRecord r;
        r.command     = command;
        r.seq         = ++seq_;
        r.sent_at     = now;
        r.deadline_at = now + timeout_ms;
        q_.push_back(r);
        return r.seq;
    }

    // Matches an inbound Response frame. FIFO: pops the FRONT or fails. On
    // failure the caller closes the connection -- there is no recovery, because
    // after one mismatched answer we no longer know what any later answer is
    // answering.
    //
    // `return_code` is the levin rc from the bucket header, and only a NEGATIVE
    // one is a refusal (see rc_is_error above: monerod answers a healthy invoke
    // with its handler's `return 1`). A refusal is still a real answer to the
    // front record, so the record IS consumed; it reports PeerError, which the
    // caller turns into a fault for that request.
    bool match_response(std::uint32_t command,
                        std::int32_t  return_code,
                        Millis        now,
                        InvokeRecord& out,
                        InvokeError&  err) {
        err = InvokeError::None;
        if (q_.empty()) { err = InvokeError::Unsolicited; return false; }
        if (q_.front().command != command) { err = InvokeError::WrongCommand; return false; }
        out = q_.front();
        q_.pop_front();
        last_matched_rtt_ms_ = (now >= out.sent_at) ? (now - out.sent_at) : 0;
        if (rc_is_error(return_code)) { err = InvokeError::PeerError; return false; }
        return true;
    }

    // The oldest record whose deadline has passed, if any. Deadlines are per
    // record and the timeouts differ by command (5 s handshake, 120 s the
    // rest), so this scans rather than peeking the front; the queue is at most
    // MAX_OUTSTANDING long.
    std::optional<InvokeRecord> expired(Millis now) const {
        const InvokeRecord* oldest = nullptr;
        for (const InvokeRecord& r : q_) {
            if (now < r.deadline_at) continue;
            if (!oldest || r.sent_at < oldest->sent_at) oldest = &r;
        }
        if (!oldest) return std::nullopt;
        return *oldest;
    }

    bool        empty() const noexcept { return q_.empty(); }
    std::size_t size()  const noexcept { return q_.size(); }
    std::uint64_t last_seq() const noexcept { return seq_; }

    // Round-trip time of the most recently matched response. This is the
    // per-peer latency gauge the observability surface reports (design section
    // 7: "last TIMED_SYNC round-trip").
    Millis last_matched_rtt_ms() const noexcept { return last_matched_rtt_ms_; }

    const InvokeRecord* front() const noexcept { return q_.empty() ? nullptr : &q_.front(); }

    // Connection is going away: every outstanding question is now unanswerable.
    void clear() noexcept { q_.clear(); }

private:
    std::deque<InvokeRecord> q_;
    std::uint64_t            seq_ = 0;
    Millis                   last_matched_rtt_ms_ = 0;
};

// --- the notify-answered legs ------------------------------------------------
// 2003 REQUEST_GET_OBJECTS is answered by a 2004 NOTIFICATION, and 2006
// REQUEST_CHAIN by a 2007 NOTIFICATION. Because they are notifications they
// carry no response flag and never reach InvokeQueue; monerod tracks them with
// `m_expect_response` + `m_last_request_time` on the connection context and
// drops a peer that sends one unasked. Exactly one such request may be in
// flight per connection, which is also monerod's behaviour (it asks the next
// chunk only after the previous answer lands).
inline constexpr std::uint32_t response_command_for(std::uint32_t request_cmd) noexcept {
    if (request_cmd == CMD_REQUEST_GET_OBJECTS) return CMD_RESPONSE_GET_OBJECTS;
    if (request_cmd == CMD_REQUEST_CHAIN)       return CMD_RESPONSE_CHAIN_ENTRY;
    return 0;
}

class ExpectResponse {
public:
    // Arms the tracker for a 2003 or 2006 we are about to write. False when the
    // command has no notify answer or one is already outstanding.
    bool arm(std::uint32_t request_cmd, Millis now) noexcept {
        const std::uint32_t expect = response_command_for(request_cmd);
        if (expect == 0 || expected_ != 0) return false;
        expected_        = expect;
        requested_cmd_   = request_cmd;
        last_request_at_ = now;
        return true;
    }

    // Accepts an inbound notification. True disarms; false means the peer sent
    // a 2004/2007 we never asked for, which is a close.
    bool accept(std::uint32_t notify_cmd, Millis now) noexcept {
        if (expected_ == 0 || notify_cmd != expected_) return false;
        last_rtt_ms_   = (now >= last_request_at_) ? (now - last_request_at_) : 0;
        expected_      = 0;
        requested_cmd_ = 0;
        return true;
    }

    // monerod's own two-stage rule: NON_RESPONSIVE_PEER_KICK_TIME (20 s) is
    // when the request is re-aimed at another peer, IDLE_PEER_KICK_TIME (240 s)
    // is when the connection itself is dropped.
    bool kick_due(Millis now, Millis kick_ms = NON_RESPONSIVE_PEER_KICK_MS) const noexcept {
        return expected_ != 0 && now >= last_request_at_ + kick_ms;
    }
    bool idle_drop_due(Millis now, Millis idle_ms = IDLE_PEER_KICK_MS) const noexcept {
        return expected_ != 0 && now >= last_request_at_ + idle_ms;
    }

    void disarm() noexcept { expected_ = 0; requested_cmd_ = 0; }

    bool          armed()          const noexcept { return expected_ != 0; }
    std::uint32_t expected()       const noexcept { return expected_; }
    std::uint32_t requested_cmd()  const noexcept { return requested_cmd_; }
    Millis        last_request_at()const noexcept { return last_request_at_; }
    Millis        last_rtt_ms()    const noexcept { return last_rtt_ms_; }

private:
    std::uint32_t expected_        = 0;
    std::uint32_t requested_cmd_   = 0;
    Millis        last_request_at_ = 0;
    Millis        last_rtt_ms_     = 0;
};

// --- inbound liveness --------------------------------------------------------
// THE INVARIANT worth stating on its own: only INBOUND bytes push the deadline.
// A connection that we keep writing to is not alive; a connection that answers
// is. Reusing the DASH PeerLiveness semantics with TIMED_SYNC in place of
// ping/pong (design section 2.2) means this one rule carries over unchanged.
class InboundLiveness {
public:
    void on_inbound_bytes(Millis now) noexcept {
        last_inbound_at_ = now;
        if (first_inbound_at_ == 0) first_inbound_at_ = now;
    }
    void on_relay_frame(Millis now) noexcept { relay_seen_at_ = now; }
    void start(Millis now) noexcept { last_inbound_at_ = now; }

    bool timed_out(Millis now, Millis peer_timeout_ms = PEER_TIMEOUT_MS) const noexcept {
        return now >= last_inbound_at_ + peer_timeout_ms;
    }

    // The silent-starvation tripwire from design section 2.3: handshaked, the
    // socket is healthy, and yet no relay frame has ever arrived. Two block
    // intervals of that means the peer is holding us in state_synchronizing.
    bool relay_silent(Millis now, Millis window_ms = 240'000) const noexcept {
        const Millis since = (relay_seen_at_ != 0) ? relay_seen_at_ : first_inbound_at_;
        return since != 0 && now >= since + window_ms;
    }

    Millis last_inbound_at() const noexcept { return last_inbound_at_; }
    Millis relay_seen_at()   const noexcept { return relay_seen_at_; }

private:
    Millis last_inbound_at_  = 0;
    Millis first_inbound_at_ = 0;
    Millis relay_seen_at_    = 0;
};

} // namespace c2pool::xmr::native::levin
