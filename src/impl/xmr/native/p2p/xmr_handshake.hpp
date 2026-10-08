// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/p2p/xmr_handshake.hpp
//
// Wave 1, component C1b: the COMMAND_HANDSHAKE (1001) state machine and the
// sync-data validator, as a PURE object -- no socket, no timer, no thread.
// LevinLink (xmr_levin_link.hpp) drives it; this file decides.
//
//   Idle -> Dialed -> HandshakeSent -> Handshaked
//                                   \-> Failed(reason)
//
// What we send (design section 2.1, monerod src/p2p/net_node.inl
// try_to_connect_and_handshake_with_new_peer):
//
//   node_data    = { network_id, peer_id (random per process), my_port = 0,
//                    rpc_port = 0, rpc_credits_per_hash = 0,
//                    support_flags = 1 (FLUFFY_BLOCKS) }
//   payload_data = CORE_SYNC_DATA from IChainServing::our_sync_data()
//
// TWO DELIBERATE ZEROES. `my_port = 0` tells the peer we accept no inbound, so
// it skips its COMMAND_PING call-back and never white-lists us -- correct for
// an outbound-only client and one fewer round trip. `support_flags = 1` sent up
// front means the peer never has to invoke REQUEST_SUPPORT_FLAGS (1007) on us
// to learn we speak fluffy blocks (we still answer it if asked).
//
// What we REFUSE in the response, and why each one is a close rather than a
// warning:
//
//   * network_id mismatch  -- the peer is on another Monero network. Every
//     subsequent block would be off-chain. monerod bans for this.
//   * peer_id == ours      -- we dialled ourselves. Keeping it wastes a slot
//     and poisons the "witnesses per block" measurement with our own echo.
//   * peer_id == 0         -- no honest daemon sends this; it breaks the
//     per-connection identity every fault attribution hangs on.
//   * peerlist > 250       -- P2P_MAX_PEERS_IN_HANDSHAKE. monerod's own word
//     for it is "spamming"; enforced inside C1a's decoder as TooManyElements.
//   * pruning_seed neither 0 nor a valid seed -- monerod's
//     process_payload_sync_data refuses it, so a peer sending it is either
//     broken or probing.
//
// WHAT WE DO NOT REFUSE, and this is the asymmetry that matters: the peer's
// `top_version` is NOT checked against our fork table here. THE PEER checks
// OURS (design section 2.3) and disconnects if our top_version is not its ideal
// version at current_height - 1. Ours comes from C2's hard-fork table through
// our_sync_data(); a stale table kills every connection at the next fork, which
// is why R-HFFUSE lives in C2a and not here. Refusing the peer's version as
// well would only make us drop honest peers during the fork window in both
// directions.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record;
// nothing here activates v37 consensus and src/sharechain/v37 is not touched.
//
// STL only. Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "impl/xmr/native/p2p/levin_invoke_queue.hpp"
#include "impl/xmr/native/p2p/levin_messages.hpp"

namespace c2pool::xmr::native::levin {

// --- pruning seeds -----------------------------------------------------------
// src/cryptonote_basic/pruning.h. A seed packs (log_stripes, stripe) as
// (log_stripes << 7) | (stripe - 1), and only log_stripes == 3 with stripe in
// 1..8 is a seed any deployed daemon produces. Zero means "not pruned".
inline constexpr std::uint32_t PRUNING_SEED_LOG_STRIPES_SHIFT = 7;
inline constexpr std::uint32_t PRUNING_SEED_LOG_STRIPES_MASK  = 0x7;
inline constexpr std::uint32_t PRUNING_SEED_STRIPE_MASK       = 0x7f;
inline constexpr std::uint32_t PRUNING_LOG_STRIPES            = 3;

inline constexpr std::uint32_t pruning_log_stripes(std::uint32_t seed) noexcept {
    return (seed >> PRUNING_SEED_LOG_STRIPES_SHIFT) & PRUNING_SEED_LOG_STRIPES_MASK;
}
inline constexpr std::uint32_t pruning_stripe(std::uint32_t seed) noexcept {
    return (seed & PRUNING_SEED_STRIPE_MASK) + 1;
}
inline constexpr bool is_valid_pruning_seed(std::uint32_t seed) noexcept {
    if (seed == 0) return true;   // not pruned: the common case
    if (pruning_log_stripes(seed) != PRUNING_LOG_STRIPES) return false;
    const std::uint32_t stripe = pruning_stripe(seed);
    return stripe >= 1 && stripe <= (1u << PRUNING_LOG_STRIPES);
}

// --- states ------------------------------------------------------------------
enum class HandshakeState : std::uint8_t {
    Idle = 0,       // constructed, nothing dialled
    Dialed,         // TCP is up, nothing written
    HandshakeSent,  // the 1001 invoke is on the wire, the answer is owed
    Handshaked,     // validated; the connection is usable
    Failed,         // terminal; `failure()` says why
};

inline const char* to_string(HandshakeState s) noexcept {
    switch (s) {
        case HandshakeState::Idle:          return "Idle";
        case HandshakeState::Dialed:        return "Dialed";
        case HandshakeState::HandshakeSent: return "HandshakeSent";
        case HandshakeState::Handshaked:    return "Handshaked";
        case HandshakeState::Failed:        return "Failed";
    }
    return "?";
}

enum class HandshakeFailure : std::uint8_t {
    None = 0,
    ConnectFailed,
    Timeout,
    BadEncoding,        // the body is not a decodable 1001 response
    NetworkIdMismatch,
    SelfConnect,
    ZeroPeerId,
    PeerlistSpam,       // > 250 entries, or an entry that does not decode
    BadPruningSeed,
    PeerError,          // the peer answered with a negative levin return code
    WrongState,         // a response arrived when none was owed (caller bug or peer trick)
    TransportClosed,
};

inline const char* to_string(HandshakeFailure f) noexcept {
    switch (f) {
        case HandshakeFailure::None:              return "None";
        case HandshakeFailure::ConnectFailed:     return "ConnectFailed";
        case HandshakeFailure::Timeout:           return "Timeout";
        case HandshakeFailure::BadEncoding:       return "BadEncoding";
        case HandshakeFailure::NetworkIdMismatch: return "NetworkIdMismatch";
        case HandshakeFailure::SelfConnect:       return "SelfConnect";
        case HandshakeFailure::ZeroPeerId:        return "ZeroPeerId";
        case HandshakeFailure::PeerlistSpam:      return "PeerlistSpam";
        case HandshakeFailure::BadPruningSeed:    return "BadPruningSeed";
        case HandshakeFailure::PeerError:         return "PeerError";
        case HandshakeFailure::WrongState:        return "WrongState";
        case HandshakeFailure::TransportClosed:   return "TransportClosed";
    }
    return "?";
}

// --- configuration -----------------------------------------------------------
struct HandshakeConfig {
    XmrNet        net                  = XmrNet::Stagenet;
    std::uint64_t our_peer_id          = 0;   // random per process; never 0 in practice
    std::uint32_t my_port              = 0;   // R-LISTEN: outbound-only in v1
    std::uint16_t rpc_port             = 0;
    std::uint32_t rpc_credits_per_hash = 0;
    std::uint32_t support_flags        = SUPPORT_FLAG_FLUFFY_BLOCKS;
    MessageLimits limits{};                   // max_peerlist_entries = 250
};

// What the caller gets when the handshake lands.
struct HandshakeOutcome {
    BasicNodeData              node_data{};
    PeerSyncData               payload_data{};
    std::vector<PeerlistEntry> local_peerlist_new;
};

// --- the machine -------------------------------------------------------------
class HandshakeMachine {
public:
    explicit HandshakeMachine(HandshakeConfig cfg) : cfg_(cfg) {}

    HandshakeState   state()   const noexcept { return state_; }
    HandshakeFailure failure() const noexcept { return failure_; }
    const std::string& why()   const noexcept { return why_; }
    const HandshakeOutcome& outcome() const noexcept { return outcome_; }
    const HandshakeConfig&  config()  const noexcept { return cfg_; }

    bool handshaked() const noexcept { return state_ == HandshakeState::Handshaked; }
    bool terminal()   const noexcept { return state_ == HandshakeState::Failed; }

    void on_dialed() noexcept {
        if (state_ == HandshakeState::Idle) state_ = HandshakeState::Dialed;
    }

    void on_connect_failed(const std::string& why) { fail(HandshakeFailure::ConnectFailed, why); }
    void on_transport_closed(const std::string& why) {
        if (state_ == HandshakeState::Handshaked || state_ == HandshakeState::Failed) return;
        fail(HandshakeFailure::TransportClosed, why);
    }
    void on_timeout() { fail(HandshakeFailure::Timeout, "no HANDSHAKE response inside the connect timeout"); }

    // Builds the 1001 request BODY (not the frame; LevinLink wraps it with
    // make_invoke). `our_sync` is C2's answer to IChainServing::our_sync_data().
    bool build_request(const PeerSyncData&        our_sync,
                       std::vector<std::uint8_t>& body_out) {
        if (state_ != HandshakeState::Dialed) {
            fail(HandshakeFailure::WrongState, "build_request outside Dialed");
            return false;
        }
        HandshakeRequest req;
        req.node_data.network_id           = network_id_of(cfg_.net);
        req.node_data.peer_id              = cfg_.our_peer_id;
        req.node_data.my_port              = cfg_.my_port;
        req.node_data.rpc_port             = cfg_.rpc_port;
        req.node_data.rpc_credits_per_hash = cfg_.rpc_credits_per_hash;
        req.node_data.support_flags        = cfg_.support_flags;
        req.payload_data                   = our_sync;

        MessageError merr = MessageError::None;
        if (!encode_handshake_request(req, body_out, merr)) {
            fail(HandshakeFailure::BadEncoding,
                 std::string("cannot encode our own HANDSHAKE: ") + to_string(merr));
            return false;
        }
        sent_ = req;
        state_ = HandshakeState::HandshakeSent;
        return true;
    }

    // Consumes the 1001 response body. True => Handshaked, and outcome() holds
    // the peer's node data, sync data and peerlist. False => Failed, and
    // failure()/why() say which rule the peer broke.
    bool on_response(const std::uint8_t* body, std::size_t size, std::int32_t return_code) {
        if (state_ != HandshakeState::HandshakeSent) {
            fail(HandshakeFailure::WrongState, "HANDSHAKE response with none outstanding");
            return false;
        }
        // Only a NEGATIVE return code is a refusal. A deployed monerod answers
        // a good handshake with 1 -- epee copies handle_handshake's own
        // `return 1` into the header -- so insisting on LEVIN_OK here refuses
        // every honest daemon. See rc_is_error in levin_invoke_queue.hpp.
        if (rc_is_error(return_code)) {
            fail(HandshakeFailure::PeerError,
                 std::string("peer refused the handshake: ") + return_code_name(return_code));
            return false;
        }

        HandshakeResponse resp;
        MessageError merr = MessageError::None;
        if (!decode_handshake_response(body, size, resp, merr, cfg_.limits)) {
            // The 250-entry ceiling is enforced by C1a's decoder, so a peerlist
            // overrun surfaces here as TooManyElements. Report it as the
            // protocol rule it is rather than as a generic parse failure -- the
            // two get different peer scores upstream.
            if (merr == MessageError::TooManyElements) {
                fail(HandshakeFailure::PeerlistSpam,
                     "local_peerlist_new above P2P_MAX_PEERS_IN_HANDSHAKE (250)");
            } else {
                fail(HandshakeFailure::BadEncoding,
                     std::string("undecodable HANDSHAKE response: ") + to_string(merr));
            }
            return false;
        }

        if (resp.node_data.network_id != network_id_of(cfg_.net)) {
            fail(HandshakeFailure::NetworkIdMismatch, "peer is on a different Monero network");
            return false;
        }
        if (resp.node_data.peer_id == 0) {
            fail(HandshakeFailure::ZeroPeerId, "peer advertised peer_id 0");
            return false;
        }
        if (resp.node_data.peer_id == cfg_.our_peer_id) {
            fail(HandshakeFailure::SelfConnect, "peer_id equals ours: this is our own daemon");
            return false;
        }
        if (resp.local_peerlist_new.size() > cfg_.limits.max_peerlist_entries) {
            fail(HandshakeFailure::PeerlistSpam, "local_peerlist_new above the handshake ceiling");
            return false;
        }
        if (!is_valid_pruning_seed(resp.payload_data.pruning_seed)) {
            fail(HandshakeFailure::BadPruningSeed, "peer advertised an impossible pruning seed");
            return false;
        }

        // support_flags lives in basic_node_data, not CORE_SYNC_DATA; C1a's
        // decoder leaves the sync-data copy at zero on purpose. Fill it in here
        // so downstream sees one coherent view of the peer.
        outcome_.node_data    = resp.node_data;
        outcome_.payload_data = resp.payload_data;
        outcome_.payload_data.support_flags = resp.node_data.support_flags;
        outcome_.local_peerlist_new = std::move(resp.local_peerlist_new);

        state_   = HandshakeState::Handshaked;
        failure_ = HandshakeFailure::None;
        why_.clear();
        return true;
    }

    // Validates a sync-data update arriving later (a TIMED_SYNC response, or an
    // inbound TIMED_SYNC request). Same pruning-seed rule; height going
    // backwards is a peer SCORE event upstream, not a close, so it is reported
    // and not enforced here.
    static bool validate_sync_data(const PeerSyncData& s, std::string& why) {
        if (!is_valid_pruning_seed(s.pruning_seed)) {
            why = "impossible pruning seed";
            return false;
        }
        if (s.current_height == 0) {
            // current_height is "tip + 1" and every chain has a genesis, so 0
            // is not a slow peer, it is a malformed one.
            why = "current_height 0";
            return false;
        }
        return true;
    }

    // What we advertised, for the parity capture hooks in C6.
    const HandshakeRequest& sent() const noexcept { return sent_; }

private:
    void fail(HandshakeFailure f, const std::string& why) {
        state_   = HandshakeState::Failed;
        failure_ = f;
        why_     = why;
    }

    HandshakeConfig  cfg_;
    HandshakeState   state_   = HandshakeState::Idle;
    HandshakeFailure failure_ = HandshakeFailure::None;
    std::string      why_;
    HandshakeRequest sent_{};
    HandshakeOutcome outcome_{};
};

} // namespace c2pool::xmr::native::levin
