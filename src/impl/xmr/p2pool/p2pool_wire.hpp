// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/p2pool_wire.hpp
//
// THE P2POOL P2P FRAMING, and -- more important than the framing -- the place
// where READ-ONLY stops being a promise and becomes a shape.
//
// The wire is deliberately plain: no magic prefix, no command string, no
// checksum, no length on most messages. A frame is one message-id byte
// followed by a body whose length is a function of the id alone (17 bytes for a
// handshake challenge, 33 for a block request, 2 + 19n for a peer list) except
// for four ids that carry an explicit little-endian u32 length. There is
// nothing to resynchronise on, which is why frame_size() below refuses a bad id
// outright instead of scanning forward: a reader that can be steered to
// resynchronise is a reader an attacker can steer.
//
// ---------------------------------------------------------------------------
// THE WRITE SURFACE IS AN ENUM WITH FOUR VALUES
// ---------------------------------------------------------------------------
// P2Pool's protocol has twelve message ids. Five of them PUBLISH: BLOCK_RESPONSE
// and BLOCK_BROADCAST and BLOCK_BROADCAST_COMPACT hand a sidechain block to a
// peer, AUX_JOB_DONATION hands it a merge-mining job, MONERO_BLOCK_BROADCAST
// hands it a Monero block. Two more ANNOUNCE: LISTEN_PORT tells a peer we are
// reachable, which is what makes it put us in its peer list and gossip our
// address onward, and BLOCK_NOTIFY tells it we hold a block.
//
// This tree can encode NONE of those seven. `ControlMessage` has exactly four
// values, `encode()` is the only function anywhere under p2pool/ that returns
// bytes destined for a socket, and it is a total function over that enum -- so
// "can this observer publish?" is answered by reading one enum declaration
// rather than by auditing a call graph. There is no PoolBlock serialiser in
// this tree at all: p2pool_block.hpp declares `deserialize` and nothing that
// writes. The KAT (test/p2pool_parse_kat.cpp) pins the encoder's id set at
// {0, 1, 3, 6} so that adding a fifth encoder is a test failure, not a review
// oversight.
//
// The four that remain, and why each is a read and not a write:
//
//   HANDSHAKE_CHALLENGE / HANDSHAKE_SOLUTION -- the membership proof. Both are
//       fixed-size hashes of a random challenge and the consensus id. They
//       carry no chain data and change nothing on the peer beyond letting the
//       connection continue.
//   BLOCK_REQUEST -- "send me the block with this id" (all-zero id means "your
//       current tip"). It is a GET: 33 constant bytes, no payload, and the
//       peer's answer is the only thing that moves. It cannot add, replace or
//       advertise anything.
//   PEER_LIST_REQUEST -- one byte, "who else do you know". Upstream rate-limits
//       it to one per 60 seconds and answers an empty list if asked sooner.
//
// LISTEN_PORT is the interesting omission and it is deliberate. Sending it
// would put this observer into every peer's gossiped peer list, which is a
// write to P2Pool's peer state even though it is not a write to its sidechain.
// Not sending it has one consequence, and the consequence is in the upstream
// source: P2PClient::is_good() requires m_listenPort >= 0, and on_broadcast()
// skips peers that are not good -- so a node that never announces a port is
// never SENT block broadcasts. This observer therefore PULLS: it polls the tip
// with BLOCK_REQUEST and walks parents. See p2pool_observer.hpp for the timing
// rule that keeps a pulling peer from being disconnected as idle.
//
// Header-only, STL only. Nothing here hashes, connects or allocates beyond the
// caller's buffer.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "impl/xmr/p2pool/p2pool_consensus.hpp"

namespace c2pool::xmr::p2pool {

// p2pool src/p2p_server.h :: P2PServer::MessageId. The numbering is positional
// in upstream's enum; it is spelled out here so a future upstream insertion is
// a visible conflict rather than a silent renumber.
enum class MessageId : std::uint8_t {
    HandshakeChallenge    = 0,
    HandshakeSolution     = 1,
    ListenPort            = 2,
    BlockRequest          = 3,
    BlockResponse         = 4,
    BlockBroadcast        = 5,
    PeerListRequest       = 6,
    PeerListResponse      = 7,
    BlockBroadcastCompact = 8,
    BlockNotify           = 9,
    AuxJobDonation        = 10,
    MoneroBlockBroadcast  = 11,
};
inline constexpr std::uint8_t kLastMessageId = 11;

inline const char* to_string(MessageId id) noexcept {
    switch (id) {
        case MessageId::HandshakeChallenge:    return "HANDSHAKE_CHALLENGE";
        case MessageId::HandshakeSolution:     return "HANDSHAKE_SOLUTION";
        case MessageId::ListenPort:            return "LISTEN_PORT";
        case MessageId::BlockRequest:          return "BLOCK_REQUEST";
        case MessageId::BlockResponse:         return "BLOCK_RESPONSE";
        case MessageId::BlockBroadcast:        return "BLOCK_BROADCAST";
        case MessageId::PeerListRequest:       return "PEER_LIST_REQUEST";
        case MessageId::PeerListResponse:      return "PEER_LIST_RESPONSE";
        case MessageId::BlockBroadcastCompact: return "BLOCK_BROADCAST_COMPACT";
        case MessageId::BlockNotify:           return "BLOCK_NOTIFY";
        case MessageId::AuxJobDonation:        return "AUX_JOB_DONATION";
        case MessageId::MoneroBlockBroadcast:  return "MONERO_BLOCK_BROADCAST";
    }
    return "?";
}

inline constexpr std::size_t kChallengeSize       = 8;
inline constexpr std::size_t kHashSize            = 32;
inline constexpr std::uint64_t kChallengeDifficulty = 10000;   // p2pool CHALLENGE_DIFFICULTY
inline constexpr std::size_t kPeerEntrySize       = 19;        // 1 flag + 16 ip + 2 port
inline constexpr std::size_t kPeerListMaxPeers    = 16;        // PEER_LIST_RESPONSE_MAX_PEERS

// The wire is little-endian everywhere. Hosts c2pool builds on are too, but the
// conversion is spelled out rather than assumed so a big-endian port cannot
// quietly misread a length; these are no-ops on LE.
inline constexpr std::uint32_t le32(std::uint32_t v) noexcept {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    return __builtin_bswap32(v);
#else
    return v;
#endif
}

inline constexpr std::uint16_t le16(std::uint16_t v) noexcept {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    return __builtin_bswap16(v);
#else
    return v;
#endif
}

// ---------------------------------------------------------------------------
// FRAME SPLITTING (read side)
// ---------------------------------------------------------------------------
enum class FrameStatus : std::uint8_t {
    Complete = 0,   // `size` holds the whole frame length
    Incomplete,     // need more bytes; `size` is a lower bound on what is needed
    BadId,          // message id above LAST -- fatal, close the connection
    TooBig,         // length-prefixed body above MAX_BLOCK_SIZE -- fatal
};

// How many bytes the frame starting at `buf` occupies, if that is knowable yet.
// Never reads past `avail`, never modifies anything.
inline FrameStatus frame_size(const std::uint8_t* buf, std::size_t avail,
                              std::size_t& size) noexcept {
    size = 0;
    if (avail < 1) { size = 1; return FrameStatus::Incomplete; }
    const std::uint8_t raw = buf[0];
    if (raw > kLastMessageId) return FrameStatus::BadId;

    const MessageId id = static_cast<MessageId>(raw);
    switch (id) {
        case MessageId::HandshakeChallenge:
            size = 1 + kChallengeSize + sizeof(std::uint64_t);       // 17
            break;
        case MessageId::HandshakeSolution:
            size = 1 + kHashSize + kChallengeSize;                   // 41
            break;
        case MessageId::ListenPort:
            size = 1 + sizeof(std::int32_t);                         // 5
            break;
        case MessageId::BlockRequest:
        case MessageId::BlockNotify:
            size = 1 + kHashSize;                                    // 33
            break;
        case MessageId::PeerListRequest:
            size = 1;
            break;
        case MessageId::PeerListResponse: {
            if (avail < 2) { size = 2; return FrameStatus::Incomplete; }
            const std::size_t n = buf[1];
            if (n > kPeerListMaxPeers) return FrameStatus::TooBig;
            size = 2 + n * kPeerEntrySize;
            break;
        }
        case MessageId::BlockResponse:
        case MessageId::BlockBroadcast:
        case MessageId::BlockBroadcastCompact:
        case MessageId::AuxJobDonation:
        case MessageId::MoneroBlockBroadcast: {
            if (avail < 5) { size = 5; return FrameStatus::Incomplete; }
            std::uint32_t len = 0;
            std::memcpy(&len, buf + 1, sizeof(len));                 // wire is LE
            len = le32(len);
            if (len > kMaxBlockSize) return FrameStatus::TooBig;
            size = 5 + static_cast<std::size_t>(len);
            break;
        }
    }
    return (avail >= size) ? FrameStatus::Complete : FrameStatus::Incomplete;
}

// Payload length of a length-prefixed frame; 0 for every other id.
inline std::uint32_t frame_body_length(const std::uint8_t* buf, std::size_t frame_len) noexcept {
    if (frame_len < 5) return 0;
    std::uint32_t len = 0;
    std::memcpy(&len, buf + 1, sizeof(len));
    return le32(len);
}

// ---------------------------------------------------------------------------
// THE WRITE SURFACE -- all of it
// ---------------------------------------------------------------------------
// Four values. Adding a fifth is the only way this observer could ever put a
// byte on the wire that is not one of these, and the KAT pins the set.
enum class ControlMessage : std::uint8_t {
    HandshakeChallenge = 0,   // 17 bytes: our challenge + our ephemeral peer id
    HandshakeSolution  = 1,   // 41 bytes: keccak solution + salt
    BlockRequest       = 2,   // 33 bytes: "send me this block" (zero id = tip)
    PeerListRequest    = 3,   // 1 byte:   "who else do you know"
};

inline constexpr std::size_t kControlMessageCount = 4;

// The p2pool message id each control message is emitted as. This is the
// observer's ENTIRE outbound id set, and nothing outside it can be produced.
inline MessageId wire_id_of(ControlMessage c) noexcept {
    switch (c) {
        case ControlMessage::HandshakeChallenge: return MessageId::HandshakeChallenge;
        case ControlMessage::HandshakeSolution:  return MessageId::HandshakeSolution;
        case ControlMessage::BlockRequest:       return MessageId::BlockRequest;
        case ControlMessage::PeerListRequest:    return MessageId::PeerListRequest;
    }
    return MessageId::PeerListRequest;
}

// Arguments for the two control messages that carry a value. A block id of all
// zeroes asks for the peer's current sidechain tip, which is how upstream
// spells it too (SideChain::get_block_blob).
struct ControlArgs {
    std::array<std::uint8_t, kChallengeSize> challenge{};   // HandshakeChallenge
    std::uint64_t                            peer_id = 0;   // HandshakeChallenge
    std::array<std::uint8_t, kHashSize>      solution{};     // HandshakeSolution
    std::array<std::uint8_t, kChallengeSize> salt{};         // HandshakeSolution
    std::array<std::uint8_t, kHashSize>      block_id{};     // BlockRequest
};

// THE ONLY OUTBOUND ENCODER IN THIS TREE. Appends to `out`.
inline void encode(ControlMessage c, const ControlArgs& a, std::vector<std::uint8_t>& out) {
    out.push_back(static_cast<std::uint8_t>(wire_id_of(c)));
    switch (c) {
        case ControlMessage::HandshakeChallenge: {
            out.insert(out.end(), a.challenge.begin(), a.challenge.end());
            std::uint64_t k = a.peer_id;
            for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
                out.push_back(static_cast<std::uint8_t>(k & 0xFFu));
                k >>= 8;
            }
            break;
        }
        case ControlMessage::HandshakeSolution:
            out.insert(out.end(), a.solution.begin(), a.solution.end());
            out.insert(out.end(), a.salt.begin(), a.salt.end());
            break;
        case ControlMessage::BlockRequest:
            out.insert(out.end(), a.block_id.begin(), a.block_id.end());
            break;
        case ControlMessage::PeerListRequest:
            break;
    }
}

inline std::vector<std::uint8_t> encode(ControlMessage c, const ControlArgs& a) {
    std::vector<std::uint8_t> out;
    out.reserve(48);
    encode(c, a, out);
    return out;
}

// ---------------------------------------------------------------------------
// PEER_LIST_RESPONSE decoding
// ---------------------------------------------------------------------------
// 19 bytes per entry: an is-v6 flag, a 16-byte address (IPv4 lives in the last
// four bytes behind the ::ffff: prefix) and a little-endian port. Upstream
// smuggles a VERSION announcement through the same shape -- address bytes
// 12..15 all 0xFF and port 0xFFFF -- so that older clients, which skip such an
// entry as an unusable address, ignore it harmlessly.
struct PeerEntry {
    bool                              is_v6 = false;
    std::array<std::uint8_t, 16>      addr{};
    std::uint16_t                     port = 0;

    bool is_version_announcement() const noexcept {
        return port == 0xFFFFu && addr[12] == 0xFF && addr[13] == 0xFF
            && addr[14] == 0xFF && addr[15] == 0xFF;
    }
    std::uint32_t announced_protocol_version() const noexcept {
        std::uint32_t v = 0; std::memcpy(&v, addr.data(), 4); return le32(v);
    }
    std::uint32_t announced_software_version() const noexcept {
        std::uint32_t v = 0; std::memcpy(&v, addr.data() + 4, 4); return le32(v);
    }
    std::uint32_t announced_software_id() const noexcept {
        std::uint32_t v = 0; std::memcpy(&v, addr.data() + 8, 4); return le32(v);
    }
    bool is_ipv4_mapped() const noexcept {
        static const std::uint8_t pfx[12] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF};
        return std::memcmp(addr.data(), pfx, 12) == 0;
    }
};

// `frame` must be a COMPLETE PEER_LIST_RESPONSE frame as measured by frame_size.
inline bool decode_peer_list(const std::uint8_t* frame, std::size_t frame_len,
                             std::vector<PeerEntry>& out) {
    out.clear();
    if (frame_len < 2 || frame[0] != static_cast<std::uint8_t>(MessageId::PeerListResponse))
        return false;
    const std::size_t n = frame[1];
    if (n > kPeerListMaxPeers) return false;
    if (frame_len < 2 + n * kPeerEntrySize) return false;
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        const std::uint8_t* p = frame + 2 + i * kPeerEntrySize;
        PeerEntry e;
        e.is_v6 = (p[0] != 0);
        std::memcpy(e.addr.data(), p + 1, 16);
        std::uint16_t port = 0;
        std::memcpy(&port, p + 17, 2);
        e.port = le16(port);
        out.push_back(e);
    }
    return true;
}

} // namespace c2pool::xmr::p2pool
