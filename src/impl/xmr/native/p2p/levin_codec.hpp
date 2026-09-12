// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/p2p/levin_codec.hpp
//
// Wave 1, component C1a: the levin BUCKET HEADER codec -- the 33-byte frame
// that wraps every message on the Monero P2P wire, plus the command ids, the
// frame classification rules and the inbound size caps.
//
// This header is PURE CODEC. It opens no socket, starts no thread and holds no
// connection state: it turns 33 bytes into a struct and back, and answers "how
// many body bytes is this command allowed to be". The socket, the invoke FIFO
// and the handshake state machine are C1b.
//
// Ground truth (read verbatim, monerod master, 2026-09-10):
//   contrib/epee/include/net/levin_base.h          -- bucket_head2, flags, codes
//   contrib/epee/include/net/levin_protocol_handler_async.h -- dispatch rules
//   src/cryptonote_basic/connection_context.cpp    -- get_max_bytes per command
//   src/p2p/p2p_protocol_defs.h                    -- P2P_COMMANDS_POOL_BASE
//   src/cryptonote_protocol/cryptonote_protocol_defs.h -- BC_COMMANDS_POOL_BASE
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record;
// nothing here activates v37 consensus and src/sharechain/v37 is not touched.
//
// STL only. Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace c2pool::xmr::native::levin {

// --- frame constants ---------------------------------------------------------
// "Bender's nightmare". On the wire (little-endian) this is the byte sequence
// 01 21 01 01 01 01 01 01.
inline constexpr std::uint64_t SIGNATURE   = 0x0101010101012101ull;
inline constexpr std::size_t   HEADER_SIZE = 33;   // sizeof(bucket_head2), packed
inline constexpr std::uint32_t PROTOCOL_VER_1 = 1;

inline constexpr std::uint32_t PACKET_REQUEST  = 0x00000001;
inline constexpr std::uint32_t PACKET_RESPONSE = 0x00000002;
inline constexpr std::uint32_t PACKET_BEGIN    = 0x00000004;
inline constexpr std::uint32_t PACKET_END      = 0x00000008;

// Return codes carried in responses (levin_base.h). LEVIN_OK is the only value
// a healthy exchange uses; the negative ones are transport-level failures the
// peer reports instead of an answer body.
inline constexpr std::int32_t RC_OK                            =  0;
inline constexpr std::int32_t RC_ERROR_CONNECTION              = -1;
inline constexpr std::int32_t RC_ERROR_CONNECTION_NOT_FOUND    = -2;
inline constexpr std::int32_t RC_ERROR_CONNECTION_DESTROYED    = -3;
inline constexpr std::int32_t RC_ERROR_CONNECTION_TIMEDOUT     = -4;
inline constexpr std::int32_t RC_ERROR_NO_DUPLEX_PROTOCOL      = -5;
inline constexpr std::int32_t RC_ERROR_HANDLER_NOT_DEFINED     = -6;
inline constexpr std::int32_t RC_ERROR_FORMAT                  = -7;

inline const char* return_code_name(std::int32_t rc) noexcept {
    switch (rc) {
        case RC_OK:                         return "LEVIN_OK";
        case RC_ERROR_CONNECTION:           return "LEVIN_ERROR_CONNECTION";
        case RC_ERROR_CONNECTION_NOT_FOUND: return "LEVIN_ERROR_CONNECTION_NOT_FOUND";
        case RC_ERROR_CONNECTION_DESTROYED: return "LEVIN_ERROR_CONNECTION_DESTROYED";
        case RC_ERROR_CONNECTION_TIMEDOUT:  return "LEVIN_ERROR_CONNECTION_TIMEDOUT";
        case RC_ERROR_NO_DUPLEX_PROTOCOL:   return "LEVIN_ERROR_CONNECTION_NO_DUPLEX_PROTOCOL";
        case RC_ERROR_HANDLER_NOT_DEFINED:  return "LEVIN_ERROR_CONNECTION_HANDLER_NOT_DEFINED";
        case RC_ERROR_FORMAT:               return "LEVIN_ERROR_FORMAT";
        default:                            return "unknown code";
    }
}

// --- command ids -------------------------------------------------------------
// Admin commands sit at P2P_COMMANDS_POOL_BASE = 1000, cryptonote commands at
// BC_COMMANDS_POOL_BASE = 2000. 1004..1006 (stat info, network state, peer id)
// exist in old sources and are unsupported by every deployed daemon.
inline constexpr std::uint32_t CMD_HANDSHAKE             = 1001;
inline constexpr std::uint32_t CMD_TIMED_SYNC            = 1002;
inline constexpr std::uint32_t CMD_PING                  = 1003;
inline constexpr std::uint32_t CMD_REQUEST_SUPPORT_FLAGS = 1007;

inline constexpr std::uint32_t CMD_NEW_BLOCK                 = 2001;
inline constexpr std::uint32_t CMD_NEW_TRANSACTIONS          = 2002;
inline constexpr std::uint32_t CMD_REQUEST_GET_OBJECTS       = 2003;
inline constexpr std::uint32_t CMD_RESPONSE_GET_OBJECTS      = 2004;
inline constexpr std::uint32_t CMD_REQUEST_CHAIN             = 2006;
inline constexpr std::uint32_t CMD_RESPONSE_CHAIN_ENTRY      = 2007;
inline constexpr std::uint32_t CMD_NEW_FLUFFY_BLOCK          = 2008;
inline constexpr std::uint32_t CMD_REQUEST_FLUFFY_MISSING_TX = 2009;
inline constexpr std::uint32_t CMD_GET_TXPOOL_COMPLEMENT     = 2010;

inline const char* command_name(std::uint32_t cmd) noexcept {
    switch (cmd) {
        case CMD_HANDSHAKE:                 return "HANDSHAKE";
        case CMD_TIMED_SYNC:                return "TIMED_SYNC";
        case CMD_PING:                      return "PING";
        case CMD_REQUEST_SUPPORT_FLAGS:     return "REQUEST_SUPPORT_FLAGS";
        case CMD_NEW_BLOCK:                 return "NEW_BLOCK";
        case CMD_NEW_TRANSACTIONS:          return "NEW_TRANSACTIONS";
        case CMD_REQUEST_GET_OBJECTS:       return "REQUEST_GET_OBJECTS";
        case CMD_RESPONSE_GET_OBJECTS:      return "RESPONSE_GET_OBJECTS";
        case CMD_REQUEST_CHAIN:             return "REQUEST_CHAIN";
        case CMD_RESPONSE_CHAIN_ENTRY:      return "RESPONSE_CHAIN_ENTRY";
        case CMD_NEW_FLUFFY_BLOCK:          return "NEW_FLUFFY_BLOCK";
        case CMD_REQUEST_FLUFFY_MISSING_TX: return "REQUEST_FLUFFY_MISSING_TX";
        case CMD_GET_TXPOOL_COMPLEMENT:     return "GET_TXPOOL_COMPLEMENT";
        default:                            return "UNKNOWN";
    }
}

// --- size caps ---------------------------------------------------------------
// monerod's own numbers, kept so the "what the peer will accept from us" side is
// exact. Ours (below) are deliberately tighter on the inbound side.
inline constexpr std::uint64_t MONEROD_INITIAL_MAX_PACKET_SIZE = 256u * 1024u;      // pre-handshake
inline constexpr std::uint64_t MONEROD_DEFAULT_MAX_PACKET_SIZE = 100000000ull;      // post-handshake

// R-CAPS (plan section 11, recommendation as listed): the inbound per-command
// ceilings C1 enforces. They are below monerod's because a pool never
// legitimately receives a 100 MB frame. `0` means "we do not speak this
// command": a frame carrying it is dropped and the connection closed.
struct CapTable {
    std::uint64_t handshake            = 64u * 1024u;          // 1001, monerod's own
    std::uint64_t timed_sync           = 64u * 1024u;          // 1002, monerod's own
    std::uint64_t ping                 = 4096;                 // 1003, monerod's own
    std::uint64_t support_flags        = 4096;                 // 1007, monerod's own
    std::uint64_t new_block            = 4u * 1024u * 1024u;   // 2001, monerod allows 128 MB
    std::uint64_t new_transactions     = 4u * 1024u * 1024u;   // 2002, monerod allows 128 MB
    std::uint64_t request_get_objects  = 4096;                 // 2003, we serve <= 100 ids
    std::uint64_t response_get_objects = 32u * 1024u * 1024u;  // 2004, we ask <= 100 pruned blocks
    std::uint64_t request_chain        = 64u * 1024u;          // 2006, a locator is ~40 ids
    std::uint64_t response_chain_entry = 4u * 1024u * 1024u;   // 2007, monerod's own
    std::uint64_t new_fluffy_block     = 4u * 1024u * 1024u;   // 2008, monerod's own
    std::uint64_t fluffy_missing_tx    = 1u * 1024u * 1024u;   // 2009, monerod's own
    std::uint64_t txpool_complement    = 4u * 1024u * 1024u;   // 2010, monerod's own

    // Everything before the handshake completes, whatever the command.
    std::uint64_t pre_handshake = MONEROD_INITIAL_MAX_PACKET_SIZE;

    // Unknown / unsupported commands. Zero means "close the connection".
    std::uint64_t unknown = 0;
};

inline constexpr CapTable DEFAULT_CAPS{};

// The cap that applies to `cmd` for a connection in the given handshake state.
// Pre-handshake the pre_handshake ceiling also applies, and the result is the
// smaller of the two -- exactly monerod's min(max_packet_size, max_bytes).
inline constexpr std::uint64_t max_body_bytes(std::uint32_t   cmd,
                                              bool            handshaked,
                                              const CapTable& caps = DEFAULT_CAPS) noexcept {
    std::uint64_t per_command = caps.unknown;
    switch (cmd) {
        case CMD_HANDSHAKE:                 per_command = caps.handshake;            break;
        case CMD_TIMED_SYNC:                per_command = caps.timed_sync;           break;
        case CMD_PING:                      per_command = caps.ping;                 break;
        case CMD_REQUEST_SUPPORT_FLAGS:     per_command = caps.support_flags;        break;
        case CMD_NEW_BLOCK:                 per_command = caps.new_block;            break;
        case CMD_NEW_TRANSACTIONS:          per_command = caps.new_transactions;     break;
        case CMD_REQUEST_GET_OBJECTS:       per_command = caps.request_get_objects;  break;
        case CMD_RESPONSE_GET_OBJECTS:      per_command = caps.response_get_objects; break;
        case CMD_REQUEST_CHAIN:             per_command = caps.request_chain;        break;
        case CMD_RESPONSE_CHAIN_ENTRY:      per_command = caps.response_chain_entry; break;
        case CMD_NEW_FLUFFY_BLOCK:          per_command = caps.new_fluffy_block;     break;
        case CMD_REQUEST_FLUFFY_MISSING_TX: per_command = caps.fluffy_missing_tx;    break;
        case CMD_GET_TXPOOL_COMPLEMENT:     per_command = caps.txpool_complement;    break;
        default:                            per_command = caps.unknown;              break;
    }
    if (!handshaked && per_command > caps.pre_handshake) per_command = caps.pre_handshake;
    return per_command;
}

// Pre-handshake, the ONLY command we expect to see is the HANDSHAKE response we
// asked for (we dial out and never listen in v1). REQUEST_SUPPORT_FLAGS is the
// one invoke a peer legitimately sends us before our handshake completes.
inline constexpr bool command_allowed_pre_handshake(std::uint32_t cmd) noexcept {
    return cmd == CMD_HANDSHAKE || cmd == CMD_REQUEST_SUPPORT_FLAGS;
}

// --- the header --------------------------------------------------------------
struct BucketHead {
    std::uint64_t signature           = SIGNATURE;
    std::uint64_t cb                  = 0;      // body length, EXCLUDES the header
    bool          have_to_return_data = false;  // set => the peer must answer
    std::uint32_t command             = 0;
    std::int32_t  return_code         = 0;      // 0 in requests
    std::uint32_t flags               = 0;
    std::uint32_t protocol_version    = PROTOCOL_VER_1;
};

// How the dispatch layer must treat a frame. This mirrors
// levin_protocol_handler_async.h exactly, including the two oddities: a frame
// with neither REQUEST nor RESPONSE set is a fragment, and a fragment with BOTH
// BEGIN and END set is white-noise padding that is silently skipped.
enum class FrameClass : std::uint8_t {
    Notify = 0,      // REQUEST, have_to_return_data == 0 -- one way
    Invoke,          // REQUEST, have_to_return_data != 0 -- an answer is owed
    Response,        // RESPONSE -- answers the OLDEST outstanding invoke (FIFO)
    Noise,           // fragment with BEGIN|END -- skip, do not deliver
    FragmentBegin,   // fragment, BEGIN set, END clear
    FragmentMiddle,  // fragment, neither BEGIN nor END
    FragmentEnd,     // fragment, END set, BEGIN clear
};

inline constexpr FrameClass classify(const BucketHead& h) noexcept {
    const bool req  = (h.flags & PACKET_REQUEST)  != 0;
    const bool resp = (h.flags & PACKET_RESPONSE) != 0;
    if (!req && !resp) {
        const bool begin = (h.flags & PACKET_BEGIN) != 0;
        const bool end   = (h.flags & PACKET_END)   != 0;
        if (begin && end) return FrameClass::Noise;
        if (begin)        return FrameClass::FragmentBegin;
        if (end)          return FrameClass::FragmentEnd;
        return FrameClass::FragmentMiddle;
    }
    // monerod checks RESPONSE first: a frame with both bits set is a response.
    if (resp) return FrameClass::Response;
    return h.have_to_return_data ? FrameClass::Invoke : FrameClass::Notify;
}

inline const char* frame_class_name(FrameClass c) noexcept {
    switch (c) {
        case FrameClass::Notify:         return "Notify";
        case FrameClass::Invoke:         return "Invoke";
        case FrameClass::Response:       return "Response";
        case FrameClass::Noise:          return "Noise";
        case FrameClass::FragmentBegin:  return "FragmentBegin";
        case FrameClass::FragmentMiddle: return "FragmentMiddle";
        case FrameClass::FragmentEnd:    return "FragmentEnd";
    }
    return "?";
}

enum class HeaderError : std::uint8_t {
    None = 0,
    ShortBuffer,          // fewer than 33 bytes available
    BadSignature,         // not Bender's nightmare -- close, never resync
    BadProtocolVersion,   // != 1 under the strict policy
    BodyTooLarge,         // cb above the cap for this command / handshake state
    UnsupportedCommand,   // cap table says 0
    FragmentOnClearnet,   // fragments are the tor/i2p noise feature only
};

inline const char* to_string(HeaderError e) noexcept {
    switch (e) {
        case HeaderError::None:               return "None";
        case HeaderError::ShortBuffer:        return "ShortBuffer";
        case HeaderError::BadSignature:       return "BadSignature";
        case HeaderError::BadProtocolVersion: return "BadProtocolVersion";
        case HeaderError::BodyTooLarge:       return "BodyTooLarge";
        case HeaderError::UnsupportedCommand: return "UnsupportedCommand";
        case HeaderError::FragmentOnClearnet: return "FragmentOnClearnet";
    }
    return "?";
}

// --- little-endian helpers ---------------------------------------------------
inline void put_u16_le(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
}
inline void put_u32_le(std::vector<std::uint8_t>& out, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
}
inline void put_u64_le(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
}
inline std::uint16_t get_u16_le(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(p[0] | (static_cast<std::uint16_t>(p[1]) << 8));
}
inline std::uint32_t get_u32_le(const std::uint8_t* p) noexcept {
    std::uint32_t v = 0;
    for (int i = 3; i >= 0; --i) v = (v << 8) | p[static_cast<std::size_t>(i)];
    return v;
}
inline std::uint64_t get_u64_le(const std::uint8_t* p) noexcept {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[static_cast<std::size_t>(i)];
    return v;
}

// --- header codec ------------------------------------------------------------
// Appends the 33 bytes to `out`.
inline void write_header(const BucketHead& h, std::vector<std::uint8_t>& out) {
    out.reserve(out.size() + HEADER_SIZE);
    put_u64_le(out, h.signature);
    put_u64_le(out, h.cb);
    out.push_back(h.have_to_return_data ? std::uint8_t{1} : std::uint8_t{0});
    put_u32_le(out, h.command);
    put_u32_le(out, static_cast<std::uint32_t>(h.return_code));
    put_u32_le(out, h.flags);
    put_u32_le(out, h.protocol_version);
}

// Policy knobs for the read side. `strict_protocol_version` refuses anything
// but version 1; monerod itself only records the value, but no deployed daemon
// sends anything else and accepting an unknown dialect buys nothing.
// `accept_fragments` is false on clearnet: fragmentation exists solely for the
// tor/i2p white-noise feature, and a fragment arriving on a TCP link is either
// a bug or an attempt to make us buffer unbounded state.
struct HeaderPolicy {
    bool strict_protocol_version = true;
    bool accept_fragments        = false;
    bool handshaked              = false;
    CapTable caps{};
};

// Parses a header out of `data`. Returns false and sets `err` on any of the
// close-the-connection conditions; the caller never resyncs by scanning.
inline bool read_header(const std::uint8_t*  data,
                        std::size_t          size,
                        const HeaderPolicy&  policy,
                        BucketHead&          out,
                        HeaderError&         err) noexcept {
    err = HeaderError::None;
    if (!data || size < HEADER_SIZE) { err = HeaderError::ShortBuffer; return false; }

    BucketHead h;
    h.signature           = get_u64_le(data + 0);
    h.cb                  = get_u64_le(data + 8);
    h.have_to_return_data = data[16] != 0;
    h.command             = get_u32_le(data + 17);
    h.return_code         = static_cast<std::int32_t>(get_u32_le(data + 21));
    h.flags               = get_u32_le(data + 25);
    h.protocol_version    = get_u32_le(data + 29);

    if (h.signature != SIGNATURE) { err = HeaderError::BadSignature; return false; }
    if (policy.strict_protocol_version && h.protocol_version != PROTOCOL_VER_1) {
        err = HeaderError::BadProtocolVersion;
        return false;
    }

    const FrameClass cls = classify(h);
    const bool is_fragment = (cls == FrameClass::Noise
                              || cls == FrameClass::FragmentBegin
                              || cls == FrameClass::FragmentMiddle
                              || cls == FrameClass::FragmentEnd);
    if (is_fragment) {
        if (!policy.accept_fragments) { err = HeaderError::FragmentOnClearnet; return false; }
        // A fragment's command field is meaningless until reassembly, so the
        // only bound available is the packet ceiling.
        const std::uint64_t ceiling = policy.handshaked ? MONEROD_DEFAULT_MAX_PACKET_SIZE
                                                        : policy.caps.pre_handshake;
        if (h.cb > ceiling) { err = HeaderError::BodyTooLarge; return false; }
        out = h;
        return true;
    }

    if (!policy.handshaked && !command_allowed_pre_handshake(h.command)) {
        err = HeaderError::UnsupportedCommand;
        return false;
    }

    const std::uint64_t cap = max_body_bytes(h.command, policy.handshaked, policy.caps);
    if (cap == 0)    { err = HeaderError::UnsupportedCommand; return false; }
    if (h.cb > cap)  { err = HeaderError::BodyTooLarge;       return false; }

    out = h;
    return true;
}

// --- frame builders ----------------------------------------------------------
// Each returns a complete frame: 33-byte header followed by the body.
inline std::vector<std::uint8_t> make_frame(std::uint32_t                    command,
                                            const std::vector<std::uint8_t>& body,
                                            std::uint32_t                    flags,
                                            std::int32_t                     return_code,
                                            bool                             expect_response) {
    BucketHead h;
    h.signature           = SIGNATURE;
    h.cb                  = body.size();
    h.have_to_return_data = expect_response;
    h.command             = command;
    h.return_code         = return_code;
    h.flags               = flags;
    h.protocol_version    = PROTOCOL_VER_1;

    std::vector<std::uint8_t> frame;
    frame.reserve(HEADER_SIZE + body.size());
    write_header(h, frame);
    frame.insert(frame.end(), body.begin(), body.end());
    return frame;
}

// One-way. The peer answers nothing.
inline std::vector<std::uint8_t> make_notify(std::uint32_t command,
                                             const std::vector<std::uint8_t>& body) {
    return make_frame(command, body, PACKET_REQUEST, RC_OK, false);
}

// Asks a question. The answer arrives as a Response with the SAME command and
// no request id -- responses are matched to invokes by arrival order, which is
// why C1b keeps a per-connection FIFO instead of a keyed reply matcher.
inline std::vector<std::uint8_t> make_invoke(std::uint32_t command,
                                             const std::vector<std::uint8_t>& body) {
    return make_frame(command, body, PACKET_REQUEST, RC_OK, true);
}

inline std::vector<std::uint8_t> make_response(std::uint32_t command,
                                               const std::vector<std::uint8_t>& body,
                                               std::int32_t return_code = RC_OK) {
    return make_frame(command, body, PACKET_RESPONSE, return_code, false);
}

} // namespace c2pool::xmr::native::levin
