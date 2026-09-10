// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/p2p/levin_messages.hpp
//
// Wave 1, component C1a: the typed Monero P2P MESSAGES and their codecs.
// Everything the pool speaks, and nothing it does not:
//
//   admin       1001 HANDSHAKE            (invoke + response)
//               1002 TIMED_SYNC           (invoke + response)
//               1003 PING                 (invoke + response)
//               1007 REQUEST_SUPPORT_FLAGS(invoke + response)
//   cryptonote  2001 NEW_BLOCK                 (accepted, never sent)
//               2002 NEW_TRANSACTIONS
//               2003 REQUEST_GET_OBJECTS  / 2004 RESPONSE_GET_OBJECTS
//               2006 REQUEST_CHAIN        / 2007 RESPONSE_CHAIN_ENTRY
//               2008 NEW_FLUFFY_BLOCK
//               2009 REQUEST_FLUFFY_MISSING_TX
//               2010 GET_TXPOOL_COMPLEMENT
//
// Ground truth (read verbatim, monerod master, 2026-09-10):
//   src/p2p/p2p_protocol_defs.h                        -- 1001/1002/1003/1007
//   src/cryptonote_protocol/cryptonote_protocol_defs.h -- 2001..2010, CORE_SYNC_DATA
//   contrib/epee/include/net/net_utils_base.h          -- network_address
//   contrib/epee/include/net/enums.h                   -- address_type ids
//   src/cryptonote_config.h                            -- network ids, ports
//
// The decoders produce the W0 contract value types (contracts/types.hpp) where
// one exists -- BlockEntry, ChainEntry, TxBlobEntry, PeerSyncData -- so C2 and
// C3 consume wire data without a second conversion step. Where no contract type
// exists (basic_node_data, peerlist_entry, network_address) the struct lives
// here and C1a owns it.
//
// This header is PURE CODEC: no socket, no thread, no connection state. The
// invoke FIFO, the handshake state machine and the peer pool are C1b/C1c.
//
// STL only. Header-only.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "impl/xmr/native/contracts/fetcher.hpp"
#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/p2p/epee_storage.hpp"
#include "impl/xmr/native/p2p/levin_codec.hpp"

namespace c2pool::xmr::native::levin {

// KV_SERIALIZE_CONTAINER_POD_AS_BLOB memcpy's the raw POD bytes into one
// string, so a `vector<uint64_t>` on the wire is host-order 64-bit words. Every
// deployed daemon and every c2pool target is little-endian; say so out loud
// rather than silently producing byte-swapped weights on a big-endian host.
static_assert(std::endian::native == std::endian::little,
              "the Monero P2P wire format assumes a little-endian host");

using Hash = ::c2pool::xmr::native::Hash;
using U128 = ::c2pool::xmr::native::U128;

// --- network ids and default ports (cryptonote_config.h) ---------------------
enum class XmrNet : std::uint8_t { Mainnet = 0, Testnet = 1, Stagenet = 2 };

using NetworkId = std::array<std::uint8_t, 16>;

inline constexpr NetworkId NETWORK_ID_MAINNET{
    0x12, 0x30, 0xF1, 0x71, 0x61, 0x04, 0x41, 0x61,
    0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x10};
inline constexpr NetworkId NETWORK_ID_TESTNET{
    0x12, 0x30, 0xF1, 0x71, 0x61, 0x04, 0x41, 0x61,
    0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x11};
inline constexpr NetworkId NETWORK_ID_STAGENET{
    0x12, 0x30, 0xF1, 0x71, 0x61, 0x04, 0x41, 0x61,
    0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x12};

inline constexpr NetworkId network_id_of(XmrNet net) noexcept {
    switch (net) {
        case XmrNet::Testnet:  return NETWORK_ID_TESTNET;
        case XmrNet::Stagenet: return NETWORK_ID_STAGENET;
        case XmrNet::Mainnet:  break;
    }
    return NETWORK_ID_MAINNET;
}

inline constexpr std::uint16_t p2p_default_port(XmrNet net) noexcept {
    switch (net) {
        case XmrNet::Testnet:  return 28080;
        case XmrNet::Stagenet: return 38080;
        case XmrNet::Mainnet:  break;
    }
    return 18080;
}

// --- protocol constants the message layer enforces ---------------------------
inline constexpr std::size_t   MAX_PEERS_IN_HANDSHAKE = 250;   // P2P_MAX_PEERS_IN_HANDSHAKE
inline constexpr std::uint32_t SUPPORT_FLAG_FLUFFY_BLOCKS = 0x01;
inline constexpr const char*   PING_OK_RESPONSE_STATUS_TEXT = "OK";

// --- errors ------------------------------------------------------------------
enum class MessageError : std::uint8_t {
    None = 0,
    BadStorage,        // the portable-storage body did not parse
    MissingField,      // a field with no default was absent
    BadFieldType,      // present but the wrong shape or out of range
    BadBlobLength,     // a POD-as-blob field whose length is not a multiple
    TooManyElements,   // above a protocol or policy cap
    Unencodable,       // the value cannot be written (over a varint ceiling)
};

inline const char* to_string(MessageError e) noexcept {
    switch (e) {
        case MessageError::None:            return "None";
        case MessageError::BadStorage:      return "BadStorage";
        case MessageError::MissingField:    return "MissingField";
        case MessageError::BadFieldType:    return "BadFieldType";
        case MessageError::BadBlobLength:   return "BadBlobLength";
        case MessageError::TooManyElements: return "TooManyElements";
        case MessageError::Unencodable:     return "Unencodable";
    }
    return "?";
}

// Structural ceilings applied while decoding. These are policy, not protocol:
// they bound what a peer can make us allocate before any higher layer looks at
// the message. The defaults follow the per-command byte caps in levin_codec.hpp.
struct MessageLimits {
    std::size_t max_peerlist_entries = MAX_PEERS_IN_HANDSHAKE;
    std::size_t max_blocks           = 128;      // 2004: we ask <= 100 ids
    std::size_t max_txs_per_block    = 32768;
    std::size_t max_txs_in_relay     = 16384;    // 2002
    std::size_t max_hashes           = 131072;   // 2010: 4 MB / 32
    std::size_t max_indices          = 131072;   // 2009
    std::size_t max_chain_ids        = 10000;    // BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT
};

// --- value types owned by C1a ------------------------------------------------
// network_address: a section { "type": u8, "addr": section }. C1 speaks IPv4
// (and parses IPv6); tor and i2p entries appear in real peerlists and are
// PARSED AND DISCARDED -- the kind is retained so the peer store can count them
// without ever dialling one.
struct NetworkAddress {
    enum class Kind : std::uint8_t { Invalid = 0, Ipv4 = 1, Ipv6 = 2, I2p = 3, Tor = 4 };

    Kind kind = Kind::Invalid;

    // monerod's ipv4_network_address::m_ip verbatim: a uint32 whose LITTLE
    // ENDIAN bytes are the dotted octets in order, so 1.2.3.4 is 0x04030201.
    // Use ipv4_from_octets/ipv4_octets rather than assuming a byte order.
    std::uint32_t                m_ip = 0;
    std::array<std::uint8_t, 16> ipv6{};
    std::uint16_t                port = 0;

    bool dialable() const noexcept { return kind == Kind::Ipv4 || kind == Kind::Ipv6; }
};

inline constexpr std::uint32_t ipv4_from_octets(std::uint8_t a, std::uint8_t b,
                                                std::uint8_t c, std::uint8_t d) noexcept {
    return static_cast<std::uint32_t>(a)
         | (static_cast<std::uint32_t>(b) << 8)
         | (static_cast<std::uint32_t>(c) << 16)
         | (static_cast<std::uint32_t>(d) << 24);
}

inline std::array<std::uint8_t, 4> ipv4_octets(std::uint32_t m_ip) noexcept {
    return {static_cast<std::uint8_t>(m_ip & 0xff),
            static_cast<std::uint8_t>((m_ip >> 8) & 0xff),
            static_cast<std::uint8_t>((m_ip >> 16) & 0xff),
            static_cast<std::uint8_t>((m_ip >> 24) & 0xff)};
}

struct PeerlistEntry {
    NetworkAddress adr;
    std::uint64_t  id                   = 0;
    std::int64_t   last_seen            = 0;
    std::uint32_t  pruning_seed         = 0;
    std::uint16_t  rpc_port             = 0;
    std::uint32_t  rpc_credits_per_hash = 0;
};

struct BasicNodeData {
    NetworkId     network_id{};
    std::uint64_t peer_id              = 0;
    std::uint32_t my_port              = 0;   // 0 = we accept no inbound (R-LISTEN)
    std::uint16_t rpc_port             = 0;
    std::uint32_t rpc_credits_per_hash = 0;
    std::uint32_t support_flags        = 0;
};

// --- messages ----------------------------------------------------------------
// PeerSyncData (contracts/types.hpp) is CORE_SYNC_DATA. Note that its
// `support_flags` member has no CORE_SYNC_DATA counterpart: it lives in
// basic_node_data, and C1b fills it in after the handshake. The decoders here
// leave it at zero.
struct HandshakeRequest {
    BasicNodeData node_data;
    PeerSyncData  payload_data;
};

struct HandshakeResponse {
    BasicNodeData              node_data;
    PeerSyncData               payload_data;
    std::vector<PeerlistEntry> local_peerlist_new;
};

struct TimedSyncRequest  { PeerSyncData payload_data; };
struct TimedSyncResponse { PeerSyncData payload_data; std::vector<PeerlistEntry> local_peerlist_new; };

struct PingResponse         { std::string   status;        std::uint64_t peer_id = 0; };
struct SupportFlagsResponse { std::uint32_t support_flags = 0; };

// 2001 and 2008 share this shape; 2001 is a deprecated alias monerod forwards to
// its fluffy handler. We accept both and send only 2008 (R-CITIZEN).
struct NewBlock {
    BlockEntry    b;
    std::uint64_t current_blockchain_height = 0;
};

struct NewTransactions {
    std::vector<std::vector<std::uint8_t>> txs;
    std::vector<std::uint8_t>              padding;             // the "_" field
    bool                                   dandelionpp_fluff = true;
};

struct RequestGetObjects  { std::vector<Hash> blocks; bool prune = false; };

struct ResponseGetObjects {
    std::vector<BlockEntry> blocks;
    std::vector<Hash>       missed_ids;
    std::uint64_t           current_blockchain_height = 0;
};

struct RequestChain { std::vector<Hash> block_ids; bool prune = false; };

struct RequestFluffyMissingTx {
    Hash                       block_hash{};
    std::uint64_t              current_blockchain_height = 0;
    std::vector<std::uint64_t> missing_tx_indices;
};

struct GetTxpoolComplement { std::vector<Hash> hashes; };

// --- small helpers -----------------------------------------------------------
namespace detail {

inline epee::Value blob_of_hashes(const std::vector<Hash>& hashes) {
    std::vector<std::uint8_t> out;
    out.reserve(hashes.size() * 32);
    for (const Hash& h : hashes) out.insert(out.end(), h.begin(), h.end());
    return epee::v_blob(std::move(out));
}

inline epee::Value blob_of_u64(const std::vector<std::uint64_t>& values) {
    std::vector<std::uint8_t> out;
    out.reserve(values.size() * 8);
    for (std::uint64_t v : values)
        for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
    return epee::v_blob(std::move(out));
}

// An absent POD-as-blob key means an empty container (fact 3 in epee_storage).
inline bool read_hash_blob(const epee::Value& sec, std::string_view name,
                           std::vector<Hash>& out, std::size_t max, MessageError& err) {
    out.clear();
    const std::vector<std::uint8_t>* blob = epee::get_blob(sec, name);
    if (!blob) {
        if (epee::find(sec, name)) { err = MessageError::BadFieldType; return false; }
        return true;
    }
    if (blob->size() % 32 != 0) { err = MessageError::BadBlobLength; return false; }
    const std::size_t n = blob->size() / 32;
    if (n > max) { err = MessageError::TooManyElements; return false; }
    out.resize(n);
    for (std::size_t i = 0; i < n; ++i)
        std::memcpy(out[i].data(), blob->data() + i * 32, 32);
    return true;
}

inline bool read_u64_blob(const epee::Value& sec, std::string_view name,
                          std::vector<std::uint64_t>& out, std::size_t max, MessageError& err) {
    out.clear();
    const std::vector<std::uint8_t>* blob = epee::get_blob(sec, name);
    if (!blob) {
        if (epee::find(sec, name)) { err = MessageError::BadFieldType; return false; }
        return true;
    }
    if (blob->size() % 8 != 0) { err = MessageError::BadBlobLength; return false; }
    const std::size_t n = blob->size() / 8;
    if (n > max) { err = MessageError::TooManyElements; return false; }
    out.resize(n);
    for (std::size_t i = 0; i < n; ++i) {
        std::uint64_t v = 0;
        for (int b = 0; b < 8; ++b)
            v |= static_cast<std::uint64_t>((*blob)[i * 8 + static_cast<std::size_t>(b)]) << (8 * b);
        out[i] = v;
    }
    return true;
}

inline bool read_fixed_blob(const epee::Value& sec, std::string_view name,
                            std::uint8_t* dst, std::size_t n, MessageError& err) {
    const std::vector<std::uint8_t>* blob = epee::get_blob(sec, name);
    if (!blob) { err = MessageError::MissingField; return false; }
    if (blob->size() != n) { err = MessageError::BadBlobLength; return false; }
    std::memcpy(dst, blob->data(), n);
    return true;
}

} // namespace detail

// --- network_address ---------------------------------------------------------
// Encodes ipv4 / ipv6 only; anything else is Unencodable, because we never
// forward a peerlist entry we could not dial.
inline bool encode_network_address(const NetworkAddress& a, epee::Value& out, MessageError& err) {
    std::vector<epee::Entry> addr;
    if (a.kind == NetworkAddress::Kind::Ipv4) {
        addr.push_back({"m_ip",   epee::v_u32(a.m_ip)});
        addr.push_back({"m_port", epee::v_u16(a.port)});
    } else if (a.kind == NetworkAddress::Kind::Ipv6) {
        addr.push_back({"addr",   epee::v_blob(std::vector<std::uint8_t>(a.ipv6.begin(), a.ipv6.end()))});
        addr.push_back({"m_port", epee::v_u16(a.port)});
    } else {
        err = MessageError::Unencodable;
        return false;
    }
    out = epee::v_object({
        {"type", epee::v_u8(static_cast<std::uint8_t>(a.kind))},
        {"addr", epee::v_object(std::move(addr))},
    });
    return true;
}

// Never fails on an address type we do not speak: the entry is returned with
// its Kind set and nothing else, so the peer store can count and ignore it.
inline bool decode_network_address(const epee::Value& sec, NetworkAddress& out, MessageError& err) {
    out = NetworkAddress{};
    std::uint8_t type = 0;
    if (!epee::get_uint_as(sec, "type", type)) { err = MessageError::MissingField; return false; }
    switch (type) {
        case 1: out.kind = NetworkAddress::Kind::Ipv4;    break;
        case 2: out.kind = NetworkAddress::Kind::Ipv6;    break;
        case 3: out.kind = NetworkAddress::Kind::I2p;     break;
        case 4: out.kind = NetworkAddress::Kind::Tor;     break;
        default: out.kind = NetworkAddress::Kind::Invalid; return true;
    }
    if (!out.dialable()) return true;   // tor / i2p: parsed and discarded

    const epee::Value* addr = epee::get_object(sec, "addr");
    if (!addr) { err = MessageError::MissingField; return false; }

    if (out.kind == NetworkAddress::Kind::Ipv4) {
        if (!epee::get_uint_as(*addr, "m_ip", out.m_ip)) { err = MessageError::MissingField; return false; }
    } else {
        if (!detail::read_fixed_blob(*addr, "addr", out.ipv6.data(), out.ipv6.size(), err)) return false;
    }
    if (!epee::get_uint_as(*addr, "m_port", out.port)) { err = MessageError::MissingField; return false; }
    return true;
}

// --- peerlist_entry ----------------------------------------------------------
// KV_SERIALIZE_OPT on last_seen / pruning_seed / rpc_port / rpc_credits_per_hash
// omits each on store when it equals zero.
inline bool encode_peerlist_entry(const PeerlistEntry& p, epee::Value& out, MessageError& err) {
    epee::Value adr;
    if (!encode_network_address(p.adr, adr, err)) return false;

    std::vector<epee::Entry> e;
    e.push_back({"adr", std::move(adr)});
    e.push_back({"id",  epee::v_u64(p.id)});
    if (p.last_seen            != 0) e.push_back({"last_seen",            epee::v_i64(p.last_seen)});
    if (p.pruning_seed         != 0) e.push_back({"pruning_seed",         epee::v_u32(p.pruning_seed)});
    if (p.rpc_port             != 0) e.push_back({"rpc_port",             epee::v_u16(p.rpc_port)});
    if (p.rpc_credits_per_hash != 0) e.push_back({"rpc_credits_per_hash", epee::v_u32(p.rpc_credits_per_hash)});
    out = epee::v_object(std::move(e));
    return true;
}

inline bool decode_peerlist_entry(const epee::Value& sec, PeerlistEntry& out, MessageError& err) {
    out = PeerlistEntry{};
    const epee::Value* adr = epee::get_object(sec, "adr");
    if (!adr) { err = MessageError::MissingField; return false; }
    if (!decode_network_address(*adr, out.adr, err)) return false;
    if (!epee::get_uint_as(sec, "id", out.id)) { err = MessageError::MissingField; return false; }
    epee::get_int(sec, "last_seen", out.last_seen);
    epee::get_uint_as(sec, "pruning_seed", out.pruning_seed);
    epee::get_uint_as(sec, "rpc_port", out.rpc_port);
    epee::get_uint_as(sec, "rpc_credits_per_hash", out.rpc_credits_per_hash);
    return true;
}

inline bool encode_peerlist(const std::vector<PeerlistEntry>& peers,
                            std::vector<epee::Value>& out, MessageError& err) {
    out.clear();
    out.reserve(peers.size());
    for (const PeerlistEntry& p : peers) {
        epee::Value v;
        if (!encode_peerlist_entry(p, v, err)) return false;
        out.push_back(std::move(v));
    }
    return true;
}

inline bool decode_peerlist(const epee::Value& sec, std::string_view name,
                            std::vector<PeerlistEntry>& out,
                            const MessageLimits& limits, MessageError& err) {
    out.clear();
    const epee::Value* arr = epee::get_array(sec, name, epee::Type::Object);
    if (!arr) {
        // Absent means empty (monerod never writes an empty container and its
        // loader discards the lookup failure). A key of the wrong shape is a
        // real defect and is refused.
        if (epee::find(sec, name)) { err = MessageError::BadFieldType; return false; }
        return true;
    }
    if (arr->arr.size() > limits.max_peerlist_entries) {
        err = MessageError::TooManyElements;   // "spamming" in monerod's words
        return false;
    }
    out.reserve(arr->arr.size());
    for (const epee::Value& v : arr->arr) {
        PeerlistEntry p;
        if (!decode_peerlist_entry(v, p, err)) return false;
        out.push_back(std::move(p));
    }
    return true;
}

// --- basic_node_data ---------------------------------------------------------
inline epee::Value encode_basic_node_data(const BasicNodeData& n) {
    std::vector<epee::Entry> e;
    e.push_back({"network_id", epee::v_blob(std::vector<std::uint8_t>(n.network_id.begin(), n.network_id.end()))});
    e.push_back({"peer_id",    epee::v_u64(n.peer_id)});
    e.push_back({"my_port",    epee::v_u32(n.my_port)});
    if (n.rpc_port             != 0) e.push_back({"rpc_port",             epee::v_u16(n.rpc_port)});
    if (n.rpc_credits_per_hash != 0) e.push_back({"rpc_credits_per_hash", epee::v_u32(n.rpc_credits_per_hash)});
    if (n.support_flags        != 0) e.push_back({"support_flags",        epee::v_u32(n.support_flags)});
    return epee::v_object(std::move(e));
}

inline bool decode_basic_node_data(const epee::Value& sec, BasicNodeData& out, MessageError& err) {
    out = BasicNodeData{};
    if (!detail::read_fixed_blob(sec, "network_id", out.network_id.data(), out.network_id.size(), err))
        return false;
    if (!epee::get_uint_as(sec, "peer_id", out.peer_id)) { err = MessageError::MissingField; return false; }
    if (!epee::get_uint_as(sec, "my_port", out.my_port)) { err = MessageError::MissingField; return false; }
    epee::get_uint_as(sec, "rpc_port", out.rpc_port);
    epee::get_uint_as(sec, "rpc_credits_per_hash", out.rpc_credits_per_hash);
    epee::get_uint_as(sec, "support_flags", out.support_flags);
    return true;
}

// --- CORE_SYNC_DATA ----------------------------------------------------------
// cumulative_difficulty_top64 is written UNCONDITIONALLY on store (monerod
// branches on is_store and only makes it optional when loading); top_version and
// pruning_seed are KV_SERIALIZE_OPT and are omitted when zero.
inline epee::Value encode_core_sync_data(const PeerSyncData& s) {
    std::vector<epee::Entry> e;
    e.push_back({"current_height",              epee::v_u64(s.current_height)});
    e.push_back({"cumulative_difficulty",       epee::v_u64(s.cumulative_difficulty.lo)});
    e.push_back({"cumulative_difficulty_top64", epee::v_u64(s.cumulative_difficulty.hi)});
    e.push_back({"top_id", epee::v_blob(std::vector<std::uint8_t>(s.top_id.begin(), s.top_id.end()))});
    if (s.top_version  != 0) e.push_back({"top_version",  epee::v_u8(s.top_version)});
    if (s.pruning_seed != 0) e.push_back({"pruning_seed", epee::v_u32(s.pruning_seed)});
    return epee::v_object(std::move(e));
}

inline bool decode_core_sync_data(const epee::Value& sec, PeerSyncData& out, MessageError& err) {
    out = PeerSyncData{};
    if (!epee::get_uint_as(sec, "current_height", out.current_height)) {
        err = MessageError::MissingField;
        return false;
    }
    if (!epee::get_uint(sec, "cumulative_difficulty", out.cumulative_difficulty.lo)) {
        err = MessageError::MissingField;
        return false;
    }
    epee::get_uint(sec, "cumulative_difficulty_top64", out.cumulative_difficulty.hi);
    if (!detail::read_fixed_blob(sec, "top_id", out.top_id.data(), out.top_id.size(), err)) return false;
    epee::get_uint_as(sec, "top_version", out.top_version);
    epee::get_uint_as(sec, "pruning_seed", out.pruning_seed);
    return true;
}

// --- block_complete_entry ----------------------------------------------------
// The `pruned` flag decides the SHAPE of "txs": an array of objects
// {blob, prunable_hash} when pruned, a flat array of blobs when not. Getting
// this wrong is silent on the encode side and fatal on the decode side, which
// is why both directions branch on the same flag here.
inline epee::Value encode_block_complete_entry(const BlockEntry& b) {
    std::vector<epee::Entry> e;
    if (b.pruned) e.push_back({"pruned", epee::v_bool(true)});
    e.push_back({"block", epee::v_blob(b.block_blob)});
    if (b.block_weight_claimed_hint != 0)
        e.push_back({"block_weight", epee::v_u64(b.block_weight_claimed_hint)});

    if (!b.txs.empty()) {
        std::vector<epee::Value> txs;
        txs.reserve(b.txs.size());
        if (b.pruned) {
            for (const TxBlobEntry& t : b.txs) {
                txs.push_back(epee::v_object({
                    {"blob", epee::v_blob(t.blob)},
                    {"prunable_hash",
                     epee::v_blob(std::vector<std::uint8_t>(t.prunable_hash.begin(), t.prunable_hash.end()))},
                }));
            }
            e.push_back({"txs", epee::v_array(epee::Type::Object, std::move(txs))});
        } else {
            for (const TxBlobEntry& t : b.txs) txs.push_back(epee::v_blob(t.blob));
            e.push_back({"txs", epee::v_array(epee::Type::String, std::move(txs))});
        }
    }
    return epee::v_object(std::move(e));
}

inline bool decode_block_complete_entry(const epee::Value& sec, BlockEntry& out,
                                        const MessageLimits& limits, MessageError& err) {
    out = BlockEntry{};
    epee::get_bool(sec, "pruned", out.pruned);

    const std::vector<std::uint8_t>* block = epee::get_blob(sec, "block");
    if (!block) { err = MessageError::MissingField; return false; }
    out.block_blob = *block;

    epee::get_uint(sec, "block_weight", out.block_weight_claimed_hint);

    const epee::Value* txs = epee::find(sec, "txs");
    if (!txs) return true;                          // absent == empty
    if (!txs->is_array) { err = MessageError::BadFieldType; return false; }
    if (txs->arr.size() > limits.max_txs_per_block) { err = MessageError::TooManyElements; return false; }

    out.txs.reserve(txs->arr.size());
    if (out.pruned) {
        if (txs->type != epee::Type::Object) { err = MessageError::BadFieldType; return false; }
        for (const epee::Value& t : txs->arr) {
            TxBlobEntry entry;
            const std::vector<std::uint8_t>* blob = epee::get_blob(t, "blob");
            if (!blob) { err = MessageError::MissingField; return false; }
            entry.blob = *blob;
            if (!detail::read_fixed_blob(t, "prunable_hash",
                                         entry.prunable_hash.data(), entry.prunable_hash.size(), err))
                return false;
            entry.pruned = true;
            out.txs.push_back(std::move(entry));
        }
    } else {
        if (txs->type != epee::Type::String) { err = MessageError::BadFieldType; return false; }
        for (const epee::Value& t : txs->arr) {
            TxBlobEntry entry;
            entry.blob = t.str;
            entry.pruned = false;
            out.txs.push_back(std::move(entry));
        }
    }
    return true;
}

// --- generic body encode / decode -------------------------------------------
inline bool encode_body(const epee::Value& root, std::vector<std::uint8_t>& out, MessageError& err) {
    epee::StorageError serr = epee::StorageError::None;
    if (!epee::write_storage(root, out, serr)) {
        err = (serr == epee::StorageError::VarintTooLarge) ? MessageError::Unencodable
                                                           : MessageError::BadStorage;
        return false;
    }
    return true;
}

inline bool parse_body(const std::uint8_t* data, std::size_t size, epee::Value& root,
                       MessageError& err, const epee::Limits& limits = epee::Limits{}) {
    epee::StorageError serr = epee::StorageError::None;
    if (!epee::read_storage(data, size, root, serr, limits, nullptr)) {
        err = MessageError::BadStorage;
        return false;
    }
    return true;
}

// --- 1001 HANDSHAKE ----------------------------------------------------------
inline bool encode_handshake_request(const HandshakeRequest& m,
                                     std::vector<std::uint8_t>& out, MessageError& err) {
    return encode_body(epee::v_object({
        {"node_data",    encode_basic_node_data(m.node_data)},
        {"payload_data", encode_core_sync_data(m.payload_data)},
    }), out, err);
}

inline bool decode_handshake_request(const std::uint8_t* data, std::size_t size,
                                     HandshakeRequest& out, MessageError& err,
                                     const MessageLimits& = MessageLimits{}) {
    epee::Value root;
    if (!parse_body(data, size, root, err)) return false;
    const epee::Value* nd = epee::get_object(root, "node_data");
    const epee::Value* pd = epee::get_object(root, "payload_data");
    if (!nd || !pd) { err = MessageError::MissingField; return false; }
    return decode_basic_node_data(*nd, out.node_data, err)
        && decode_core_sync_data(*pd, out.payload_data, err);
}

inline bool encode_handshake_response(const HandshakeResponse& m,
                                      std::vector<std::uint8_t>& out, MessageError& err) {
    std::vector<epee::Entry> e;
    e.push_back({"node_data",    encode_basic_node_data(m.node_data)});
    e.push_back({"payload_data", encode_core_sync_data(m.payload_data)});
    if (!m.local_peerlist_new.empty()) {
        std::vector<epee::Value> peers;
        if (!encode_peerlist(m.local_peerlist_new, peers, err)) return false;
        e.push_back({"local_peerlist_new", epee::v_array(epee::Type::Object, std::move(peers))});
    }
    return encode_body(epee::v_object(std::move(e)), out, err);
}

inline bool decode_handshake_response(const std::uint8_t* data, std::size_t size,
                                      HandshakeResponse& out, MessageError& err,
                                      const MessageLimits& limits = MessageLimits{}) {
    epee::Value root;
    if (!parse_body(data, size, root, err)) return false;
    const epee::Value* nd = epee::get_object(root, "node_data");
    const epee::Value* pd = epee::get_object(root, "payload_data");
    if (!nd || !pd) { err = MessageError::MissingField; return false; }
    return decode_basic_node_data(*nd, out.node_data, err)
        && decode_core_sync_data(*pd, out.payload_data, err)
        && decode_peerlist(root, "local_peerlist_new", out.local_peerlist_new, limits, err);
}

// --- 1002 TIMED_SYNC ---------------------------------------------------------
inline bool encode_timed_sync_request(const TimedSyncRequest& m,
                                      std::vector<std::uint8_t>& out, MessageError& err) {
    return encode_body(epee::v_object({{"payload_data", encode_core_sync_data(m.payload_data)}}), out, err);
}

inline bool decode_timed_sync_request(const std::uint8_t* data, std::size_t size,
                                      TimedSyncRequest& out, MessageError& err,
                                      const MessageLimits& = MessageLimits{}) {
    epee::Value root;
    if (!parse_body(data, size, root, err)) return false;
    const epee::Value* pd = epee::get_object(root, "payload_data");
    if (!pd) { err = MessageError::MissingField; return false; }
    return decode_core_sync_data(*pd, out.payload_data, err);
}

inline bool encode_timed_sync_response(const TimedSyncResponse& m,
                                       std::vector<std::uint8_t>& out, MessageError& err) {
    std::vector<epee::Entry> e;
    e.push_back({"payload_data", encode_core_sync_data(m.payload_data)});
    if (!m.local_peerlist_new.empty()) {
        std::vector<epee::Value> peers;
        if (!encode_peerlist(m.local_peerlist_new, peers, err)) return false;
        e.push_back({"local_peerlist_new", epee::v_array(epee::Type::Object, std::move(peers))});
    }
    return encode_body(epee::v_object(std::move(e)), out, err);
}

inline bool decode_timed_sync_response(const std::uint8_t* data, std::size_t size,
                                       TimedSyncResponse& out, MessageError& err,
                                       const MessageLimits& limits = MessageLimits{}) {
    epee::Value root;
    if (!parse_body(data, size, root, err)) return false;
    const epee::Value* pd = epee::get_object(root, "payload_data");
    if (!pd) { err = MessageError::MissingField; return false; }
    return decode_core_sync_data(*pd, out.payload_data, err)
        && decode_peerlist(root, "local_peerlist_new", out.local_peerlist_new, limits, err);
}

// --- 1003 PING / 1007 REQUEST_SUPPORT_FLAGS ----------------------------------
// Both requests are an EMPTY section: the 9-byte storage header plus a single
// zero varint. They are not zero-length bodies.
inline std::vector<std::uint8_t> encode_empty_request() {
    std::vector<std::uint8_t> out;
    MessageError err = MessageError::None;
    (void)encode_body(epee::v_object({}), out, err);
    return out;
}

inline bool encode_ping_response(const PingResponse& m,
                                 std::vector<std::uint8_t>& out, MessageError& err) {
    return encode_body(epee::v_object({
        {"status",  epee::v_str(m.status)},
        {"peer_id", epee::v_u64(m.peer_id)},
    }), out, err);
}

inline bool decode_ping_response(const std::uint8_t* data, std::size_t size,
                                 PingResponse& out, MessageError& err,
                                 const MessageLimits& = MessageLimits{}) {
    epee::Value root;
    if (!parse_body(data, size, root, err)) return false;
    const std::vector<std::uint8_t>* status = epee::get_blob(root, "status");
    if (!status) { err = MessageError::MissingField; return false; }
    out.status.assign(status->begin(), status->end());
    if (!epee::get_uint_as(root, "peer_id", out.peer_id)) { err = MessageError::MissingField; return false; }
    return true;
}

inline bool encode_support_flags_response(const SupportFlagsResponse& m,
                                          std::vector<std::uint8_t>& out, MessageError& err) {
    return encode_body(epee::v_object({{"support_flags", epee::v_u32(m.support_flags)}}), out, err);
}

inline bool decode_support_flags_response(const std::uint8_t* data, std::size_t size,
                                          SupportFlagsResponse& out, MessageError& err,
                                          const MessageLimits& = MessageLimits{}) {
    epee::Value root;
    if (!parse_body(data, size, root, err)) return false;
    if (!epee::get_uint_as(root, "support_flags", out.support_flags)) {
        err = MessageError::MissingField;
        return false;
    }
    return true;
}

// --- 2001 NEW_BLOCK / 2008 NEW_FLUFFY_BLOCK ----------------------------------
inline bool encode_new_block(const NewBlock& m, std::vector<std::uint8_t>& out, MessageError& err) {
    return encode_body(epee::v_object({
        {"b", encode_block_complete_entry(m.b)},
        {"current_blockchain_height", epee::v_u64(m.current_blockchain_height)},
    }), out, err);
}

inline bool decode_new_block(const std::uint8_t* data, std::size_t size, NewBlock& out,
                             MessageError& err, const MessageLimits& limits = MessageLimits{}) {
    epee::Value root;
    if (!parse_body(data, size, root, err)) return false;
    const epee::Value* b = epee::get_object(root, "b");
    if (!b) { err = MessageError::MissingField; return false; }
    if (!decode_block_complete_entry(*b, out.b, limits, err)) return false;
    if (!epee::get_uint(root, "current_blockchain_height", out.current_blockchain_height)) {
        err = MessageError::MissingField;
        return false;
    }
    return true;
}

// 2008 is byte-identical in shape to 2001; the aliases exist so call sites read
// as the command they mean.
inline bool encode_new_fluffy_block(const NewBlock& m, std::vector<std::uint8_t>& out, MessageError& err) {
    return encode_new_block(m, out, err);
}
inline bool decode_new_fluffy_block(const std::uint8_t* data, std::size_t size, NewBlock& out,
                                    MessageError& err, const MessageLimits& limits = MessageLimits{}) {
    return decode_new_block(data, size, out, err, limits);
}

// --- 2002 NEW_TRANSACTIONS ---------------------------------------------------
inline bool encode_new_transactions(const NewTransactions& m,
                                    std::vector<std::uint8_t>& out, MessageError& err) {
    std::vector<epee::Entry> e;
    if (!m.txs.empty()) {
        std::vector<epee::Value> txs;
        txs.reserve(m.txs.size());
        for (const std::vector<std::uint8_t>& t : m.txs) txs.push_back(epee::v_blob(t));
        e.push_back({"txs", epee::v_array(epee::Type::String, std::move(txs))});
    }
    // The padding field is written even when empty: it is a plain KV_SERIALIZE
    // of a std::string, not a container.
    e.push_back({"_", epee::v_blob(m.padding)});
    if (!m.dandelionpp_fluff) e.push_back({"dandelionpp_fluff", epee::v_bool(false)});
    return encode_body(epee::v_object(std::move(e)), out, err);
}

inline bool decode_new_transactions(const std::uint8_t* data, std::size_t size,
                                    NewTransactions& out, MessageError& err,
                                    const MessageLimits& limits = MessageLimits{}) {
    out = NewTransactions{};
    epee::Value root;
    if (!parse_body(data, size, root, err)) return false;

    const epee::Value* txs = epee::find(root, "txs");
    if (txs) {
        if (!txs->is_array || txs->type != epee::Type::String) { err = MessageError::BadFieldType; return false; }
        if (txs->arr.size() > limits.max_txs_in_relay) { err = MessageError::TooManyElements; return false; }
        out.txs.reserve(txs->arr.size());
        for (const epee::Value& t : txs->arr) out.txs.push_back(t.str);
    }
    if (const std::vector<std::uint8_t>* pad = epee::get_blob(root, "_")) out.padding = *pad;
    out.dandelionpp_fluff = true;                 // KV_SERIALIZE_OPT default
    epee::get_bool(root, "dandelionpp_fluff", out.dandelionpp_fluff);
    return true;
}

// --- 2003 REQUEST_GET_OBJECTS / 2004 RESPONSE_GET_OBJECTS --------------------
inline bool encode_request_get_objects(const RequestGetObjects& m,
                                       std::vector<std::uint8_t>& out, MessageError& err) {
    if (m.blocks.size() > MAX_OBJECT_REQUEST_IDS) { err = MessageError::TooManyElements; return false; }
    std::vector<epee::Entry> e;
    if (!m.blocks.empty()) e.push_back({"blocks", detail::blob_of_hashes(m.blocks)});
    if (m.prune) e.push_back({"prune", epee::v_bool(true)});
    return encode_body(epee::v_object(std::move(e)), out, err);
}

inline bool decode_request_get_objects(const std::uint8_t* data, std::size_t size,
                                       RequestGetObjects& out, MessageError& err,
                                       const MessageLimits& = MessageLimits{}) {
    out = RequestGetObjects{};
    epee::Value root;
    if (!parse_body(data, size, root, err)) return false;
    // monerod drops a peer that asks for more than
    // CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT ids; we hold ourselves and our
    // peers to the same number.
    if (!detail::read_hash_blob(root, "blocks", out.blocks, MAX_OBJECT_REQUEST_IDS, err)) return false;
    epee::get_bool(root, "prune", out.prune);
    return true;
}

inline bool encode_response_get_objects(const ResponseGetObjects& m,
                                        std::vector<std::uint8_t>& out, MessageError& err) {
    std::vector<epee::Entry> e;
    if (!m.blocks.empty()) {
        std::vector<epee::Value> blocks;
        blocks.reserve(m.blocks.size());
        for (const BlockEntry& b : m.blocks) blocks.push_back(encode_block_complete_entry(b));
        e.push_back({"blocks", epee::v_array(epee::Type::Object, std::move(blocks))});
    }
    if (!m.missed_ids.empty()) e.push_back({"missed_ids", detail::blob_of_hashes(m.missed_ids)});
    e.push_back({"current_blockchain_height", epee::v_u64(m.current_blockchain_height)});
    return encode_body(epee::v_object(std::move(e)), out, err);
}

inline bool decode_response_get_objects(const std::uint8_t* data, std::size_t size,
                                        ResponseGetObjects& out, MessageError& err,
                                        const MessageLimits& limits = MessageLimits{}) {
    out = ResponseGetObjects{};
    epee::Value root;
    if (!parse_body(data, size, root, err)) return false;

    if (const epee::Value* blocks = epee::find(root, "blocks")) {
        if (!blocks->is_array || blocks->type != epee::Type::Object) {
            err = MessageError::BadFieldType;
            return false;
        }
        if (blocks->arr.size() > limits.max_blocks) { err = MessageError::TooManyElements; return false; }
        out.blocks.reserve(blocks->arr.size());
        for (const epee::Value& b : blocks->arr) {
            BlockEntry entry;
            if (!decode_block_complete_entry(b, entry, limits, err)) return false;
            out.blocks.push_back(std::move(entry));
        }
    }
    if (!detail::read_hash_blob(root, "missed_ids", out.missed_ids, limits.max_blocks, err)) return false;
    if (!epee::get_uint(root, "current_blockchain_height", out.current_blockchain_height)) {
        err = MessageError::MissingField;
        return false;
    }
    return true;
}

// --- 2006 REQUEST_CHAIN / 2007 RESPONSE_CHAIN_ENTRY --------------------------
inline bool encode_request_chain(const RequestChain& m,
                                 std::vector<std::uint8_t>& out, MessageError& err) {
    std::vector<epee::Entry> e;
    if (!m.block_ids.empty()) e.push_back({"block_ids", detail::blob_of_hashes(m.block_ids)});
    if (m.prune) e.push_back({"prune", epee::v_bool(true)});
    return encode_body(epee::v_object(std::move(e)), out, err);
}

inline bool decode_request_chain(const std::uint8_t* data, std::size_t size,
                                 RequestChain& out, MessageError& err,
                                 const MessageLimits& limits = MessageLimits{}) {
    out = RequestChain{};
    epee::Value root;
    if (!parse_body(data, size, root, err)) return false;
    if (!detail::read_hash_blob(root, "block_ids", out.block_ids, limits.max_chain_ids, err)) return false;
    epee::get_bool(root, "prune", out.prune);
    return true;
}

// 2007 maps onto the W0 ChainEntry: `cumulative_difficulty_hint` and
// `weights_claimed_hint` are named hints in the contract precisely because they
// are the PEER'S CLAIM, recomputed by C2 and never a fork-choice input.
// `first_block` is a plain KV_SERIALIZE (written even when empty).
inline bool encode_response_chain_entry(const ChainEntry& m,
                                        std::vector<std::uint8_t>& out, MessageError& err) {
    std::vector<epee::Entry> e;
    e.push_back({"start_height",                epee::v_u64(m.start_height)});
    e.push_back({"total_height",                epee::v_u64(m.total_height)});
    e.push_back({"cumulative_difficulty",       epee::v_u64(m.cumulative_difficulty_hint.lo)});
    e.push_back({"cumulative_difficulty_top64", epee::v_u64(m.cumulative_difficulty_hint.hi)});
    if (!m.ids.empty())                  e.push_back({"m_block_ids",     detail::blob_of_hashes(m.ids)});
    if (!m.weights_claimed_hint.empty()) e.push_back({"m_block_weights", detail::blob_of_u64(m.weights_claimed_hint)});
    e.push_back({"first_block", epee::v_blob(m.first_block)});
    return encode_body(epee::v_object(std::move(e)), out, err);
}

inline bool decode_response_chain_entry(const std::uint8_t* data, std::size_t size,
                                        ChainEntry& out, MessageError& err,
                                        const MessageLimits& limits = MessageLimits{}) {
    out = ChainEntry{};
    epee::Value root;
    if (!parse_body(data, size, root, err)) return false;
    if (!epee::get_uint(root, "start_height", out.start_height)
        || !epee::get_uint(root, "total_height", out.total_height)
        || !epee::get_uint(root, "cumulative_difficulty", out.cumulative_difficulty_hint.lo)) {
        err = MessageError::MissingField;
        return false;
    }
    epee::get_uint(root, "cumulative_difficulty_top64", out.cumulative_difficulty_hint.hi);
    if (!detail::read_hash_blob(root, "m_block_ids", out.ids, limits.max_chain_ids, err)) return false;
    if (!detail::read_u64_blob(root, "m_block_weights", out.weights_claimed_hint,
                               limits.max_chain_ids, err))
        return false;
    if (const std::vector<std::uint8_t>* fb = epee::get_blob(root, "first_block")) out.first_block = *fb;
    return true;
}

// --- 2009 REQUEST_FLUFFY_MISSING_TX ------------------------------------------
inline bool encode_request_fluffy_missing_tx(const RequestFluffyMissingTx& m,
                                             std::vector<std::uint8_t>& out, MessageError& err) {
    std::vector<epee::Entry> e;
    e.push_back({"block_hash",
                 epee::v_blob(std::vector<std::uint8_t>(m.block_hash.begin(), m.block_hash.end()))});
    e.push_back({"current_blockchain_height", epee::v_u64(m.current_blockchain_height)});
    if (!m.missing_tx_indices.empty())
        e.push_back({"missing_tx_indices", detail::blob_of_u64(m.missing_tx_indices)});
    return encode_body(epee::v_object(std::move(e)), out, err);
}

inline bool decode_request_fluffy_missing_tx(const std::uint8_t* data, std::size_t size,
                                             RequestFluffyMissingTx& out, MessageError& err,
                                             const MessageLimits& limits = MessageLimits{}) {
    out = RequestFluffyMissingTx{};
    epee::Value root;
    if (!parse_body(data, size, root, err)) return false;
    if (!detail::read_fixed_blob(root, "block_hash", out.block_hash.data(), out.block_hash.size(), err))
        return false;
    if (!epee::get_uint(root, "current_blockchain_height", out.current_blockchain_height)) {
        err = MessageError::MissingField;
        return false;
    }
    return detail::read_u64_blob(root, "missing_tx_indices", out.missing_tx_indices,
                                 limits.max_indices, err);
}

// --- 2010 GET_TXPOOL_COMPLEMENT ----------------------------------------------
inline bool encode_get_txpool_complement(const GetTxpoolComplement& m,
                                         std::vector<std::uint8_t>& out, MessageError& err) {
    std::vector<epee::Entry> e;
    if (!m.hashes.empty()) e.push_back({"hashes", detail::blob_of_hashes(m.hashes)});
    return encode_body(epee::v_object(std::move(e)), out, err);
}

inline bool decode_get_txpool_complement(const std::uint8_t* data, std::size_t size,
                                         GetTxpoolComplement& out, MessageError& err,
                                         const MessageLimits& limits = MessageLimits{}) {
    out = GetTxpoolComplement{};
    epee::Value root;
    if (!parse_body(data, size, root, err)) return false;
    return detail::read_hash_blob(root, "hashes", out.hashes, limits.max_hashes, err);
}

} // namespace c2pool::xmr::native::levin
