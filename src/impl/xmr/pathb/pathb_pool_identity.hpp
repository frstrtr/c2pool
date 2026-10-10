// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_pool_identity.hpp
// Path B pool identity (C23) and position 0 of the carrier chain.
//
//   pool_genesis = sha256d("V37GEN" || monero_block_hash(H) || u8 len || headline)
//                  6 ASCII bytes, no terminator; 1 <= len <= 120; the headline
//                  bytes as given (printable ASCII 0x20..0x7E, no edge space)
//   pool_id      = sha256d("V37PID" || u8 network || u32 chain_id (LE) || pool_genesis)
//   raw default  = sha256d("V37PG" || u8 network)        (raw form only)
//   network      = the HELLO network byte (LaneNet)
//
//   Forms:
//     derived  --pool-genesis-from <H>:<hash64>:"<headline>"; every network;
//              the only form on mainnet. H at least
//              CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW deep on the node's chain.
//     raw      --pool-genesis <hex64>:<H>, or the network's raw default with
//              --pool-genesis-height <H>; not on mainnet; H required (no H:
//              start refused).
//   Position 0 (the genesis node of the carrier chain): id = pool_id,
//   H(0) = H + 1, b0 = H(0); a pure function of the identity.
//
// Integer and byte functions only. Header-only. Not included by any running
// component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "sharechain/v37/v37_hash.hpp"  // ::v37::sha256d

#include "pathb_lane_rules.hpp"  // LaneNet
#include "pathb_params.hpp"      // Hash32, CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW

namespace c2pool::xmr::pathb {

inline constexpr std::string_view kGenesisTag = "V37GEN";
inline constexpr std::string_view kPoolIdTag = "V37PID";
inline constexpr std::string_view kRawGenesisTag = "V37PG";

inline constexpr std::size_t kHeadlineMaxBytes = 120;
inline constexpr std::uint8_t kHeadlineByteLo = 0x20;
inline constexpr std::uint8_t kHeadlineByteHi = 0x7E;
inline constexpr std::uint64_t kGenesisMinDepth = CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

inline constexpr std::string_view kPoolGenesisFromFlag = "--pool-genesis-from";
inline constexpr std::string_view kPoolGenesisFlag = "--pool-genesis";
inline constexpr std::string_view kPoolGenesisHeightFlag = "--pool-genesis-height";

namespace pid_detail {

inline void put_tag(std::vector<std::uint8_t>& b, std::string_view t) { b.insert(b.end(), t.begin(), t.end()); }

inline std::string hex(const std::uint8_t* p, std::size_t n) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string s;
    s.reserve(2 * n);
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(kDigits[p[i] >> 4]);
        s.push_back(kDigits[p[i] & 0x0f]);
    }
    return s;
}

inline std::string hex(const Hash32& h) { return hex(h.data(), h.size()); }

inline int nibble(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// A decimal u64 (no sign, no space); nullopt otherwise or on overflow.
inline std::optional<std::uint64_t> parse_u64(std::string_view s) {
    if (s.empty()) return std::nullopt;
    std::uint64_t v = 0;
    for (const char c : s) {
        if (c < '0' || c > '9') return std::nullopt;
        const std::uint64_t d = static_cast<std::uint64_t>(c - '0');
        if (v > (UINT64_MAX - d) / 10) return std::nullopt;
        v = v * 10 + d;
    }
    return v;
}

}  // namespace pid_detail

// ---------------------------------------------------------------------------
// The headline grammar (a start-time input check, not a lane rule): 1..120
// bytes, each 0x20..0x7E, no leading or trailing space. Hashed as given.
// "" = well-formed; else the refusal text.
// ---------------------------------------------------------------------------
inline std::string headline_refusal(std::string_view h) {
    if (h.empty()) return "genesis: the headline is empty (1..120 printable ASCII bytes)";
    if (h.size() > kHeadlineMaxBytes)
        return "genesis: the headline is " + std::to_string(h.size()) + " bytes, the limit is " +
               std::to_string(kHeadlineMaxBytes);
    for (std::size_t i = 0; i < h.size(); ++i) {
        const std::uint8_t c = static_cast<std::uint8_t>(h[i]);
        if (c < kHeadlineByteLo || c > kHeadlineByteHi)
            return "genesis: the headline has a non-printable or non-ASCII byte 0x" + pid_detail::hex(&c, 1) +
                   " at offset " + std::to_string(i) + " (printable ASCII 0x20..0x7E only)";
    }
    if (h.front() == ' ' || h.back() == ' ') return "genesis: the headline must not start or end with a space";
    return {};
}

// pool_genesis of the derived form. The caller checks the headline first.
inline Hash32 pool_genesis_derived(const Hash32& block_hash, std::string_view headline) {
    std::vector<std::uint8_t> b;
    b.reserve(kGenesisTag.size() + kHashBytes + 1 + headline.size());
    pid_detail::put_tag(b, kGenesisTag);
    b.insert(b.end(), block_hash.begin(), block_hash.end());
    b.push_back(static_cast<std::uint8_t>(headline.size()));
    b.insert(b.end(), headline.begin(), headline.end());
    return ::v37::sha256d(b);
}

// pool_id = sha256d("V37PID" || u8 network || u32 chain_id LE || pool_genesis).
inline Hash32 pool_id_of(LaneNet network, std::uint32_t chain_id, const Hash32& pool_genesis) {
    std::vector<std::uint8_t> b;
    b.reserve(kPoolIdTag.size() + 1 + sizeof(std::uint32_t) + kHashBytes);
    pid_detail::put_tag(b, kPoolIdTag);
    b.push_back(static_cast<std::uint8_t>(network));
    for (std::size_t i = 0; i < sizeof(std::uint32_t); ++i) b.push_back(static_cast<std::uint8_t>(chain_id >> (8 * i)));
    b.insert(b.end(), pool_genesis.begin(), pool_genesis.end());
    return ::v37::sha256d(b);
}

// The raw default genesis of a network: sha256d("V37PG" || u8 network).
inline Hash32 default_pool_genesis(LaneNet network) {
    std::vector<std::uint8_t> b;
    pid_detail::put_tag(b, kRawGenesisTag);
    b.push_back(static_cast<std::uint8_t>(network));
    return ::v37::sha256d(b);
}

// 64 hex digits (either case), nothing else.
inline std::optional<Hash32> parse_genesis_hex(std::string_view h) {
    if (h.size() != 2 * kHashBytes) return std::nullopt;
    Hash32 out{};
    for (std::size_t i = 0; i < kHashBytes; ++i) {
        const int hi = pid_detail::nibble(h[2 * i]), lo = pid_detail::nibble(h[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return out;
}

// ---------------------------------------------------------------------------
// --pool-genesis-from <H>:<hash64>:"<headline>"
// ---------------------------------------------------------------------------
struct GenesisSpec {
    std::uint64_t height = 0;  // H
    Hash32 block_hash{};       // the hash stated for H (checked against the chain)
    std::string headline;      // the bytes as hashed

    friend bool operator==(const GenesisSpec&, const GenesisSpec&) = default;
};

// Decimal H, ':', 64 hex digits, ':', the headline (one pair of surrounding
// double quotes stripped when present; the headline may contain ':').
// "" = parsed; else the refusal text.
inline std::string parse_genesis_from(std::string_view arg, GenesisSpec& out) {
    const std::size_t c1 = arg.find(':');
    if (c1 == std::string_view::npos || c1 == 0)
        return "genesis: --pool-genesis-from wants <H>:<hash64>:\"<headline>\" (no height before the first ':')";
    const std::optional<std::uint64_t> h = pid_detail::parse_u64(arg.substr(0, c1));
    if (!h) return "genesis: --pool-genesis-from: the height '" + std::string(arg.substr(0, c1)) + "' is not a decimal u64";
    const std::size_t c2 = arg.find(':', c1 + 1);
    if (c2 == std::string_view::npos)
        return "genesis: --pool-genesis-from wants <H>:<hash64>:\"<headline>\" (no ':' after the hash)";
    const std::optional<Hash32> bh = parse_genesis_hex(arg.substr(c1 + 1, c2 - c1 - 1));
    if (!bh)
        return "genesis: --pool-genesis-from: the block hash wants exactly 64 hex digits, got '" +
               std::string(arg.substr(c1 + 1, c2 - c1 - 1)) + "'";
    std::string_view hl = arg.substr(c2 + 1);
    if (hl.size() >= 2 && hl.front() == '"' && hl.back() == '"') hl = hl.substr(1, hl.size() - 2);
    if (std::string r = headline_refusal(hl); !r.empty()) return r;
    out.height = *h;
    out.block_hash = *bh;
    out.headline = std::string(hl);
    return {};
}

// The derived form against the node's own Monero chain: `hash_at_h` the block
// id its view holds at H (nullopt: not held), `tip` the chain's best height.
// "" = the inputs are on this chain and H is at least d_conf deep.
inline std::string genesis_chain_refusal(const GenesisSpec& g, const std::optional<Hash32>& hash_at_h,
                                         std::uint64_t tip, std::uint64_t d_conf = kGenesisMinDepth) {
    if (!hash_at_h)
        return "genesis: this chain view does not hold height " + std::to_string(g.height) + " (tip " +
               std::to_string(tip) + "): the block hash cannot be checked";
    if (*hash_at_h != g.block_hash)
        return "genesis: block " + pid_detail::hex(g.block_hash) + " is not height " + std::to_string(g.height) +
               " on this chain";
    const std::uint64_t depth = tip >= g.height ? tip - g.height : 0;
    if (depth < d_conf) return "genesis: H is " + std::to_string(depth) + " deep, needs >= " + std::to_string(d_conf);
    return {};
}

// ---------------------------------------------------------------------------
// The raw form
// ---------------------------------------------------------------------------
// "" = the raw form is accepted on this network; else the refusal.
inline std::string raw_genesis_refusal(LaneNet network) {
    if (network == LaneNet::Mainnet) return "mainnet: the pool genesis must be derived, use --pool-genesis-from";
    return {};
}

// Printed on testnet and stagenet when the raw form is used.
inline constexpr std::string_view kRawGenesisWarning =
        "pool genesis given raw: not derived from the chain, not verifiable by hand";

struct RawGenesisSpec {
    Hash32 genesis{};
    std::optional<std::uint64_t> height;  // H; required

    friend bool operator==(const RawGenesisSpec&, const RawGenesisSpec&) = default;
};

// --pool-genesis <hex64>:<H> (also <hex64> alone: no height, refused at start
// by raw_height_refusal). "" = parsed; else the refusal text.
inline std::string parse_pool_genesis_raw(std::string_view arg, RawGenesisSpec& out) {
    const std::size_t c = arg.find(':');
    const std::optional<Hash32> g = parse_genesis_hex(arg.substr(0, c));
    if (!g) return "genesis: --pool-genesis wants <hex64>:<H> (64 hex digits)";
    RawGenesisSpec s;
    s.genesis = *g;
    if (c != std::string_view::npos) {
        const std::optional<std::uint64_t> h = pid_detail::parse_u64(arg.substr(c + 1));
        if (!h) return "genesis: --pool-genesis: the height '" + std::string(arg.substr(c + 1)) + "' is not a decimal u64";
        s.height = *h;
    }
    out = s;
    return {};
}

// --pool-genesis-height <H>. "" = parsed.
inline std::string parse_pool_genesis_height(std::string_view arg, std::uint64_t& out) {
    const std::optional<std::uint64_t> h = pid_detail::parse_u64(arg);
    if (!h) return "genesis: --pool-genesis-height: '" + std::string(arg) + "' is not a decimal u64";
    out = *h;
    return {};
}

// A raw start with no height is refused (the raw form REQUIRES H).
inline std::string raw_height_refusal(const std::optional<std::uint64_t>& height) {
    if (!height) return "genesis: the raw pool genesis needs its height: --pool-genesis <hex64>:<H> or --pool-genesis-height <H>";
    return {};
}

// ---------------------------------------------------------------------------
// The identity a node runs with
// ---------------------------------------------------------------------------
enum class GenesisForm : std::uint8_t { Derived = 1, Raw = 2 };

struct PoolIdentity {
    LaneNet network = LaneNet::Regtest;
    std::uint32_t chain_id = 0;
    GenesisForm form = GenesisForm::Raw;
    std::uint64_t height = 0;  // H (both forms)
    GenesisSpec spec;          // derived: (H, hash, headline); raw: empty
    Hash32 pool_genesis{};
    Hash32 pool_id{};

    friend bool operator==(const PoolIdentity&, const PoolIdentity&) = default;
};

inline PoolIdentity identity_derived(LaneNet network, std::uint32_t chain_id, const GenesisSpec& g) {
    PoolIdentity id;
    id.network = network;
    id.chain_id = chain_id;
    id.form = GenesisForm::Derived;
    id.height = g.height;
    id.spec = g;
    id.pool_genesis = pool_genesis_derived(g.block_hash, g.headline);
    id.pool_id = pool_id_of(network, chain_id, id.pool_genesis);
    return id;
}

// The raw form with its height; the caller has passed raw_genesis_refusal and
// raw_height_refusal.
inline PoolIdentity identity_raw(LaneNet network, std::uint32_t chain_id, const Hash32& genesis, std::uint64_t height) {
    PoolIdentity id;
    id.network = network;
    id.chain_id = chain_id;
    id.form = GenesisForm::Raw;
    id.height = height;
    id.pool_genesis = genesis;
    id.pool_id = pool_id_of(network, chain_id, genesis);
    return id;
}

// A raw start: the refusals in order (mainnet, then the height), else the identity.
struct RawIdentity {
    std::string refusal;  // "" = ok
    PoolIdentity identity;
};

inline RawIdentity raw_identity(LaneNet network, std::uint32_t chain_id, const RawGenesisSpec& raw) {
    RawIdentity out;
    out.refusal = raw_genesis_refusal(network);
    if (out.refusal.empty()) out.refusal = raw_height_refusal(raw.height);
    if (out.refusal.empty()) out.identity = identity_raw(network, chain_id, raw.genesis, *raw.height);
    return out;
}

// Position 0 of the carrier chain: id = pool_id, H(0) = H + 1 (b0 = H(0)).
struct GenesisPosition {
    Hash32 id{};
    std::uint64_t height = 0;  // H(0)

    friend bool operator==(const GenesisPosition&, const GenesisPosition&) = default;
};

inline std::optional<GenesisPosition> genesis_position(const PoolIdentity& id) {
    if (id.height == UINT64_MAX) return std::nullopt;
    return GenesisPosition{id.pool_id, id.height + 1};
}

// The start line: genesis: H=.. hash=.. headline=".." (hex ..) pool_genesis=.. pool_id=..
inline std::string identity_line(const PoolIdentity& id) {
    std::string s = "genesis: H=" + std::to_string(id.height) + "  ";
    if (id.form == GenesisForm::Derived) {
        const std::string& hl = id.spec.headline;
        s += "hash=" + pid_detail::hex(id.spec.block_hash) + "  headline=\"" + hl + "\" (hex " +
             pid_detail::hex(reinterpret_cast<const std::uint8_t*>(hl.data()), hl.size()) + ")  ";
    } else {
        s += "RAW (not derived)  ";
    }
    s += "pool_genesis=" + pid_detail::hex(id.pool_genesis) + "  pool_id=" + pid_detail::hex(id.pool_id);
    return s;
}

}  // namespace c2pool::xmr::pathb
