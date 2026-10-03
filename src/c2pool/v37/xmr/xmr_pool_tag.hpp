// SPDX-License-Identifier: AGPL-3.0-or-later
//
// POOL IDENTITY (RULES RATCHET R1, operator rulings 2026-10-03; the LAST flag
// day before the mainnet genesis).
//
// A pool is named by a GENESIS nobody could have chosen in advance and by the
// network and lane it lives on. Nothing on chain names a RULE any more: a lane
// block names its POOL and its EPOCH (xmr_credit_cut.hpp, the V37P v2 field);
// the rules of every epoch ride the relay HELLO and the RATCHET event.
//
//   pool_genesis = sha256d( "V37GEN"                     6 bytes, ASCII, no NUL
//                        || b32 monero_block_hash(H)      the block at height H on the pool's OWN
//                                                        Monero network (mainnet/testnet/stagenet/regtest)
//                        || u8  len                       1 <= len <= 120
//                        || headline[len] )               the headline bytes, no NUL, no normalisation
//   pool_id      = sha256d( "V37PID" || u8 network || u32 chain_id || b32 pool_genesis )
//   network: 0 mainnet 1 testnet 2 stagenet 3 regtest (the relay HELLO network byte)
//
// "Nothing up my sleeve": H must be at least D_conf (60) blocks deep when the
// pool launches, the block hash is public (any explorer), the headline is a
// printable sentence of the day. Anyone recomputes pool_id by hand from the
// node's start line and compares it with the field in every lane coinbase and
// with the HELLO (docs/xmr-lane/pool-genesis.md).
//
// The RAW form (--pool-genesis <hex64>, or the per-network default below) stays
// accepted on regtest, and on testnet / stagenet with a WARNING; on mainnet it is
// REFUSED: the mainnet pool genesis must be derived.
//
// Retired: pool_tag = sha256d('V37PT2' || lane_tag || pool_genesis || rules_digest)
// (POOL-LINEAGE 09-25 / LANE-RULES 10-02). lane_tag stays what the relay HELLO's
// PoolId carries (geometry, consensus version, authority); the rules digest moved
// to the epoch table (xmr_epoch.hpp).
//
// Integer-only, no allocation beyond the byte vectors.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <c2pool/v37/roundabout/rb_lane_tag.hpp>   // S1 lane_tag (read-only use)
#include <sharechain/v37/v37_hash.hpp>

#include "xmr_credit_cut.hpp"                      // the V37P v2 field codec + classify_lineage

namespace c2pool::v37n::xmr::lineage {

using ::v37::bytes32;

inline constexpr const char* TAG_GENESIS      = "V37GEN";  // the derived pool genesis domain
inline constexpr const char* TAG_POOL_ID      = "V37PID";  // the pool id domain
inline constexpr const char* TAG_POOL_GENESIS = "V37PG";   // the raw per-network default genesis (test networks only)

inline constexpr std::size_t   kHeadlineMaxBytes = 120;    // u8 length prefix, <= 120 B
inline constexpr std::uint64_t kGenesisMinDepth  = 60;     // H must be >= D_conf deep (C1)

// ── the headline grammar (operator default 2026-10-03: printable ASCII) ────
// Every byte 0x20..0x7E, 1..120 bytes, no leading or trailing space. The bytes
// are hashed exactly as given: no NFC, no case folding, no trimming.
// "" = well-formed; else the refusal text.
inline std::string headline_refusal(const std::string& h) {
    if (h.empty()) return "genesis: the headline is empty (1..120 printable ASCII bytes)";
    if (h.size() > kHeadlineMaxBytes)
        return "genesis: the headline is " + std::to_string(h.size()) + " bytes, the limit is " +
               std::to_string(kHeadlineMaxBytes);
    for (std::size_t i = 0; i < h.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(h[i]);
        if (c < 0x20 || c > 0x7E)
            return "genesis: the headline has a non-printable or non-ASCII byte 0x" +
                   std::string(1, "0123456789abcdef"[c >> 4]) + std::string(1, "0123456789abcdef"[c & 15]) +
                   " at offset " + std::to_string(i) + " (printable ASCII 0x20..0x7E only)";
    }
    if (h.front() == ' ' || h.back() == ' ') return "genesis: the headline must not start or end with a space";
    return {};
}

// pool_genesis = sha256d("V37GEN" || block_hash(H) || u8 len || headline). The
// caller validates the headline first (headline_refusal); the bytes are hashed
// as given.
inline bytes32 pool_genesis_derived(const bytes32& block_hash, const std::string& headline) {
    std::vector<std::uint8_t> b;
    b.reserve(6 + 32 + 1 + headline.size());
    ::c2pool::v37n::rb::put_tag(b, TAG_GENESIS);
    ::c2pool::v37n::rb::put_b32(b, block_hash);
    b.push_back(static_cast<std::uint8_t>(headline.size()));
    b.insert(b.end(), headline.begin(), headline.end());
    return ::c2pool::v37n::rb::hash_bytes(b);
}

// pool_id = sha256d("V37PID" || u8 network || u32 chain_id || b32 pool_genesis): fixed for life.
inline bytes32 pool_id(std::uint8_t network, std::uint32_t chain_id, const bytes32& pool_genesis) {
    std::vector<std::uint8_t> b;
    b.reserve(6 + 1 + 4 + 32);
    ::c2pool::v37n::rb::put_tag(b, TAG_POOL_ID);
    b.push_back(network);
    ::c2pool::v37n::rb::put_u32(b, chain_id);
    ::c2pool::v37n::rb::put_b32(b, pool_genesis);
    return ::c2pool::v37n::rb::hash_bytes(b);
}

// The RAW default pool genesis of a network: sha256d('V37PG' || u8 network).
// Test networks only (refused on mainnet by raw_genesis_refusal below).
inline bytes32 default_pool_genesis(std::uint8_t network) {
    std::vector<std::uint8_t> b;
    ::c2pool::v37n::rb::put_tag(b, TAG_POOL_GENESIS);
    b.push_back(network);
    return ::c2pool::v37n::rb::hash_bytes(b);
}

// The S1 lane_tag of a pool's single roundabout (== relay::pool_id_of().lane_tag).
// Carried in HELLO (geometry, consensus version, authority); not a pool_id input.
inline bytes32 lane_tag_of(std::uint32_t chain_id, const ::v37::LaneParams& p,
                           std::uint32_t version = ::v37::SHIPPED_CONSENSUS_VERSION,
                           std::uint32_t authority = 0) {
    const auto ctx = ::c2pool::v37n::rb::LaneTagContext::of(chain_id, p, version, authority);
    return ::c2pool::v37n::rb::lane_tag(ctx, 0, 0, 0);
}

// 64 hex digits (either case), nothing else.
inline bool parse_genesis_hex(const std::string& h, bytes32& out) {
    if (h.size() != 64) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < 32; ++i) {
        const int hi = nib(h[2 * i]), lo = nib(h[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

// ── --pool-genesis-from <H>:<hash64>:"<headline>" ───────────────────────────
struct GenesisSpec {
    std::uint64_t height = 0;      // H
    bytes32       block_hash{};    // the hash the operator states for H (checked against the chain)
    std::string   headline;        // the headline bytes, exactly as hashed
    bool operator==(const GenesisSpec&) const = default;
};

// The argument grammar: decimal H, ':', 64 hex digits, ':', the headline (one
// pair of surrounding double quotes is stripped when present; the headline
// itself may contain ':'). "" = parsed; else the refusal text.
inline std::string parse_genesis_from(const std::string& arg, GenesisSpec& out) {
    const std::size_t c1 = arg.find(':');
    if (c1 == std::string::npos || c1 == 0)
        return "genesis: --pool-genesis-from wants <H>:<hash64>:\"<headline>\" (no height before the first ':')";
    std::uint64_t h = 0;
    for (std::size_t i = 0; i < c1; ++i) {
        const char c = arg[i];
        if (c < '0' || c > '9') return "genesis: --pool-genesis-from: the height '" + arg.substr(0, c1) + "' is not a decimal number";
        if (h > (~std::uint64_t{0} - static_cast<std::uint64_t>(c - '0')) / 10) return "genesis: --pool-genesis-from: the height overflows";
        h = h * 10 + static_cast<std::uint64_t>(c - '0');
    }
    const std::size_t c2 = arg.find(':', c1 + 1);
    if (c2 == std::string::npos) return "genesis: --pool-genesis-from wants <H>:<hash64>:\"<headline>\" (no ':' after the hash)";
    bytes32 bh{};
    if (!parse_genesis_hex(arg.substr(c1 + 1, c2 - c1 - 1), bh))
        return "genesis: --pool-genesis-from: the block hash wants exactly 64 hex digits, got '" + arg.substr(c1 + 1, c2 - c1 - 1) + "'";
    std::string hl = arg.substr(c2 + 1);
    if (hl.size() >= 2 && hl.front() == '"' && hl.back() == '"') hl = hl.substr(1, hl.size() - 2);
    if (const std::string r = headline_refusal(hl); !r.empty()) return r;
    out.height = h; out.block_hash = bh; out.headline = hl;
    return {};
}

// What the chain says about the stated (H, hash): `hash_at_h` is the block id
// the node's chain view carries at height H (nullopt: not held / not synced),
// `tip` the chain's best height. "" = the genesis inputs are on this chain and
// deep enough; else the refusal text (the node refuses to start).
inline std::string genesis_chain_refusal(const GenesisSpec& g, const std::optional<bytes32>& hash_at_h,
                                         std::uint64_t tip, std::uint64_t d_conf = kGenesisMinDepth) {
    static const char* d = "0123456789abcdef";
    std::string hx;
    for (std::uint8_t b : g.block_hash) { hx.push_back(d[b >> 4]); hx.push_back(d[b & 15]); }
    if (!hash_at_h)
        return "genesis: this chain view does not hold height " + std::to_string(g.height) + " (tip " + std::to_string(tip) +
               "): the block hash cannot be checked";
    if (!(*hash_at_h == g.block_hash))
        return "genesis: block " + hx + " is not height " + std::to_string(g.height) + " on this chain";
    const std::uint64_t depth = tip >= g.height ? tip - g.height : 0;
    if (depth < d_conf)
        return "genesis: H is " + std::to_string(depth) + " deep, needs >= " + std::to_string(d_conf);
    return {};
}

// ── the raw form on a network ────────────────────────────────────────────────
// "" = accepted; else the refusal (mainnet only).
inline std::string raw_genesis_refusal(std::uint8_t network) {
    if (network == 0) return "mainnet: the pool genesis must be derived, use --pool-genesis-from";
    return {};
}
// The WARNING printed on testnet / stagenet when the raw form is used (regtest: silent).
inline const char* raw_genesis_warning() {
    return "pool genesis given raw: not derived from the chain, not verifiable by hand";
}

// ── the identity a node runs with (printed at every start, persisted in GenesisRec v2) ──
enum class GenesisForm : std::uint8_t { Derived = 1, Raw = 2 };

struct PoolIdentity {
    std::uint8_t  network = 3;
    std::uint32_t chain_id = 0;
    bytes32       pool_genesis{};
    bytes32       pool_id{};
    GenesisForm   form = GenesisForm::Raw;
    GenesisSpec   spec;            // derived: (H, hash, headline); raw: zeros / empty
    bool operator==(const PoolIdentity&) const = default;
};

inline PoolIdentity identity_derived(std::uint8_t network, std::uint32_t chain_id, const GenesisSpec& g) {
    PoolIdentity id;
    id.network = network; id.chain_id = chain_id; id.form = GenesisForm::Derived; id.spec = g;
    id.pool_genesis = pool_genesis_derived(g.block_hash, g.headline);
    id.pool_id = pool_id(network, chain_id, id.pool_genesis);
    return id;
}
inline PoolIdentity identity_raw(std::uint8_t network, std::uint32_t chain_id, const bytes32& genesis) {
    PoolIdentity id;
    id.network = network; id.chain_id = chain_id; id.form = GenesisForm::Raw;
    id.pool_genesis = genesis;
    id.pool_id = pool_id(network, chain_id, genesis);
    return id;
}

// The start line: genesis: H=.. hash=.. headline="..." (hex ..) pool_genesis=.. pool_id=..
inline std::string identity_line(const PoolIdentity& id) {
    static const char* d = "0123456789abcdef";
    auto hx = [&](const bytes32& b) { std::string s; for (std::uint8_t x : b) { s.push_back(d[x >> 4]); s.push_back(d[x & 15]); } return s; };
    std::string s = "genesis: ";
    if (id.form == GenesisForm::Derived) {
        std::string hh;
        for (unsigned char c : id.spec.headline) { hh.push_back(d[c >> 4]); hh.push_back(d[c & 15]); }
        s += "H=" + std::to_string(id.spec.height) + " hash=" + hx(id.spec.block_hash) + "  headline=\"" + id.spec.headline +
             "\" (hex " + hh + ")  ";
    } else {
        s += "RAW (not derived)  ";
    }
    s += "pool_genesis=" + hx(id.pool_genesis) + "  pool_id=" + hx(id.pool_id);
    return s;
}

// Chain-block classification by the V37P v2 field (the codec and the classifier
// live beside the field in xmr_credit_cut.hpp so the coinbase-authority decoder
// needs no roundabout headers).
using ::c2pool::v37n::xmr::credit::BlockLineage;
using ::c2pool::v37n::xmr::credit::PoolField;
using ::c2pool::v37n::xmr::credit::classify_lineage;
using ::c2pool::v37n::xmr::credit::to_string;

} // namespace c2pool::v37n::xmr::lineage
