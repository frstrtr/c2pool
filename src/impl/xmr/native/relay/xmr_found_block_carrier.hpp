// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/relay/xmr_found_block_carrier.hpp
//
// C5, second half: the c2pool-side REDUNDANT BROADCAST.
//
// The v36/DASH pattern that this ports: the winning share carries enough for
// every peer to rebuild the parent block, and every peer that can rebuild it
// broadcasts it. Duplicates are a non-event at the receiving daemon; a miss is
// a lost block. Bandwidth is bought for the one message that must not be
// missed.
//
// The carrier is small because a Monero block blob IS already the compact form:
//
//     header || miner_tx || varint(n) || 32*n tx ids
//
// Bodies never travel inside a block; they travel by the fluffy protocol. A
// stagenet or mainnet block blob is single-digit KB, so the carrier is the blob
// plus attribution:
//
//     xmr_found_block { height, block_id, full_blob, nonce, extra_nonce,
//                       coinbase_inputs_ref, origin_node_id }
//
// ADMISSION ORDER IS THE POINT (the W3 discipline, cheap -> heavy, RandomX
// LAST): dedup, then structure and id, then the tip relation, then the
// canonical-coinbase check, and only then the ~25 ms RandomX verify. A peer
// that can make us spend a RandomX hash for free has a denial-of-service
// primitive; the order above means every rejection that can be made cheaply is
// made cheaply, and the expensive one is reached only by a carrier that is
// already well-formed, on our tip, and paying the canonical settlement.
//
// WHAT EARNS A BAN, and what does not. A block id that is not the id of the
// blob, a coinbase that is not the canonical settlement for that lane state,
// and a RandomX hash BELOW TARGET are all "you forged this": ban. A block on a
// branch we do not have, or a RandomX verdict that blames OUR verifier (no
// seed, no VM), is "we cannot judge this right now": defer, never ban. Getting
// that asymmetry wrong is how a pool bans its own network.
//
// Note the fence around the coinbase check: here it gates RELAY only. Whether a
// non-canonical coinbase is admissible to the LANE is a separate, unwired
// question (#1551), and this component does not answer it.
//
// SCOPE FENCE: src/impl/xmr/ only; no consensus digest; src/sharechain/v37 is
// not touched.
// ---------------------------------------------------------------------------
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "impl/xmr/native/consensus/xmr_block_id.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/contracts/chain_index.hpp"
#include "impl/xmr/native/contracts/relay.hpp"
#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/relay/xmr_block_relay.hpp"

namespace c2pool::xmr::native::relay {

// The XMR carrier cap. A block that does not fit is not a block we could have
// built, so the cap is a structural reject, not a tuning knob.
inline constexpr std::size_t FOUND_BLOCK_MAX_BLOB = 128u * 1024u;
inline constexpr std::uint8_t FOUND_BLOCK_WIRE_VERSION = 1;

// Enough for any peer holding the same lane state to RE-DERIVE the coinbase
// bytes (#1551 canonical K_fair payees) and check that ours is the canonical
// one. The bytes themselves are already in full_blob; this is what they must
// agree with.
struct CoinbaseInputsRef {
    Hash          chain_id{};
    Hash          lane_commitment{};
    std::uint64_t reward     = 0;
    std::uint64_t ledger_seq = 0;
};

struct FoundBlockCarrier {
    std::uint64_t             height = 0;
    Hash                      block_id{};
    std::vector<std::uint8_t> full_blob;
    std::uint32_t             nonce       = 0;
    std::uint32_t             extra_nonce = 0;
    CoinbaseInputsRef         inputs;
    Hash                      origin_node_id{};
};

enum class CarrierWireError : std::uint8_t {
    None = 0,
    Truncated,
    BadVersion,
    Oversize,
};

inline const char* to_string(CarrierWireError e) noexcept {
    switch (e) {
        case CarrierWireError::None:       return "None";
        case CarrierWireError::Truncated:  return "Truncated";
        case CarrierWireError::BadVersion: return "BadVersion";
        case CarrierWireError::Oversize:   return "Oversize";
    }
    return "?";
}

// --- wire codec (fixed-width little-endian; no varints, nothing to disagree
//     about across implementations) ------------------------------------------
namespace detail {

inline void put_u32(std::vector<std::uint8_t>& o, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) o.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
}
inline void put_u64(std::vector<std::uint8_t>& o, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) o.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
}
inline void put_hash(std::vector<std::uint8_t>& o, const Hash& h) {
    o.insert(o.end(), h.begin(), h.end());
}

struct Cursor {
    const std::uint8_t* p = nullptr;
    std::size_t         n = 0;
    std::size_t         i = 0;

    bool take(void* dst, std::size_t k) {
        if (n - i < k) return false;
        std::memcpy(dst, p + i, k);
        i += k;
        return true;
    }
    bool u32(std::uint32_t& v) {
        std::uint8_t b[4];
        if (!take(b, 4)) return false;
        v = 0;
        for (int k = 0; k < 4; ++k) v |= static_cast<std::uint32_t>(b[k]) << (8 * k);
        return true;
    }
    bool u64(std::uint64_t& v) {
        std::uint8_t b[8];
        if (!take(b, 8)) return false;
        v = 0;
        for (int k = 0; k < 8; ++k) v |= static_cast<std::uint64_t>(b[k]) << (8 * k);
        return true;
    }
    bool hash(Hash& h) { return take(h.data(), h.size()); }
};

} // namespace detail

inline std::vector<std::uint8_t> encode_found_block(const FoundBlockCarrier& c) {
    std::vector<std::uint8_t> o;
    o.reserve(c.full_blob.size() + 160);
    o.push_back(FOUND_BLOCK_WIRE_VERSION);
    detail::put_u64(o, c.height);
    detail::put_hash(o, c.block_id);
    detail::put_u32(o, static_cast<std::uint32_t>(c.full_blob.size()));
    o.insert(o.end(), c.full_blob.begin(), c.full_blob.end());
    detail::put_u32(o, c.nonce);
    detail::put_u32(o, c.extra_nonce);
    detail::put_hash(o, c.inputs.chain_id);
    detail::put_hash(o, c.inputs.lane_commitment);
    detail::put_u64(o, c.inputs.reward);
    detail::put_u64(o, c.inputs.ledger_seq);
    detail::put_hash(o, c.origin_node_id);
    return o;
}

inline bool decode_found_block(const std::uint8_t* data, std::size_t size,
                               FoundBlockCarrier& out, CarrierWireError& err) {
    out = FoundBlockCarrier{};
    err = CarrierWireError::None;
    detail::Cursor r{data, size, 0};

    std::uint8_t ver = 0;
    if (!r.take(&ver, 1))                    { err = CarrierWireError::Truncated;  return false; }
    if (ver != FOUND_BLOCK_WIRE_VERSION)     { err = CarrierWireError::BadVersion; return false; }
    if (!r.u64(out.height))                  { err = CarrierWireError::Truncated;  return false; }
    if (!r.hash(out.block_id))               { err = CarrierWireError::Truncated;  return false; }

    std::uint32_t blob_len = 0;
    if (!r.u32(blob_len))                    { err = CarrierWireError::Truncated;  return false; }
    // Checked BEFORE the allocation, so an oversize claim costs nothing.
    if (blob_len > FOUND_BLOCK_MAX_BLOB)     { err = CarrierWireError::Oversize;   return false; }
    if (size - r.i < blob_len)               { err = CarrierWireError::Truncated;  return false; }
    out.full_blob.assign(data + r.i, data + r.i + blob_len);
    r.i += blob_len;

    if (!r.u32(out.nonce))                    { err = CarrierWireError::Truncated; return false; }
    if (!r.u32(out.extra_nonce))              { err = CarrierWireError::Truncated; return false; }
    if (!r.hash(out.inputs.chain_id))         { err = CarrierWireError::Truncated; return false; }
    if (!r.hash(out.inputs.lane_commitment))  { err = CarrierWireError::Truncated; return false; }
    if (!r.u64(out.inputs.reward))            { err = CarrierWireError::Truncated; return false; }
    if (!r.u64(out.inputs.ledger_seq))        { err = CarrierWireError::Truncated; return false; }
    if (!r.hash(out.origin_node_id))          { err = CarrierWireError::Truncated; return false; }
    return true;
}

inline bool decode_found_block(const std::vector<std::uint8_t>& bytes,
                               FoundBlockCarrier& out, CarrierWireError& err) {
    return decode_found_block(bytes.data(), bytes.size(), out, err);
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------
enum class CarrierVerdict : std::uint8_t {
    Relayed = 0,
    Duplicate,          // we already relayed this block id
    Malformed,          // the blob is not a block
    IdMismatch,         // the blob does not hash to the claimed id
    HeightMismatch,     // the coinbase height is not the claimed height
    NonceMismatch,      // the claimed winning nonce is not in the blob
    ForeignBranch,      // not on our tip: defer, this is not misbehaviour
    CoinbaseMismatch,   // not the canonical settlement for that lane state
    PowRejected,        // BelowTarget / Malformed: forged
    PowDeferred,        // our verifier could not judge it
    BudgetExceeded,     // per-peer carrier budget
    RelayRefused,       // the relay itself refused (see relay.why)
};

inline const char* to_string(CarrierVerdict v) noexcept {
    switch (v) {
        case CarrierVerdict::Relayed:          return "Relayed";
        case CarrierVerdict::Duplicate:        return "Duplicate";
        case CarrierVerdict::Malformed:        return "Malformed";
        case CarrierVerdict::IdMismatch:       return "IdMismatch";
        case CarrierVerdict::HeightMismatch:   return "HeightMismatch";
        case CarrierVerdict::NonceMismatch:    return "NonceMismatch";
        case CarrierVerdict::ForeignBranch:    return "ForeignBranch";
        case CarrierVerdict::CoinbaseMismatch: return "CoinbaseMismatch";
        case CarrierVerdict::PowRejected:      return "PowRejected";
        case CarrierVerdict::PowDeferred:      return "PowDeferred";
        case CarrierVerdict::BudgetExceeded:   return "BudgetExceeded";
        case CarrierVerdict::RelayRefused:     return "RelayRefused";
    }
    return "?";
}

struct CarrierOutcome {
    CarrierVerdict    verdict = CarrierVerdict::Malformed;
    bool              ban     = false;   // forged: the sender is lying to us
    bool              defer   = false;   // we could not judge it: keep the peer
    std::string       why;
    BlockRelayVerdict relay{};           // set when verdict == Relayed
};

// The peer-side ACCEPT gate for the coinbase: re-derive the canonical
// settlement coinbase from the carrier's CoinbaseInputsRef and compare it with
// the bytes in the blob. Supplied by the lane (it is lane state, not chain
// state); UNSET means "not wired", and unwired is NOT a pass -- an unchecked
// coinbase would let a peer spend our bandwidth relaying a block that pays
// somebody else. Configure `require_coinbase_check = false` only for a node
// that deliberately relays without the lane check.
using CanonicalCoinbaseCheck =
    std::function<bool(const FoundBlockCarrier&, const ParsedBlock&,
                       const std::uint8_t* block_blob, std::string& why)>;

struct CarrierConfig {
    bool          require_coinbase_check = true;
    std::size_t   max_seen               = 512;    // dedup book, bounded
    std::uint32_t seen_seconds           = 3600;
    std::uint32_t max_per_peer_per_window = 8;     // carriers, not bytes
    std::uint32_t window_seconds          = 60;
    // How far off our tip a carrier may sit and still be relayed. A block at
    // tip+1 is the normal case; anything else we defer rather than push.
    bool          require_on_tip         = true;
};

// ---------------------------------------------------------------------------
// FoundBlockIngress -- one carrier in, one relay decision out.
// ---------------------------------------------------------------------------
class FoundBlockIngress {
public:
    FoundBlockIngress(IBlockRelay&             relay_out,
                      const IChainView*        chain,
                      CarrierConfig            cfg = CarrierConfig{},
                      RelayLog                 log = RelayLog{})
        : m_relay(relay_out), m_chain(chain), m_cfg(cfg), m_log(std::move(log)) {}

    void set_pow_gate(PowGate g)                { m_pow = std::move(g); }
    void set_coinbase_check(CanonicalCoinbaseCheck c) { m_coinbase = std::move(c); }
    void set_clock(RelayClock c)                { m_clock = std::move(c); }

    // Ask the relay's own retained book whether this block already went out, so
    // two ingress paths (a carrier and our own find) cannot double-announce.
    // A plain hook rather than a downcast: the ingress must work against any
    // IBlockRelay, including a test double.
    void set_already_relayed(std::function<bool(const Hash&)> f) {
        m_already_relayed = std::move(f);
    }

    // How many times the RandomX gate was actually entered. The KAT asserts
    // this stays at zero for every carrier a cheaper check rejected.
    std::uint64_t pow_calls() const noexcept { return m_pow_calls; }

    CarrierOutcome on_carrier(const PeerRef& from, const FoundBlockCarrier& c) {
        CarrierOutcome o;

        // --- 0. per-peer budget (before we touch the bytes) ----------------
        if (!take_token(from)) {
            o.verdict = CarrierVerdict::BudgetExceeded;
            o.why     = "peer " + from.addr + " over its carrier budget";
            return o;
        }

        // --- 1. dedup ------------------------------------------------------
        expire_seen();
        if (m_seen.count(key(c.block_id)) != 0 ||
            (m_already_relayed && m_already_relayed(c.block_id))) {
            o.verdict = CarrierVerdict::Duplicate;
            o.why     = "already relayed";
            return o;
        }

        // --- 2. structure and identity -------------------------------------
        if (c.full_blob.empty() || c.full_blob.size() > FOUND_BLOCK_MAX_BLOB) {
            o.verdict = CarrierVerdict::Malformed;
            o.ban     = true;
            o.why     = "blob is empty or over the carrier cap";
            return o;
        }
        ParsedBlock   pb;
        BlockIdentity ident;
        const BlockParseStatus st = parse_and_identify(c.full_blob, pb, ident);
        if (st != BlockParseStatus::Ok) {
            o.verdict = CarrierVerdict::Malformed;
            o.ban     = true;
            o.why     = std::string("blob does not parse: ") + native::to_string(st);
            return o;
        }
        if (ident.id != c.block_id) {
            o.verdict = CarrierVerdict::IdMismatch;
            o.ban     = true;
            o.why     = "blob does not hash to the claimed block id";
            return o;
        }
        if (pb.header.nonce != c.nonce) {
            o.verdict = CarrierVerdict::NonceMismatch;
            o.ban     = true;
            o.why     = "the claimed winning nonce is not the blob's nonce";
            return o;
        }
        CoinbaseFields cb;
        if (!parse_coinbase_fields(c.full_blob.data(), pb, cb)) {
            o.verdict = CarrierVerdict::Malformed;
            o.ban     = true;
            o.why     = "coinbase does not parse";
            return o;
        }
        if (cb.height != c.height) {
            o.verdict = CarrierVerdict::HeightMismatch;
            o.ban     = true;
            o.why     = "coinbase height is not the claimed height";
            return o;
        }

        // --- 3. the tip relation. NEVER a ban: a peer on another branch, or
        //        one that is simply ahead of us, is not misbehaving ---------
        if (m_cfg.require_on_tip && m_chain) {
            const std::optional<node::ChainMainBlock> tip = m_chain->tip();
            if (!tip) {
                o.verdict = CarrierVerdict::ForeignBranch;
                o.defer   = true;
                o.why     = "we have no tip yet";
                return o;
            }
            if (pb.header.prev_id != tip->id || c.height != tip->height + 1) {
                o.verdict = CarrierVerdict::ForeignBranch;
                o.defer   = true;
                o.why     = "block does not extend our tip";
                return o;
            }
        }

        // --- 4. the canonical coinbase (cheap, and it is the lane's rule) --
        if (m_coinbase) {
            std::string why;
            if (!m_coinbase(c, pb, c.full_blob.data(), why)) {
                o.verdict = CarrierVerdict::CoinbaseMismatch;
                o.ban     = true;
                o.why     = why.empty() ? "coinbase is not the canonical settlement" : why;
                return o;
            }
        } else if (m_cfg.require_coinbase_check) {
            o.verdict = CarrierVerdict::CoinbaseMismatch;
            o.defer   = true;   // OUR gap, not the peer's fault
            o.why     = "no canonical-coinbase check is wired; refusing to relay blind";
            return o;
        }

        // --- 5. RandomX, LAST ----------------------------------------------
        BlockRelayRequest req;
        req.block_id    = c.block_id;
        req.height      = c.height;
        req.block_blob  = c.full_blob;
        req.tx_hashes   = pb.tx_hashes;
        req.nonce       = c.nonce;
        req.extra_nonce = c.extra_nonce;

        ++m_pow_calls;
        const PowVerdict pv = m_pow ? m_pow(req, ident.hashing_blob) : PowVerdict::Unavailable;
        if (pv != PowVerdict::Accept) {
            if (pow_blames_the_block(pv)) {
                o.verdict = CarrierVerdict::PowRejected;
                o.ban     = true;
                o.why     = std::string("randomx: ") + to_string(pv);
            } else {
                o.verdict = CarrierVerdict::PowDeferred;
                o.defer   = true;
                o.why     = std::string("randomx could not judge it: ") + to_string(pv);
            }
            say(true, "carrier from " + from.addr + " rejected: " + o.why);
            return o;
        }

        // --- 6. relay it under OUR OWN arms and policy ---------------------
        // The relay re-runs its own gate (attestation or verifier) and applies
        // rule 5 itself: a node that holds no bodies falls back to its daemon
        // arm, and a node with neither reports reached_network() == false.
        remember(c.block_id);
        o.relay   = m_relay.relay(req);
        o.verdict = o.relay.reached_network() ? CarrierVerdict::Relayed
                                              : CarrierVerdict::RelayRefused;
        o.why     = o.relay.why;
        return o;
    }

private:
    using Key = std::string;

    static Key key(const Hash& h) {
        return Key(reinterpret_cast<const char*>(h.data()), h.size());
    }

    std::uint64_t now() const {
        if (m_clock) return m_clock();
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
    }

    void say(bool err, const std::string& line) const {
        if (m_log) m_log(err, line);
    }

    void remember(const Hash& id) {
        m_seen[key(id)] = now();
        m_order.push_back(key(id));
        while (m_order.size() > m_cfg.max_seen) {
            m_seen.erase(m_order.front());
            m_order.pop_front();
        }
    }

    void expire_seen() {
        const std::uint64_t t = now();
        while (!m_order.empty()) {
            const auto it = m_seen.find(m_order.front());
            if (it == m_seen.end()) { m_order.pop_front(); continue; }
            if (t >= it->second && t - it->second > m_cfg.seen_seconds) {
                m_seen.erase(it);
                m_order.pop_front();
                continue;
            }
            break;
        }
    }

    bool take_token(const PeerRef& p) {
        const std::uint64_t t = now();
        Bucket&             b = m_buckets[p.addr];
        if (t < b.window_start || t - b.window_start >= m_cfg.window_seconds) {
            b.window_start = t;
            b.used         = 0;
        }
        if (b.used >= m_cfg.max_per_peer_per_window) return false;
        ++b.used;
        return true;
    }

    struct Bucket {
        std::uint64_t window_start = 0;
        std::uint32_t used         = 0;
    };

    IBlockRelay&           m_relay;
    const IChainView*      m_chain = nullptr;
    CarrierConfig          m_cfg;
    RelayLog               m_log;
    PowGate                m_pow;
    CanonicalCoinbaseCheck m_coinbase;
    RelayClock             m_clock;
    std::function<bool(const Hash&)> m_already_relayed;

    std::unordered_map<Key, std::uint64_t> m_seen;
    std::deque<Key>                        m_order;
    std::unordered_map<std::string, Bucket> m_buckets;
    std::uint64_t                          m_pow_calls = 0;
};

} // namespace c2pool::xmr::native::relay
