// SPDX-License-Identifier: AGPL-3.0-or-later
//
// POOL-LINEAGE (operator ruling 2026-09-25): a BLOCK-LEVEL pool id.
//
// Two defects share one root: nothing in a found block said WHICH pool built
// it. (1) Two v37 pools on one Monero chain stalled each other's settlement
// (each pool's nodes booked the other pool's found blocks as their own lane cut
// and waited for a relay repair no peer could serve). (2) A fresh node booting
// on a chain that still carries lane blocks of an EARLIER pool (same chain_id
// and config) could not decide their roots, held them and suspended the lane.
//
//   pool_tag = sha256d( 'V37PT2' || lane_tag || pool_genesis_id || rules_digest )   (32 B)
//
// (LANE-RULES flag day, operator ruling R3 2026-10-02: rules_digest joined the
// preimage and the domain moved from 'V37PT' to 'V37PT2'; the V37P field, its
// 37 bytes and its version byte are unchanged.)
//
//   lane_tag         the S1 roundabout tag the relay HELLO already carries
//                    (rb_lane_tag.hpp, single-roundabout values map_epoch 0,
//                    rb_index 0, stripe 0: chain_id + LaneParams geometry +
//                    consensus version + authority 0)
//   pool_genesis_id  a 32-byte per-POOL constant (--pool-genesis <hex64>).
//                    Default: the fixed per-network constant below, so there
//                    is ONE default pool per network; a new pool picks its own
//                    random id (e.g. `openssl rand -hex 32`) and every node of
//                    that pool runs with it.
//   rules_digest     sha256d of the node's LaneRules list (xmr_lane_rules.hpp):
//                    every settlement rule outside LaneParams (D_conf, owed
//                    floor, output cap, root-age bound, booking order, ledger
//                    rule bits, compiled-in constants, the drain placeholders)
//                    plus the HELLO lane_params_digest and enrol digest. A node
//                    with other rules computes ANOTHER pool_tag, so our lane
//                    blocks are Foreign ("not-lane") on it and it books none of
//                    them: never Mismatch / debit-only. Every input is a
//                    HELLO-compared field, so HELLO-compatible <=> equal tag.
//
// Every lane block a pool builds commits pool_tag in the V37C coinbase tail
// (the versioned "V37P" field, xmr_credit_cut.hpp). A chain block is a LANE
// block for this pool iff its tail carries OUR pool_tag; a different tag, an
// untagged (pre-lineage) tail or a malformed field make it an ORDINARY Monero
// block for this pool: never booked as a lane cut, never refused, never held,
// never a lane-root question. The relay HELLO carries pool_genesis_id next to
// lane_tag, so a node of another pool is refused as TAG_MISMATCH
// field=pool_genesis before anything crosses.
//
// CONSENSUS BYTES: the V37P field changes the coinbase (+37 B); a flag day
// before mainnet, accepted by the operator.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <c2pool/v37/roundabout/rb_lane_tag.hpp>   // S1 lane_tag (read-only use)
#include <sharechain/v37/v37_hash.hpp>

#include "xmr_credit_cut.hpp"                      // the V37P field codec

namespace c2pool::v37n::xmr::lineage {

using ::v37::bytes32;

inline constexpr const char* TAG_POOL_TAG     = "V37PT2";  // pool_tag domain (LANE-RULES: was "V37PT")
inline constexpr const char* TAG_POOL_GENESIS = "V37PG";   // default per-network genesis domain

// The default pool genesis of a network (0 mainnet 1 testnet 2 stagenet 3
// regtest, the relay HELLO network byte): sha256d('V37PG' || u8 network).
inline bytes32 default_pool_genesis(std::uint8_t network) {
    std::vector<std::uint8_t> b;
    ::c2pool::v37n::rb::put_tag(b, TAG_POOL_GENESIS);
    b.push_back(network);
    return ::c2pool::v37n::rb::hash_bytes(b);
}

// The S1 lane_tag of a pool's single roundabout (== relay::pool_id_of().lane_tag).
inline bytes32 lane_tag_of(std::uint32_t chain_id, const ::v37::LaneParams& p,
                           std::uint32_t version = ::v37::SHIPPED_CONSENSUS_VERSION,
                           std::uint32_t authority = 0) {
    const auto ctx = ::c2pool::v37n::rb::LaneTagContext::of(chain_id, p, version, authority);
    return ::c2pool::v37n::rb::lane_tag(ctx, 0, 0, 0);
}

// `rules_digest` = lanerules::rules_digest(the node's LaneRules). There is no
// overload without it: a tag that ignores the lane rules is the A2 fork.
inline bytes32 pool_tag(const bytes32& lane_tag, const bytes32& pool_genesis_id, const bytes32& rules_digest) {
    std::vector<std::uint8_t> b;
    ::c2pool::v37n::rb::put_tag(b, TAG_POOL_TAG);
    ::c2pool::v37n::rb::put_b32(b, lane_tag);
    ::c2pool::v37n::rb::put_b32(b, pool_genesis_id);
    ::c2pool::v37n::rb::put_b32(b, rules_digest);
    return ::c2pool::v37n::rb::hash_bytes(b);
}

inline bytes32 pool_tag_for(std::uint32_t chain_id, const ::v37::LaneParams& p, const bytes32& pool_genesis_id,
                            const bytes32& rules_digest) {
    return pool_tag(lane_tag_of(chain_id, p), pool_genesis_id, rules_digest);
}

// --pool-genesis <hex64>: exactly 64 hex digits (either case), nothing else.
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

// Chain-block classification by the V37C tail's pool tag (the codec and the
// classifier live beside the V37P field in xmr_credit_cut.hpp so the coinbase-
// authority decoder needs no roundabout headers).
using ::c2pool::v37n::xmr::credit::BlockLineage;
using ::c2pool::v37n::xmr::credit::classify_lineage;
using ::c2pool::v37n::xmr::credit::to_string;

} // namespace c2pool::v37n::xmr::lineage
