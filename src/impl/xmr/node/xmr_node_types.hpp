/*
 * This file is part of c2pool <https://github.com/frstrtr/c2pool>
 * Copyright (c) 2024-2026 The c2pool developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

// ===========================================================================
// src/impl/xmr/node/xmr_node_types.hpp   (Track X / Family B: XMR lane, X2)
//
// AUTHORED for c2pool (not ported). Value types the monerod adapter surfaces to
// the XMR lane (V37Engine / W4 settlement / W5 template build). Header-only and
// STL-only on purpose: no libuv, no ZMQ, no rapidjson dependency here, so the
// consensus-relevant shapes (seed reach, difficulty, mainchain events, backlog)
// are compile-checkable and testable in isolation on an OOM-pressured host.
//
// PATTERN PROVENANCE (structure only; NO source lines copied -- clean reimpl):
//   SChernykh/p2pool (GPL-3.0; patterns portable into c2pool AGPL-3.0 via
//     AGPLv3 §13) src/common.h  struct MinerData / struct ChainMain /
//     struct TxMempoolData  --- the fielded shape of "what monerod hands a pool".
//   v37 RESHAPES them: (a) difficulty_type -> Difficulty128 (explicit u128, no
//   boost::multiprecision); (b) DROP p2pool's aux_chains / aux_nonce merge-mining
//   carriers (v37 places its own owed_digest commitment -- scoping OI-W4-6);
//   (c) ADD an explicit MainchainEvent stream (Extend / Reorg / Orphan) that
//   p2pool never surfaces at the adapter layer -- p2pool handles reorgs inside
//   its SideChain (prev_id walk), which is exactly the pool-model we do NOT port.
//   W4 needs the event stream to track confirmation depth WITHOUT monitoring any
//   recipient address (scoping O5.3 "SETTLED + opaque, never monitor an address").
//
// Relationship to the X1 coin leg: the 32-byte hash here is a plain std::array
// (wire bytes), distinct from xmr::coin::Hash256 (the crypto-typed view). The
// R-1 difficulty test on a RandomX output is NOT done here -- it is done by the
// X1 primitive xmr::coin::check_hash(Hash256, dlo, dhi); this Difficulty128 is
// the value that feeds it. Seed-height math is the X1 primitive too -- see
// mainchain_index.hpp, which #includes impl/xmr/coin/xmr_seedheight.hpp.
// ===========================================================================
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace c2pool::xmr::node {

// --- 32-byte Monero/Keccak hash (block id, prev_id, seed hash, tx id) --------
using Hash = std::array<std::uint8_t, 32>;

inline bool is_zero(const Hash& h) noexcept {
    for (std::uint8_t b : h) if (b) return false;
    return true;
}

// --- 128-bit cumulative/network difficulty ----------------------------------
// Monero difficulty is 128-bit (cryptonote::difficulty_type == uint128_t; JSON
// wire carries {"difficulty": lo64, "difficulty_top64": hi64}). Kept minimal and
// dependency-free; feeds xmr::coin::check_hash(hash, lo, hi) at R-1 pin time.
struct Difficulty128 {
    std::uint64_t lo = 0;   // low  64 bits  (JSON "difficulty")
    std::uint64_t hi = 0;   // high 64 bits  (JSON "difficulty_top64")

    constexpr bool empty() const noexcept { return lo == 0 && hi == 0; }

    friend constexpr bool operator==(const Difficulty128& a, const Difficulty128& b) noexcept {
        return a.hi == b.hi && a.lo == b.lo;
    }
    friend constexpr bool operator<(const Difficulty128& a, const Difficulty128& b) noexcept {
        return (a.hi != b.hi) ? (a.hi < b.hi) : (a.lo < b.lo);
    }
};

// --- one txpool / tx-backlog entry ------------------------------------------
// From get_miner_data.tx_backlog[] and from ZMQ json-minimal-txpool_add[].
// Mirrors p2pool src/common.h TxMempoolData {id, blob_size, weight, fee, ...}.
// This is the ONLY tx data the daemon-ful adapter needs: v37 never validates a
// relayed tx body (that is the embedded-node trap -- see monero_node_adapter.hpp).
struct TxBacklogEntry {
    Hash          id{};            // 32-byte tx hash
    std::uint64_t blob_size = 0;   // serialized size in bytes
    std::uint64_t weight    = 0;   // consensus weight (>= blob_size for bulletproofs)
    std::uint64_t fee       = 0;   // total fee, piconero
    std::uint64_t time_received = 0; // unix seconds (0 when from get_miner_data)
};

// --- miner_data snapshot (get_miner_data RPC / json-full-miner_data ZMQ) ------
// Everything W5 needs to build a whole block template EXCEPT the tx bodies (v37
// re-fetches selected txs by id, or reads the ZMQ full-chain blob). The fee
// estimate is a SEPARATE monerod call (get_fee_estimate); kept out of this snap.
struct MinerData {
    std::uint8_t  major_version = 0; // Monero HF major_version -> RandomX algo select
    std::uint64_t height        = 0; // height of the block being mined (tip + 1)
    Hash          prev_id{};         // == the tip's block id (the origin-bin key)
    Hash          seed_hash{};       // RandomX seed (key) block hash for `height`
    Difficulty128 difficulty{};      // network difficulty for `height`
    std::uint64_t median_weight = 0; // long-term median weight (penalty knee)
    std::uint64_t already_generated_coins = 0; // for base-reward computation
    std::uint64_t median_timestamp = 0;        // for template timestamp bounds
    std::vector<TxBacklogEntry> tx_backlog;    // fee-sorted candidate txs

    std::uint64_t local_recv_ns = 0; // local monotonic stamp set by the adapter

    bool valid() const noexcept {
        return height != 0 && !is_zero(prev_id) && !difficulty.empty();
    }
};

// --- a settled main-chain block header (get_block_header_by_height / ZMQ) -----
// Mirrors p2pool src/common.h ChainMain {difficulty, height, timestamp, reward,
// id}. The row stored in the MainchainIndex. `reward` = base + fees, what W4's
// CONS-2 audit ("finalW deltas == coinbases actually paid") checks against. No
// tx bodies, no outputs, no addresses are retained (scoping O5.3).
struct ChainMainBlock {
    Difficulty128 difficulty{};
    std::uint64_t height    = 0;
    std::uint64_t timestamp = 0;
    std::uint64_t reward    = 0;   // piconero (base_reward + total tx fees)
    Hash          id{};            // 32-byte block id
    Hash          prev_id{};       // parent block id (v37 addition: lets the index
                                   // detect a reorg by parent mismatch without a
                                   // daemon round-trip; p2pool relies on SideChain).
};

// --- fee estimate (get_fee_estimate RPC) ------------------------------------
// Feeds k_live(XMR) := Monero dynamic base fee at settlement height (scoping §16
// row `k_live`, OQ-X9). p2pool does not call this (it recomputes reward from
// median_weight); v37's byte-denominated h_min needs it, so it is first-class.
struct FeeEstimate {
    std::uint64_t fee_per_byte = 0;       // "fee" (per-byte base, piconero)
    std::uint64_t fees[4] = {0, 0, 0, 0}; // priority tiers (slow/normal/fast/fastest)
    std::uint64_t quantization_mask = 1;  // round fee/byte up to a multiple of this
    std::uint64_t height = 0;             // height the estimate was taken at
};

// --- mainchain event stream (v37 addition, NOT in p2pool) --------------------
// The single output of the node leg that W4 consumes. Emitted by MainchainIndex.
enum class MainchainEventKind : std::uint8_t {
    Extend = 0,  // a new block extends the current best tip (normal case)
    Reorg  = 1,  // best tip moved to a different branch: `depth` blocks were
                 // rolled back, `block` is the new tip
    Orphan = 2,  // a block previously on the best chain is no longer on it; its id
                 // (orphaned_id) is now dead, so W4 can un-confirm a settlement
};

struct MainchainEvent {
    MainchainEventKind kind = MainchainEventKind::Extend;
    ChainMainBlock     block{};       // new tip (Extend/Reorg) or orphaned block (Orphan)
    std::uint64_t      depth = 0;     // Reorg: blocks rolled back; else 0
    Hash               orphaned_id{}; // Orphan: the id that left the best chain
};

// --- daemon endpoint config --------------------------------------------------
struct DaemonEndpoint {
    std::string   rpc_host = "127.0.0.1";
    std::uint16_t rpc_port = 18081;   // mainnet monerod restricted/unrestricted RPC
    std::uint16_t zmq_port = 18083;   // monerod --zmq-pub tcp://127.0.0.1:18083
    std::string   rpc_login;          // "user:pass" for digest auth, empty = none
    bool          rpc_ssl = false;
    std::string   socks5_proxy;       // optional
    // monerod >= v0.18.0.0 is REQUIRED: get_miner_data and the three ZMQ topics
    // (json-full-chain_main / json-full-miner_data / json-minimal-txpool_add) did
    // not exist before it (scoping §14.3).
};

// The three monerod --zmq-pub topics the daemon-ful adapter subscribes to.
inline constexpr const char* ZMQ_TOPIC_CHAIN_MAIN  = "json-full-chain_main";
inline constexpr const char* ZMQ_TOPIC_MINER_DATA  = "json-full-miner_data";
inline constexpr const char* ZMQ_TOPIC_TXPOOL_ADD  = "json-minimal-txpool_add";

} // namespace c2pool::xmr::node
