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
// src/impl/xmr/node/xmr_node_types.hpp
//
// AUTHORED for c2pool (not ported). Value types the monerod adapter surfaces to
// the XMR lane (V37Engine / W4 settlement). Header-only, STL-only, no libuv / no
// ZMQ / no rapidjson dependency here on purpose so the consensus-relevant shapes
// (seed reach, difficulty, mainchain events) are compile-checkable in isolation.
//
// PATTERN PROVENANCE (structure only; NO source lines copied — clean reimpl):
//   SChernykh/p2pool  v4.18 @ 128643114f9bea55bfdb95462eaeffa2e3f666bd
//     src/common.h  struct MinerData / struct ChainMain / struct TxMempoolData
//   The p2pool structs are the fielded shape of "what monerod hands a pool".
//   v37 REShapeS them: (a) difficulty_type -> Difficulty128 (explicit u128, no
//   boost::multiprecision); (b) drop p2pool's aux_chains/aux_nonce merge-mining
//   carriers (v37 places its owed_digest commitment itself — OI-W4-6); (c) ADD an
//   explicit MainchainEvent stream (Extend / Reorg / Orphan) that p2pool never
//   surfaces at the adapter layer — p2pool handles reorgs inside its SideChain by
//   walking prev_id, which is exactly the pool-model we do NOT port. W4 needs the
//   event stream to track confirmation depth WITHOUT monitoring any address
//   (scoping O5.3 "SETTLED + opaque, never monitor a recipient address").
// ===========================================================================
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace c2pool::xmr::node {

// --- 32-byte Monero/Keccak hash (block id, prev_id, seed hash, tx id) --------
using Hash = std::array<uint8_t, 32>;

inline bool is_zero(const Hash& h) noexcept {
    for (uint8_t b : h) if (b) return false;
    return true;
}

// --- 128-bit cumulative difficulty ------------------------------------------
// Monero difficulty is 128-bit (cryptonote::difficulty_type == uint128_t; JSON
// wire carries {"difficulty": lo64, "difficulty_top64": hi64}). p2pool wraps it
// in its own difficulty_type; we keep a minimal, dependency-free equivalent.
struct Difficulty128 {
    uint64_t lo = 0;   // low  64 bits  (JSON "difficulty")
    uint64_t hi = 0;   // high 64 bits  (JSON "difficulty_top64")

    constexpr bool empty() const noexcept { return lo == 0 && hi == 0; }

    friend constexpr bool operator==(const Difficulty128& a, const Difficulty128& b) noexcept {
        return a.hi == b.hi && a.lo == b.lo;
    }
    friend constexpr bool operator<(const Difficulty128& a, const Difficulty128& b) noexcept {
        return (a.hi != b.hi) ? (a.hi < b.hi) : (a.lo < b.lo);
    }
    // target = 2^256 / difficulty is computed in the RandomX-verify leg, not here.
};

// --- one txpool / tx-backlog entry ------------------------------------------
// From get_miner_data.tx_backlog[] and from ZMQ json-minimal-txpool_add[].
// Mirrors p2pool src/common.h TxMempoolData {id, blob_size, weight, fee, ...}.
// This is the ONLY tx data the daemon-ful adapter needs: v37 never validates a
// relayed tx (that is the embedded-node trap, see monero_node_adapter.hpp).
struct TxBacklogEntry {
    Hash     id{};             // 32-byte tx hash
    uint64_t blob_size = 0;    // serialized size in bytes
    uint64_t weight    = 0;    // consensus weight (>= blob_size for bulletproofs)
    uint64_t fee       = 0;    // total fee, piconero
    uint64_t time_received = 0;// unix seconds (0 when from get_miner_data)
};

// --- miner_data snapshot (get_miner_data RPC / json-full-miner_data ZMQ) ------
// Everything W5 needs to build a whole block template EXCEPT the tx bodies (v37
// re-fetches selected txs by id, or uses the ZMQ full-chain blob). Fee estimate
// is a SEPARATE call in monerod (get_fee_estimate); we keep it out of this snap.
struct MinerData {
    uint8_t  major_version = 0; // Monero HF major_version -> RandomX algo select
    uint64_t height        = 0; // height of the block being mined (tip + 1)
    Hash     prev_id{};         // == the tip's block id (this is the origin-bin key)
    Hash     seed_hash{};       // RandomX seed (key) block hash for `height`
    Difficulty128 difficulty{}; // network difficulty for `height`
    uint64_t median_weight = 0; // long-term median weight (penalty knee)
    uint64_t already_generated_coins = 0; // for base-reward computation
    uint64_t median_timestamp = 0;         // for template timestamp bounds
    std::vector<TxBacklogEntry> tx_backlog; // fee-sorted candidate txs

    // received-time is a local monotonic stamp set by the adapter, not wire data.
    uint64_t local_recv_ns = 0;

    bool valid() const noexcept {
        return height != 0 && !is_zero(prev_id) && !difficulty.empty();
    }
};

// --- a settled main-chain block header (get_block_header_by_height / ZMQ) -----
// Mirrors p2pool src/common.h ChainMain {difficulty, height, timestamp, reward,
// id}. This is the row stored in the MainchainIndex. `reward` = base + fees, and
// is what W4's CONS-2 audit ("finalW deltas == coinbases actually paid") checks
// against. No tx bodies, no outputs, no addresses are retained.
struct ChainMainBlock {
    Difficulty128 difficulty{};
    uint64_t height    = 0;
    uint64_t timestamp = 0;
    uint64_t reward    = 0;   // piconero (base_reward + total tx fees)
    Hash     id{};            // 32-byte block id
    Hash     prev_id{};       // parent block id (v37 addition: lets the index
                              // detect a reorg by parent mismatch without asking
                              // the daemon; p2pool relies on its SideChain here)
};

// --- fee estimate (get_fee_estimate RPC) ------------------------------------
// Feeds k_live(XMR) := Monero dynamic base fee at settlement height (scoping
// §16 row `k_live`). p2pool does not call this (it recomputes reward from
// median_weight); v37's byte-denominated h_min needs it, so the adapter exposes
// it as a first-class query.
struct FeeEstimate {
    uint64_t fee_per_byte = 0;        // "fee" (per-byte base, piconero)
    uint64_t fees[4] = {0, 0, 0, 0};  // priority tiers (slow/normal/fast/fastest)
    uint64_t quantization_mask = 1;   // round fee/byte up to a multiple of this
    uint64_t height = 0;              // height the estimate was taken at
};

// --- mainchain event stream (v37 addition, NOT in p2pool) --------------------
// The single output of the node leg that W4 consumes. Emitted by MainchainIndex.
enum class MainchainEventKind : uint8_t {
    Extend = 0,  // a new block extends the current best tip (normal case)
    Reorg  = 1,  // best tip moved to a different id at an equal-or-lower height:
                 // `depth` blocks were rolled back, `block` is the new tip
    Orphan = 2,  // a block previously at `height` is no longer on the best chain
                 // (its id is now dead); carried so W4 can un-confirm settlements
};

struct MainchainEvent {
    MainchainEventKind kind = MainchainEventKind::Extend;
    ChainMainBlock     block{};     // the new tip (Extend/Reorg) or the orphaned block (Orphan)
    uint64_t           depth = 0;   // Reorg: number of blocks rolled back; else 0
    Hash               orphaned_id{}; // Orphan: the id that left the best chain
};

// --- daemon endpoint config --------------------------------------------------
struct DaemonEndpoint {
    std::string rpc_host = "127.0.0.1";
    uint16_t    rpc_port = 18081;   // mainnet monerod restricted/unrestricted RPC
    uint16_t    zmq_port = 18083;   // monerod --zmq-pub tcp://127.0.0.1:18083
    std::string rpc_login;          // "user:pass" for digest auth, empty = none
    bool        rpc_ssl = false;
    std::string socks5_proxy;       // optional
    // monerod >= v0.18.0.0 is REQUIRED: get_miner_data and the three ZMQ topics
    // (json-full-chain_main / json-full-miner_data / json-minimal-txpool_add)
    // did not exist before it (scoping §14.3).
};

} // namespace c2pool::xmr::node
