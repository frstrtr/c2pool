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
// src/impl/xmr/node/mainchain_index.hpp
//
// AUTHORED for c2pool (not ported). The mainchain index: a bounded mirror of
// monerod's best chain, keyed by height and by id, providing
//   (1) RandomX seed resolution with >= 2112-block reach (2048 epoch + 64 lag);
//   (2) a fee-sorted tx backlog snapshot for W5 template building;
//   (3) an Extend / Reorg / Orphan event stream for W4 settlement.
// Header-only and STL-only so this consensus-relevant logic compiles and runs
// standalone (see xmr_node_index_check.cpp).
//
// PATTERN PROVENANCE (structure only, clean reimpl — NO source lines copied):
//   SChernykh/p2pool v4.18 @ 128643114f9bea55bfdb95462eaeffa2e3f666bd
//     src/p2pool.h   std::map<uint64_t,ChainMain> m_mainchainByHeight;
//                    unordered_map<hash,ChainMain> m_mainchainByHash;
//                    get_seed_height() / get_seed() / cleanup_mainchain_data()
//     src/p2pool.cpp SEEDHASH_EPOCH_BLOCKS=2048; SEEDHASH_EPOCH_LAG=64;
//                    BLOCK_HEADERS_REQUIRED=720; the by-height/by-hash upsert in
//                    handle_miner_data()/handle_chain_main(); the prune that
//                    keeps 720 recent heights + the 3-4 live seed-epoch anchors.
//
//   v37 DELTAS over p2pool (all documented at each call site):
//     * Reorg/Orphan EVENTS. p2pool overwrites m_mainchainByHeight[h] and never
//       tells anyone a height changed id; its reorg logic lives in SideChain
//       (prev_id walk) — the pool-model we do NOT port. W4 needs the delta to
//       un-confirm settlements, so the index emits it.
//     * prev_id stored per row so a reorg is detected by parent mismatch without
//       a daemon round-trip.
//     * Retain-reach is a first-class invariant (>= 2112) rather than a side
//       effect of the 720-window prune; the seed anchors are pinned explicitly.
//     * NO address / output state is ever stored (scoping O5.3).
//
//   Consensus constants (SEEDHASH_EPOCH_*, seed_height formula) are DUPLICATED
//   here only for the standalone build. In the c2pool tree this header MUST
//   `#include "impl/xmr/coin/xmr_seedheight.hpp"` and call the single canonical
//   rx_seed_height(); two copies of a consensus constant is a split-risk.
// ===========================================================================
#pragma once

#include "xmr_node_types.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <unordered_map>
#include <vector>

namespace c2pool::xmr::node {

// --- RandomX seed epoch (monerod src/crypto/rx-slow-hash.c) ------------------
// Canonical form matches monero-project @ 3d3920d7 rx_seedheight() and the
// c2pool coin leg's xmr_seedheight.hpp. Compile-time constants (NOT env-tunable;
// monerod exposes an env override for tests that a consensus verifier must not
// honor).
inline constexpr uint64_t SEEDHASH_EPOCH_BLOCKS = 2048;
inline constexpr uint64_t SEEDHASH_EPOCH_LAG    = 64;
inline constexpr uint64_t SEED_REACH_MIN        = SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG; // 2112

// The height of the block whose id keys the RandomX cache used to verify `h`.
inline constexpr uint64_t rx_seed_height(uint64_t h) noexcept {
    if (h <= SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG) return 0;
    return (h - SEEDHASH_EPOCH_LAG - 1) & ~(SEEDHASH_EPOCH_BLOCKS - 1);
}

// FNV-1a over the 32 bytes for the by-hash map.
struct HashHasher {
    std::size_t operator()(const Hash& h) const noexcept {
        std::size_t x = 1469598103934665603ull;
        for (uint8_t b : h) { x ^= b; x *= 1099511628211ull; }
        return x;
    }
};

class MainchainIndex {
public:
    using EventSink = std::function<void(const MainchainEvent&)>;

    // retain_recent: contiguous heights kept below the tip. Default 720 matches
    // p2pool BLOCK_HEADERS_REQUIRED (the daemon's own re-org horizon). W4 raises
    // it to its D_spine margin. The seed anchors reaching back >= 2112 are pinned
    // on TOP of this window regardless, so seed resolution never breaks.
    explicit MainchainIndex(uint64_t retain_recent = 720, EventSink sink = {})
        : retain_recent_(retain_recent), sink_(std::move(sink)) {}

    void set_sink(EventSink sink) { sink_ = std::move(sink); }

    uint64_t best_height() const noexcept { return best_height_; }
    const Hash& best_id() const noexcept { return best_id_; }
    bool empty() const noexcept { return by_height_.empty(); }

    // -----------------------------------------------------------------------
    // Core state transition. `apply` mirrors monerod's best chain from a
    // json-full-chain_main push (or a backfill row). Returns the event emitted.
    // monerod is the fork-choice oracle; this never does fork choice, it only
    // classifies the pushed block relative to the mirror and surfaces the delta.
    // -----------------------------------------------------------------------
    MainchainEvent apply(const ChainMainBlock& blk) {
        MainchainEvent ev;
        ev.block = blk;

        if (by_height_.empty()) {
            // First block seen: adopt as tip, no classification possible.
            upsert(blk);
            best_height_ = blk.height;
            best_id_     = blk.id;
            ev.kind = MainchainEventKind::Extend;
            emit(ev);
            prune();
            return ev;
        }

        const bool clean_extend =
            (blk.height == best_height_ + 1) &&
            (is_zero(blk.prev_id) || blk.prev_id == best_id_);

        if (clean_extend) {
            upsert(blk);
            best_height_ = blk.height;
            best_id_     = blk.id;
            ev.kind = MainchainEventKind::Extend;
            emit(ev);
            prune();
            return ev;
        }

        // Gap forward (we missed one or more heights): treat as Extend but flag
        // for the adapter to backfill via get_block_headers_range. Not a reorg.
        if (blk.height > best_height_ + 1) {
            upsert(blk);
            best_height_ = blk.height;
            best_id_     = blk.id;
            ev.kind = MainchainEventKind::Extend;
            resync_needed_ = true;
            emit(ev);
            prune();
            return ev;
        }

        // Otherwise blk.height <= best_height_, or it claims height best+1 but
        // does not build on our tip: monerod re-orged. Every stored best-chain
        // block at heights [blk.height .. best_height_] whose id differs is now
        // orphaned. Emit Orphan for each (descending), then Reorg for the new tip.
        uint64_t depth = 0;
        for (uint64_t h = best_height_; h >= blk.height; --h) {
            auto it = by_height_.find(h);
            if (it != by_height_.end() && !is_zero(it->second.id) &&
                !(h == blk.height && it->second.id == blk.id)) {
                MainchainEvent orph;
                orph.kind        = MainchainEventKind::Orphan;
                orph.block       = it->second;
                orph.orphaned_id = it->second.id;
                emit(orph);
                by_hash_.erase(it->second.id);
                ++depth;
            }
            if (h == 0) break; // guard against unsigned underflow
        }

        upsert(blk);
        best_height_ = blk.height;
        best_id_     = blk.id;
        ev.kind  = MainchainEventKind::Reorg;
        ev.depth = depth;
        emit(ev);
        prune();
        return ev;
    }

    // Fill a settled header without emitting an event (get_block_header_by_height
    // / get_block_headers_range backfill for seed anchors below the tip). Never
    // moves the tip. Mirrors p2pool parse_block_header() populating the maps.
    void backfill(const ChainMainBlock& blk) {
        upsert(blk);
    }

    // -----------------------------------------------------------------------
    // Seed resolution. Returns the id of the block that keys the RandomX cache
    // for verifying a receipt/share whose Monero height is `h`. std::nullopt when
    // the anchor is not (yet) in the index — the adapter then RPC-backfills it.
    // -----------------------------------------------------------------------
    std::optional<Hash> seed_hash_for_height(uint64_t h) const {
        const uint64_t sh = rx_seed_height(h);
        auto it = by_height_.find(sh);
        if (it == by_height_.end() || is_zero(it->second.id)) return std::nullopt;
        return it->second.id;
    }

    // The set of seed anchor heights that MUST be resident to verify anything in
    // the retained window [best-retain_recent_ .. best]. Straddling an epoch edge
    // means both the current and the previous anchor are needed; W3 receipts up
    // to N_CTX bins deep push this one epoch further, hence we keep back to
    // rx_seed_height(best - retain_recent_) inclusive. >= 2112 reach by
    // construction (the oldest anchor is <= best - 2112 + slack).
    std::vector<uint64_t> required_seed_heights() const {
        std::vector<uint64_t> out;
        if (by_height_.empty()) return out;
        const uint64_t lo_h = (best_height_ > retain_recent_) ? best_height_ - retain_recent_ : 0;
        uint64_t sh   = rx_seed_height(best_height_);
        const uint64_t oldest = rx_seed_height(lo_h);
        for (;;) {
            out.push_back(sh);
            if (sh <= oldest || sh < SEEDHASH_EPOCH_BLOCKS) break;
            sh -= SEEDHASH_EPOCH_BLOCKS;
        }
        return out;
    }

    // Anchors named by required_seed_heights() that are NOT resident: the adapter
    // RPC-backfills each via get_block_header_by_height. If this is non-empty,
    // seed reach is not yet satisfied.
    std::vector<uint64_t> missing_seed_heights() const {
        std::vector<uint64_t> miss;
        for (uint64_t h : required_seed_heights()) {
            auto it = by_height_.find(h);
            if (it == by_height_.end() || is_zero(it->second.id)) miss.push_back(h);
        }
        return miss;
    }

    // True once every required seed anchor is resident, i.e. any receipt in the
    // retained window can be RandomX-verified locally.
    bool seed_reach_satisfied() const { return missing_seed_heights().empty(); }

    // -----------------------------------------------------------------------
    // W4 confirmation depth WITHOUT address monitoring (scoping O5.3). Given the
    // settlement (coinbase-carrying) block id, returns how many blocks confirm it
    // on the CURRENT best chain, or 0 if it is unknown or has been orphaned.
    // -----------------------------------------------------------------------
    uint64_t confirmation_depth(const Hash& block_id) const {
        auto it = by_hash_.find(block_id);
        if (it == by_hash_.end()) return 0;
        const uint64_t h = it->second.height;
        // Must still be the block occupying its height on the best chain.
        auto hit = by_height_.find(h);
        if (hit == by_height_.end() || hit->second.id != block_id) return 0; // orphaned
        if (h > best_height_) return 0;
        return best_height_ - h + 1;
    }

    std::optional<ChainMainBlock> by_hash(const Hash& id) const {
        auto it = by_hash_.find(id);
        if (it == by_hash_.end()) return std::nullopt;
        return it->second;
    }
    std::optional<ChainMainBlock> by_height(uint64_t h) const {
        auto it = by_height_.find(h);
        if (it == by_height_.end()) return std::nullopt;
        return it->second;
    }

    // -----------------------------------------------------------------------
    // Tx backlog snapshot (from the latest miner_data). W5 selects from this;
    // json-minimal-txpool_add deltas keep it fresh between miner_data pushes.
    // Kept fee/byte-sorted-descending on insert like p2pool TxMempoolData::<.
    // -----------------------------------------------------------------------
    void set_backlog(std::vector<TxBacklogEntry> txs) { backlog_ = std::move(txs); }
    void add_backlog_tx(const TxBacklogEntry& tx) {
        for (const auto& e : backlog_) if (e.id == tx.id) return; // dedup by id
        backlog_.push_back(tx);
    }
    void remove_backlog_txs(const std::vector<Hash>& mined) {
        if (mined.empty() || backlog_.empty()) return;
        std::unordered_map<Hash, char, HashHasher> gone;
        for (const auto& h : mined) gone.emplace(h, 1);
        std::vector<TxBacklogEntry> keep;
        keep.reserve(backlog_.size());
        for (auto& e : backlog_) if (!gone.count(e.id)) keep.push_back(std::move(e));
        backlog_.swap(keep);
    }
    const std::vector<TxBacklogEntry>& backlog() const noexcept { return backlog_; }

    bool resync_needed() const noexcept { return resync_needed_; }
    void clear_resync() noexcept { resync_needed_ = false; }
    std::size_t size() const noexcept { return by_height_.size(); }

private:
    void upsert(const ChainMainBlock& blk) {
        by_height_[blk.height] = blk;
        if (!is_zero(blk.id)) by_hash_[blk.id] = blk;
    }

    void emit(const MainchainEvent& ev) { if (sink_) sink_(ev); }

    // Prune everything older than retain_recent_ below the tip, EXCEPT the live
    // seed-epoch anchors (so seed reach stays >= 2112). Mirrors p2pool
    // cleanup_mainchain_data(), but computed from required_seed_heights().
    void prune() {
        if (by_height_.size() <= retain_recent_) return;
        const uint64_t keep_from = (best_height_ > retain_recent_) ? best_height_ - retain_recent_ : 0;

        std::unordered_map<uint64_t, char> anchors;
        for (uint64_t h : required_seed_heights()) anchors.emplace(h, 1);

        for (auto it = by_height_.begin(); it != by_height_.end();) {
            const uint64_t h = it->first;
            if (h >= keep_from) break;                 // reached the retained window
            if (anchors.count(h)) { ++it; continue; }  // pinned seed anchor
            by_hash_.erase(it->second.id);
            it = by_height_.erase(it);
        }
    }

    uint64_t retain_recent_;
    EventSink sink_;
    std::map<uint64_t, ChainMainBlock> by_height_;
    std::unordered_map<Hash, ChainMainBlock, HashHasher> by_hash_;
    std::vector<TxBacklogEntry> backlog_;
    uint64_t best_height_ = 0;
    Hash     best_id_{};
    bool     resync_needed_ = false;
};

} // namespace c2pool::xmr::node
