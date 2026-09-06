/*
 * This file is part of c2pool <https://github.com/frstrtr/c2pool>
 * Copyright (c) 2024-2026 The c2pool developers
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See COPYING in the repository root.
 */

// ===========================================================================
// src/impl/xmr/node/mainchain_index.hpp   (Track X / Family B: XMR lane, X2)
//
// AUTHORED for c2pool (not ported). The mainchain index: a bounded mirror of
// monerod's best chain, keyed by height and by id, providing
//   (1) RandomX seed resolution with >= 2112-block reach (2048 epoch + 64 lag),
//       using the X1 coin primitive ::xmr::coin::rx_seedheight() -- NOT a local copy;
//   (2) a fee-sorted tx backlog snapshot for W5 template building;
//   (3) an Extend / Reorg / Orphan event stream for W4 settlement confirmation.
// Header-only + STL-only so this consensus-relevant logic compiles and runs
// standalone on an OOM-pressured host (see test/x2_adapter_kat.cpp).
//
// SEED-HEIGHT SOURCE OF TRUTH: this file #includes the X1 header
//   impl/xmr/coin/xmr_seedheight.hpp   (base branch v37/xmr-x1-primitives)
// and calls ::xmr::coin::rx_seedheight(). The X1 header hard-codes the epoch/lag
// constants (2048/64) as compile-time, env-UNtunable values -- a consensus
// verifier must not inherit monerod's env-override test hook. Keeping ONE copy
// of that constant across the coin leg and the node leg removes a split-risk.
//
// PATTERN PROVENANCE (structure only, clean reimpl -- NO source lines copied):
//   SChernykh/p2pool (GPL-3.0; portable to AGPL-3.0 via AGPLv3 §13)
//     src/p2pool.h   std::map<uint64_t,ChainMain> m_mainchainByHeight;
//                    unordered_map<hash,ChainMain> m_mainchainByHash;
//                    get_seed_height()/get_seed()/cleanup_mainchain_data()
//     src/p2pool.cpp SEEDHASH_EPOCH_BLOCKS=2048; SEEDHASH_EPOCH_LAG=64;
//                    BLOCK_HEADERS_REQUIRED=720; the by-height/by-hash upsert and
//                    the prune keeping 720 recent heights + the live seed anchors.
//   v37 DELTAS (documented at each call site):
//     * Reorg/Orphan EVENTS. p2pool overwrites m_mainchainByHeight[h] silently and
//       resolves reorgs inside its SideChain (prev_id walk) -- the pool-model we
//       do NOT port. W4 needs the delta to un-confirm settlements, so we emit it.
//     * prev_id stored per row: a reorg is detected by parent mismatch with no
//       extra daemon round-trip.
//     * Seed reach (>= 2112) is a first-class invariant with pinned anchors, not a
//       side effect of the 720 window.
//     * NO address/output state is ever stored (scoping O5.3).
// ===========================================================================
#pragma once

#include "xmr_node_types.hpp"

// X1 primitive (base branch v37/xmr-x1-primitives). Compile with -I <c2pool>/src.
#include "impl/xmr/coin/xmr_seedheight.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <unordered_map>
#include <vector>

namespace c2pool::xmr::node {

// The minimum seed reach an XMR-lane verifier must keep resident below the tip:
// one full RandomX epoch (2048) plus the 64-block key lag. Derived from the X1
// coin-leg constants so the two legs can never disagree.
inline constexpr std::uint64_t SEED_REACH_MIN =
    ::xmr::coin::SEEDHASH_EPOCH_BLOCKS + ::xmr::coin::SEEDHASH_EPOCH_LAG; // 2112

// The height whose block id keys the RandomX cache used to verify a block at `h`.
// Thin alias over the X1 primitive so call sites here read naturally.
inline std::uint64_t rx_seed_height(std::uint64_t h) noexcept {
    return ::xmr::coin::rx_seedheight(h);
}

// FNV-1a over the 32 bytes for the by-hash map.
struct HashHasher {
    std::size_t operator()(const Hash& h) const noexcept {
        std::size_t x = 1469598103934665603ull;
        for (std::uint8_t b : h) { x ^= b; x *= 1099511628211ull; }
        return x;
    }
};

class MainchainIndex {
public:
    using EventSink = std::function<void(const MainchainEvent&)>;

    // retain_recent: contiguous heights kept below the tip. Default 720 matches
    // p2pool BLOCK_HEADERS_REQUIRED (the daemon's own reorg horizon). W4 may raise
    // it to its D_spine margin. The seed anchors reaching back >= 2112 are pinned
    // ON TOP of this window regardless, so seed resolution never breaks.
    explicit MainchainIndex(std::uint64_t retain_recent = 720, EventSink sink = {})
        : retain_recent_(retain_recent), sink_(std::move(sink)) {}

    void set_sink(EventSink sink) { sink_ = std::move(sink); }

    std::uint64_t best_height() const noexcept { return best_height_; }
    const Hash&   best_id()     const noexcept { return best_id_; }
    bool empty() const noexcept { return by_height_.empty(); }
    std::size_t size() const noexcept { return by_height_.size(); }

    // -----------------------------------------------------------------------
    // Core state transition. `apply` mirrors monerod's best chain from a
    // json-full-chain_main push (or a backfill row promoted to the tip). monerod
    // is the fork-choice oracle; this never does fork choice, it only classifies
    // the pushed block against the mirror and surfaces the delta. Returns the
    // (primary) event emitted (Reorg carries depth; per-block Orphans precede it).
    // -----------------------------------------------------------------------
    MainchainEvent apply(const ChainMainBlock& blk) {
        MainchainEvent ev;
        ev.block = blk;

        if (by_height_.empty()) {
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

        // Gap forward (missed one or more heights): adopt as tip, flag a resync so
        // the adapter backfills the interior via get_block_headers_range. Not a
        // reorg -- we simply lost intermediate ZMQ frames.
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

        // Otherwise blk.height <= best_height_ (or it claims best+1 but does not
        // build on our tip): monerod reorged. Every stored best-chain block at
        // heights [blk.height .. best_height_] whose id differs is now orphaned.
        // Emit Orphan for each (descending), then Reorg for the adopted tip.
        std::uint64_t depth = 0;
        for (std::uint64_t h = best_height_; h >= blk.height; --h) {
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
            if (h == 0) break; // guard unsigned underflow
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

    // Fill a settled header WITHOUT moving the tip or emitting an event
    // (get_block_header_by_height / get_block_headers_range backfill for seed
    // anchors below the tip). Mirrors p2pool parse_block_header() populating maps.
    void backfill(const ChainMainBlock& blk) { upsert(blk); }

    // Register a RandomX seed anchor from a source that has only (height, id) --
    // e.g. json-full-miner_data hands us seed_hash for the epoch directly, sparing
    // a get_block_header round-trip. Never moves the tip, never emits. Does not
    // clobber a richer row already present at that height.
    void note_seed_anchor(std::uint64_t seed_height, const Hash& seed_id) {
        if (is_zero(seed_id)) return;
        auto it = by_height_.find(seed_height);
        if (it != by_height_.end() && !is_zero(it->second.id)) return; // keep richer row
        ChainMainBlock a;
        a.height = seed_height;
        a.id     = seed_id;
        upsert(a);
    }

    // Enrich an already-resident row with data that arrives on a later feed
    // (json-full-chain_main carries the plaintext coinbase reward + timestamp; the
    // tip id came from json-full-miner_data). Matched by height. No event. This is
    // what W4's CONS-2 ("finalW deltas == coinbases actually paid") reads.
    bool annotate(std::uint64_t height, std::uint64_t reward, std::uint64_t timestamp,
                  const Difficulty128& diff = {}) {
        auto it = by_height_.find(height);
        if (it == by_height_.end()) return false;
        if (reward)    it->second.reward    = reward;
        if (timestamp) it->second.timestamp = timestamp;
        if (!diff.empty()) it->second.difficulty = diff;
        if (!is_zero(it->second.id)) by_hash_[it->second.id] = it->second;
        return true;
    }

    // -----------------------------------------------------------------------
    // Seed resolution. Returns the id of the block that keys the RandomX cache
    // for verifying a receipt/share whose Monero height is `h`. nullopt when the
    // anchor is not (yet) resident -- the adapter then RPC-backfills it.
    // -----------------------------------------------------------------------
    std::optional<Hash> seed_hash_for_height(std::uint64_t h) const {
        const std::uint64_t sh = rx_seed_height(h);
        auto it = by_height_.find(sh);
        if (it == by_height_.end() || is_zero(it->second.id)) return std::nullopt;
        return it->second.id;
    }

    // The seed-anchor heights that MUST be resident to RandomX-verify anything in
    // the retained window [best-retain_recent_ .. best]. Straddling an epoch edge
    // means the previous anchor is needed too, so we walk anchors down to
    // rx_seed_height(window bottom). Reach is >= 2112 by construction.
    std::vector<std::uint64_t> required_seed_heights() const {
        std::vector<std::uint64_t> out;
        if (by_height_.empty()) return out;
        const std::uint64_t lo_h = (best_height_ > retain_recent_) ? best_height_ - retain_recent_ : 0;
        std::uint64_t sh = rx_seed_height(best_height_);
        const std::uint64_t oldest = rx_seed_height(lo_h);
        for (;;) {
            out.push_back(sh);
            if (sh <= oldest || sh < ::xmr::coin::SEEDHASH_EPOCH_BLOCKS) break;
            sh -= ::xmr::coin::SEEDHASH_EPOCH_BLOCKS;
        }
        return out;
    }

    // Anchors named by required_seed_heights() that are NOT resident: the adapter
    // RPC-backfills each via get_block_header_by_height. Non-empty => seed reach
    // is not yet satisfied.
    std::vector<std::uint64_t> missing_seed_heights() const {
        std::vector<std::uint64_t> miss;
        for (std::uint64_t h : required_seed_heights()) {
            auto it = by_height_.find(h);
            if (it == by_height_.end() || is_zero(it->second.id)) miss.push_back(h);
        }
        return miss;
    }

    // True once every required seed anchor is resident: any receipt in the
    // retained window can be RandomX-verified locally.
    bool seed_reach_satisfied() const { return missing_seed_heights().empty(); }

    // -----------------------------------------------------------------------
    // W4 confirmation depth WITHOUT address monitoring (scoping O5.3). Given the
    // settlement (coinbase-carrying) block id, returns how many blocks confirm it
    // on the CURRENT best chain, or 0 if it is unknown or has been orphaned.
    // -----------------------------------------------------------------------
    std::uint64_t confirmation_depth(const Hash& block_id) const {
        auto it = by_hash_.find(block_id);
        if (it == by_hash_.end()) return 0;
        const std::uint64_t h = it->second.height;
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
    std::optional<ChainMainBlock> by_height(std::uint64_t h) const {
        auto it = by_height_.find(h);
        if (it == by_height_.end()) return std::nullopt;
        return it->second;
    }

    // -----------------------------------------------------------------------
    // Tx backlog snapshot (from the latest miner_data). W5 selects from this;
    // json-minimal-txpool_add deltas keep it fresh between miner_data pushes.
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

private:
    void upsert(const ChainMainBlock& blk) {
        by_height_[blk.height] = blk;
        if (!is_zero(blk.id)) by_hash_[blk.id] = blk;
    }
    void emit(const MainchainEvent& ev) { if (sink_) sink_(ev); }

    // Prune everything older than retain_recent_ below the tip, EXCEPT the live
    // seed-epoch anchors (so seed reach stays >= 2112). Mirrors p2pool
    // cleanup_mainchain_data(), computed from required_seed_heights().
    void prune() {
        if (by_height_.size() <= retain_recent_) return;
        const std::uint64_t keep_from = (best_height_ > retain_recent_) ? best_height_ - retain_recent_ : 0;

        std::unordered_map<std::uint64_t, char> anchors;
        for (std::uint64_t h : required_seed_heights()) anchors.emplace(h, 1);

        for (auto it = by_height_.begin(); it != by_height_.end();) {
            const std::uint64_t h = it->first;
            if (h >= keep_from) break;                 // reached the retained window
            if (anchors.count(h)) { ++it; continue; }  // pinned seed anchor
            by_hash_.erase(it->second.id);
            it = by_height_.erase(it);
        }
    }

    std::uint64_t retain_recent_;
    EventSink     sink_;
    std::map<std::uint64_t, ChainMainBlock> by_height_;
    std::unordered_map<Hash, ChainMainBlock, HashHasher> by_hash_;
    std::vector<TxBacklogEntry> backlog_;
    std::uint64_t best_height_ = 0;
    Hash          best_id_{};
    bool          resync_needed_ = false;
};

} // namespace c2pool::xmr::node
