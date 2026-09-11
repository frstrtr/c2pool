// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/chain/xmr_row_store.hpp
//
// THE HEIGHT INDEX: height -> block metadata for the retained window, the id map
// that inverts it, and the RandomX seed anchors that must outlive both.
//
// WHY THIS EXISTS SEPARATELY FROM THE CONSENSUS STATE. The consensus state keeps
// rows because it needs them to roll its five windows back; the index keeps rows
// because four different consumers ask questions of them -- the settlement clock
// asks "how deep is this block buried", a peer asks "give me the ids after this
// one", the fork chooser asks "what were the timestamps and cumulative
// difficulties around the fork point", and a restart asks "what did I know
// before I stopped". Keeping the index's own table means all four are answered
// without reaching into the state's internals, and, decisively, that a RESTORED
// index can answer them at all: a snapshot re-seeds the consensus windows at the
// tip, which leaves the state with exactly one row, while the burial and serving
// questions are about the 2048 rows underneath it.
//
// RETENTION (D-9): 2048 rows -- one RandomX epoch. It is the deepest reorg the
// node will ever service, the horizon a peer may ask us to supplement from, and
// far more than the 60-block burial the settlement clock needs.
//
// SEED ANCHORS ARE NOT ROWS. The id at an epoch height (h % 2048 == 0) keys a
// RandomX cache for the 2048 heights that follow it, so it must stay reachable
// after its own row has been trimmed -- otherwise a node that has been running
// for an epoch can no longer verify the blocks it is receiving. They are kept in
// their own small map, and they are dropped ONLY by a rollback that removes the
// block itself, because a reorg across an epoch edge genuinely changes the seed.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/native/chain/xmr_consensus_state.hpp"
#include "impl/xmr/native/consensus/xmr_epoch.hpp"
#include "impl/xmr/native/contracts/types.hpp"

namespace c2pool::xmr::native {

// One row as the index keeps it: the consensus row plus the two facts only the
// index knows -- whether we mined it (D-14 PREFER-OWN) and what its PoW hash was
// (kept for the parity oracle, which compares it against monerod's pow_hash).
struct RowRecord {
    ChainRow row{};
    bool     own_mined = false;
    Hash     pow_hash{};
};

class RowStore {
public:
    void clear() {
        rows_.clear();
        by_id_.clear();
        seed_anchors_.clear();
        pre_window_.clear();
        pre_begin_ = 0;
        pre_end_   = 0;
    }

    void set_retention(std::size_t n) {
        retention_ = n ? n : 1;
        trim_();
    }
    std::size_t retention() const noexcept { return retention_; }

    bool          empty()         const noexcept { return rows_.empty(); }
    std::size_t   size()          const noexcept { return rows_.size(); }
    std::uint64_t tip_height()    const noexcept { return rows_.empty() ? 0 : rows_.back().row.height; }
    std::uint64_t oldest_height() const noexcept { return rows_.empty() ? 0 : rows_.front().row.height; }

    const RowRecord* tip() const noexcept { return rows_.empty() ? nullptr : &rows_.back(); }

    const std::deque<RowRecord>& records() const noexcept { return rows_; }

    // Append one row. It must be the immediate successor of the current tip;
    // the index never inserts out of order, and an out-of-order push is a bug
    // rather than an input, so it is refused rather than "handled".
    bool push(const ChainRow& row, bool own_mined, const Hash& pow_hash) {
        if (!rows_.empty() && row.height != rows_.back().row.height + 1) return false;
        RowRecord rec;
        rec.row       = row;
        rec.own_mined = own_mined;
        rec.pow_hash  = pow_hash;
        by_id_[key_(row.id)] = row.height;
        if (row.height % SEEDHASH_EPOCH_BLOCKS == 0) seed_anchors_[row.height] = row.id;
        rows_.push_back(rec);
        trim_();
        return true;
    }

    // Remove the tip. Returns what left, so the caller can park it as an alt
    // candidate instead of forgetting it existed.
    bool pop(RowRecord& out) {
        if (rows_.empty()) return false;
        out = rows_.back();
        by_id_.erase(key_(out.row.id));
        if (out.row.height % SEEDHASH_EPOCH_BLOCKS == 0) seed_anchors_.erase(out.row.height);
        rows_.pop_back();
        return true;
    }

    // Install a restored window wholesale (snapshot resume). Heights must be
    // contiguous and ascending; anything else is refused, because a store with a
    // hole in it answers burial questions wrongly and silently.
    bool install(const std::vector<RowRecord>& rows) {
        clear();
        for (const RowRecord& r : rows) {
            if (!rows_.empty() && r.row.height != rows_.back().row.height + 1) {
                clear();
                return false;
            }
            by_id_[key_(r.row.id)] = r.row.height;
            if (r.row.height % SEEDHASH_EPOCH_BLOCKS == 0)
                seed_anchors_[r.row.height] = r.row.id;
            rows_.push_back(r);
        }
        trim_();
        return true;
    }

    const RowRecord* by_height(std::uint64_t h) const noexcept {
        if (rows_.empty()) return nullptr;
        const std::uint64_t lo = rows_.front().row.height;
        const std::uint64_t hi = rows_.back().row.height;
        if (h < lo || h > hi) return nullptr;
        return &rows_[static_cast<std::size_t>(h - lo)];
    }

    const RowRecord* by_id(const Hash& id) const noexcept {
        const auto it = by_id_.find(key_(id));
        if (it == by_id_.end()) return nullptr;
        return by_height(it->second);
    }

    std::optional<std::uint64_t> height_of(const Hash& id) const {
        const auto it = by_id_.find(key_(id));
        if (it == by_id_.end()) return std::nullopt;
        return it->second;
    }

    bool contains(const Hash& id) const { return by_id_.find(key_(id)) != by_id_.end(); }

    // The id at an epoch height, from the seed anchors first (they outlive their
    // rows) and from the retained rows otherwise.
    std::optional<Hash> id_at_epoch_height(std::uint64_t epoch_height) const {
        const auto it = seed_anchors_.find(epoch_height);
        if (it != seed_anchors_.end()) return it->second;
        if (const RowRecord* r = by_height(epoch_height)) return r->row.id;
        return std::nullopt;
    }

    // A seed anchor from outside the retained rows: the anchor bundle carries
    // the epoch ids for the first post-anchor epochs, and a snapshot restores
    // the ones it had. Refused for a non-epoch height so a wrong call cannot
    // poison the seed table.
    bool remember_seed_anchor(std::uint64_t epoch_height, const Hash& id) {
        if (epoch_height % SEEDHASH_EPOCH_BLOCKS != 0) return false;
        seed_anchors_[epoch_height] = id;
        return true;
    }

    const std::map<std::uint64_t, Hash>& seed_anchors() const noexcept { return seed_anchors_; }

    // The (timestamp, cumulative difficulty) rows the anchor bundle carries for
    // the 735 heights ending at the anchor. They are NOT rows: there are no ids,
    // no weights and no rewards in a bundle window, so they can answer exactly
    // one question -- what the difficulty retarget saw at a height below the
    // first block we connected ourselves.
    //
    // Without them a freshly booted node could not judge ANY fork for its first
    // 735 blocks, because the window a fork point needs reaches below the single
    // row an anchor boot starts with. It would follow the main chain correctly
    // and simply be unable to weigh an alternative for about a day -- safe, and
    // needlessly blind.
    void seed_pre_window(std::uint64_t end_height, const std::vector<DifficultyRow>& rows) {
        pre_window_ = rows;
        pre_end_    = end_height;
        pre_begin_  = rows.size() ? end_height + 1 - rows.size() : end_height + 1;
    }

    // The height of the first block this store can speak for: the start of the
    // seeded pre-window when there is one, and otherwise the oldest row it
    // retains. Zero means we hold the chain from its very first block, so there
    // is nothing missing BELOW us -- only, possibly, nothing there at all yet.
    std::uint64_t base_height() const noexcept {
        if (!pre_window_.empty()) return pre_begin_;
        return rows_.empty() ? 0 : rows_.front().row.height;
    }

    // The (timestamp, cumulative difficulty) window ending at `height`, oldest
    // first, as the difficulty retarget wants it. Returns false when the store
    // cannot reach far enough back -- which is exactly the condition that makes
    // a deep fork unjudgeable and therefore refusable, rather than guessed at.
    //
    // `allow_young_chain` is the one case where a window SHORTER than `count` is
    // the right answer rather than a refusal: the chain itself is younger than
    // the window. monerod does not refuse there --
    // Blockchain::get_difficulty_for_next_block collects min(height, 735) rows --
    // and neither does this index's own tip fast path, which reads the consensus
    // state's rolling window and therefore gets exactly the rows that exist.
    // Only the BRANCH path came through here, so only the branch path refused,
    // and a from-genesis node could not weigh ANY fork below its own tip until
    // the chain was 735 blocks long: every regtest rig, always, and the first
    // day of any from-genesis sync.
    //
    // The relaxation is granted only when base_height() == 0 -- we genuinely
    // hold the chain from its first block. A store that merely STARTS high
    // (trimmed rows, or an anchored boot whose pre-window does not reach the
    // fork point) still cannot see far enough back, and that refusal must stay
    // a refusal: a guessed window would put a wrong difficulty on a branch and
    // the apply path would then disagree with itself.
    bool difficulty_window_ending_at(std::uint64_t height, std::size_t count,
                                     std::vector<DifficultyRow>& out,
                                     bool allow_young_chain = false) const {
        out.clear();
        if (rows_.empty() || height > rows_.back().row.height) return false;
        if (height < rows_.front().row.height) return false;

        const std::uint64_t span = static_cast<std::uint64_t>(count);
        const bool young = allow_young_chain && base_height() == 0;
        if (height + 1 < span && !young) return false;    // no such window exists
        const std::uint64_t lo = height + 1 >= span ? height + 1 - span : 0;

        const std::uint64_t rows_lo = rows_.front().row.height;
        out.reserve(static_cast<std::size_t>(span));
        for (std::uint64_t h = lo; h <= height; ++h) {
            if (h < rows_lo) {
                if (h < pre_begin_ || h > pre_end_) { out.clear(); return false; }
                out.push_back(pre_window_[static_cast<std::size_t>(h - pre_begin_)]);
                continue;
            }
            const RowRecord* r = by_height(h);
            if (!r) { out.clear(); return false; }
            out.push_back(DifficultyRow{r->row.timestamp, r->row.cumulative_difficulty});
        }
        return true;
    }

private:
    using Key = std::string;   // 32 raw bytes; std::array has no std::hash

    static Key key_(const Hash& h) {
        return Key(reinterpret_cast<const char*>(h.data()), h.size());
    }

    void trim_() {
        while (rows_.size() > retention_) {
            by_id_.erase(key_(rows_.front().row.id));
            // The seed anchor deliberately survives: see the header comment.
            rows_.pop_front();
        }
    }

    std::deque<RowRecord>         rows_;
    std::map<Key, std::uint64_t>  by_id_;
    std::map<std::uint64_t, Hash> seed_anchors_;
    std::vector<DifficultyRow>    pre_window_;
    std::uint64_t                 pre_begin_ = 0;
    std::uint64_t                 pre_end_   = 0;
    std::size_t                   retention_ = 2048;   // D-9
};

} // namespace c2pool::xmr::native
