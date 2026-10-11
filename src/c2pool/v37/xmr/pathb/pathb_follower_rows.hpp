// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_follower_rows.hpp
// The Path B follower rows over the native Monero node's chain index (the
// IMoneroRows a FollowerBranchView reads):
//   on_row       the row sink (ChainIndex::subscribe_rows): RowWeights of each
//                connected or seeded row, by id (snapshot_after_connect)
//   block        a held row by id: a main-chain row or a resolved alt block
//   block_at_or_below_anchor
//                the seeded difficulty rows by height
//   anchor       the oldest main-chain row held
//   weights      RowWeights by id
//   main_tip     the index's tip
//   frontier     the height of the highest main-chain row whose RowWeights
//                record is written (the consumer frontier)
//   load / save  the RowWeights table file (encode_row_weights_table); save
//                drops the ids the index no longer holds
//
// Threading: on_row runs under the chain index mutex (the native node's verify
// thread); every other call takes the table mutex without the index mutex held
// and calls the index only outside the table mutex.
//
// Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/pathb/pathb_branch_follower.hpp"

namespace c2pool::xmr::pathb {

class PathbFollowerRows final : public IMoneroRows {
public:
    explicit PathbFollowerRows(std::string table_path) : path_(std::move(table_path)) {}

    // The index the rows are read from (after the native node started).
    void bind(const ::c2pool::xmr::native::ChainIndex* index) { index_ = index; }

    // The row sink: the state whose tip is `row`, right after it connected or was seeded.
    void on_row(const ::c2pool::xmr::native::ConsensusState& st, const ::c2pool::xmr::native::ChainRow& row, bool) {
        const std::optional<RowWeights> w = snapshot_after_connect(st, row);
        if (!w) return;
        std::lock_guard<std::mutex> lk(mu_);
        table_[row.id] = *w;
        ++recorded_;
    }

    // ---- IMoneroRows ----
    std::optional<BranchBlock> block(const Hash32& id) const override {
        if (index_ == nullptr) return std::nullopt;
        const auto r = index_->held_row(id);
        if (!r) return std::nullopt;
        return branch_block(*r);
    }
    std::optional<BranchBlock> block_at_or_below_anchor(std::uint64_t height) const override {
        if (index_ == nullptr) return std::nullopt;
        const auto d = index_->seeded_row_at(height);
        if (!d) return std::nullopt;
        BranchBlock b;
        b.height = height;
        b.timestamp = d->timestamp;
        b.cumulative_difficulty = d->cumulative_difficulty;
        return b;
    }
    std::optional<RowWeights> weights(const Hash32& id) const override {
        std::lock_guard<std::mutex> lk(mu_);
        const auto it = table_.find(id);
        if (it == table_.end()) return std::nullopt;
        return it->second;
    }
    BranchBlock anchor() const override {
        if (index_ == nullptr) return BranchBlock{};
        const auto r = index_->oldest_row();
        return r ? branch_block(*r) : BranchBlock{};
    }
    Hash32 main_tip() const override {
        if (index_ == nullptr) return Hash32{};
        const auto t = index_->tip();
        return t ? t->id : Hash32{};
    }

    // The height of the highest main-chain row with a RowWeights record, at
    // most `max_walk` rows below the tip; nullopt when none is found.
    std::optional<std::uint64_t> frontier(std::uint64_t max_walk = 4096) const {
        if (index_ == nullptr) return std::nullopt;
        const auto t = index_->tip();
        if (!t) return std::nullopt;
        for (std::uint64_t k = 0; k <= max_walk && k <= t->height; ++k) {
            const auto b = index_->by_height(t->height - k);
            if (!b) return std::nullopt;
            if (weights(b->id)) return b->height;
        }
        return std::nullopt;
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lk(mu_);
        return table_.size();
    }
    std::uint64_t recorded() const {
        std::lock_guard<std::mutex> lk(mu_);
        return recorded_;
    }
    const std::string& path() const noexcept { return path_; }

    // ---- the table file ----
    // Absent file: an empty table (true). A file that does not decode: false.
    bool load(std::string& why) {
        std::ifstream f(path_, std::ios::binary);
        if (!f) return true;
        const std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        const auto t = decode_row_weights_table(bytes);
        if (!t) {
            why = "row weights table " + path_ + " does not decode";
            return false;
        }
        std::lock_guard<std::mutex> lk(mu_);
        for (const auto& [id, w] : *t) table_.emplace(id, w);
        loaded_ = t->size();
        return true;
    }
    // Drops the ids the index holds no longer, then writes the table (a temp
    // file renamed over the old one).
    bool save(std::string& why) {
        std::vector<Hash32> ids;
        {
            std::lock_guard<std::mutex> lk(mu_);
            ids.reserve(table_.size());
            for (const auto& [id, w] : table_) ids.push_back(id);
        }
        std::vector<Hash32> gone;
        if (index_ != nullptr)
            for (const Hash32& id : ids)
                if (!index_->held_row(id)) gone.push_back(id);
        std::vector<std::uint8_t> bytes;
        {
            std::lock_guard<std::mutex> lk(mu_);
            for (const Hash32& id : gone) table_.erase(id);
            bytes = encode_row_weights_table(table_);
        }
        const std::string tmp = path_ + ".tmp";
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (!f) {
                why = "cannot write " + tmp;
                return false;
            }
            f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            if (!f) {
                why = "cannot write " + tmp;
                return false;
            }
        }
        if (std::rename(tmp.c_str(), path_.c_str()) != 0) {
            why = "cannot rename " + tmp;
            return false;
        }
        return true;
    }
    std::size_t loaded() const noexcept { return loaded_; }

private:
    static BranchBlock branch_block(const ::c2pool::xmr::native::ChainIndex::HeldRow& r) {
        BranchBlock b;
        b.id = r.id;
        b.prev_id = r.prev_id;
        b.height = r.height;
        b.timestamp = r.timestamp;
        b.cumulative_difficulty = r.cumulative_difficulty;
        return b;
    }

    std::string path_;
    const ::c2pool::xmr::native::ChainIndex* index_ = nullptr;
    mutable std::mutex mu_;
    std::map<Hash32, RowWeights> table_;
    std::uint64_t recorded_ = 0;
    std::size_t loaded_ = 0;
};

}  // namespace c2pool::xmr::pathb
