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
//                connected or seeded row and of each alt block on its own
//                branch, by id (snapshot_after_connect)
//   block        a held row by id: a main-chain row or a resolved alt block
//   block_at_or_below_anchor
//                the seeded difficulty rows by height
//   anchor       the oldest main-chain row held
//   weights      RowWeights by id
//   main_tip     the index's tip
//   frontier     the height of the highest main-chain row whose RowWeights
//                record is written (the consumer frontier)
//   load / save  the RowWeights table files: `row_weights` (encode_row_weights_table) the
//                main-chain rows the index holds; `row_weights_alt` (encode_alt_row_weights)
//                every other row with its height (alternative blocks, held or not), kept
//                across a restart while its height is within k_alt (P-07) of the index
//                tip; save drops the rest
//
// Threading: on_row runs under the chain index mutex (the native node's verify
// thread); every other call takes the table mutex without the index mutex held
// and calls the index only outside the table mutex.
//
// Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/pathb/pathb_branch_follower.hpp"
#include "impl/xmr/pathb/pathb_caps.hpp"  // kAltDepth (P-07)

namespace c2pool::xmr::pathb {

// The alternative rows' file (node-local): u32 n | n x (id 32 | u64 height LE | RowWeights 33), ids ascending.
inline constexpr std::size_t kAltRowBytes = kHashBytes + sizeof(std::uint64_t) + kRowWeightsBytes;

inline std::vector<std::uint8_t> encode_alt_row_weights(const std::map<Hash32, std::pair<std::uint64_t, RowWeights>>& t) {
    std::vector<std::uint8_t> out;
    out.reserve(4 + t.size() * kAltRowBytes);
    const std::uint32_t n = static_cast<std::uint32_t>(t.size());
    for (std::size_t i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>(n >> (8 * i)));
    for (const auto& [id, hw] : t) {
        out.insert(out.end(), id.begin(), id.end());
        for (std::size_t i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>(hw.first >> (8 * i)));
        encode_row_weights(hw.second, out);
    }
    return out;
}

inline std::optional<std::map<Hash32, std::pair<std::uint64_t, RowWeights>>> decode_alt_row_weights(
        std::span<const std::uint8_t> in) {
    if (in.size() < 4) return std::nullopt;
    std::uint32_t n = 0;
    for (std::size_t i = 0; i < 4; ++i) n |= std::uint32_t{in[i]} << (8 * i);
    if ((in.size() - 4) % kAltRowBytes != 0 || (in.size() - 4) / kAltRowBytes != n) return std::nullopt;
    std::map<Hash32, std::pair<std::uint64_t, RowWeights>> t;
    Hash32 prev{};
    for (std::size_t k = 0; k < n; ++k) {
        const std::size_t o = 4 + k * kAltRowBytes;
        Hash32 id{};
        std::copy_n(in.begin() + static_cast<std::ptrdiff_t>(o), kHashBytes, id.begin());
        if (k > 0 && !(prev < id)) return std::nullopt;
        std::uint64_t h = 0;
        for (std::size_t i = 0; i < 8; ++i) h |= std::uint64_t{in[o + kHashBytes + i]} << (8 * i);
        const std::optional<RowWeights> w = decode_row_weights(in.subspan(o + kHashBytes + 8, kRowWeightsBytes));
        if (!w) return std::nullopt;
        t.emplace(id, std::make_pair(h, *w));
        prev = id;
    }
    return t;
}

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
        heights_[row.id] = row.height;
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
        std::ifstream fa(alt_path(), std::ios::binary);
        if (!fa) return true;
        const std::vector<std::uint8_t> abytes((std::istreambuf_iterator<char>(fa)), std::istreambuf_iterator<char>());
        const auto a = decode_alt_row_weights(abytes);
        if (!a) {
            why = "row weights table " + alt_path() + " does not decode";
            return false;
        }
        for (const auto& [id, hw] : *a) {
            if (table_.emplace(id, hw.second).second) ++loaded_;
            heights_.emplace(id, hw.first);
        }
        return true;
    }
    // Writes the main-chain rows the index holds to `row_weights` and every other row whose height is within
    // k_alt of the index tip to `row_weights_alt` (each a temp file renamed over the old one); drops the rest.
    bool save(std::string& why) {
        std::vector<std::pair<Hash32, std::optional<std::uint64_t>>> ids;
        {
            std::lock_guard<std::mutex> lk(mu_);
            ids.reserve(table_.size());
            for (const auto& [id, w] : table_) {
                const auto h = heights_.find(id);
                ids.emplace_back(id, h == heights_.end() ? std::nullopt : std::optional<std::uint64_t>(h->second));
            }
        }
        std::vector<Hash32> gone, alt;
        if (index_ != nullptr) {
            const auto tip = index_->tip();
            const std::uint64_t tip_h = tip ? tip->height : 0;
            for (const auto& [id, h0] : ids) {
                const auto r = index_->held_row(id);
                if (r && r->main) continue;
                const std::optional<std::uint64_t> h = r ? std::optional<std::uint64_t>(r->height) : h0;
                if (h && *h + alt_keep_ >= tip_h)
                    alt.push_back(id);
                else
                    gone.push_back(id);
            }
        }
        std::vector<std::uint8_t> bytes, abytes;
        {
            std::lock_guard<std::mutex> lk(mu_);
            for (const Hash32& id : gone) {
                table_.erase(id);
                heights_.erase(id);
            }
            std::map<Hash32, RowWeights> main = table_;
            std::map<Hash32, std::pair<std::uint64_t, RowWeights>> alts;
            for (const Hash32& id : alt) {
                const auto it = table_.find(id);
                if (it == table_.end()) continue;
                const auto r = index_ != nullptr ? index_->held_row(id) : std::nullopt;
                const auto h = heights_.find(id);
                const std::uint64_t height = r ? r->height : (h != heights_.end() ? h->second : 0);
                heights_[id] = height;
                alts.emplace(id, std::make_pair(height, it->second));
                main.erase(id);
            }
            bytes = encode_row_weights_table(main);
            abytes = encode_alt_row_weights(alts);
        }
        return write_file(path_, bytes, why) && write_file(alt_path(), abytes, why);
    }
    // k_alt (P-07): how far below the index tip a row off the main chain is kept.
    void set_alt_keep(std::uint64_t k) noexcept { alt_keep_ = k; }
    std::string alt_path() const { return path_ + "_alt"; }
    std::size_t loaded() const noexcept { return loaded_; }

private:
    static bool write_file(const std::string& path, const std::vector<std::uint8_t>& bytes, std::string& why) {
        const std::string tmp = path + ".tmp";
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
        if (std::rename(tmp.c_str(), path.c_str()) != 0) {
            why = "cannot rename " + tmp;
            return false;
        }
        return true;
    }

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
    std::map<Hash32, std::uint64_t> heights_;  // the height of every row recorded or loaded with one
    std::uint64_t alt_keep_ = kAltDepth;
    std::uint64_t recorded_ = 0;
    std::size_t loaded_ = 0;
};

}  // namespace c2pool::xmr::pathb
