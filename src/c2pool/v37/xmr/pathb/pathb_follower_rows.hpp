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
//   block        a held row by id: a main-chain row or a resolved alt block; else a row
//                off the main chain kept from before a restart
//   block_at_or_below_anchor
//                the seeded difficulty rows by height
//   anchor       the oldest main-chain row held
//   weights      RowWeights by id
//   main_tip     the index's tip
//   frontier     the height of the highest main-chain row whose RowWeights
//                record is written (the consumer frontier)
//   load / save  the RowWeights table files: `row_weights` (encode_row_weights_table) the
//                main-chain rows the index holds; `row_weights_alt` (encode_alt_rows) every
//                other row with the row itself (alternative blocks, held or not), kept
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

// The alternative rows' file (node-local): u32 n | n x (id 32 | prev 32 | u64 height | u64 timestamp |
// u64 cumulative difficulty lo | u64 hi | RowWeights 33), integers LE, ids ascending: each row as a connected row
// survives a restart (the row from the index's snapshot, its RowWeights from row_weights).
struct AltRow {
    BranchBlock row;
    RowWeights w;
};
inline constexpr std::size_t kAltRowBytes = 2 * kHashBytes + 4 * sizeof(std::uint64_t) + kRowWeightsBytes;

namespace detail_alt {
inline void put_u64(std::vector<std::uint8_t>& o, std::uint64_t x) {
    for (std::size_t i = 0; i < 8; ++i) o.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
}
inline std::uint64_t get_u64(std::span<const std::uint8_t> in, std::size_t o) {
    std::uint64_t x = 0;
    for (std::size_t i = 0; i < 8; ++i) x |= std::uint64_t{in[o + i]} << (8 * i);
    return x;
}
}  // namespace detail_alt

inline std::vector<std::uint8_t> encode_alt_rows(const std::map<Hash32, AltRow>& t) {
    std::vector<std::uint8_t> out;
    out.reserve(4 + t.size() * kAltRowBytes);
    const std::uint32_t n = static_cast<std::uint32_t>(t.size());
    for (std::size_t i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>(n >> (8 * i)));
    for (const auto& [id, a] : t) {
        out.insert(out.end(), id.begin(), id.end());
        out.insert(out.end(), a.row.prev_id.begin(), a.row.prev_id.end());
        detail_alt::put_u64(out, a.row.height);
        detail_alt::put_u64(out, a.row.timestamp);
        detail_alt::put_u64(out, a.row.cumulative_difficulty.lo);
        detail_alt::put_u64(out, a.row.cumulative_difficulty.hi);
        encode_row_weights(a.w, out);
    }
    return out;
}

inline std::optional<std::map<Hash32, AltRow>> decode_alt_rows(std::span<const std::uint8_t> in) {
    if (in.size() < 4) return std::nullopt;
    std::uint32_t n = 0;
    for (std::size_t i = 0; i < 4; ++i) n |= std::uint32_t{in[i]} << (8 * i);
    if ((in.size() - 4) % kAltRowBytes != 0 || (in.size() - 4) / kAltRowBytes != n) return std::nullopt;
    std::map<Hash32, AltRow> t;
    Hash32 prev{};
    for (std::size_t k = 0; k < n; ++k) {
        const std::size_t o = 4 + k * kAltRowBytes;
        AltRow a;
        std::copy_n(in.begin() + static_cast<std::ptrdiff_t>(o), kHashBytes, a.row.id.begin());
        if (k > 0 && !(prev < a.row.id)) return std::nullopt;
        std::copy_n(in.begin() + static_cast<std::ptrdiff_t>(o + kHashBytes), kHashBytes, a.row.prev_id.begin());
        const std::size_t q = o + 2 * kHashBytes;
        a.row.height = detail_alt::get_u64(in, q);
        a.row.timestamp = detail_alt::get_u64(in, q + 8);
        a.row.cumulative_difficulty.lo = detail_alt::get_u64(in, q + 16);
        a.row.cumulative_difficulty.hi = detail_alt::get_u64(in, q + 24);
        const std::optional<RowWeights> w = decode_row_weights(in.subspan(q + 32, kRowWeightsBytes));
        if (!w) return std::nullopt;
        a.w = *w;
        prev = a.row.id;
        t.emplace(a.row.id, a);
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
        BranchBlock b;
        b.id = row.id;
        b.prev_id = row.prev_id;
        b.height = row.height;
        b.timestamp = row.timestamp;
        b.cumulative_difficulty = row.cumulative_difficulty;
        rows_[row.id] = b;
        ++recorded_;
    }

    // ---- IMoneroRows ----
    // A held row (main or alt); else a row off the main chain kept from before a restart (row_weights_alt).
    std::optional<BranchBlock> block(const Hash32& id) const override {
        if (index_ == nullptr) return std::nullopt;
        if (const auto r = index_->held_row(id)) return branch_block(*r);
        std::lock_guard<std::mutex> lk(mu_);
        const auto it = kept_.find(id);
        if (it == kept_.end()) return std::nullopt;
        return it->second;
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
        const auto a = decode_alt_rows(abytes);
        if (!a) {
            why = "row weights table " + alt_path() + " does not decode";
            return false;
        }
        for (const auto& [id, ar] : *a) {
            if (table_.emplace(id, ar.w).second) ++loaded_;
            rows_.emplace(id, ar.row);
            kept_.emplace(id, ar.row);
        }
        return true;
    }
    // Writes the main-chain rows the index holds to `row_weights` and every other row whose height is within
    // k_alt of the index tip to `row_weights_alt` (each a temp file renamed over the old one); drops the rest.
    bool save(std::string& why) {
        std::vector<Hash32> ids;
        {
            std::lock_guard<std::mutex> lk(mu_);
            ids.reserve(table_.size());
            for (const auto& [id, w] : table_) ids.push_back(id);
        }
        // off the main chain: the row as the index holds it, or as recorded / kept before
        std::vector<std::pair<Hash32, std::optional<BranchBlock>>> off;
        std::uint64_t tip_h = 0;
        if (index_ != nullptr) {
            const auto tip = index_->tip();
            tip_h = tip ? tip->height : 0;
            for (const Hash32& id : ids) {
                const auto r = index_->held_row(id);
                if (r && r->main) continue;
                off.emplace_back(id, r ? std::optional<BranchBlock>(branch_block(*r)) : std::nullopt);
            }
        }
        std::vector<std::uint8_t> bytes, abytes;
        {
            std::lock_guard<std::mutex> lk(mu_);
            std::map<Hash32, AltRow> alts;
            for (auto& [id, held] : off) {
                std::optional<BranchBlock> row = held;
                if (!row) {
                    const auto it = rows_.find(id);
                    if (it != rows_.end()) row = it->second;
                }
                const auto w = table_.find(id);
                if (row && w != table_.end() && row->height + alt_keep_ >= tip_h) {
                    alts.emplace(id, AltRow{*row, w->second});
                    rows_[id] = *row;
                    kept_[id] = *row;
                } else {
                    table_.erase(id);
                    rows_.erase(id);
                    kept_.erase(id);
                }
            }
            std::map<Hash32, RowWeights> main = table_;
            for (const auto& [id, a] : alts) main.erase(id);
            for (auto it = rows_.begin(); it != rows_.end();)  // rows of ids no longer in the table
                it = table_.count(it->first) ? std::next(it) : rows_.erase(it);
            bytes = encode_row_weights_table(main);
            abytes = encode_alt_rows(alts);
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
    std::map<Hash32, BranchBlock> rows_;  // the row of every RowWeights recorded or loaded with one
    std::map<Hash32, BranchBlock> kept_;  // rows off the main chain kept across a restart (served by block())
    std::uint64_t alt_keep_ = kAltDepth;
    std::uint64_t recorded_ = 0;
    std::size_t loaded_ = 0;
};

}  // namespace c2pool::xmr::pathb
