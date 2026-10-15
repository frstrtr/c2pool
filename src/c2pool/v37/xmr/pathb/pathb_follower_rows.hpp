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
//                kept from before a restart
//   block_at_or_below_anchor
//                the seeded difficulty rows by height
//   anchor       the oldest main-chain row held
//   weights      RowWeights by id
//   main_tip     the index's tip
//   frontier     the height of the highest main-chain row whose RowWeights
//                record is written (the consumer frontier)
//   load / save  the RowWeights table files: `row_weights` (encode_row_weights_table) the
//                main-chain rows the index holds; `row_weights_kept` (encode_kept_rows) every
//                row within k_alt (P-07) of the index tip with the row itself (main or off
//                it, held or not), so it survives a restart as a connected row does; save
//                drops the rows off the main chain below k_alt
//
// Threading: on_row runs under the chain index mutex (the native node's verify
// thread); every other call takes the table mutex without the index mutex held
// and calls the index only outside the table mutex.
//
// Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/pathb/pathb_branch_follower.hpp"
#include "impl/xmr/pathb/pathb_caps.hpp"  // kAltDepth (P-07)

namespace c2pool::xmr::pathb {

// The kept rows' file (node-local): u32 n | n x (id 32 | prev 32 | u64 height | u64 timestamp |
// u64 cumulative difficulty lo | u64 hi | RowWeights 33), integers LE, ids ascending: the rows within k_alt of the
// index tip, each with its RowWeights, so that a row survives a restart as a connected row does (its block may
// not be held after it: a pool-found block off the chain, or a tip a restart finds off the chain).
struct KeptRow {
    BranchBlock row;
    RowWeights w;
};
inline constexpr std::size_t kKeptRowBytes = 2 * kHashBytes + 4 * sizeof(std::uint64_t) + kRowWeightsBytes;

namespace detail_kept {
inline void put_u64(std::vector<std::uint8_t>& o, std::uint64_t x) {
    for (std::size_t i = 0; i < 8; ++i) o.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
}
inline std::uint64_t get_u64(std::span<const std::uint8_t> in, std::size_t o) {
    std::uint64_t x = 0;
    for (std::size_t i = 0; i < 8; ++i) x |= std::uint64_t{in[o + i]} << (8 * i);
    return x;
}
}  // namespace detail_kept

inline std::vector<std::uint8_t> encode_kept_rows(const std::map<Hash32, KeptRow>& t) {
    std::vector<std::uint8_t> out;
    out.reserve(4 + t.size() * kKeptRowBytes);
    const std::uint32_t n = static_cast<std::uint32_t>(t.size());
    for (std::size_t i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>(n >> (8 * i)));
    for (const auto& [id, a] : t) {
        out.insert(out.end(), id.begin(), id.end());
        out.insert(out.end(), a.row.prev_id.begin(), a.row.prev_id.end());
        detail_kept::put_u64(out, a.row.height);
        detail_kept::put_u64(out, a.row.timestamp);
        detail_kept::put_u64(out, a.row.cumulative_difficulty.lo);
        detail_kept::put_u64(out, a.row.cumulative_difficulty.hi);
        encode_row_weights(a.w, out);
    }
    return out;
}

inline std::optional<std::map<Hash32, KeptRow>> decode_kept_rows(std::span<const std::uint8_t> in) {
    if (in.size() < 4) return std::nullopt;
    std::uint32_t n = 0;
    for (std::size_t i = 0; i < 4; ++i) n |= std::uint32_t{in[i]} << (8 * i);
    if ((in.size() - 4) % kKeptRowBytes != 0 || (in.size() - 4) / kKeptRowBytes != n) return std::nullopt;
    std::map<Hash32, KeptRow> t;
    Hash32 prev{};
    for (std::size_t k = 0; k < n; ++k) {
        const std::size_t o = 4 + k * kKeptRowBytes;
        KeptRow a;
        std::copy_n(in.begin() + static_cast<std::ptrdiff_t>(o), kHashBytes, a.row.id.begin());
        if (k > 0 && !(prev < a.row.id)) return std::nullopt;
        std::copy_n(in.begin() + static_cast<std::ptrdiff_t>(o + kHashBytes), kHashBytes, a.row.prev_id.begin());
        const std::size_t q = o + 2 * kHashBytes;
        a.row.height = detail_kept::get_u64(in, q);
        a.row.timestamp = detail_kept::get_u64(in, q + 8);
        a.row.cumulative_difficulty.lo = detail_kept::get_u64(in, q + 16);
        a.row.cumulative_difficulty.hi = detail_kept::get_u64(in, q + 24);
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
    // A held row (main or alt); else a row kept from before a restart (row_weights_kept) while within k_alt of the
    // index tip.
    std::optional<BranchBlock> block(const Hash32& id) const override {
        if (index_ == nullptr) return std::nullopt;
        if (const auto r = index_->held_row(id)) return branch_block(*r);
        const auto tip = index_->tip();
        const std::uint64_t tip_h = tip ? tip->height : 0;
        std::lock_guard<std::mutex> lk(mu_);
        const auto it = kept_.find(id);
        if (it == kept_.end() || it->second.height + alt_keep_ < tip_h) return std::nullopt;
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
    // Absent file: an empty table (true). A main table that does not decode: false. Kept rows that do not decode:
    // true, the main rows only, `why` says so.
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
        std::ifstream fa(kept_path(), std::ios::binary);
        if (!fa) return true;
        // the kept rows: their count read first and the file's size checked against it before the rest is read
        const auto refused = [&]() {
            why = "kept rows " + kept_path() + " do not decode -- the main rows only";
            return true;
        };
        std::error_code ec;
        const std::uintmax_t size = std::filesystem::file_size(kept_path(), ec);
        std::array<std::uint8_t, 4> nb{};
        if (ec || size < nb.size() || !fa.read(reinterpret_cast<char*>(nb.data()), nb.size())) return refused();
        const std::uint64_t n = std::uint64_t{nb[0]} | std::uint64_t{nb[1]} << 8 | std::uint64_t{nb[2]} << 16 |
                                std::uint64_t{nb[3]} << 24;
        if (size != nb.size() + n * kKeptRowBytes) return refused();
        std::vector<std::uint8_t> abytes(static_cast<std::size_t>(size));
        std::copy(nb.begin(), nb.end(), abytes.begin());
        if (!fa.read(reinterpret_cast<char*>(abytes.data() + nb.size()), static_cast<std::streamsize>(size - nb.size())))
            return refused();
        const auto a = decode_kept_rows(abytes);
        if (!a) return refused();
        for (const auto& [id, ar] : *a) {
            if (table_.emplace(id, ar.w).second) ++loaded_;
            rows_.emplace(id, ar.row);
            kept_.emplace(id, ar.row);
        }
        return true;
    }
    // Writes the main-chain rows the index holds to `row_weights` and every row within k_alt of the index tip, with
    // the row, to `row_weights_kept` (each a temp file renamed over the old one); drops the rows off the main chain
    // below k_alt.
    bool save(std::string& why) {
        std::vector<Hash32> ids;
        {
            std::lock_guard<std::mutex> lk(mu_);
            ids.reserve(table_.size());
            for (const auto& [id, w] : table_) ids.push_back(id);
        }
        // each row: main-chain held or not, and the row as the index holds it (else as recorded / kept before)
        std::vector<std::tuple<Hash32, bool, std::optional<BranchBlock>>> rows;
        std::uint64_t tip_h = 0;
        if (index_ != nullptr) {
            const auto tip = index_->tip();
            tip_h = tip ? tip->height : 0;
            for (const Hash32& id : ids) {
                const auto r = index_->held_row(id);
                rows.emplace_back(id, r && r->main, r ? std::optional<BranchBlock>(branch_block(*r)) : std::nullopt);
            }
        }
        std::vector<std::uint8_t> bytes, kbytes;
        {
            std::lock_guard<std::mutex> lk(mu_);
            std::map<Hash32, RowWeights> main;
            std::map<Hash32, KeptRow> kept;
            for (auto& [id, is_main, held] : rows) {
                std::optional<BranchBlock> row = held;
                if (!row) {
                    const auto it = rows_.find(id);
                    if (it != rows_.end()) row = it->second;
                }
                const auto w = table_.find(id);
                if (w == table_.end()) continue;
                const bool recent = row && row->height + alt_keep_ >= tip_h;
                if (is_main) main.emplace(id, w->second);
                if (recent) {
                    kept.emplace(id, KeptRow{*row, w->second});
                    rows_[id] = *row;
                    kept_[id] = *row;
                } else {
                    kept_.erase(id);
                    if (!is_main) {
                        table_.erase(id);
                        rows_.erase(id);
                    }
                }
            }
            for (auto it = rows_.begin(); it != rows_.end();)  // rows of ids no longer in the table
                it = table_.count(it->first) ? std::next(it) : rows_.erase(it);
            bytes = encode_row_weights_table(main);
            kbytes = encode_kept_rows(kept);
        }
        return write_file(path_, bytes, why) && write_file(kept_path(), kbytes, why);
    }
    // k_alt (P-07): how far below the index tip a row off the main chain is kept.
    void set_alt_keep(std::uint64_t k) noexcept { alt_keep_ = k; }
    std::string kept_path() const { return path_ + "_kept"; }
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
    std::map<Hash32, BranchBlock> kept_;  // rows kept across a restart (served by block() when not held)
    std::uint64_t alt_keep_ = kAltDepth;
    std::uint64_t recorded_ = 0;
    std::size_t loaded_ = 0;
};

}  // namespace c2pool::xmr::pathb
