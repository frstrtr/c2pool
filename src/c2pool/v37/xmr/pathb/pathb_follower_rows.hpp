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
//                drops the rows off the main chain below k_alt; `row_weights_kept_blobs`
//                (encode_kept_blobs) the block of each kept row off the main chain the
//                index holds (or held before a restart), served as a Monero context
//                (kept_blob) after a restart
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
#include <functional>
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
#include "impl/xmr/native/consensus/xmr_block_id.hpp"
#include "impl/xmr/pathb/pathb_branch_follower.hpp"
#include "impl/xmr/pathb/pathb_caps.hpp"  // kAltDepth (P-07), blob_cap_ctx, zone
#include "impl/xmr/pathb/pathb_emission.hpp"  // kHf16

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

// The kept file's sanity bound on its rows: those within k_alt (P-07) of the index tip, the main ones (k_alt + 1) plus
// the alternatives the native index's alt store holds (alt_max_blocks, by default k_alt): 721 + 720 = 1,441 at the
// code's values.
inline std::uint64_t kept_rows_cap(std::size_t alt_max_blocks = ::c2pool::xmr::native::ChainIndexOptions{}.alt_max_blocks) {
    return (kAltDepth + 1) + static_cast<std::uint64_t>(alt_max_blocks);
}

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

inline std::optional<std::map<Hash32, KeptRow>> decode_kept_rows(std::span<const std::uint8_t> in,
                                                                 std::uint64_t cap = kept_rows_cap()) {
    if (in.size() < 4) return std::nullopt;
    std::uint32_t n = 0;
    for (std::size_t i = 0; i < 4; ++i) n |= std::uint32_t{in[i]} << (8 * i);
    if (n > cap || (in.size() - 4) % kKeptRowBytes != 0 || (in.size() - 4) / kKeptRowBytes != n)
        return std::nullopt;
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

// The alt store's verified class byte cap: alt_max_blocks x blob_cap_ctx(hf, Z) of a child of the index tip (`tip_w`,
// its RowWeights), at least at hf 16 (the relay's context frame floor); `lower` (--alt-max-bytes, 0 = none) only
// lowers it. alt_verified_bytes_cap_max: the most at any hf the code knows (a saved kept-blobs file's bound at load).
inline std::uint64_t alt_verified_bytes_cap(std::size_t alt_max_blocks, const std::optional<RowWeights>& tip_w,
                                            std::uint64_t lower = 0) {
    std::uint64_t per = blob_cap_ctx(kHf16, zone(kHf16)).value_or(0);
    if (tip_w) per = std::max(per, blob_cap_ctx(tip_w->hf_child, tip_w->z_child).value_or(0));
    const std::uint64_t cap = static_cast<std::uint64_t>(alt_max_blocks) * per;
    return lower != 0 ? std::min(cap, lower) : cap;
}
inline std::uint64_t alt_verified_bytes_cap_max(std::size_t alt_max_blocks, std::uint64_t lower = 0) {
    const std::uint64_t per = std::max(blob_cap_ctx(kHf16, zone(kHf16)).value_or(0),
                                       blob_cap_ctx(HF_VERSION_FCMP_PLUS_PLUS, zone(HF_VERSION_FCMP_PLUS_PLUS)).value_or(0));
    const std::uint64_t cap = static_cast<std::uint64_t>(alt_max_blocks) * per;
    return lower != 0 ? std::min(cap, lower) : cap;
}

// The kept blobs' file (node-local): u32 n | n x (id 32 | u32 len | blob len B), integers LE, ids ascending: the block of
// each kept row off the main chain. Bounded by the native alt store: n <= alt_max_blocks, the sum of len <=
// alt_max_bytes (each len checked against what is left before its blob is read).
inline std::vector<std::uint8_t> encode_kept_blobs(const std::map<Hash32, std::vector<std::uint8_t>>& t) {
    std::vector<std::uint8_t> out;
    const auto put_u32 = [&](std::uint32_t x) {
        for (std::size_t i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
    };
    put_u32(static_cast<std::uint32_t>(t.size()));
    for (const auto& [id, blob] : t) {
        out.insert(out.end(), id.begin(), id.end());
        put_u32(static_cast<std::uint32_t>(blob.size()));
        out.insert(out.end(), blob.begin(), blob.end());
    }
    return out;
}
// nullopt: the file does not decode within the caps (n, a len, the sum, the order, trailing bytes).
inline std::optional<std::map<Hash32, std::vector<std::uint8_t>>> decode_kept_blobs(std::span<const std::uint8_t> in,
                                                                                  std::uint64_t max_blocks,
                                                                                  std::uint64_t max_bytes) {
    const auto get_u32 = [&](std::size_t o) {
        std::uint32_t x = 0;
        for (std::size_t i = 0; i < 4; ++i) x |= std::uint32_t{in[o + i]} << (8 * i);
        return x;
    };
    if (in.size() < 4) return std::nullopt;
    const std::uint64_t n = get_u32(0);
    if (n > max_blocks) return std::nullopt;
    std::map<Hash32, std::vector<std::uint8_t>> t;
    std::size_t o = 4;
    std::uint64_t sum = 0;
    Hash32 prev{};
    for (std::uint64_t k = 0; k < n; ++k) {
        if (in.size() - o < kHashBytes + 4) return std::nullopt;
        Hash32 id{};
        std::copy_n(in.begin() + static_cast<std::ptrdiff_t>(o), kHashBytes, id.begin());
        if (k > 0 && !(prev < id)) return std::nullopt;
        const std::uint64_t len = get_u32(o + kHashBytes);
        o += kHashBytes + 4;
        if (len == 0 || len > max_bytes - sum || in.size() - o < len) return std::nullopt;
        t.emplace(id, std::vector<std::uint8_t>(in.begin() + static_cast<std::ptrdiff_t>(o),
                                                in.begin() + static_cast<std::ptrdiff_t>(o + len)));
        o += static_cast<std::size_t>(len);
        sum += len;
        prev = id;
    }
    if (o != in.size()) return std::nullopt;
    return t;
}
// A block blob's own id (parsed and identified): nullopt when it does not parse.
inline std::optional<Hash32> kept_blob_id(const std::vector<std::uint8_t>& blob) {
    ::c2pool::xmr::native::ParsedBlock pb;
    ::c2pool::xmr::native::BlockIdentity bi;
    if (::c2pool::xmr::native::parse_and_identify(blob, pb, bi) != ::c2pool::xmr::native::BlockParseStatus::Ok)
        return std::nullopt;
    Hash32 id{};
    std::copy(bi.id.begin(), bi.id.end(), id.begin());
    return id;
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

    // A kept alternative block's blob (loaded from `row_weights_kept_blobs`) while its row is kept: the Monero context
    // a restarted node serves when its index no longer holds the block.
    bool kept_blob(const Hash32& id, std::vector<std::uint8_t>& out) const {
        std::uint64_t tip_h = 0;
        if (index_ != nullptr)
            if (const auto tip = index_->tip()) tip_h = tip->height;
        std::lock_guard<std::mutex> lk(mu_);
        const auto b = kept_blobs_.find(id);
        const auto r = kept_.find(id);
        if (b == kept_blobs_.end() || r == kept_.end() || r->second.height + alt_keep_ < tip_h) return false;
        out = b->second;
        return true;
    }
    std::size_t kept_blobs() const {
        std::lock_guard<std::mutex> lk(mu_);
        return kept_blobs_.size();
    }

    // ---- the table file ----
    // Absent file: an empty table (true). A main table that does not decode: false. Kept rows that do not decode:
    // true, the main rows only, `why` says so.
    // `unix_s`: the caller's clock for the name of a kept blobs' file moved aside (the rows read no clock).
    bool load(std::string& why, std::uint64_t unix_s = 0) {
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
        // the kept rows: the file's size checked against the cap, their count read and checked against the cap and the
        // size, before the rest is read
        const auto refused = [&]() {
            why = "kept rows " + kept_path() + " do not decode -- the main rows only";
            return true;
        };
        std::error_code ec;
        const std::uintmax_t size = std::filesystem::file_size(kept_path(), ec);
        std::array<std::uint8_t, 4> nb{};
        if (ec || size < nb.size() || size > nb.size() + kept_rows_cap(alt_max_blocks_) * kKeptRowBytes
            || !fa.read(reinterpret_cast<char*>(nb.data()), nb.size()))
            return refused();
        const std::uint64_t n = std::uint64_t{nb[0]} | std::uint64_t{nb[1]} << 8 | std::uint64_t{nb[2]} << 16 |
                                std::uint64_t{nb[3]} << 24;
        if (n > kept_rows_cap(alt_max_blocks_) || size != nb.size() + n * kKeptRowBytes) return refused();
        std::vector<std::uint8_t> abytes(static_cast<std::size_t>(size));
        std::copy(nb.begin(), nb.end(), abytes.begin());
        if (!fa.read(reinterpret_cast<char*>(abytes.data() + nb.size()), static_cast<std::streamsize>(size - nb.size())))
            return refused();
        const auto a = decode_kept_rows(abytes, kept_rows_cap(alt_max_blocks_));
        if (!a) return refused();
        for (const auto& [id, ar] : *a) {
            if (table_.emplace(id, ar.w).second) ++loaded_;
            rows_.emplace(id, ar.row);
            kept_.emplace(id, ar.row);
        }
        load_kept_blobs_locked(why, unix_s);
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
        std::vector<std::pair<std::uint64_t, Hash32>> alt_ids;  // the kept rows off the main chain: (height, id)
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
            const std::uint64_t cap = kept_rows_cap(alt_max_blocks_);
            if (kept.size() > cap) {  // the file's bound: the highest rows kept
                std::vector<std::pair<std::uint64_t, Hash32>> by_h;
                for (const auto& [id, kr] : kept) by_h.emplace_back(kr.row.height, id);
                std::sort(by_h.begin(), by_h.end());
                for (std::size_t i = 0; i + cap < by_h.size(); ++i) kept.erase(by_h[i].second);
            }
            bytes = encode_row_weights_table(main);
            kbytes = encode_kept_rows(kept);
            for (const auto& [id, kr] : kept)
                if (main.count(id) == 0) alt_ids.push_back(std::make_pair(kr.row.height, id));
        }
        // the blob of each kept row off the main chain: the index's (a PoW-checked alternative), else the one loaded
        // before a restart; the highest rows first within the alt store's caps
        std::sort(alt_ids.begin(), alt_ids.end(), [](const auto& x, const auto& y) { return x.first > y.first; });
        std::map<Hash32, std::vector<std::uint8_t>> blobs;
        std::uint64_t sum = 0;
        for (const auto& [h, id] : alt_ids) {
            if (blobs.size() >= alt_max_blocks_) break;
            std::vector<std::uint8_t> blob;
            bool have = false;
            if (index_ != nullptr) {
                ::c2pool::xmr::native::Hash nid{};
                std::copy(id.begin(), id.end(), nid.begin());
                have = index_->block_blob_of(nid, blob);
            }
            if (!have) {
                std::lock_guard<std::mutex> lk(mu_);
                const auto it = kept_blobs_.find(id);
                if (it != kept_blobs_.end()) {
                    blob = it->second;
                    have = true;
                }
            }
            if (!have || blob.empty() || blob.size() > alt_max_bytes_ - sum) continue;
            sum += blob.size();
            blobs.emplace(id, std::move(blob));
        }
        const std::vector<std::uint8_t> bbytes = encode_kept_blobs(blobs);
        {
            std::lock_guard<std::mutex> lk(mu_);
            for (auto it = kept_blobs_.begin(); it != kept_blobs_.end();)  // what is no longer kept leaves memory too
                it = blobs.count(it->first) ? std::next(it) : kept_blobs_.erase(it);
        }
        return write_file(blobs_path(), bbytes, why) && write_file(path_, bytes, why) && write_file(kept_path(), kbytes, why);
    }
    // k_alt (P-07): how far below the index tip a row off the main chain is kept.
    void set_alt_keep(std::uint64_t k) noexcept { alt_keep_ = k; }
    // The native index's alt store count (--alt-max-blocks): the kept rows' bound is (k_alt + 1) + this.
    void set_alt_max_blocks(std::size_t n) noexcept { alt_max_blocks_ = n; }
    std::uint64_t kept_cap() const noexcept { return kept_rows_cap(alt_max_blocks_); }
    std::string kept_path() const { return path_ + "_kept"; }
    std::string blobs_path() const { return path_ + "_kept_blobs"; }
    // The native alt store's byte cap (alt_max_bytes): the kept blobs' bound on disk.
    void set_alt_max_bytes(std::uint64_t n) noexcept { alt_max_bytes_ = n; }
    std::size_t loaded() const noexcept { return loaded_; }
    std::size_t kept_blobs_loaded() const noexcept { return kept_blobs_loaded_; }

private:
    // Under mu_: the kept blobs' file read against the caps (n, each len, the sum) before its bytes; each blob's id
    // recomputed from the blob and kept only for a kept row of that id. A file that does not decode is moved aside to
    // `<file>.corrupt-<unix s>` (-2, -3 ... if taken; nothing deleted) and the node starts with no kept blobs.
    void load_kept_blobs_locked(std::string& why, std::uint64_t unix_s) {
        const std::string path = blobs_path();
        std::error_code ec;
        if (!std::filesystem::exists(path, ec)) return;
        const std::uintmax_t size = std::filesystem::file_size(path, ec);
        const std::uint64_t max_file = 4 + alt_max_blocks_ * (kHashBytes + 4) + alt_max_bytes_;
        std::optional<std::map<Hash32, std::vector<std::uint8_t>>> t;
        if (!ec && size <= max_file) {
            std::ifstream f(path, std::ios::binary);
            std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
            if (f && f.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size)))
                t = decode_kept_blobs(bytes, alt_max_blocks_, alt_max_bytes_);
        }
        if (!t) {
            std::string aside = path + ".corrupt-" + std::to_string(unix_s);
            for (int k = 2; std::filesystem::exists(aside, ec) && k < 1000; ++k)
                aside = path + ".corrupt-" + std::to_string(unix_s) + "-" + std::to_string(k);
            std::filesystem::rename(path, aside, ec);
            why += std::string(why.empty() ? "" : "; ") + "kept blobs " + path + " do not decode: moved aside to " + aside +
                   "; no kept blobs";
            return;
        }
        std::size_t kept = 0, skipped = 0;
        for (auto& [id, blob] : *t) {
            const std::optional<Hash32> own = kept_blob_id(blob);
            if (!own || *own != id || kept_.count(id) == 0) {
                ++skipped;
                continue;
            }
            kept_blobs_[id] = std::move(blob);
            ++kept;
        }
        if (skipped > 0)
            why += std::string(why.empty() ? "" : "; ") + "kept blobs: " + std::to_string(skipped) +
                   " not kept (id not its own, or no kept row)";
        kept_blobs_loaded_ = kept;
    }

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
    std::size_t alt_max_blocks_ = ::c2pool::xmr::native::ChainIndexOptions{}.alt_max_blocks;
    std::uint64_t alt_max_bytes_ = ::c2pool::xmr::native::ChainIndexOptions{}.alt_max_bytes;
    std::map<Hash32, std::vector<std::uint8_t>> kept_blobs_;  // kept alternative blocks' blobs from before a restart
    std::size_t kept_blobs_loaded_ = 0;
    std::uint64_t recorded_ = 0;
    std::size_t loaded_ = 0;
};

// The Monero context a node serves (FB_GETCTX): a block its index holds (a connected body, or a PoW-checked
// alternative), else a kept alternative block's blob from before a restart (kept_blob).
inline std::function<bool(const Hash32&, std::vector<std::uint8_t>&)> served_ctx_blob(
        std::function<bool(const Hash32&, std::vector<std::uint8_t>&)> held, const PathbFollowerRows* rows) {
    return [held = std::move(held), rows](const Hash32& id, std::vector<std::uint8_t>& out) {
        if (held && held(id, out)) return true;
        return rows != nullptr && rows->kept_blob(id, out);
    };
}

}  // namespace c2pool::xmr::pathb
