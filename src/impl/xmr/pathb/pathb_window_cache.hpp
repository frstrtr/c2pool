// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_window_cache.hpp
// Path B, slice S3b-1b: the (tip, v) window cache and the WindowAt it fills for
// the coinbase check (admission #12) and the roots (#13). [C38, C41]
//
//   WindowCache   key (tip id, v = hf(h(r))) -> the evaluated window(t, v), its
//                 window_root, sum and mmr_root_at(t). A DEFER is returned and
//                 never stored. LRU by bytes.
//   window_at(w)  WindowAt{window, tip, v, window_root, mmr_root}; no window
//                 (a DEFER) -> window nullptr.
//
// Policy P-35 (ruling 23): budget default 64 MB, flag --pathb-window-cache-mb;
// a miss recomputes, the final verdict does not depend on the budget.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <string_view>
#include <tuple>
#include <utility>

#include "pathb_coinbase_split.hpp"  // WindowAt
#include "pathb_window_chain.hpp"

namespace c2pool::xmr::pathb {

inline constexpr std::size_t kWindowCacheBytesDefault = std::size_t{64} << 20;
inline constexpr std::string_view kWindowCacheFlag = "--pathb-window-cache-mb";

// The WindowAt of an evaluated window (bound to its tip and v).
inline WindowAt window_at(const TipWindow& w) {
    WindowAt at;
    at.window = w.ok() ? w.window.get() : nullptr;
    at.tip = w.tip;
    at.v = w.v;
    at.window_root = w.window_root;
    at.mmr_root = w.mmr_root;
    return at;
}

class WindowCache {
public:
    explicit WindowCache(std::size_t budget_bytes = kWindowCacheBytesDefault) : budget_(budget_bytes) {}

    // window(tip, v): a hit returns the stored evaluation; a miss runs
    // compute() (-> TipWindow for (tip, v)) and stores it when evaluated.
    template <class Compute>
    TipWindow get(const Hash32& tip, std::uint8_t v, Compute&& compute) {
        const Key key{tip, v};
        if (auto it = map_.find(key); it != map_.end()) {
            lru_.splice(lru_.begin(), lru_, it->second.lru);
            ++hits_;
            return it->second.w;
        }
        ++computations_;
        TipWindow w = compute();
        if (w.ok() && w.tip == tip && w.v == v) insert(key, w);
        return w;
    }

    std::uint64_t computations() const noexcept { return computations_; }
    std::uint64_t hits() const noexcept { return hits_; }
    std::size_t bytes() const noexcept { return bytes_; }
    std::size_t entries() const noexcept { return map_.size(); }
    std::size_t budget() const noexcept { return budget_; }

    // Bytes charged for an entry: the entry, one map node per payee and the rows.
    static std::size_t entry_bytes(const Window& w) noexcept {
        constexpr std::size_t kMapNode = sizeof(std::pair<const Hash32, Work>) + 4 * sizeof(void*);
        return sizeof(Entry) + sizeof(Key) + sizeof(Window) + w.weight.size() * kMapNode
               + w.rows.size() * sizeof(BucketRow);
    }

private:
    struct Key {
        Hash32 tip{};
        std::uint8_t v = 0;

        friend bool operator<(const Key& a, const Key& b) { return std::tie(a.tip, a.v) < std::tie(b.tip, b.v); }
    };
    struct Entry {
        TipWindow w;
        std::size_t bytes = 0;
        std::list<Key>::iterator lru;
    };

    void insert(const Key& key, const TipWindow& w) {
        Entry e;
        e.w = w;
        e.bytes = w.window != nullptr ? entry_bytes(*w.window) : sizeof(Entry) + sizeof(Key);
        if (e.bytes > budget_) return;  // larger than the whole budget: not kept
        while (bytes_ + e.bytes > budget_ && !lru_.empty()) {
            auto it = map_.find(lru_.back());
            bytes_ -= it->second.bytes;
            lru_.pop_back();
            map_.erase(it);
        }
        lru_.push_front(key);
        e.lru = lru_.begin();
        bytes_ += e.bytes;
        map_.emplace(key, std::move(e));
    }

    std::size_t budget_;
    std::size_t bytes_ = 0;
    std::uint64_t computations_ = 0;
    std::uint64_t hits_ = 0;
    std::map<Key, Entry> map_;
    std::list<Key> lru_;  // most recent first
};

}  // namespace c2pool::xmr::pathb
