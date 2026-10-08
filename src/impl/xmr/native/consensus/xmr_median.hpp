// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/consensus/xmr_median.hpp
//
// The MEDIAN, exactly as monerod computes it, and a rolling window that can
// produce one over 100 000 entries on every block without sorting 100 000
// entries on every block.
//
// Three medians are consensus-relevant to this node: the 100-block short-term
// weight median, the 100 000-block long-term weight median, and the 60-block
// timestamp median. All three go through this file, so there is exactly one
// definition of "median" in the native tree.
//
// MONEROD'S DEFINITION, WHICH IS NOT THE OBVIOUS ONE (epee misc_language.h):
//
//     empty        -> 0
//     one element  -> that element
//     odd  size n  -> sorted[n/2]
//     even size n  -> get_mid(sorted[n/2 - 1], sorted[n/2])
//
// and get_mid is not (a+b)/2 -- it is the overflow-safe spelling
//
//     a/2 + b/2 + ((a - 2*(a/2)) + (b - 2*(b/2))) / 2
//
// which equals floor((a+b)/2) without ever forming a+b. For weights and
// timestamps the two agree, and they are written out here anyway: this is
// consensus arithmetic, and "it can't overflow in practice" is the kind of
// reasoning that makes a node fork three years later.
//
// THE ROLLING WINDOW. monerod keeps a rolling-median heap (epee
// rolling_median.h) beside the database precisely because re-reading 100 000
// weights per block is not viable. The window here is an ORDERED HISTOGRAM
// (value -> count) plus the value sequence, which gives the same answer with a
// much simpler invariant: insert and erase are O(log distinct), the median is
// one walk over distinct values, and -- the property the heap does not have --
// it can be rolled BACKWARDS, which is what a reorg needs.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <vector>

namespace c2pool::xmr::native {

// epee::misc_utils::get_mid, verbatim in intent: floor((a+b)/2), no sum formed.
inline constexpr std::uint64_t median_get_mid(std::uint64_t a, std::uint64_t b) noexcept {
    return (a / 2) + (b / 2) + ((a - 2 * (a / 2)) + (b - 2 * (b / 2))) / 2;
}

// epee::misc_utils::median over a copy of the values. Used where the window is
// small (the 100-block and 60-block ones) or in tests as the reference the
// rolling window must reproduce.
inline std::uint64_t median_of(std::vector<std::uint64_t> v) {
    if (v.empty()) return 0;
    if (v.size() == 1) return v[0];
    const std::size_t n = v.size() / 2;
    std::sort(v.begin(), v.end());
    if (v.size() % 2) return v[n];
    return median_get_mid(v[n - 1], v[n]);
}

// ---------------------------------------------------------------------------
// A fixed-capacity window of unsigned values with a median in O(distinct) and
// exact rollback.
//
// `push` appends and evicts the oldest when the window is full; the evicted
// value is returned so a caller that must restore it on rollback can keep it.
// `pop_back` removes the newest and, given the value that fell out of the far
// end when it was pushed, restores the window exactly as it was.
// ---------------------------------------------------------------------------
class MedianWindow {
public:
    MedianWindow() = default;
    explicit MedianWindow(std::size_t capacity) : cap_(capacity) {}

    void set_capacity(std::size_t capacity) { cap_ = capacity; trim_(); }
    std::size_t capacity() const noexcept { return cap_; }
    std::size_t size()     const noexcept { return values_.size(); }
    bool        empty()    const noexcept { return values_.empty(); }
    bool        full()     const noexcept { return cap_ && values_.size() >= cap_; }

    void clear() { values_.clear(); hist_.clear(); }

    // Appends `v`. If that pushed a value out of the window, writes it to
    // `evicted` and returns true; otherwise returns false.
    bool push(std::uint64_t v, std::uint64_t& evicted) {
        add_(v);
        values_.push_back(v);
        if (cap_ && values_.size() > cap_) {
            evicted = values_.front();
            values_.pop_front();
            remove_(evicted);
            return true;
        }
        return false;
    }

    void push(std::uint64_t v) {
        std::uint64_t ignored = 0;
        (void)push(v, ignored);
    }

    // Removes the newest value. `restore` is the value that `push` evicted when
    // this element went in, and `had_eviction` says whether there was one --
    // exactly the pair `push` returned. Returns false if the window is empty.
    bool pop_back(bool had_eviction, std::uint64_t restore) {
        if (values_.empty()) return false;
        const std::uint64_t back = values_.back();
        values_.pop_back();
        remove_(back);
        if (had_eviction) {
            values_.push_front(restore);
            add_(restore);
        }
        return true;
    }

    // monerod's median over the window's current contents.
    std::uint64_t median() const {
        const std::size_t n = values_.size();
        if (n == 0) return 0;
        if (n == 1) return values_.front();
        const std::size_t mid = n / 2;
        if (n % 2) return nth_(mid);
        return median_get_mid(nth_(mid - 1), nth_(mid));
    }

    // The window's contents, oldest first. For KATs and for the anchor writer.
    std::vector<std::uint64_t> values() const {
        return std::vector<std::uint64_t>(values_.begin(), values_.end());
    }

    std::uint64_t newest() const { return values_.empty() ? 0 : values_.back(); }
    std::uint64_t oldest() const { return values_.empty() ? 0 : values_.front(); }

private:
    void add_(std::uint64_t v) { ++hist_[v]; }

    void remove_(std::uint64_t v) {
        const auto it = hist_.find(v);
        if (it == hist_.end()) return;      // cannot happen; never corrupt on it
        if (--it->second == 0) hist_.erase(it);
    }

    // The k-th smallest (0-based) by walking the ordered histogram.
    std::uint64_t nth_(std::size_t k) const {
        std::size_t seen = 0;
        for (const auto& kv : hist_) {
            seen += static_cast<std::size_t>(kv.second);
            if (k < seen) return kv.first;
        }
        return values_.empty() ? 0 : values_.back();
    }

    void trim_() {
        while (cap_ && values_.size() > cap_) {
            remove_(values_.front());
            values_.pop_front();
        }
    }

    std::size_t                          cap_ = 0;   // 0 = unbounded
    std::deque<std::uint64_t>            values_;
    std::map<std::uint64_t, std::uint64_t> hist_;    // value -> count
};

} // namespace c2pool::xmr::native
