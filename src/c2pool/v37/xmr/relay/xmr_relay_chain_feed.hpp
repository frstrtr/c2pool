// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_relay_chain_feed.hpp   (D6b)
//
// THE RELAY'S CHAIN VIEW FEED, FROM THE NATIVE INDEX.
//
// The receipt relay resolves a peer receipt's prev_id to (bin height, RandomX
// seed) through relay::ChainView. Under --arm-order daemon-first the view is
// fed from monerod: once per new tip ONE get_block_headers_range over the last
// 128 blocks (+ get_block_header_by_height for a RandomX seed block not in the
// window). Under p2p-first that arm is switched off (no daemon on the
// chain-view path).
//
// This feed is the p2p-first replacement. It runs the daemon arm's body --
// same window, same seed rule, same notes -- over a NativeFeedSource, which
// main binds to the embedded native node's chain index. Nothing in it calls a
// daemon; the monerod path stays as an optional COMPARE-ONLY oracle in main
// (it counts, it never decides).
//
// Receipt CONTEXT (the block blob behind our own wants and a peer's
// FB_GETCTX) is NOT served here: RC-CTX's NativeCtxFeeder::serve
// (xmr_relay_native_ctx.hpp) is the one place that serves it, from the
// native node's retained bodies and held alternatives.
//
// Differences from the daemon arm, all additive (a note is idempotent):
//   * it re-ingests on a tip-ID change, not only on a best-HEIGHT change, so a
//     same-height reorg re-notes the new branch instead of waiting for the
//     next height;
//   * a seed block the index does not hold is a counted miss, never a fetch.
//
// Threading: main thread only (like the daemon arm it replaces).
// SCOPE FENCE: consumer tree. No consensus digest; src/sharechain/v37 untouched.
// ===========================================================================
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_seedheight.hpp"

namespace c2pool::v37n::xmr::relay {

using FeedId = std::array<std::uint8_t, 32>;

// What the feed reads. main binds every member to the native chain index
// (o2::NativeChainSource); a KAT binds scripted chains. All optional-returning
// members answer nullopt for "not held" -- never a guess.
struct NativeFeedSource {
    // (height, id) of the best-chain tip, or nullopt while the index is empty.
    std::function<std::optional<std::pair<std::uint64_t, FeedId>>()> tip;
    // The id the best chain carries at `height`, or nullopt (not retained).
    std::function<std::optional<FeedId>(std::uint64_t height)> id_at;
    // The RandomX seed id for a block AT `height` (= the id at
    // rx_seedheight(height); the index keeps epoch ids beyond its row window).
    std::function<std::optional<FeedId>(std::uint64_t height)> seed_for;

    explicit operator bool() const noexcept {
        return static_cast<bool>(tip) && static_cast<bool>(id_at) && static_cast<bool>(seed_for);
    }
};

// Where the notes go (main: relay::ChainView::note / note_seed).
struct FeedSink {
    std::function<void(const FeedId& prev_id, std::uint64_t height, const FeedId& seed)> note;
    std::function<void(std::uint64_t seed_height, const FeedId& seed)> note_seed;
};

struct NativeFeedStats {
    std::uint64_t tips = 0;          // tip changes ingested
    std::uint64_t reorg_tips = 0;    // ... of which replaced a tip at the same or a lower height
    std::uint64_t headers = 0;       // window headers noted
    std::uint64_t seed_miss = 0;     // a window header skipped: its seed block is not held
    std::uint64_t row_miss = 0;      // a window height the index did not answer
};

class NativeRelayChainFeed {
public:
    static constexpr std::uint64_t kWindow = 128;   // == the daemon arm's window

    // Once per main-loop tick. Returns true when a new tip was ingested.
    bool tick(const NativeFeedSource& src, const FeedSink& sink) {
        if (!src) return false;
        const auto t = src.tip();
        if (!t) return false;
        const auto [best, tip_id] = *t;
        if (best == 0) return false;
        if (m_have_tip && best == m_best && tip_id == m_tip_id) return false;
        if (m_have_tip && best <= m_best) ++m_stats.reorg_tips;
        m_have_tip = true; m_best = best; m_tip_id = tip_id;
        ++m_stats.tips;
        const std::uint64_t lo = best > kWindow ? best - kWindow : 0;
        for (std::uint64_t h = lo; h <= best; ++h) {
            const auto id = src.id_at(h);
            if (!id) { ++m_stats.row_miss; continue; }
            const std::uint64_t sh = ::xmr::coin::rx_seedheight(h + 1);
            const auto seed = src.seed_for(h + 1);
            if (!seed) { ++m_stats.seed_miss; continue; }
            if (sink.note) sink.note(*id, h + 1, *seed);
            if (sink.note_seed) sink.note_seed(sh, *seed);
            ++m_stats.headers;
        }
        return true;
    }

    const NativeFeedStats& stats() const noexcept { return m_stats; }
    std::uint64_t best() const noexcept { return m_best; }

private:
    bool            m_have_tip = false;
    std::uint64_t   m_best = 0;
    FeedId          m_tip_id{};
    NativeFeedStats m_stats;
};

// The compare-only oracle's verdict for one window: the native feed's
// (height -> id) against monerod's get_block_headers_range answer.
struct FeedCompare {
    std::uint64_t equal = 0, mismatch = 0, native_only = 0, monerod_only = 0;
};
inline FeedCompare compare_windows(const std::map<std::uint64_t, FeedId>& native,
                                   const std::map<std::uint64_t, FeedId>& monerod) {
    FeedCompare c;
    for (const auto& [h, id] : native) {
        const auto it = monerod.find(h);
        if (it == monerod.end()) ++c.native_only;
        else if (it->second == id) ++c.equal;
        else ++c.mismatch;
    }
    for (const auto& [h, id] : monerod) if (!native.count(h)) ++c.monerod_only;
    return c;
}

} // namespace c2pool::v37n::xmr::relay
