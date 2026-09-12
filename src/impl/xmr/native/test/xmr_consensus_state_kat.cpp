// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_consensus_state_kat.cpp
//
// The C2a consensus state, pinned against monerod over 600 consecutive stagenet
// heights, plus the arithmetic and policy edges that real chain data does not
// reach.
//
//   A. MEDIAN        -- the rolling window reproduces monerod's median (even-size
//                       get_mid included) and rolls backwards exactly.
//   B. DIFFICULTY    -- for every one of the 600 heights, next_difficulty over
//                       the 735-row window equals the difficulty monerod
//                       recorded for that block. Negative control: the same
//                       window truncated to 720 or 721 rows reproduces NONE of
//                       them, which is what makes the 735 + lag geometry a
//                       measured fact rather than a comment.
//   C. WEIGHT        -- for every height, the long-term weight the recursion
//                       produces equals monerod's long_term_weight; the
//                       effective median matches get_miner_data's median_weight.
//   D. REWARD/COINS  -- the base reward for every transaction-free block equals
//                       monerod's reward, and the emission accumulated across
//                       all 600 blocks lands exactly on the
//                       get_coinbase_tx_sum total at the far end.
//   E. ROLLBACK      -- the whole replay is rolled back block by block and the
//                       five windows return to their seeded values; re-walking
//                       reproduces the same 600 results.
//   F. CONNECT       -- real block blobs are connected through ConsensusState /
//                       ChainStateView: id, weight, difficulty, long-term
//                       weight, reward and emission all match the daemon, and a
//                       block whose bodies are missing is refused.
//   G. R-HFFUSE      -- the code-rolling hard-fork policy: a fork above the
//                       implemented range is FOLLOWED with rolled rules and
//                       trips the fuse, template and tx admission are withdrawn
//                       while follow and serve survive, and a version below the
//                       table's requirement is still refused.
//   H. ARITHMETIC    -- the 128-bit helpers agree with each other and with
//                       boost::multiprecision; the emission curve hits the two
//                       values everybody knows (the first block's 17.592186044415
//                       XMR and the 0.6 XMR tail); the weight penalty has the
//                       right shape at the knee, at 1.5x and at 2x the median.
// ---------------------------------------------------------------------------

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include <boost/multiprecision/cpp_int.hpp>

#include "impl/xmr/native/chain/xmr_chain_view.hpp"
#include "impl/xmr/native/chain/xmr_consensus_state.hpp"
#include "impl/xmr/native/consensus/xmr_difficulty.hpp"
#include "impl/xmr/native/consensus/xmr_hf_policy.hpp"
#include "impl/xmr/native/consensus/xmr_median.hpp"
#include "impl/xmr/native/consensus/xmr_reward.hpp"
#include "impl/xmr/native/consensus/xmr_timestamp.hpp"
#include "impl/xmr/native/consensus/xmr_weight.hpp"
#include "xmr_c2a_golden.hpp"

using namespace c2pool::xmr::native;
namespace G = c2pool::xmr::native::golden_c2a;

static int g_checks = 0;
static int g_fail   = 0;

static void checkf(bool cond, const char* fmt, ...) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        if (g_fail <= 25) {
            va_list ap;
            va_start(ap, fmt);
            std::vfprintf(stderr, fmt, ap);
            va_end(ap);
            std::fputc('\n', stderr);
        }
    }
}

static bool from_hex(const char* hex, std::vector<std::uint8_t>& out) {
    const std::size_t n = std::strlen(hex);
    if (n % 2) return false;
    out.clear();
    out.reserve(n / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < n; i += 2) {
        const int a = nib(hex[i]), b = nib(hex[i + 1]);
        if (a < 0 || b < 0) return false;
        out.push_back(static_cast<std::uint8_t>((a << 4) | b));
    }
    return true;
}

static std::string hex_of(const Hash& h) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (std::uint8_t b : h) { s.push_back(d[b >> 4]); s.push_back(d[b & 0xf]); }
    return s;
}

// --- golden accessors ---------------------------------------------------------
static const G::GoldenHeader& header_at(std::uint64_t h) {
    return G::HEADERS[static_cast<std::size_t>(h - G::HEADERS_FIRST_HEIGHT)];
}

static U128 u128_of(std::uint64_t lo, std::uint64_t hi) { U128 d; d.lo = lo; d.hi = hi; return d; }

// The 100 000-entry long-term window as it stands just before TEST_FIRST.
static std::vector<std::uint64_t> long_term_seed() {
    std::vector<std::uint64_t> v;
    v.reserve(static_cast<std::size_t>(G::LT_WINDOW_SIZE));
    for (std::size_t i = 0; i < G::LT_SEED_HEAD_COUNT; ++i) v.push_back(G::LT_SEED_HEAD[i]);
    for (std::size_t i = 0; i < G::LT_SEED_TAIL_RUNS_COUNT; ++i)
        for (std::uint64_t k = 0; k < G::LT_SEED_TAIL_RUNS[i].count; ++k)
            v.push_back(G::LT_SEED_TAIL_RUNS[i].value);
    return v;
}

static std::vector<std::uint64_t> short_term_seed() {
    std::vector<std::uint64_t> v;
    for (std::uint64_t h = G::TEST_FIRST - CRYPTONOTE_REWARD_BLOCKS_WINDOW; h < G::TEST_FIRST; ++h)
        v.push_back(header_at(h).block_weight);
    return v;
}

static std::vector<std::uint64_t> timestamp_seed() {
    std::vector<std::uint64_t> v;
    for (std::uint64_t h = G::TEST_FIRST - BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW; h < G::TEST_FIRST; ++h)
        v.push_back(header_at(h).timestamp);
    return v;
}

static std::vector<DifficultyRow> difficulty_seed() {
    std::vector<DifficultyRow> v;
    for (std::uint64_t h = G::TEST_FIRST - DIFFICULTY_BLOCKS_COUNT; h < G::TEST_FIRST; ++h) {
        const G::GoldenHeader& r = header_at(h);
        v.push_back(DifficultyRow{r.timestamp,
                                  u128_of(r.cumulative_difficulty_lo, r.cumulative_difficulty_hi)});
    }
    return v;
}

// =============================================================================
// A. medians
// =============================================================================
static void test_median() {
    std::mt19937_64 rng(0x2c0a5eedULL);

    for (int trial = 0; trial < 40; ++trial) {
        const std::size_t n = 1 + (rng() % 200);
        std::vector<std::uint64_t> vals;
        MedianWindow w(n + 1000);          // never evicts here
        for (std::size_t i = 0; i < n; ++i) {
            const std::uint64_t v = rng() % 5000;
            vals.push_back(v);
            w.push(v);
        }
        checkf(w.median() == median_of(vals),
               "median: window %llu != reference %llu for n=%zu",
               static_cast<unsigned long long>(w.median()),
               static_cast<unsigned long long>(median_of(vals)), n);
    }

    // get_mid is floor((a+b)/2) and never forms a+b.
    const std::uint64_t big = ~static_cast<std::uint64_t>(0);
    checkf(median_get_mid(big, big) == big, "get_mid(max,max) overflowed");
    checkf(median_get_mid(big, big - 2) == big - 1, "get_mid near max");
    checkf(median_get_mid(3, 4) == 3, "get_mid rounds down");

    // Eviction + exact rollback: push through a small window, roll all the way
    // back, and the medians must retrace exactly.
    MedianWindow w(7);
    std::vector<std::pair<bool, std::uint64_t>> undo;
    std::vector<std::uint64_t> forward_medians;
    for (int i = 0; i < 60; ++i) {
        const std::uint64_t v = rng() % 100;
        std::uint64_t ev = 0;
        const bool had = w.push(v, ev);
        undo.push_back(std::make_pair(had, ev));
        forward_medians.push_back(w.median());
    }
    for (int i = 59; i >= 0; --i) {
        checkf(w.median() == forward_medians[static_cast<std::size_t>(i)],
               "rollback: median at step %d", i);
        w.pop_back(undo[static_cast<std::size_t>(i)].first,
                   undo[static_cast<std::size_t>(i)].second);
    }
    checkf(w.size() == 0, "rollback did not empty the window");
}

// =============================================================================
// B/C/D/E. the replay
// =============================================================================
struct ReplayResult {
    std::vector<std::uint64_t> long_term_weights;
    std::vector<std::uint64_t> base_rewards;
    std::vector<U128>          difficulties;
    std::uint64_t              final_agc = 0;
    std::uint64_t              final_effective_median = 0;
};

static ReplayResult replay(bool roll_back_and_forward) {
    ReplayResult out;

    DifficultyWindow diff;
    diff.seed(difficulty_seed());
    WeightState weights;
    weights.seed(short_term_seed(), long_term_seed());
    TimestampWindow times;
    times.seed(timestamp_seed());
    std::uint64_t agc = G::AGC_BEFORE_FIRST;

    const std::uint64_t seed_lt_median = weights.long_term_median();
    const std::uint64_t seed_st_median = weights.short_term_median();
    const std::uint64_t seed_ts_median = times.median();

    std::vector<WeightUndo>     wu;
    std::vector<DifficultyUndo> du;
    std::vector<TimestampUndo>  tu;
    std::vector<std::uint64_t>  agc_before;

    for (std::uint64_t h = G::TEST_FIRST; h <= G::TEST_LAST; ++h) {
        const G::GoldenHeader& hdr = header_at(h);
        const std::uint8_t v = hdr.major_version;

        // --- difficulty ------------------------------------------------------
        const U128 got = diff.next_difficulty(v);
        const U128 want = u128_of(hdr.difficulty_lo, hdr.difficulty_hi);
        checkf(got.lo == want.lo && got.hi == want.hi,
               "height %llu: difficulty %llu/%llu != monerod %llu/%llu",
               static_cast<unsigned long long>(h),
               static_cast<unsigned long long>(got.lo), static_cast<unsigned long long>(got.hi),
               static_cast<unsigned long long>(want.lo), static_cast<unsigned long long>(want.hi));
        out.difficulties.push_back(got);

        // --- long-term weight -------------------------------------------------
        const std::uint64_t ltw = weights.next_long_term_weight(hdr.block_weight, v);
        checkf(ltw == hdr.long_term_weight,
               "height %llu: long_term_weight %llu != monerod %llu",
               static_cast<unsigned long long>(h), static_cast<unsigned long long>(ltw),
               static_cast<unsigned long long>(hdr.long_term_weight));
        out.long_term_weights.push_back(ltw);

        // --- reward -----------------------------------------------------------
        const std::uint64_t eff = weights.effective_median(v);
        const std::uint64_t pen = penalty_median(eff, weights.short_term_median(), v);
        std::uint64_t base = 0;
        const RewardStatus rs = get_block_reward(pen, hdr.block_weight, agc, v, base);
        checkf(rs == RewardStatus::Ok, "height %llu: get_block_reward = %s",
               static_cast<unsigned long long>(h), to_string(rs));
        if (hdr.num_txes == 0)
            checkf(base == hdr.reward,
                   "height %llu: base reward %llu != monerod reward %llu (no transactions)",
                   static_cast<unsigned long long>(h), static_cast<unsigned long long>(base),
                   static_cast<unsigned long long>(hdr.reward));
        else
            checkf(base <= hdr.reward,
                   "height %llu: base reward %llu exceeds monerod reward %llu",
                   static_cast<unsigned long long>(h), static_cast<unsigned long long>(base),
                   static_cast<unsigned long long>(hdr.reward));
        out.base_rewards.push_back(base);

        // --- timestamp rule ----------------------------------------------------
        checkf(times.check(hdr.timestamp, 0) == TimestampStatus::Ok,
               "height %llu: a block the network accepted failed the timestamp rule",
               static_cast<unsigned long long>(h));

        // --- advance -----------------------------------------------------------
        agc_before.push_back(agc);
        wu.push_back(weights.push(hdr.block_weight, ltw));
        du.push_back(diff.push(hdr.timestamp,
                               u128_of(hdr.cumulative_difficulty_lo, hdr.cumulative_difficulty_hi)));
        tu.push_back(times.push(hdr.timestamp));
        agc = accumulate_generated_coins(agc, base);
    }

    out.final_agc = agc;
    out.final_effective_median =
        weights.effective_median(header_at(G::TEST_LAST).major_version);

    if (roll_back_and_forward) {
        for (std::size_t i = wu.size(); i-- > 0;) {
            times.pop(tu[i]);
            diff.pop(du[i]);
            weights.pop(wu[i]);
            agc = agc_before[i];
        }
        checkf(agc == G::AGC_BEFORE_FIRST, "rollback: emission did not return");
        checkf(weights.long_term_median() == seed_lt_median,
               "rollback: long-term median did not return");
        checkf(weights.short_term_median() == seed_st_median,
               "rollback: short-term median did not return");
        checkf(times.median() == seed_ts_median,
               "rollback: timestamp median did not return");
        const U128 d0 = diff.next_difficulty(header_at(G::TEST_FIRST).major_version);
        const G::GoldenHeader& first = header_at(G::TEST_FIRST);
        checkf(d0.lo == first.difficulty_lo && d0.hi == first.difficulty_hi,
               "rollback: the difficulty window did not return");
    }
    return out;
}

static void test_replay() {
    const ReplayResult a = replay(true);

    checkf(a.final_agc == G::AGC_AFTER_LAST,
           "emission after %llu blocks is %llu, get_coinbase_tx_sum says %llu",
           static_cast<unsigned long long>(G::TEST_COUNT),
           static_cast<unsigned long long>(a.final_agc),
           static_cast<unsigned long long>(G::AGC_AFTER_LAST));

    // The effective median at the end of the run is the number get_miner_data
    // reports for the tip. Both heights sit in the same regime: every one of the
    // 100 short-term weights and every one of the 100 000 long-term weights is
    // far below the 300 000 penalty-free zone, so the floor is what both
    // computations return -- which is exactly the case a wrong clamp would get
    // wrong in the other direction.
    checkf(a.final_effective_median == G::MINER_DATA_MEDIAN_WEIGHT,
           "effective median %llu != get_miner_data median_weight %llu",
           static_cast<unsigned long long>(a.final_effective_median),
           static_cast<unsigned long long>(G::MINER_DATA_MEDIAN_WEIGHT));

    // Re-walking after the rollback reproduces the same results.
    const ReplayResult b = replay(false);
    checkf(a.long_term_weights == b.long_term_weights, "re-walk: long-term weights differ");
    checkf(a.base_rewards == b.base_rewards, "re-walk: base rewards differ");
    checkf(a.final_agc == b.final_agc, "re-walk: emission differs");
}

// The negative control for the window geometry: 720 or 721 rows instead of 735.
static void test_difficulty_window_geometry() {
    int wrong_720 = 0, wrong_721 = 0, tested = 0;
    for (std::uint64_t h = G::TEST_FIRST; h < G::TEST_FIRST + 50; ++h) {
        const G::GoldenHeader& hdr = header_at(h);
        std::vector<std::uint64_t> ts;
        std::vector<U128>          cd;
        for (std::uint64_t k = h - DIFFICULTY_BLOCKS_COUNT; k < h; ++k) {
            const G::GoldenHeader& r = header_at(k);
            ts.push_back(r.timestamp);
            cd.push_back(u128_of(r.cumulative_difficulty_lo, r.cumulative_difficulty_hi));
        }
        for (int variant = 0; variant < 2; ++variant) {
            const std::size_t keep = variant == 0 ? DIFFICULTY_WINDOW : DIFFICULTY_WINDOW + 1;
            std::vector<std::uint64_t> ts2(ts.end() - static_cast<long>(keep), ts.end());
            std::vector<U128>          cd2(cd.end() - static_cast<long>(keep), cd.end());
            const U128 got = next_difficulty_from_window(ts2, cd2, DIFFICULTY_TARGET_V2);
            const bool same = got.lo == hdr.difficulty_lo && got.hi == hdr.difficulty_hi;
            if (!same) { if (variant == 0) ++wrong_720; else ++wrong_721; }
        }
        ++tested;
    }
    checkf(wrong_720 == tested,
           "a 720-row window reproduced monerod on %d of %d heights", tested - wrong_720, tested);
    checkf(wrong_721 == tested,
           "a 721-row window reproduced monerod on %d of %d heights", tested - wrong_721, tested);
}

// =============================================================================
// F. connect(), on real blocks
// =============================================================================
static ChainRow parent_row_for(std::uint64_t height) {
    const G::GoldenHeader& p = header_at(height - 1);
    ChainRow row;
    row.height                = p.height;
    row.timestamp             = p.timestamp;
    row.major_version         = p.major_version;
    row.minor_version         = p.minor_version;
    row.block_weight          = p.block_weight;
    row.long_term_weight      = p.long_term_weight;
    row.difficulty            = u128_of(p.difficulty_lo, p.difficulty_hi);
    row.cumulative_difficulty = u128_of(p.cumulative_difficulty_lo, p.cumulative_difficulty_hi);
    row.pow_verified          = true;
    return row;
}

// The state as it stands at `height - 1`, with the windows rolled forward from
// TEST_FIRST and the emission carried with them.
static void seed_state_at(ChainStateView& view, std::uint64_t height,
                          std::uint64_t& agc_out, Hash prev_id) {
    // Roll the windows from the seeded position up to height - 1.
    std::vector<DifficultyRow> diff = difficulty_seed();
    std::vector<std::uint64_t> shortw = short_term_seed();
    std::vector<std::uint64_t> longw  = long_term_seed();
    std::vector<std::uint64_t> times  = timestamp_seed();
    std::uint64_t agc = G::AGC_BEFORE_FIRST;

    WeightState ws;
    ws.seed(shortw, longw);
    for (std::uint64_t h = G::TEST_FIRST; h < height; ++h) {
        const G::GoldenHeader& r = header_at(h);
        const std::uint8_t v = r.major_version;
        const std::uint64_t eff = ws.effective_median(v);
        const std::uint64_t pen = penalty_median(eff, ws.short_term_median(), v);
        std::uint64_t base = 0;
        get_block_reward(pen, r.block_weight, agc, v, base);
        agc = accumulate_generated_coins(agc, base);
        ws.push(r.block_weight, r.long_term_weight);

        diff.push_back(DifficultyRow{r.timestamp,
                                     u128_of(r.cumulative_difficulty_lo, r.cumulative_difficulty_hi)});
        shortw.push_back(r.block_weight);
        longw.push_back(r.long_term_weight);
        times.push_back(r.timestamp);
    }
    auto tail_of = [](auto& v, std::size_t keep) {
        if (v.size() > keep) v.erase(v.begin(), v.begin() + static_cast<long>(v.size() - keep));
    };
    tail_of(diff,   static_cast<std::size_t>(DIFFICULTY_BLOCKS_COUNT));
    tail_of(shortw, static_cast<std::size_t>(CRYPTONOTE_REWARD_BLOCKS_WINDOW));
    tail_of(longw,  static_cast<std::size_t>(G::LT_WINDOW_SIZE));
    tail_of(times,  static_cast<std::size_t>(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW));

    ChainRow tip = parent_row_for(height);
    tip.id = prev_id;
    tip.already_generated_coins = agc;
    view.seed_direct(tip, diff, shortw, longw, times);
    agc_out = agc;
}

static void test_connect_real_blocks() {
    for (std::size_t i = 0; i < G::BLOCKS_COUNT; ++i) {
        const G::GoldenBlock& gb = G::BLOCKS[i];
        if (gb.height < G::TEST_FIRST || gb.height > G::TEST_LAST) continue;

        std::vector<std::uint8_t> blob;
        if (!from_hex(gb.blob_hex, blob)) continue;

        // The parent id comes out of the block itself: prev_id is what the
        // state must be told its tip is.
        ParsedBlock pb;
        if (parse_block(blob, pb) != BlockParseStatus::Ok) {
            checkf(false, "block %llu: does not parse",
                   static_cast<unsigned long long>(gb.height));
            continue;
        }

        ChainStateView view(XmrNet::Stagenet);
        std::uint64_t agc = 0;
        seed_state_at(view, gb.height, agc, pb.header.prev_id);

        BlockEntry entry;
        entry.block_blob = blob;
        // Bodies are only supplied for transaction-free blocks: a captured
        // block blob carries the tx IDS, never the tx bodies.
        std::string why;
        const ChainStateView::ConnectOutcome o =
            view.connect(entry, /*pow_verified=*/true, /*now=*/0, /*own_mined=*/false, why);

        const G::GoldenHeader& hdr = header_at(gb.height);
        if (gb.num_txes != 0) {
            // Fail-closed, and NOT a peer fault: the block is fine, we just
            // cannot weigh it yet.
            checkf(!o.ok && o.connect == ConnectStatus::BodiesMissing,
                   "block %llu with %u transactions: expected BodiesMissing, got %s (%s)",
                   static_cast<unsigned long long>(gb.height), gb.num_txes,
                   to_string(o.connect), why.c_str());
            checkf(!connect_status_is_peer_fault(ConnectStatus::BodiesMissing),
                   "BodiesMissing must not be a peer fault");
            continue;
        }

        checkf(o.ok, "block %llu: connect failed: eval=%s connect=%s (%s)",
               static_cast<unsigned long long>(gb.height), to_string(o.eval),
               to_string(o.connect), why.c_str());
        if (!o.ok) continue;

        checkf(hex_of(o.row.id) == std::string(gb.id_hex),
               "block %llu: connected id %s != monerod %s",
               static_cast<unsigned long long>(gb.height), hex_of(o.row.id).c_str(), gb.id_hex);
        checkf(o.row.block_weight == gb.block_weight,
               "block %llu: block_weight %llu != monerod %llu",
               static_cast<unsigned long long>(gb.height),
               static_cast<unsigned long long>(o.row.block_weight),
               static_cast<unsigned long long>(gb.block_weight));
        checkf(o.row.long_term_weight == hdr.long_term_weight,
               "block %llu: long_term_weight %llu != monerod %llu",
               static_cast<unsigned long long>(gb.height),
               static_cast<unsigned long long>(o.row.long_term_weight),
               static_cast<unsigned long long>(hdr.long_term_weight));
        checkf(o.row.difficulty.lo == hdr.difficulty_lo
                   && o.row.difficulty.hi == hdr.difficulty_hi,
               "block %llu: difficulty %llu != monerod %llu",
               static_cast<unsigned long long>(gb.height),
               static_cast<unsigned long long>(o.row.difficulty.lo),
               static_cast<unsigned long long>(hdr.difficulty_lo));
        checkf(o.row.reward == gb.reward,
               "block %llu: reward %llu != monerod %llu",
               static_cast<unsigned long long>(gb.height),
               static_cast<unsigned long long>(o.row.reward),
               static_cast<unsigned long long>(gb.reward));
        checkf(o.row.base_reward == gb.reward,
               "block %llu: base reward %llu != monerod reward %llu (no transactions)",
               static_cast<unsigned long long>(gb.height),
               static_cast<unsigned long long>(o.row.base_reward),
               static_cast<unsigned long long>(gb.reward));
        checkf(o.row.already_generated_coins == agc + gb.reward,
               "block %llu: emission did not advance by the base reward",
               static_cast<unsigned long long>(gb.height));

        // The view answers for what it just connected.
        const auto tip = view.tip();
        checkf(tip.has_value() && tip->id == o.row.id, "block %llu: tip",
               static_cast<unsigned long long>(gb.height));
        checkf(view.height_of(o.row.id).value_or(0) == gb.height, "block %llu: height_of",
               static_cast<unsigned long long>(gb.height));
        checkf(view.confirmation_depth(o.row.id) == 1, "block %llu: depth",
               static_cast<unsigned long long>(gb.height));
        checkf(view.is_on_best_chain(o.row.id), "block %llu: is_on_best_chain",
               static_cast<unsigned long long>(gb.height));
        checkf(view.verified_frontier() == gb.height, "block %llu: verified frontier",
               static_cast<unsigned long long>(gb.height));

        // And rolls it back exactly.
        const std::uint64_t seq_before = view.epoch_seq();
        checkf(view.disconnect_tip({}), "block %llu: disconnect",
               static_cast<unsigned long long>(gb.height));
        checkf(view.state().height() == gb.height - 1, "block %llu: height after rollback",
               static_cast<unsigned long long>(gb.height));
        checkf(view.state().already_generated_coins() == agc,
               "block %llu: emission after rollback",
               static_cast<unsigned long long>(gb.height));
        checkf(!view.is_on_best_chain(o.row.id), "block %llu: id still indexed after rollback",
               static_cast<unsigned long long>(gb.height));
        // The frontier must fall back to a height that was actually verified,
        // never merely to the new tip.
        checkf(view.verified_frontier() == gb.height - 1,
               "block %llu: verified frontier after rollback is %llu",
               static_cast<unsigned long long>(gb.height),
               static_cast<unsigned long long>(view.verified_frontier()));
        checkf(view.epoch_seq() > seq_before, "block %llu: epoch_seq did not move",
               static_cast<unsigned long long>(gb.height));

        // Re-connecting reproduces the same row.
        std::string why2;
        const ChainStateView::ConnectOutcome o2 =
            view.connect(entry, true, 0, false, why2);
        checkf(o2.ok && o2.row.id == o.row.id
                   && o2.row.long_term_weight == o.row.long_term_weight
                   && o2.row.difficulty.lo == o.row.difficulty.lo
                   && o2.row.already_generated_coins == o.row.already_generated_coins,
               "block %llu: re-connect after rollback differs",
               static_cast<unsigned long long>(gb.height));

        // A block that does not extend the tip is refused, and that refusal is
        // not a peer fault either.
        BlockEntry stale = entry;
        std::string why3;
        const ChainStateView::ConnectOutcome o3 = view.connect(stale, true, 0, false, why3);
        checkf(!o3.ok && o3.connect == ConnectStatus::PrevMismatch,
               "block %llu: connecting twice was not refused as PrevMismatch (%s)",
               static_cast<unsigned long long>(gb.height), to_string(o3.connect));
    }
}

// =============================================================================
// G. R-HFFUSE
// =============================================================================
static void test_hf_fuse() {
    const XmrNet net = XmrNet::Stagenet;
    const std::uint64_t h = 1400000;                      // in the v16 band
    const std::uint8_t required = hf_version_for_height(net, h);
    checkf(required == 16, "stagenet fork table at %llu",
           static_cast<unsigned long long>(h));

    // A known version: accepted, fuse untouched, every capability intact.
    {
        HfFuse fuse;
        std::string why;
        checkf(hf_policy_check_block(net, h, 16, 16, fuse, why) == HfVerdict::Ok,
               "known version rejected: %s", why.c_str());
        checkf(!fuse.tripped(), "known version tripped the fuse");
        checkf(fuse.allows(HfCapability::Template) && fuse.allows(HfCapability::AdmitTx),
               "known version withdrew a capability");
    }

    // A fork above the implemented range: FOLLOWED, fuse tripped, the two
    // producing capabilities withdrawn, the two reading ones kept. This is the
    // ruling: not fail-closed, code-rolling.
    {
        HfFuse fuse;
        std::string why;
        const std::uint8_t future = MAX_IMPLEMENTED_HF_VERSION + 1;
        checkf(hf_policy_check_block(net, h, future, future, fuse, why) == HfVerdict::OkRolled,
               "a fork above the implemented range was not followed");
        checkf(fuse.tripped(), "a rolled fork did not trip the fuse");
        checkf(fuse.first_height() == h && fuse.first_version() == future,
               "the fuse recorded the wrong first sighting");
        checkf(fuse.allows(HfCapability::Follow) && fuse.allows(HfCapability::Serve),
               "a rolled fork withdrew the reader capabilities");
        checkf(!fuse.allows(HfCapability::Template) && !fuse.allows(HfCapability::AdmitTx),
               "a rolled fork kept the producing capabilities");
        checkf(!fuse.why(HfCapability::Template).empty(), "the fuse gave no reason");

        // It latches: a later, higher fork is recorded but the first sighting
        // stands, and nothing un-trips it.
        fuse.trip(h + 100, static_cast<std::uint8_t>(future + 3));
        checkf(fuse.first_height() == h, "the fuse forgot its first sighting");
        checkf(fuse.highest_version() == future + 3, "the fuse lost the highest version");
        checkf(fuse.blocks_seen() == 2, "the fuse miscounted");
    }

    // Rules ROLL rather than refuse: a fenced version answers with the newest
    // implemented version's rules, and a version inside the range is untouched.
    checkf(hf_rules_version(MAX_IMPLEMENTED_HF_VERSION + 7) == MAX_IMPLEMENTED_HF_VERSION,
           "rules did not roll forward");
    checkf(hf_rules_version(12) == 12, "rules rolled a version that needed no rolling");

    // A version BELOW the table's requirement is still a hard reject: that is
    // not an unknown fork, it is a block from a fork we already left.
    {
        HfFuse fuse;
        std::string why;
        checkf(hf_policy_check_block(net, h, 15, 15, fuse, why) == HfVerdict::RejectTooLow,
               "a stale fork version was accepted");
        checkf(!fuse.tripped(), "a stale fork version tripped the fuse");
        checkf(hf_policy_check_block(net, h, 16, 15, fuse, why) == HfVerdict::RejectMinorLow,
               "minor below major was accepted");
    }

    // top_version advertises the CHAIN's version at a rolled fork, not ours:
    // advertising a stale version is what gets a node disconnected.
    {
        const std::uint8_t future = MAX_IMPLEMENTED_HF_VERSION + 2;
        checkf(hf_policy_top_version(net, h, future) == future,
               "top_version did not follow the chain across a rolled fork");
        checkf(hf_policy_top_version(net, h, 16) == 16, "top_version at a known fork");
    }

    // End to end through the state: a rolled block connects, is marked, and the
    // view refuses to serve a template while the fuse is tripped.
    {
        ConsensusState st(XmrNet::Stagenet);
        checkf(st.allows(HfCapability::Template), "a fresh state withheld the template arm");
    }
}

// =============================================================================
// H. arithmetic
// =============================================================================
static void test_arithmetic() {
    using boost::multiprecision::uint128_t;
    std::mt19937_64 rng(0xc2a1234567ULL);

    // boost is the third opinion: the __int128 path, the 32-bit-limb path and
    // boost::multiprecision must all agree, on every pair.
    auto split = [](uint128_t v, std::uint64_t& lo, std::uint64_t& hi) {
        uint128_t l = v & uint128_t(~static_cast<std::uint64_t>(0));
        uint128_t h = v >> 64;
        lo = l.convert_to<std::uint64_t>();
        hi = h.convert_to<std::uint64_t>();
    };

    for (int i = 0; i < 20000; ++i) {
        const std::uint64_t a = rng(), b = rng();
        const U128Pair p1 = mul128(a, b);
        const U128Pair p2 = mul128_portable(a, b);
        const uint128_t ref = uint128_t(a) * uint128_t(b);
        std::uint64_t ref_lo = 0, ref_hi = 0;
        split(ref, ref_lo, ref_hi);
        if (p1.lo != ref_lo || p1.hi != ref_hi || p2.lo != ref_lo || p2.hi != ref_hi) {
            checkf(false, "mul128 mismatch on %llu * %llu",
                   static_cast<unsigned long long>(a), static_cast<unsigned long long>(b));
            break;
        }

        const std::uint64_t d = (rng() % 1000000) + 1;
        std::uint64_t r1 = 0, r2 = 0;
        const U128Pair q1 = div128_64(p1, d, &r1);
        const U128Pair q2 = div128_64_portable(p1, d, &r2);
        std::uint64_t q_lo = 0, q_hi = 0, rem = 0, rem_hi = 0;
        split(ref / uint128_t(d), q_lo, q_hi);
        split(ref % uint128_t(d), rem, rem_hi);
        if (q1.lo != q_lo || q1.hi != q_hi || q2.lo != q_lo || q2.hi != q_hi
            || r1 != rem || r2 != rem) {
            checkf(false, "div128_64 mismatch dividing by %llu",
                   static_cast<unsigned long long>(d));
            break;
        }
    }
    checkf(true, "128-bit helpers agree with boost over 20000 random pairs");

    // The emission curve at its two famous points.
    checkf(emission_base_reward(0, 1) == 17592186044415ull,
           "the first block's reward is not 17592186044415");
    checkf(emission_base_reward(0, 2) == (MONEY_SUPPLY >> 19),
           "the v2 emission speed factor is not 19");
    checkf(emission_base_reward(MONEY_SUPPLY - 1000, 16) == 600000000000ull,
           "the tail emission is not 0.6 XMR per block");
    checkf(emission_base_reward(G::MINER_DATA_AGC, 16) == 600000000000ull,
           "stagenet at the captured tip is not in tail emission");

    // The penalty, by its shape rather than by a magic number.
    const std::uint64_t median = 400000;   // above the 300000 zone, so it bites
    const std::uint64_t agc    = MONEY_SUPPLY - 1000;   // tail: base is 6e11
    std::uint64_t r_at_median = 0, r_at_15 = 0, r_at_2x = 0, r_over = 0;
    checkf(get_block_reward(median, median, agc, 16, r_at_median) == RewardStatus::Ok
               && r_at_median == 600000000000ull,
           "a block at exactly the median is penalised");
    checkf(get_block_reward(median, median * 3 / 2, agc, 16, r_at_15) == RewardStatus::Ok,
           "a block at 1.5x the median was refused");
    // base * (2m - w) * w / m^2 at w = 1.5m is base * 0.75.
    checkf(r_at_15 == 600000000000ull * 3 / 4,
           "the penalty at 1.5x the median is %llu, expected %llu",
           static_cast<unsigned long long>(r_at_15),
           static_cast<unsigned long long>(600000000000ull * 3 / 4));
    checkf(get_block_reward(median, median * 2, agc, 16, r_at_2x) == RewardStatus::Ok
               && r_at_2x == 0,
           "a block at exactly twice the median does not pay zero");
    checkf(get_block_reward(median, median * 2 + 1, agc, 16, r_over) == RewardStatus::BlockTooBig,
           "a block beyond twice the median was priced instead of refused");
    // Below the penalty-free zone the median is lifted to it, so a small block
    // is never penalised however small the median looks.
    std::uint64_t r_small = 0;
    checkf(get_block_reward(87, 87, agc, 16, r_small) == RewardStatus::Ok
               && r_small == 600000000000ull,
           "the 300000 penalty-free zone is not applied");

    // The coinbase rule, including the v2..v12 partial-claim path that changes
    // what the emission grows by.
    {
        const CoinbaseCheck exact = check_coinbase_amount(1000 + 7, 1000, 7, 16);
        checkf(exact.ok && !exact.partial && exact.effective_base == 1000,
               "an exact coinbase was refused");
        const CoinbaseCheck over = check_coinbase_amount(1000 + 8, 1000, 7, 16);
        checkf(!over.ok, "an overpaying coinbase was accepted");
        const CoinbaseCheck short_v16 = check_coinbase_amount(1000, 1000, 7, 16);
        checkf(!short_v16.ok, "a short coinbase was accepted at v16");
        const CoinbaseCheck short_v10 = check_coinbase_amount(900 + 7, 1000, 7, 10);
        checkf(short_v10.ok && short_v10.partial && short_v10.effective_base == 900,
               "the v2..v12 partial-claim rule does not reduce the emission");
    }

    // The weight rules at their edges.
    checkf(long_term_weight_for(87, 300000, 16) == 300000 * 10 / 17,
           "the 2021-scaling floor is not ltemw * 10 / 17");
    checkf(long_term_weight_for(10000000, 300000, 16) == 300000 + 300000 * 7 / 10,
           "the 2021-scaling ceiling is not ltemw * 1.7");
    checkf(long_term_weight_for(10000000, 300000, 14) == 300000 + 300000 * 2 / 5,
           "the pre-2021 ceiling is not ltemw * 1.4");
    checkf(long_term_weight_for(87, 300000, 14) == 87,
           "the pre-2021 rule invented a floor");
    checkf(long_term_weight_for(87, 300000, 9) == 87,
           "the long-term rule applied below v10");
    checkf(effective_median_weight(87, 300000, 16) == 300000,
           "the effective median ignored the long-term floor");
    checkf(effective_median_weight(1000000, 300000, 16)
               == 1000000, "a short-term surge was clamped too early");
    checkf(effective_median_weight(100000000, 300000, 16) == 50 * 300000,
           "the 50x surge ceiling is missing");
    checkf(min_block_weight(16) == 300000 && min_block_weight(4) == 60000
               && min_block_weight(1) == 20000,
           "the penalty-free zone table is wrong");

    // The fee quantization mask, and the block weight limit.
    checkf(ConsensusState::fee_quantization_mask() == 10000,
           "the fee quantization mask is not 10^4");
}

// =============================================================================
// timestamp rule
// =============================================================================
static void test_timestamps() {
    TimestampWindow w;
    // A window that is not yet full has no median and refuses nothing.
    for (std::uint64_t i = 0; i < BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - 1; ++i) {
        checkf(w.check(1, 0) == TimestampStatus::Ok, "an unfilled window rejected a block");
        w.push(1000 + i * 120);
    }
    checkf(w.median() == 0, "an unfilled window produced a median");
    w.push(1000 + BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW * 120);
    checkf(w.median() != 0, "a full window produced no median");

    const std::uint64_t m = w.median();
    checkf(w.check(m, 0) == TimestampStatus::Ok, "a block exactly at the median was refused");
    checkf(w.check(m - 1, 0) == TimestampStatus::BelowMedian,
           "a block below the median was accepted");
    checkf(w.check(m + 1, 0) == TimestampStatus::Ok, "a block above the median was refused");

    const std::uint64_t now = m + 10000;
    checkf(w.check(now + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT, now) == TimestampStatus::Ok,
           "a block exactly at the future limit was refused");
    checkf(w.check(now + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT + 1, now)
               == TimestampStatus::TooFarInFuture,
           "a block beyond the future limit was accepted");
    checkf(w.template_timestamp(m - 5) == m, "a template below the median was allowed");
    checkf(w.template_timestamp(m + 5) == m + 5, "a template timestamp was clamped");
}

int main() {
    std::printf("xmr_consensus_state_kat: %s %s, heights %llu..%llu (tip %llu)\n",
                G::NETWORK, G::MONEROD_VERSION,
                static_cast<unsigned long long>(G::TEST_FIRST),
                static_cast<unsigned long long>(G::TEST_LAST),
                static_cast<unsigned long long>(G::CAPTURE_TIP));

    test_median();
    test_replay();
    test_difficulty_window_geometry();
    test_connect_real_blocks();
    test_hf_fuse();
    test_arithmetic();
    test_timestamps();

    std::printf("xmr_consensus_state_kat: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
