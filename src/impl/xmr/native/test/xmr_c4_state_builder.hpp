// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_c4_state_builder.hpp   --  shared KAT fixture
//
// The native chain state at the C4 parity golden's height, rebuilt from
// monerod's own numbers, plus the small hex/id helpers every KAT over it needs.
//
// It was extracted from xmr_native_template_kat.cpp when a SECOND KAT needed the
// same fixture: M2's settlement-template KAT drives the option-B assembler off
// the very same NativeMinerDataSource, and two independently rolled copies of a
// 100 000-entry long-term window would not be two tests -- they would be two
// chances to roll it differently and call the difference a finding.
//
// PROVENANCE, unchanged by the move. Every number pushed here is monerod's: the
// C2a golden's captured windows are the seed position, the C4 golden's rows are
// the roll forward, and the only values this repository computes on the way are
// the ones under test (the emission carry-forward and the weight medians). The
// expected median timestamp is restated from monerod's RULE (epee's get_mid on
// the sorted window) rather than borrowed from the state that is being judged.
//
// Header-only, test-only. Include the two goldens before it is used; both live
// beside it in this directory.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/chain/xmr_chain_view.hpp"
#include "impl/xmr/native/consensus/xmr_epoch.hpp"
#include "impl/xmr/native/consensus/xmr_reward.hpp"
#include "impl/xmr/native/consensus/xmr_weight.hpp"

#include "xmr_c2a_golden.hpp"
#include "xmr_c4_parity_golden.hpp"

namespace c2pool::xmr::native::testkit {

namespace G2 = ::c2pool::xmr::native::golden_c2a;
namespace G4 = ::c2pool::xmr::native::golden_c4;

using ::c2pool::xmr::native::ChainRow;
using ::c2pool::xmr::native::ChainStateView;
using ::c2pool::xmr::native::DifficultyRow;
using ::c2pool::xmr::native::Hash;
using ::c2pool::xmr::native::U128;
using ::c2pool::xmr::native::WeightState;
using ::c2pool::xmr::native::XmrNet;

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------
inline Hash hash_from_hex(const char* h) {
    Hash out{};
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    for (std::size_t i = 0; i < 32 && h[2 * i] && h[2 * i + 1]; ++i)
        out[i] = static_cast<std::uint8_t>((nib(h[2 * i]) << 4) | nib(h[2 * i + 1]));
    return out;
}

inline std::string hex_of(const Hash& h) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (std::uint8_t b : h) { s.push_back(d[b >> 4]); s.push_back(d[b & 0xf]); }
    return s;
}

inline Hash synthetic_id(std::uint64_t height) {
    Hash h{};
    for (std::size_t i = 0; i < 8; ++i) h[i] = static_cast<std::uint8_t>(height >> (8 * i));
    h[31] = 0xC4;
    return h;
}

inline U128 u128_of(std::uint64_t lo, std::uint64_t hi) { U128 d; d.lo = lo; d.hi = hi; return d; }

// ---------------------------------------------------------------------------
// The parity fixture: what the native arm is judged against.
//
// Either the embedded capture, or a fresh one supplied with --parity-json. The
// JSON reader is deliberately tiny and only understands the fields it needs.
// ---------------------------------------------------------------------------
struct ParityExpectation {
    std::uint64_t height = G4::MD_HEIGHT;
    Hash          prev_id{};
    Hash          seed_hash{};
    std::uint64_t difficulty_lo = G4::MD_DIFFICULTY_LO;
    std::uint64_t difficulty_hi = G4::MD_DIFFICULTY_HI;
    std::uint64_t median_weight = G4::MD_MEDIAN_WEIGHT;
    std::uint64_t already_generated_coins = G4::MD_ALREADY_GENERATED_COINS;
    std::uint8_t  major_version = G4::MD_MAJOR_VERSION;
    std::string   raw_json = G4::MD_RAW_JSON;
    std::string   provenance =
        std::string("embedded capture: monerod ") + G4::MONEROD_VERSION + " " + G4::NETWORK;
};

// ---------------------------------------------------------------------------
// Rebuild the native chain state at G4::MD_HEIGHT - 1.
//
// Seeds are the C2a golden's captured windows (its long-term window is the only
// 100 000-entry object in this repository and re-capturing it would be pure
// cost), then rolled forward with the C4 golden's rows, which are the rows
// between the two captures. Every number pushed here is monerod's.
// ---------------------------------------------------------------------------
struct BuiltState {
    ChainStateView view{XmrNet::Stagenet};
    std::uint64_t  agc = 0;
    std::uint64_t  median_timestamp_expected = 0;
};

inline std::vector<std::uint64_t> c2a_long_term_seed() {
    std::vector<std::uint64_t> v;
    v.reserve(G2::LT_WINDOW_SIZE);
    for (std::size_t i = 0; i < G2::LT_SEED_HEAD_COUNT; ++i) v.push_back(G2::LT_SEED_HEAD[i]);
    for (std::size_t i = 0; i < G2::LT_SEED_TAIL_RUNS_COUNT; ++i)
        for (std::uint64_t k = 0; k < G2::LT_SEED_TAIL_RUNS[i].count; ++k)
            v.push_back(G2::LT_SEED_TAIL_RUNS[i].value);
    return v;
}

inline const G2::GoldenHeader& c2a_header_at(std::uint64_t h) {
    return G2::HEADERS[h - G2::HEADERS_FIRST_HEIGHT];
}

// The C2a seeds, which are the windows as they stood just below TEST_FIRST.
inline std::vector<DifficultyRow> c2a_difficulty_seed() {
    std::vector<DifficultyRow> v;
    for (std::uint64_t h = G2::TEST_FIRST - DIFFICULTY_BLOCKS_COUNT; h < G2::TEST_FIRST; ++h) {
        const auto& r = c2a_header_at(h);
        v.push_back(DifficultyRow{r.timestamp,
                                  u128_of(r.cumulative_difficulty_lo, r.cumulative_difficulty_hi)});
    }
    return v;
}
inline std::vector<std::uint64_t> c2a_short_term_seed() {
    std::vector<std::uint64_t> v;
    for (std::uint64_t h = G2::TEST_FIRST - CRYPTONOTE_REWARD_BLOCKS_WINDOW; h < G2::TEST_FIRST; ++h)
        v.push_back(c2a_header_at(h).block_weight);
    return v;
}
inline std::vector<std::uint64_t> c2a_timestamp_seed() {
    std::vector<std::uint64_t> v;
    for (std::uint64_t h = G2::TEST_FIRST - BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW; h < G2::TEST_FIRST; ++h)
        v.push_back(c2a_header_at(h).timestamp);
    return v;
}

// Roll the state from the C2a seed position to `stop_height` inclusive, using
// the C4 golden's rows. Returns the view seeded at that tip.
inline void build_state(BuiltState& out, std::uint64_t stop_height, bool with_seed_id = true) {
    std::vector<DifficultyRow> diff  = c2a_difficulty_seed();
    std::vector<std::uint64_t> shortw = c2a_short_term_seed();
    std::vector<std::uint64_t> longw  = c2a_long_term_seed();
    std::vector<std::uint64_t> times  = c2a_timestamp_seed();
    std::uint64_t agc = G2::AGC_BEFORE_FIRST;

    WeightState ws;
    ws.seed(shortw, longw);

    const G4::GoldenRow* last = nullptr;
    for (std::size_t i = 0; i < G4::ROWS_COUNT; ++i) {
        const G4::GoldenRow& r = G4::ROWS[i];
        if (r.height > stop_height) break;
        const std::uint8_t  v   = r.major_version;
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
        last = &r;
    }

    auto tail_of = [](auto& v, std::size_t keep) {
        if (v.size() > keep) v.erase(v.begin(), v.begin() + static_cast<long>(v.size() - keep));
    };
    tail_of(diff,   static_cast<std::size_t>(DIFFICULTY_BLOCKS_COUNT));
    tail_of(shortw, static_cast<std::size_t>(CRYPTONOTE_REWARD_BLOCKS_WINDOW));
    tail_of(longw,  static_cast<std::size_t>(G2::LT_WINDOW_SIZE));
    tail_of(times,  static_cast<std::size_t>(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW));

    {
        // monerod's median (epee::misc_utils::median), restated here rather
        // than borrowed, so the comparison is against the RULE and not against
        // the same code the state uses: sort, and for an even count take
        // epee's get_mid = floor((a+b)/2) of the two middle values, formed
        // without ever summing a and b.
        std::vector<std::uint64_t> t = times;
        std::sort(t.begin(), t.end());
        if (t.empty()) {
            out.median_timestamp_expected = 0;
        } else if (t.size() % 2) {
            out.median_timestamp_expected = t[t.size() / 2];
        } else {
            const std::uint64_t a = t[t.size() / 2 - 1];
            const std::uint64_t b = t[t.size() / 2];
            out.median_timestamp_expected =
                (a / 2) + (b / 2) + ((a - 2 * (a / 2)) + (b - 2 * (b / 2))) / 2;
        }
    }

    ChainRow tip;
    tip.height                = last->height;
    tip.timestamp             = last->timestamp;
    tip.major_version         = last->major_version;
    tip.minor_version         = last->minor_version;
    tip.block_weight          = last->block_weight;
    tip.long_term_weight      = last->long_term_weight;
    tip.difficulty            = u128_of(last->difficulty_lo, last->difficulty_hi);
    tip.cumulative_difficulty = u128_of(last->cumulative_difficulty_lo, last->cumulative_difficulty_hi);
    tip.pow_verified          = true;
    tip.already_generated_coins = agc;
    tip.id = (last->height == G4::ROWS_LAST_HEIGHT) ? hash_from_hex(G4::TIP_ID)
                                                    : synthetic_id(last->height);

    std::vector<std::pair<std::uint64_t, Hash>> seed_ids;
    if (with_seed_id) seed_ids.emplace_back(G4::SEED_HEIGHT, hash_from_hex(G4::SEED_ID));

    out.view.seed_direct(tip, diff, shortw, longw, times, seed_ids);
    out.view.set_synced(true);
    out.agc = agc;
}

} // namespace c2pool::xmr::native::testkit
