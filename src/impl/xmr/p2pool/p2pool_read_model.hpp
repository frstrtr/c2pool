// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/p2pool_read_model.hpp
//
// WHAT THE OBSERVER KNOWS, kept apart from how it learned it.
//
// This is a pure accumulator: blocks and peer facts go in, a status line comes
// out. It holds no socket, starts no thread and cannot send anything, which is
// what makes it the natural place to put the one number the whole component
// exists to make cheap later -- SAME-HEIGHT SITUATIONS.
//
// A sidechain block at a height that already has a different block is either a
// race (two miners solved the same height within one propagation delay) or a
// reorg. P2Pool resolves those by cumulative difficulty and pays the loser
// through the uncle mechanism at a 20% penalty. For c2pool the interesting
// quantity is not who won but HOW OFTEN it happens and how wide the window is,
// because that is the empirical input to the prefer-own tiebreak steer: a
// policy that biases toward our own block at a contested height is only worth
// its complexity if contested heights are common enough to matter, and only
// safe if the window is short enough that a loser is reliably recoverable as an
// uncle. This model measures both and asserts nothing about policy.
//
// THREE DELIBERATE NON-FEATURES, because each would turn an observer into a
// participant or into a liar:
//
//   * No fork choice. Competing branches are recorded side by side. Picking a
//     winner would mean re-deriving P2Pool's consensus, and a re-derivation
//     that drifts is worse than no answer.
//   * No PPLNS accounting. The share set of each block is parsed and counted,
//     but no running payout ledger is kept: that needs the full window, and a
//     partial window produces numbers that look authoritative and are not.
//   * No estimate presented as a measurement. Every derived rate carries the
//     sample count it came from, and a window with too few samples reports
//     "insufficient" rather than a number.
//
// Header-only, STL only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "impl/xmr/p2pool/p2pool_block.hpp"
#include "impl/xmr/p2pool/p2pool_consensus.hpp"

namespace c2pool::xmr::p2pool {

// One observation of one sidechain block, with the local clock reading that
// goes with it. `first_seen_ms` is OUR receive time, never a field off the
// wire: block timestamps are miner-chosen and cannot measure our own cadence.
struct ObservedBlock {
    Hash          sidechain_id{};
    std::uint64_t sidechain_height = 0;
    Difficulty    difficulty{};
    Difficulty    cumulative_difficulty{};
    Hash              parent{};
    std::vector<Hash> uncles;             // ids this block carried as uncles
    std::uint64_t monero_height = 0;      // txin_gen_height
    Hash          monero_prev_id{};
    std::uint64_t monero_timestamp = 0;
    std::size_t   share_outputs = 0;      // PPLNS payout lines in the coinbase
    std::uint64_t total_reward = 0;
    std::size_t   tx_count = 0;
    BlobShape     shape = BlobShape::Full;
    bool          id_verified = false;
    std::uint64_t first_seen_ms = 0;
    std::string   from_peer;              // "ip:port" we first heard it from

    // Set when the embedded Monero block was re-parsed through the native lane.
    bool          monero_parsed = false;
    Hash          monero_block_id{};      // id of the template AS TEMPLATED
    std::size_t   monero_blob_size = 0;
};

struct HeightContest {
    std::uint64_t     height = 0;
    std::vector<Hash> ids;                 // in first-seen order
    std::uint64_t     first_seen_ms = 0;
    std::uint64_t     last_seen_ms  = 0;
    std::uint64_t     spread_ms() const noexcept { return last_seen_ms - first_seen_ms; }
};

// ---------------------------------------------------------------------------
// THE HISTORY RING -- one row per height the chain ADVANCED to, bounded.
//
// The model above answers "what is true now". A trend answers "what has been
// happening", and nothing in the model could produce one: by_id_ is keyed by
// id and by_height_ holds arrival instants but not the per-block figures a
// plot needs. So this ring carries them, and it carries them under three
// rules that keep it from becoming a second, disagreeing model:
//
//   * BOUNDED. kHistoryMax entries, oldest dropped. A monitor left running for
//     a week must not grow a plot buffer for a week; a widget that cannot fit
//     on a screen is not worth a byte of memory.
//   * ADVANCING HEIGHTS ONLY. A sample is appended when a block arrives at a
//     height ABOVE the last sampled one. A backfilled parent is not appended,
//     for the same reason cadence_seconds() excludes it: its first_seen_ms is
//     our fetch time, and plotting it would draw our own parent walk as though
//     it were the chain's behaviour.
//   * NO DERIVED FIELD. Everything here is copied off the block. Whether a
//     sample is inside the live window is decided by the READER against
//     frontier_height(), not stamped in at insert time -- the frontier is
//     allowed to rise during the settle window, and a flag written before it
//     rose would be permanently wrong.
// ---------------------------------------------------------------------------
struct TipSample {
    std::uint64_t at_ms         = 0;   // OUR receive clock, never a wire field
    std::uint64_t height        = 0;
    // The block's difficulty, CLAMPED to 64 bits. The exact 128-bit value is on
    // the tip row and in the state file; this copy exists to be scaled into a
    // bar, and a plot of a 2^64-wide chain is not a case that exists. The flag
    // says when the clamp fired, so a widget can decline rather than draw a
    // flat line it cannot justify.
    std::uint64_t difficulty    = 0;
    bool          difficulty_clamped = false;
    std::size_t   shares        = 0;   // PPLNS payout lines in the coinbase
    std::uint64_t monero_height = 0;   // the Monero template it was built on
    bool          uncles        = false;   // this block carried uncles
};

class ReadModel {
public:
    // How long after the first observation a later, higher block still counts
    // as "already there" rather than as a live arrival. Several peers answer
    // the opening tip request within a few hundred milliseconds of each other.
    static constexpr std::uint64_t kFrontierSettleMs = 3000;

    // How many height samples the history ring keeps. Wider than any terminal
    // a widget is drawn into, and small enough that an overnight run holds a
    // fixed few kilobytes.
    static constexpr std::size_t kHistoryMax = 256;

    explicit ReadModel(Sidechain chain) : chain_(chain), params_(params_of(chain)) {}

    Sidechain chain() const noexcept { return chain_; }

    // Returns true if this id had not been seen before.
    bool observe(const ObservedBlock& b) {
        const auto it = by_id_.find(b.sidechain_id);
        if (it != by_id_.end()) { ++duplicate_receives_; return false; }

        by_id_.emplace(b.sidechain_id, b);
        order_.push_back(b.sidechain_id);

        // THE FRONTIER: the highest height that already existed when this run
        // started. Everything at or below it may have been backfilled by a
        // parent walk and carries a fetch time, not an arrival time; everything
        // above it was mined while we were watching. It is seeded by the first
        // block observed and then allowed to rise during a short settle window,
        // because several peers answer the opening tip request at once and a
        // lagging peer's answer must not become the frontier.
        if (!have_frontier_) {
            have_frontier_   = true;
            frontier_height_ = b.sidechain_height;
            frontier_t0_ms_  = b.first_seen_ms;
        } else if (b.first_seen_ms <= frontier_t0_ms_ + kFrontierSettleMs
                   && b.sidechain_height > frontier_height_) {
            frontier_height_ = b.sidechain_height;
        }

        auto& slot = by_height_[b.sidechain_height];
        if (slot.ids.empty()) { slot.height = b.sidechain_height; slot.first_seen_ms = b.first_seen_ms; }
        slot.ids.push_back(b.sidechain_id);
        slot.last_seen_ms = b.first_seen_ms;
        if (slot.ids.size() == 2) ++contested_heights_;

        if (b.sidechain_height >= tip_height_) {
            tip_height_ = b.sidechain_height;
            tip_id_ = b.sidechain_id;
            tip_difficulty_ = b.difficulty;
            tip_cumulative_ = b.cumulative_difficulty;
        }
        monero_height_high_ = std::max(monero_height_high_, b.monero_height);
        uncles_seen_ += b.uncles.size();
        for (const Hash& u : b.uncles) referenced_uncles_.insert(u);

        // The history ring: advancing heights only, bounded, copied never
        // derived. See the note on TipSample above for why each of those is a
        // rule rather than a convenience.
        if (history_.empty() || b.sidechain_height > history_.back().height) {
            TipSample s;
            s.at_ms         = b.first_seen_ms;
            s.height        = b.sidechain_height;
            s.difficulty    = b.difficulty.hi ? ~std::uint64_t(0) : b.difficulty.lo;
            s.difficulty_clamped = b.difficulty.hi != 0;
            s.shares        = b.share_outputs;
            s.monero_height = b.monero_height;
            s.uncles        = !b.uncles.empty();
            history_.push_back(s);
            if (history_.size() > kHistoryMax)
                history_.erase(history_.begin(),
                               history_.begin()
                                   + static_cast<std::ptrdiff_t>(history_.size() - kHistoryMax));
        }
        return true;
    }

    void note_peer(const std::string& endpoint) { peers_.insert(endpoint); }
    void note_peer_gossip(std::size_t n) { gossiped_addresses_ += n; }
    void note_connected(const std::string& endpoint) { connected_.insert(endpoint); }
    void note_disconnected(const std::string& endpoint) { connected_.erase(endpoint); }
    void note_parse_failure() { ++parse_failures_; }
    void note_broadcast_seen() { ++broadcasts_seen_; }

    // --- queries --------------------------------------------------------------
    std::size_t distinct_blocks() const noexcept { return by_id_.size(); }
    std::size_t connected_peers() const noexcept { return connected_.size(); }
    std::size_t known_peers() const noexcept { return peers_.size(); }
    std::size_t gossiped_addresses() const noexcept { return gossiped_addresses_; }
    std::size_t parse_failures() const noexcept { return parse_failures_; }
    std::size_t duplicate_receives() const noexcept { return duplicate_receives_; }
    std::size_t broadcasts_seen() const noexcept { return broadcasts_seen_; }
    std::uint64_t tip_height() const noexcept { return tip_height_; }
    const Hash& tip_id() const noexcept { return tip_id_; }
    Difficulty tip_difficulty() const noexcept { return tip_difficulty_; }
    Difficulty tip_cumulative_difficulty() const noexcept { return tip_cumulative_; }
    std::uint64_t monero_height_high() const noexcept { return monero_height_high_; }
    std::size_t uncles_seen() const noexcept { return uncles_seen_; }

    std::uint64_t height_span() const noexcept {
        if (by_height_.empty()) return 0;
        return by_height_.rbegin()->first - by_height_.begin()->first;
    }

    std::vector<HeightContest> contests() const {
        std::vector<HeightContest> out;
        for (const auto& kv : by_height_)
            if (kv.second.ids.size() > 1) out.push_back(kv.second);
        return out;
    }

    std::size_t contested_heights() const noexcept { return contested_heights_; }

    // Observed cadence: wall-clock seconds per NEW sidechain height on our own
    // receive clock.
    //
    // THE BACKFILL TRAP, which the first live run walked straight into. A
    // pulling observer fetches the tip and then walks parents to fill in the
    // ancestry, so most heights in the model were RECEIVED seconds apart even
    // though they were MINED ten seconds apart. Averaging over all of them
    // reported 4.4 s/height on a chain that targets 10 -- a number that looks
    // like a finding and is an artefact of our own fetch rate.
    //
    // So cadence is measured only over the LIVE WINDOW: heights strictly above
    // the first height this run ever saw. Those could not have been backfilled,
    // because they did not exist when the run started; their first-seen times
    // are genuine arrival times. Everything below the frontier is excluded,
    // and the sample count reported beside the number is the live-window count,
    // not the model size.
    bool cadence_seconds(double& out, std::size_t& samples) const {
        out = 0.0;
        samples = 0;
        if (!have_frontier_) return false;

        std::uint64_t t_lo = 0, t_hi = 0;
        bool first = true;
        for (const auto& kv : by_height_) {
            if (kv.first <= frontier_height_) continue;
            const std::uint64_t t = kv.second.first_seen_ms;
            if (first) { t_lo = t_hi = t; first = false; }
            else { if (t < t_lo) t_lo = t; if (t > t_hi) t_hi = t; }
            ++samples;
        }
        if (samples < 2 || t_hi <= t_lo) return false;
        out = static_cast<double>(t_hi - t_lo) / 1000.0 / static_cast<double>(samples - 1);
        return true;
    }

    // The height the run started from. Everything at or below it may have been
    // backfilled; everything above it arrived while we were watching.
    std::uint64_t frontier_height() const noexcept { return frontier_height_; }

    // Sidechain hashrate implied by the tip difficulty and the chain's target
    // block time. This is P2Pool's own definition (difficulty / block time), so
    // it is a restatement of two observed numbers, not an independent estimate.
    long double implied_hashrate() const noexcept {
        if (params_.target_block_time == 0) return 0.0L;
        return tip_difficulty_.as_double() / static_cast<long double>(params_.target_block_time);
    }

    // Blocks whose coinbase paid the Monero base reward or more AND whose
    // Monero template height moved: not a claim that P2Pool found a mainnet
    // block. Finding one requires the Monero PoW target, which an observer that
    // holds no Monero chain cannot supply -- see the note in the status line.
    std::size_t monero_heights_crossed() const noexcept {
        std::set<std::uint64_t> h;
        for (const auto& kv : by_id_) h.insert(kv.second.monero_height);
        return h.size();
    }

    // A block that some OTHER block named as an uncle: direct evidence that the
    // loser of a height race was carried rather than dropped.
    std::size_t uncles_resolved() const noexcept {
        std::size_t n = 0;
        for (const Hash& u : referenced_uncles_)
            if (by_id_.count(u)) ++n;
        return n;
    }

    const std::map<Hash, ObservedBlock>& blocks() const noexcept { return by_id_; }
    const std::vector<Hash>& arrival_order() const noexcept { return order_; }

    // Per-height arrival record, ordered by height. Exposed for the reason
    // cadence_seconds() exists at all: one averaged cadence cannot say whether
    // the chain is beating steadily or arriving in bursts, and a display that
    // shows the individual gaps says more than the mean does. Callers inherit
    // the frontier caveat -- a height at or below frontier_height() carries a
    // FETCH time, not an arrival time.
    const std::map<std::uint64_t, HeightContest>& heights() const noexcept { return by_height_; }

    // The gaps between consecutive LIVE height arrivals, oldest first, at most
    // `max` of them (0 = all). Same live-window rule as cadence_seconds():
    // everything at or below the frontier is excluded, because those heights
    // were backfilled by our own parent walk and their spacing measures our
    // fetch rate rather than the chain's block rate.
    std::vector<std::uint64_t> live_arrival_gaps_ms(std::size_t max) const {
        std::vector<std::uint64_t> t;
        if (have_frontier_)
            for (const auto& kv : by_height_)
                if (kv.first > frontier_height_) t.push_back(kv.second.first_seen_ms);
        std::vector<std::uint64_t> gaps;
        for (std::size_t i = 1; i < t.size(); ++i)
            gaps.push_back(t[i] >= t[i - 1] ? t[i] - t[i - 1] : 0);
        if (max && gaps.size() > max)
            gaps.erase(gaps.begin(), gaps.end() - static_cast<std::ptrdiff_t>(max));
        return gaps;
    }

    // The history ring, oldest first. Bounded by kHistoryMax; see TipSample.
    // Callers inherit the same live-window caveat as everywhere else: a sample
    // whose height is at or below frontier_height() was fetched, not awaited.
    const std::vector<TipSample>& tip_history() const noexcept { return history_; }

    // How many DISTINCT heights this model holds. The denominator of the PPLNS
    // coverage gauge, and not the same number as distinct_blocks(): a contested
    // height holds two blocks and is one height.
    std::size_t heights_held() const noexcept { return by_height_.size(); }

    // The chain's own parameters, so a display can put an observed number next
    // to the target it is supposed to approach.
    SidechainParams params() const noexcept { return params_; }

    const ObservedBlock* find(const Hash& id) const {
        const auto it = by_id_.find(id);
        return it == by_id_.end() ? nullptr : &it->second;
    }

    // The status line. One block of text, every number beside the sample count
    // that produced it.
    std::string status(std::uint64_t elapsed_ms) const {
        std::string s;
        s += "p2pool-observer[" + std::string(to_string(chain_)) + "] READ-ONLY\n";
        s += "  peers        : connected=" + std::to_string(connected_.size())
           + " known=" + std::to_string(peers_.size())
           + " gossiped=" + std::to_string(gossiped_addresses_) + "\n";
        s += "  sidechain    : tip_height=" + std::to_string(tip_height_)
           + " tip_id=" + (tip_height_ ? hex(tip_id_) : std::string("-")) + "\n";
        s += "  difficulty   : tip=" + tip_difficulty_.to_string()
           + " cumulative=" + tip_cumulative_.to_string()
           + " implied_hashrate=" + std::to_string(static_cast<double>(implied_hashrate()))
           + " H/s\n";
        double cad = 0.0; std::size_t n = 0;
        if (cadence_seconds(cad, n))
            s += "  cadence      : " + std::to_string(cad) + " s/height over "
               + std::to_string(n) + " LIVE heights above frontier "
               + std::to_string(frontier_height_) + " (target "
               + std::to_string(params_.target_block_time) + " s)\n";
        else
            s += "  cadence      : insufficient (" + std::to_string(n)
               + " live heights above frontier " + std::to_string(frontier_height_) + ")\n";
        s += "  blocks       : distinct=" + std::to_string(by_id_.size())
           + " height_span=" + std::to_string(height_span())
           + " duplicates=" + std::to_string(duplicate_receives_)
           + " parse_failures=" + std::to_string(parse_failures_)
           + " broadcasts=" + std::to_string(broadcasts_seen_) + "\n";
        s += "  same-height  : contested=" + std::to_string(contested_heights_)
           + " uncles_named=" + std::to_string(uncles_seen_)
           + " uncles_resolved=" + std::to_string(uncles_resolved()) + "\n";
        s += "  monero       : template_heights=" + std::to_string(monero_heights_crossed())
           + " highest=" + std::to_string(monero_height_high_)
           + " (mainnet-block detection needs a Monero PoW target: not claimed)\n";
        s += "  window       : " + std::to_string(elapsed_ms / 1000) + " s\n";
        return s;
    }

private:
    Sidechain       chain_;
    SidechainParams params_;

    std::map<Hash, ObservedBlock>       by_id_;
    std::vector<Hash>                   order_;
    std::vector<TipSample>              history_;
    std::map<std::uint64_t, HeightContest> by_height_;
    std::set<std::string>               peers_;
    std::set<std::string>               connected_;
    std::set<Hash>                      referenced_uncles_;

    std::uint64_t tip_height_ = 0;
    Hash          tip_id_{};
    Difficulty    tip_difficulty_{};
    Difficulty    tip_cumulative_{};
    std::uint64_t monero_height_high_ = 0;
    std::uint64_t frontier_height_ = 0;
    std::uint64_t frontier_t0_ms_  = 0;
    bool          have_frontier_ = false;

    std::size_t contested_heights_  = 0;
    std::size_t duplicate_receives_ = 0;
    std::size_t parse_failures_     = 0;
    std::size_t gossiped_addresses_ = 0;
    std::size_t uncles_seen_        = 0;
    std::size_t broadcasts_seen_    = 0;
};

} // namespace c2pool::xmr::p2pool
