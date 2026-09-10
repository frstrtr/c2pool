// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/chain/xmr_consensus_state.hpp
//
// THE CONSENSUS STATE: the five windows a Monero chain carries, the rules that
// advance them by one block, and the exact rollback that takes one back.
//
//   difficulty   735 rows of (timestamp, cumulative difficulty)  -> next_difficulty
//   short weight 100 block weights                               -> effective median
//   long weight  100 000 long-term weights                       -> long-term median
//   timestamp    60 timestamps                                   -> template lower bound
//   emission     one number, already_generated_coins             -> base reward
//
// WHAT THIS FILE IS AND IS NOT. It is the consensus arithmetic of connecting a
// block: version rules, timestamp rule, weight, reward, emission, difficulty,
// and the state transition. It is NOT the index: no fork choice, no alt
// branches, no peers, no storage. Those are C2c, which drives this class -- and
// the split is what makes the arithmetic testable against monerod without a
// network: the KAT re-derives 600 consecutive stagenet heights (difficulty,
// long-term weight, reward, emission) through these windows, and connects the
// real block blobs it has bodies for through connect() itself.
//
// ROLLBACK IS EXACT, NOT APPROXIMATE. Every connect() returns an undo record
// carrying what fell out of each window and what the emission was before. A
// reorg pops them in reverse and the state is bit-identical to what it was --
// which the KAT proves by walking the whole replay forward, rolling all of it
// back, and re-walking to the same values. An index that re-derived the windows
// from storage instead would be correct too, and 100 000 reads slower per
// block.
//
// POW IS NOT HERE. The RandomX check is C2b's, behind its own link seam. The
// state records whether a block arrived pow-verified (`pow_verified`) and
// exposes verified_frontier() so a settlement driver can refuse to finalize
// past it; it never pretends to have checked what it has not.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <deque>
#include <string>
#include <vector>

#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/contracts/anchor.hpp"
#include "impl/xmr/native/consensus/xmr_block_id.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/consensus/xmr_difficulty.hpp"
#include "impl/xmr/native/consensus/xmr_epoch.hpp"
#include "impl/xmr/native/consensus/xmr_hf_policy.hpp"
#include "impl/xmr/native/consensus/xmr_reward.hpp"
#include "impl/xmr/native/consensus/xmr_timestamp.hpp"
#include "impl/xmr/native/consensus/xmr_weight.hpp"

namespace c2pool::xmr::native {

// --- one connected block ------------------------------------------------------
// Everything the index needs to answer a query about a block, and everything
// the state needs to undo it. `reward` is base + fees, the field
// node::ChainMainBlock carries and the RPC reports.
struct ChainRow {
    std::uint64_t height = 0;
    Hash          id{};
    Hash          prev_id{};
    std::uint64_t timestamp = 0;
    std::uint8_t  major_version = 0;
    std::uint8_t  minor_version = 0;

    std::uint64_t block_weight     = 0;
    std::uint64_t long_term_weight = 0;

    U128          difficulty{};              // of THIS block
    U128          cumulative_difficulty{};   // including this block

    std::uint64_t base_reward = 0;           // penalized, pre-fee, what emission grew by
    std::uint64_t fees        = 0;
    std::uint64_t reward      = 0;           // base_reward + fees
    std::uint64_t already_generated_coins = 0;  // AFTER this block

    bool pow_verified = false;
    bool rolled_fork  = false;               // connected under R-HFFUSE code-rolling

    node::ChainMainBlock to_chain_main_block() const {
        node::ChainMainBlock b;
        b.difficulty = difficulty;
        b.height     = height;
        b.timestamp  = timestamp;
        b.reward     = reward;
        b.id         = id;
        b.prev_id    = prev_id;
        return b;
    }
};

// --- what the caller supplies for a candidate block ---------------------------
// The index parses the block and its bodies (which is where the tx weights and
// fees come from) and hands the numbers over. `bodies_complete` is false when
// the block arrived fluffy and has not been completed yet: connect() then
// refuses, because a weight it cannot compute is a reward it cannot check.
struct BlockConnectInput {
    ParsedBlock    parsed{};
    BlockIdentity  identity{};
    CoinbaseFields coinbase{};

    std::uint64_t block_weight     = 0;   // coinbase blob + every tx weight
    std::uint64_t fees             = 0;   // sum of the block's tx fees
    bool          bodies_complete  = false;
    bool          pow_verified     = false;
};

enum class ConnectStatus : std::uint8_t {
    Ok = 0,
    PrevMismatch,       // does not extend the current tip
    HeightMismatch,     // coinbase height != block height
    ForkRejected,       // hard-fork policy said no (too low / bad minor)
    BadTimestamp,       // below the 60-block median
    FutureTimestamp,    // ahead of local time: SOFT, retry, never a ban
    BodiesMissing,      // weight not computable yet (fluffy, uncompleted)
    BlockTooBig,        // weight > 2 * median: unpayable
    BadCoinbase,        // coinbase amount does not match the reward rule
    BelowAnchor,        // refuses to touch pinned history
};

inline const char* to_string(ConnectStatus s) noexcept {
    switch (s) {
        case ConnectStatus::Ok:              return "Ok";
        case ConnectStatus::PrevMismatch:    return "PrevMismatch";
        case ConnectStatus::HeightMismatch:  return "HeightMismatch";
        case ConnectStatus::ForkRejected:    return "ForkRejected";
        case ConnectStatus::BadTimestamp:    return "BadTimestamp";
        case ConnectStatus::FutureTimestamp: return "FutureTimestamp";
        case ConnectStatus::BodiesMissing:   return "BodiesMissing";
        case ConnectStatus::BlockTooBig:     return "BlockTooBig";
        case ConnectStatus::BadCoinbase:     return "BadCoinbase";
        case ConnectStatus::BelowAnchor:     return "BelowAnchor";
    }
    return "?";
}

// A refusal that is the PEER's fault (ban-worthy) versus one that is ours or
// nobody's (retry). C1's penalise() needs the distinction.
inline constexpr bool connect_status_is_peer_fault(ConnectStatus s) noexcept {
    return s != ConnectStatus::Ok && s != ConnectStatus::FutureTimestamp
        && s != ConnectStatus::BodiesMissing && s != ConnectStatus::PrevMismatch;
}

// --- the undo record ----------------------------------------------------------
struct ConnectUndo {
    WeightUndo     weight{};
    DifficultyUndo difficulty{};
    TimestampUndo  timestamp{};
    std::uint64_t  prev_already_generated_coins = 0;
};

// --- the state ----------------------------------------------------------------
class ConsensusState {
public:
    explicit ConsensusState(XmrNet net = XmrNet::Mainnet) : net_(net) {}

    XmrNet network() const noexcept { return net_; }

    // --- seeding ---------------------------------------------------------------
    // From a verified anchor bundle: the windows are the bundle's, the tip is
    // the anchor block, and nothing at or below it is reorgable.
    void seed_from_anchor(const AnchorBundle& b,
                          const std::vector<std::uint64_t>& timestamps_60) {
        clear();
        anchor_height_ = b.height;

        std::vector<DifficultyRow> rows;
        rows.reserve(b.difficulty_window.size());
        for (const auto& p : b.difficulty_window)
            rows.push_back(DifficultyRow{p.first, p.second});
        difficulty_.seed(rows);
        weights_.seed(b.short_term_weights, b.long_term_weights);
        timestamps_.seed(timestamps_60);

        ChainRow tip;
        tip.height                  = b.height;
        tip.id                      = b.id;
        tip.prev_id                 = b.prev_id;
        tip.timestamp               = b.timestamp;
        tip.major_version           = b.major_version;
        tip.minor_version           = b.major_version;
        tip.block_weight            = b.short_term_weights.empty() ? 0 : b.short_term_weights.back();
        tip.long_term_weight        = b.long_term_weights.empty() ? 0 : b.long_term_weights.back();
        tip.cumulative_difficulty   = b.cumulative_difficulty;
        tip.already_generated_coins = b.already_generated_coins;
        tip.pow_verified            = true;   // the anchor is trust, by definition
        rows_.push_back(tip);
        agc_ = b.already_generated_coins;
        verified_frontier_ = b.height;   // the anchor is the trust root
        ++epoch_seq_;
    }

    // A bare seeding for tests and for a chain started from its genesis
    // (regtest): the windows start empty and fill as blocks connect.
    void seed_empty(std::uint64_t anchor_height = 0) {
        clear();
        anchor_height_ = anchor_height;
    }

    // Seeding for a replay that starts mid-chain with the windows supplied
    // directly rather than through an anchor file. Same invariants; used by the
    // parity KAT, which has monerod's numbers but no .inc bundle.
    void seed_direct(const ChainRow& tip,
                     const std::vector<DifficultyRow>& difficulty_window,
                     const std::vector<std::uint64_t>& short_term_weights,
                     const std::vector<std::uint64_t>& long_term_weights,
                     const std::vector<std::uint64_t>& timestamps_60) {
        clear();
        anchor_height_ = tip.height;
        difficulty_.seed(difficulty_window);
        weights_.seed(short_term_weights, long_term_weights);
        timestamps_.seed(timestamps_60);
        rows_.push_back(tip);
        agc_ = tip.already_generated_coins;
        if (tip.pow_verified) verified_frontier_ = tip.height;
        ++epoch_seq_;
    }

    void clear() {
        difficulty_.clear();
        weights_ = WeightState{};
        timestamps_ = TimestampWindow{};
        rows_.clear();
        agc_ = 0;
        anchor_height_ = 0;
        verified_frontier_ = 0;
        epoch_seq_ = 0;
        fuse_ = HfFuse{};
    }

    // --- reading ---------------------------------------------------------------
    bool                empty()        const noexcept { return rows_.empty(); }
    std::uint64_t       height()       const noexcept { return rows_.empty() ? 0 : rows_.back().height; }
    const ChainRow*     tip()          const noexcept { return rows_.empty() ? nullptr : &rows_.back(); }
    std::uint64_t       anchor_height() const noexcept { return anchor_height_; }
    std::uint64_t       verified_frontier() const noexcept { return verified_frontier_; }
    std::uint64_t       epoch_seq()    const noexcept { return epoch_seq_; }
    std::uint64_t       already_generated_coins() const noexcept { return agc_; }
    const HfFuse&       fuse()         const noexcept { return fuse_; }
    const WeightState&  weights()      const noexcept { return weights_; }
    const DifficultyWindow& difficulty_window() const noexcept { return difficulty_; }
    const TimestampWindow&  timestamp_window()  const noexcept { return timestamps_; }
    const std::deque<ChainRow>& rows() const noexcept { return rows_; }

    // How many connected rows to keep. Deep enough for the deepest reorg the
    // node will service (D-9 pins 2048); rows below it stay only as the
    // windows' contents, which is all consensus needs.
    void set_row_retention(std::size_t n) { row_retention_ = n; trim_rows_(); }

    // The version the NEXT block is expected to carry, code-rolling included:
    // at a rolled fork the chain's own version is ahead of our table and the
    // chain is the thing that is right.
    std::uint8_t next_major_version() const {
        const std::uint64_t h = height() + 1;
        const std::uint8_t table = hf_version_for_height(net_, h);
        const std::uint8_t tipv  = rows_.empty() ? 0 : rows_.back().major_version;
        return tipv > table ? tipv : table;
    }

    // --- the five windows, as a template consumer sees them ---------------------
    U128 next_difficulty() const { return difficulty_.next_difficulty(next_major_version()); }

    std::uint64_t effective_median_weight() const {
        return weights_.effective_median(next_major_version());
    }
    std::uint64_t block_weight_limit() const { return effective_median_weight() * 2; }
    std::uint64_t long_term_effective_median() const {
        return weights_.long_term_effective_median();
    }
    std::uint64_t median_timestamp() const { return timestamps_.median(); }

    // What a block of at most the median weight would pay.
    std::uint64_t expected_base_reward() const {
        return emission_base_reward(agc_, next_major_version());
    }

    // monerod's fee quantization mask: 10^(CRYPTONOTE_DISPLAY_DECIMAL_POINT -
    // PER_KB_FEE_QUANTIZATION_DECIMALS) == 10^(12 - 8) == 10000, computed the
    // way monerod computes it rather than written as a literal.
    static constexpr std::uint64_t fee_quantization_mask() noexcept {
        std::uint64_t mask = 1;
        for (int n = 8; n < 12; ++n) mask *= 10;
        return mask;
    }

    // The consensus half of TemplateInputs. The seed hashes are left zero: they
    // are block IDS at epoch heights, which is the index's table, not the
    // state's -- ChainStateView fills them in.
    TemplateInputs template_inputs_partial() const {
        TemplateInputs t;
        const std::uint8_t v = next_major_version();
        t.major_version = v;
        t.minor_version = v;
        t.height        = height() + 1;
        if (!rows_.empty()) t.prev_id = rows_.back().id;
        t.difficulty                        = next_difficulty();
        t.median_weight                     = effective_median_weight();
        t.block_weight_limit                = block_weight_limit();
        t.long_term_effective_median_weight = long_term_effective_median();
        t.already_generated_coins           = agc_;
        t.median_timestamp                  = median_timestamp();
        t.expected_base_reward              = expected_base_reward();
        t.fee_quantization_mask             = fee_quantization_mask();
        t.epoch_seq                         = epoch_seq_;
        t.synced                            = false;   // the index owns this bit
        return t;
    }

    // --- connecting -------------------------------------------------------------
    // Applies one block on top of the tip. On anything but Ok the state is
    // UNCHANGED (every check runs before the first mutation).
    //
    // `now` is the clock the future-timestamp rule is judged against; 0 skips
    // it, which is what a replay of recorded history passes.
    ConnectStatus connect(const BlockConnectInput& in, std::uint64_t now,
                          ChainRow& row_out, ConnectUndo& undo_out, std::string& why) {
        why.clear();
        const BlockHeaderFields& h = in.parsed.header;
        const std::uint64_t height_in = height() + 1;

        if (!rows_.empty() && !(h.prev_id == rows_.back().id)) {
            why = "block does not extend the current tip";
            return ConnectStatus::PrevMismatch;
        }
        if (!rows_.empty() && height_in <= anchor_height_) {
            why = "refusing to connect at or below the anchor height "
                + std::to_string(anchor_height_);
            return ConnectStatus::BelowAnchor;
        }

        const std::uint8_t major = static_cast<std::uint8_t>(h.major_version);
        const std::uint8_t minor = static_cast<std::uint8_t>(h.minor_version);

        // R-HFFUSE: a fork above our table is FOLLOWED with rolled rules and
        // trips the fuse; a fork below the table's requirement is refused.
        HfFuse probe = fuse_;      // trip only if the block is otherwise accepted
        const HfVerdict verdict =
            hf_policy_check_block(net_, height_in, major, minor, probe, why);
        if (!hf_verdict_accepts(verdict)) return ConnectStatus::ForkRejected;
        const std::uint8_t rules_v = hf_rules_version(major);

        if (in.coinbase.height != height_in) {
            why = "coinbase height " + std::to_string(in.coinbase.height)
                + " != block height " + std::to_string(height_in);
            return ConnectStatus::HeightMismatch;
        }

        const TimestampStatus ts = timestamps_.check(h.timestamp, now);
        if (ts == TimestampStatus::TooFarInFuture) {
            why = "block timestamp " + std::to_string(h.timestamp)
                + " is more than two hours ahead of local time";
            return ConnectStatus::FutureTimestamp;
        }
        if (ts == TimestampStatus::BelowMedian) {
            why = "block timestamp " + std::to_string(h.timestamp)
                + " is below the 60-block median " + std::to_string(timestamps_.median());
            return ConnectStatus::BadTimestamp;
        }

        if (!in.bodies_complete) {
            why = "block bodies are incomplete: the weight cannot be computed";
            return ConnectStatus::BodiesMissing;
        }

        // Reward: the penalty median is the effective median from v12, the
        // plain 100-block median before it.
        const std::uint64_t eff_median   = weights_.effective_median(rules_v);
        const std::uint64_t short_median = weights_.short_term_median();
        const std::uint64_t pen_median   = penalty_median(eff_median, short_median, rules_v);

        std::uint64_t base = 0;
        if (get_block_reward(pen_median, in.block_weight, agc_, rules_v, base)
            != RewardStatus::Ok) {
            why = "block weight " + std::to_string(in.block_weight)
                + " is beyond twice the median " + std::to_string(pen_median);
            return ConnectStatus::BlockTooBig;
        }

        const CoinbaseCheck cb =
            check_coinbase_amount(in.coinbase.output_sum, base, in.fees, rules_v);
        if (!cb.ok) {
            why = "coinbase pays " + std::to_string(in.coinbase.output_sum)
                + ", the rule allows " + std::to_string(cb.expected)
                + " (base " + std::to_string(base) + " + fees " + std::to_string(in.fees) + ")";
            return ConnectStatus::BadCoinbase;
        }

        // --- everything below this line mutates ---------------------------------
        fuse_ = probe;

        row_out = ChainRow{};
        row_out.height           = height_in;
        row_out.id               = in.identity.id;
        row_out.prev_id          = h.prev_id;
        row_out.timestamp        = h.timestamp;
        row_out.major_version    = major;
        row_out.minor_version    = minor;
        row_out.block_weight     = in.block_weight;
        row_out.long_term_weight = weights_.next_long_term_weight(in.block_weight, rules_v);
        row_out.difficulty       = difficulty_.next_difficulty(rules_v);
        row_out.cumulative_difficulty =
            rows_.empty() ? row_out.difficulty
                          : u128_add(rows_.back().cumulative_difficulty, row_out.difficulty);
        row_out.base_reward      = cb.effective_base;
        row_out.fees             = in.fees;
        row_out.reward           = in.coinbase.output_sum;
        row_out.pow_verified     = in.pow_verified;
        row_out.rolled_fork      = (verdict == HfVerdict::OkRolled);

        undo_out = ConnectUndo{};
        undo_out.prev_already_generated_coins = agc_;
        undo_out.weight     = weights_.push(row_out.block_weight, row_out.long_term_weight);
        undo_out.difficulty = difficulty_.push(row_out.timestamp, row_out.cumulative_difficulty);
        undo_out.timestamp  = timestamps_.push(row_out.timestamp);

        agc_ = accumulate_generated_coins(agc_, cb.effective_base);
        row_out.already_generated_coins = agc_;

        rows_.push_back(row_out);
        trim_rows_();
        if (in.pow_verified && row_out.height > verified_frontier_)
            verified_frontier_ = row_out.height;
        ++epoch_seq_;
        return ConnectStatus::Ok;
    }

    // Undo the newest block. `undo` must be the record connect() returned for
    // it, in reverse order for a multi-block rollback.
    bool disconnect(const ConnectUndo& undo) {
        if (rows_.empty()) return false;
        if (rows_.back().height <= anchor_height_) return false;
        timestamps_.pop(undo.timestamp);
        difficulty_.pop(undo.difficulty);
        weights_.pop(undo.weight);
        agc_ = undo.prev_already_generated_coins;
        rows_.pop_back();
        // The frontier must never OVERSTATE what was verified: after a rollback
        // it is the highest retained row that actually carried a PoW check, not
        // simply the new tip (which may have arrived unverified). A settlement
        // driver refuses to finalize past this number, so an optimistic value
        // here is the one error that costs something.
        if (!rows_.empty() && verified_frontier_ > rows_.back().height) {
            std::uint64_t frontier = anchor_height_;
            for (auto it = rows_.rbegin(); it != rows_.rend(); ++it) {
                if (it->pow_verified) { frontier = it->height; break; }
            }
            verified_frontier_ = frontier;
        }
        ++epoch_seq_;
        return true;
    }

    // The fuse is per-state and never resets while the state lives; exposed for
    // the telemetry surface.
    bool allows(HfCapability c) const noexcept { return fuse_.allows(c); }

private:
    void trim_rows_() {
        while (rows_.size() > row_retention_) rows_.pop_front();
    }

    XmrNet                 net_;
    DifficultyWindow       difficulty_;
    WeightState            weights_;
    TimestampWindow        timestamps_;
    std::deque<ChainRow>   rows_;
    std::size_t            row_retention_     = 2048;   // D-9
    std::uint64_t          agc_               = 0;
    std::uint64_t          anchor_height_     = 0;
    std::uint64_t          verified_frontier_ = 0;
    std::uint64_t          epoch_seq_         = 0;
    HfFuse                 fuse_{};
};

} // namespace c2pool::xmr::native
