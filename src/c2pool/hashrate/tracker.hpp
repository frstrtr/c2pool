// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <chrono>
#include <deque>
#include <mutex>
#include <ctime>
#include <nlohmann/json.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

namespace c2pool {
namespace hashrate {

/**
 * @brief Per-connection hashrate tracking and aggressive vardiff.
 *
 * Modelled after Python p2pool's per-connection pseudoshare vardiff:
 *   - Records high-resolution timestamps of recent share submissions.
 *   - After every share, checks whether the share rate diverges from target.
 *   - Normal adjust: after N shares, scale difficulty by actual/target ratio.
 *   - Timeout fallback: past 10*N*target time, adjust on what has arrived.
 *
 * Only a share credited at (at least) the CURRENT difficulty is timed: a
 * share of a job issued at an older, lower difficulty is credited at that
 * difficulty but is no evidence of the rate at the current one (the floor
 * burst a rig sends before it applies a raised difficulty ramped the old
 * timing to max_difficulty in seconds).
 *
 * The difficulty never exceeds the ceiling the session sets from the job's
 * pool-share difficulty (p2pool: target = max(target, share target)), so a
 * rig never withholds a share the pool would have counted.
 */
class HashrateTracker {
public:
    using clock = std::chrono::steady_clock;
    using time_point = clock::time_point;

private:

    struct MiningShareSubmission {
        uint64_t timestamp;   // epoch seconds (for stats)
        double difficulty;
        bool accepted;
    };

    std::deque<MiningShareSubmission> recent_mining_shares_;
    mutable std::mutex shares_mutex_;
    double current_difficulty_ = 1.0;
    double target_time_per_mining_share_ = 3.0;  // target seconds per pseudoshare (p2pool: 3)

    // Difficulty bounds
    double min_difficulty_ = 0.0005;
    double max_difficulty_ = 65536.0;

    // Vardiff state (high-resolution)
    std::deque<time_point> recent_share_times_;   // timestamps of recent submissions
    static constexpr size_t VARDIFF_TRIGGER = 12; // normal adjust after N shares (p2pool: >12)
    static constexpr double TIMEOUT_MULT   = 10.0; // p2pool: time > 10*N*share_rate
    static constexpr double MIN_ADJUST     = 0.1;  // p2pool: clip(ratio, 0.1, 10.0)
    static constexpr double MAX_ADJUST     = 10.0;  // p2pool: clip(ratio, 0.1, 10.0)

    // Whether vardiff auto-adjustment is active (only for stratum per-connection trackers)
    bool vardiff_enabled_ = false;

    // Upper bound from the pool-share difficulty of the last job issued
    // (set_difficulty_ceiling). 0 = none known: max_difficulty_ only.
    double ceiling_ = 0.0;
    // A fixed difficulty ("ADDR+N", set_fixed_difficulty): vardiff off, the
    // current difficulty is the request bounded by [min, max] and the ceiling.
    bool   fixed_ = false;
    double fixed_request_ = 0.0;

    // Start of this tracker (session): the hashrate window of a session
    // younger than 600 s is its age, not 600 s.
    uint64_t created_at_ = static_cast<uint64_t>(std::time(nullptr));

    // --- Hashrate-based vardiff (stable-by-construction; opt-in per tracker) ---
    // Sets difficulty directly from a smoothed hashrate estimate
    // (D = H_est * target_time / 2^32) instead of the ratio feedback loop, which
    // oscillates because new_diff = current_diff / ratio(current_diff). Off by
    // default; DASH opts in via set_hashrate_vardiff(true). Port of p2pool-dash
    // work.py:369-376 target modulation. The legacy ratio path stays byte-identical.
    bool     use_hashrate_vardiff_   = false;
    double   vardiff_ewma_tau_       = 90.0;  // s; hashrate estimator time constant (60-120)
    double   vardiff_deadband_       = 0.10;  // only move diff when change > 10%
    int      vardiff_warmup_shares_  = 4;     // keep seed/initial diff until warm
    double   ewma_work_              = 0.0;   // exp-decayed sum of accepted-share difficulty
    double   ewma_last_decay_time_   = 0.0;   // epoch s
    double   ewma_first_share_time_  = 0.0;   // epoch s
    uint64_t ewma_share_count_       = 0;

    // Statistics
    uint64_t total_mining_shares_submitted_ = 0;
    uint64_t total_mining_shares_accepted_ = 0;
    double total_work_done_ = 0.0;

    // Internal helper — must be called with shares_mutex_ already held
    double get_current_hashrate_unlocked() const;
    // [min, max] then the ceiling (the ceiling wins over the floor: the money
    // guard first). Caller holds shares_mutex_.
    double bounded_unlocked(double difficulty) const;
    // The fixed difficulty: bounded_unlocked(fixed_request_), on the
    // power-of-two grid with the hashrate vardiff. Caller holds shares_mutex_.
    double fixed_unlocked() const;

public:
    void record_mining_share_submission(double difficulty, bool accepted);
    /// The same at explicit clocks (tests, simulation): steady_now drives the
    /// vardiff window, epoch_now the hashrate estimator.
    void record_mining_share_submission_at(double difficulty, bool accepted,
                                           time_point steady_now, double epoch_now);
    void record_mining_share(const uint256& hash, uint64_t difficulty, uint64_t timestamp);

    double get_current_difficulty() const;
    double get_current_hashrate() const;
    nlohmann::json get_statistics() const;

    void set_difficulty_bounds(double min_difficulty, double max_difficulty);
    void set_target_time_per_mining_share(double target_seconds);
    void enable_vardiff(bool enabled = true);
    // Enable the stable-by-construction hashrate-based vardiff (DASH). Off = legacy ratio feedback.
    void set_hashrate_vardiff(bool on) { use_hashrate_vardiff_ = on; }

    // Backward compatibility
    void record_share_submission(double difficulty, bool accepted) {
        record_mining_share_submission(difficulty, accepted);
    }
    void record_share(const uint256& hash, uint64_t difficulty, uint64_t timestamp) {
        record_mining_share(hash, difficulty, timestamp);
    }
    void set_target_time_per_share(double target_seconds) {
        set_target_time_per_mining_share(target_seconds);
    }

    /// Apply a difficulty hint from the miner (mining.suggest_difficulty, the
    /// "d=N" password token): vardiff continues from it. Clamps to [min, max]
    /// and the ceiling. Ignored while a fixed difficulty is set.
    void set_difficulty_hint(double hint);

    /// Fixed difficulty for the session ("ADDR+N"): vardiff stops, the
    /// difficulty is `difficulty` bounded by [min, max] and the ceiling
    /// (rounded down to the power-of-two grid with the hashrate vardiff).
    /// A value <= 0 clears it (vardiff resumes from the current difficulty).
    void set_fixed_difficulty(double difficulty);
    bool is_fixed_difficulty() const;

    /// Ceiling from the pool-share difficulty of the job being issued (p2pool
    /// work.py: target = max(target, share_info['bits'].target)). Lowers the
    /// current difficulty at once when it is above; a vardiff difficulty is
    /// never raised by it, a fixed one is re-derived from its request. With
    /// the hashrate vardiff the bound is rounded down to its power-of-two
    /// grid. 0 = none known.
    void set_difficulty_ceiling(double ceiling);
    double get_difficulty_ceiling() const;

    /// Check if difficulty changed (caller should resend set_difficulty).
    /// Returns true if current_difficulty_ was updated.
    bool difficulty_changed_since(double old_difficulty) const;

private:
    void adjust_difficulty(time_point steady_now, double epoch_now);
    // Hashrate-based vardiff helpers (all take epoch-seconds 'now'; caller holds shares_mutex_).
    void   record_share_for_hashrate(double issued_difficulty, double now);
    double get_recent_hashrate(double now) const;   // EWMA H/s (600s get_current_hashrate() untouched)
    void   set_difficulty_from_hashrate(double now);
};

} // namespace hashrate
} // namespace c2pool