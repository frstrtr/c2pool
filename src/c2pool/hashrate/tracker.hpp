#pragma once

#include <chrono>
#include <deque>
#include <mutex>
#include <ctime>
#include <nlohmann/json.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>
#include <core/coin_params.hpp>

namespace c2pool {
namespace hashrate {

/**
 * @brief Per-connection hashrate tracking and aggressive vardiff.
 *
 * Modelled after Python p2pool's per-connection pseudoshare vardiff:
 *   - Records high-resolution timestamps of recent share submissions.
 *   - After every share, checks whether the share rate diverges from target.
 *   - Quick-ramp: if 2 shares come in < target/3 time, double difficulty.
 *   - Normal adjust: after N shares, scale difficulty by actual/target ratio.
 *   - Timeout fallback: if no shares for 5x target time, halve difficulty.
 */
class HashrateTracker {
private:
    using clock = std::chrono::steady_clock;
    using time_point = clock::time_point;

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

    // Vardiff tuning — instance fields so each coin can override.
    // Defaults match upstream p2pool-merged-v36 (LTC): 12-share trigger,
    // 10× timeout, clip(0.1, 10.0), N−1 interval denominator, no quickup.
    // Dash overrides these in dash::stratum::Session via set_vardiff_params.
    uint32_t vardiff_trigger_   = 12;
    double   vardiff_timeout_   = 10.0;
    double   vardiff_min_adj_   = 0.1;
    double   vardiff_max_adj_   = 10.0;
    uint32_t vardiff_quickup_n_ = 0;     // 0 = disabled
    double   vardiff_quickup_div_ = 3.0;
    bool     vardiff_full_window_ = false; // false = N−1 (LTC), true = N (Dash)

    // Whether vardiff auto-adjustment is active (only for stratum per-connection trackers)
    bool vardiff_enabled_ = false;

    // Statistics
    uint64_t total_mining_shares_submitted_ = 0;
    uint64_t total_mining_shares_accepted_ = 0;
    double total_work_done_ = 0.0;

    // Internal helper — must be called with shares_mutex_ already held
    double get_current_hashrate_unlocked() const;

public:
    void record_mining_share_submission(double difficulty, bool accepted);
    void record_mining_share(const uint256& hash, uint64_t difficulty, uint64_t timestamp);

    double get_current_difficulty() const;
    double get_current_hashrate() const;
    nlohmann::json get_statistics() const;

    void set_difficulty_bounds(double min_difficulty, double max_difficulty);
    void set_target_time_per_mining_share(double target_seconds);
    void enable_vardiff(bool enabled = true);

    /// Apply per-coin vardiff tuning. Defaults in CoinParams::VardiffConfig
    /// already match upstream p2pool-merged-v36 (LTC) behavior, so calling
    /// this from LTC is a no-op. Dash calls with its p2pool-dash-tuned
    /// params (10s share rate, 8-share trigger, quickup, 0.5/2.0 clip).
    void set_vardiff_params(const core::CoinParams::VardiffConfig& cfg);

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

    /// Apply a difficulty hint from the miner (mining.suggest_difficulty).
    /// Clamps to [min, max] bounds and updates current difficulty.
    void set_difficulty_hint(double hint);

    /// Check if difficulty changed (caller should resend set_difficulty).
    /// Returns true if current_difficulty_ was updated.
    bool difficulty_changed_since(double old_difficulty) const;

private:
    void adjust_difficulty();
};

} // namespace hashrate
} // namespace c2pool
