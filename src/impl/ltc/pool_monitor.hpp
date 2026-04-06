#pragma once

// Phase 3L: Log-based pool monitoring for attack detection.
//
// Emits structured [MONITOR] log lines every status cycle (~30s).
// All output is grep-friendly — no HTTP endpoints, no web changes.
//
// Log line prefixes:
//   [MONITOR-HASHRATE]    — pool hashrate vs moving average
//   [MONITOR-CONC]        — per-address work concentration
//   [MONITOR-EMERGENCY]   — emergency decay triggers / share gaps
//   [MONITOR-DIFF]        — difficulty anomaly detection
//   [MONITOR-SUMMARY]     — one-line health summary
//
// Port of p2pool-v36 p2pool/monitor.py (commit d831a045).

#include "config_pool.hpp"
#include "share_tracker.hpp"
#include "share_check.hpp"
#include "core/address_utils.hpp"

#include <core/log.hpp>
#include <core/target_utils.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ltc
{

// SI-suffix formatter for hashrate values
inline std::string fmt_hashrate(double n)
{
    static const char* suffixes[] = {"", "k", "M", "G", "T", "P"};
    for (const char* s : suffixes)
    {
        if (std::abs(n) < 1000.0)
        {
            std::ostringstream os;
            os.precision(1);
            os << std::fixed << n << s;
            return os.str();
        }
        n /= 1000.0;
    }
    std::ostringstream os;
    os.precision(1);
    os << std::fixed << n << "E";
    return os.str();
}

class PoolMonitor
{
public:
    // Configurable thresholds
    static constexpr double CONCENTRATION_WARN_PCT  = 25.0;
    static constexpr double CONCENTRATION_ALERT_PCT = 40.0;
    static constexpr double HASHRATE_SPIKE_FACTOR   = 1.5;
    static constexpr double HASHRATE_DROP_FACTOR    = 0.5;
    static constexpr double DIFF_ANOMALY_FACTOR     = 2.0;

    PoolMonitor() = default;

    // Run one monitoring cycle. Returns number of alerts emitted.
    int run_cycle(ShareTracker& tracker, const uint256& best_share_hash)
    {
        ++cycle_;
        int alerts = 0;

        if (best_share_hash.IsNull())
            return 0;

        auto [height, last] = tracker.chain.get_height_and_last(best_share_hash);
        if (height < 10)
            return 0;

        alerts += check_hashrate(tracker, best_share_hash, height);
        alerts += check_concentration(tracker, best_share_hash, height);
        alerts += check_share_gap(tracker, best_share_hash);
        alerts += check_difficulty(tracker, best_share_hash, height);

        // Summary line
        const char* status = (alerts == 0) ? "OK" : "ALERT";
        uint32_t gap = 0;
        {
            uint32_t ts = 0;
            tracker.chain.get_share(best_share_hash).invoke([&](auto* obj) {
                ts = obj->m_timestamp;
            });
            auto now = static_cast<uint32_t>(std::time(nullptr));
            gap = (now > ts) ? (now - ts) : 0;
        }
        LOG_INFO << "[MONITOR-SUMMARY] cycle=" << cycle_
                 << " height=" << height
                 << " gap=" << gap << "s"
                 << " status=" << status
                 << " alerts=" << alerts;

        return alerts;
    }

private:
    uint64_t cycle_ = 0;
    uint64_t emergency_count_ = 0;

    // 1-hour rolling hashrate history
    struct HrSample { int64_t ts; double hr; };
    std::vector<HrSample> hr_history_;

    // ── Hashrate spike/drop detection ──────────────────────────────

    int check_hashrate(ShareTracker& tracker, const uint256& best, int32_t height)
    {
        int alerts = 0;
        int32_t lookbehind = std::min(height - 1,
            static_cast<int32_t>(3600 / PoolConfig::share_period()));
        if (lookbehind < 2)
            return 0;

        auto aps = tracker.get_pool_attempts_per_second(best, lookbehind);
        double real_att_s = static_cast<double>(aps.GetLow64());

        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        hr_history_.push_back({now, real_att_s});

        // Keep 1 hour
        auto cutoff = now - 3600;
        hr_history_.erase(
            std::remove_if(hr_history_.begin(), hr_history_.end(),
                [cutoff](const HrSample& s) { return s.ts < cutoff; }),
            hr_history_.end());

        if (hr_history_.size() < 3)
            return 0;

        double sum = 0;
        for (auto& s : hr_history_) sum += s.hr;
        double avg_hr = sum / static_cast<double>(hr_history_.size());

        if (avg_hr > 0)
        {
            double ratio = real_att_s / avg_hr;
            if (ratio > HASHRATE_SPIKE_FACTOR)
            {
                LOG_WARNING << "[MONITOR-HASHRATE] ALERT spike=" << ratio
                            << "x current=" << fmt_hashrate(real_att_s) << "H/s"
                            << " avg_1h=" << fmt_hashrate(avg_hr) << "H/s";
                ++alerts;
            }
            else if (ratio < HASHRATE_DROP_FACTOR)
            {
                LOG_WARNING << "[MONITOR-HASHRATE] ALERT drop=" << ratio
                            << "x current=" << fmt_hashrate(real_att_s) << "H/s"
                            << " avg_1h=" << fmt_hashrate(avg_hr) << "H/s";
                ++alerts;
            }
            else if (cycle_ % 10 == 0)
            {
                LOG_INFO << "[MONITOR-HASHRATE] ok ratio=" << ratio
                         << " current=" << fmt_hashrate(real_att_s) << "H/s"
                         << " avg_1h=" << fmt_hashrate(avg_hr) << "H/s"
                         << " samples=" << hr_history_.size();
            }
        }
        return alerts;
    }

    // ── Per-address work concentration ─────────────────────────────

    int check_concentration(ShareTracker& tracker, const uint256& best, int32_t height)
    {
        int alerts = 0;

        struct Window { const char* label; int32_t depth; };
        std::vector<Window> windows;
        windows.push_back({"short", std::min(height, 100)});
        windows.push_back({"medium", std::min(height, 720)});
        if (height >= static_cast<int32_t>(PoolConfig::real_chain_length()))
            windows.push_back({"full", std::min(height,
                static_cast<int32_t>(PoolConfig::real_chain_length()))});

        for (auto& [label, depth] : windows)
        {
            std::map<std::vector<unsigned char>, double> addr_work;
            double total_work = 0;

            auto chain_view = tracker.chain.get_chain(best, depth);
            for (auto [hash, data] : chain_view)
            {
                double w = 0;
                std::vector<unsigned char> addr_bytes;
                data.share.invoke([&](auto* obj) {
                    auto target = chain::bits_to_target(obj->m_bits);
                    auto att = chain::target_to_average_attempts(target);
                    w = static_cast<double>(att.GetLow64());
                    addr_bytes = get_share_script(obj);
                });
                addr_work[addr_bytes] += w;
                total_work += w;
            }

            if (total_work <= 0)
                continue;

            for (auto& [addr, work] : addr_work)
            {
                double pct = 100.0 * work / total_work;
                // Convert scriptPubKey to human-readable address
                std::string addr_str = core::script_to_address(
                    addr, true /*is_litecoin*/, PoolConfig::is_testnet);
                if (addr_str.empty()) {
                    // Fallback: show truncated script hex for non-standard scripts
                    for (size_t i = 0; i < std::min(addr.size(), size_t(15)); ++i) {
                        char buf[3];
                        snprintf(buf, sizeof(buf), "%02x", addr[i]);
                        addr_str += buf;
                    }
                    addr_str = "script:" + addr_str;
                }
                if (pct >= CONCENTRATION_ALERT_PCT)
                {
                    LOG_WARNING << "[MONITOR-CONC] ALERT addr=" << addr_str
                                << " pct=" << pct << "%"
                                << " window=" << label << "(" << depth << ")";
                    ++alerts;
                }
                else if (pct >= CONCENTRATION_WARN_PCT)
                {
                    LOG_WARNING << "[MONITOR-CONC] WARN addr=" << addr_str
                                << " pct=" << pct << "%"
                                << " window=" << label << "(" << depth << ")";
                }
            }

            // Every 10th cycle, log top-3 miners
            if (cycle_ % 10 == 0)
            {
                std::vector<std::pair<std::vector<unsigned char>, double>> sorted_addrs(
                    addr_work.begin(), addr_work.end());
                std::sort(sorted_addrs.begin(), sorted_addrs.end(),
                    [](auto& a, auto& b) { return a.second > b.second; });

                std::ostringstream top3;
                int count = 0;
                for (auto& [a, w] : sorted_addrs)
                {
                    if (count >= 3) break;
                    if (count > 0) top3 << " ";
                    std::string display = core::script_to_address(
                        a, true, PoolConfig::is_testnet);
                    if (display.empty()) {
                        for (size_t i = 0; i < std::min(a.size(), size_t(8)); ++i) {
                            char buf[3]; snprintf(buf, sizeof(buf), "%02x", a[i]);
                            display += buf;
                        }
                    }
                    top3 << display << ":" << (100.0 * w / total_work) << "%";
                    ++count;
                }
                LOG_INFO << "[MONITOR-CONC] top3 window=" << label << "(" << depth << ") " << top3.str();
            }
        }
        return alerts;
    }

    // ── Share gap / emergency decay detection ──────────────────────

    int check_share_gap(ShareTracker& tracker, const uint256& best)
    {
        int alerts = 0;
        uint32_t ts = 0;
        tracker.chain.get_share(best).invoke([&](auto* obj) {
            ts = obj->m_timestamp;
        });

        auto now = static_cast<uint32_t>(std::time(nullptr));
        uint32_t gap = (now > ts) ? (now - ts) : 0;
        auto emergency_threshold = PoolConfig::share_period() * 20;

        if (gap > emergency_threshold)
        {
            ++emergency_count_;
            LOG_WARNING << "[MONITOR-EMERGENCY] ALERT gap=" << gap
                        << "s threshold=" << emergency_threshold
                        << "s emergency_count=" << emergency_count_;
            ++alerts;
        }
        else if (gap > PoolConfig::share_period() * 10)
        {
            LOG_WARNING << "[MONITOR-EMERGENCY] WARN gap=" << gap
                        << "s (approaching threshold=" << emergency_threshold << "s)";
        }
        return alerts;
    }

    // ── Difficulty anomaly detection ───────────────────────────────

    int check_difficulty(ShareTracker& tracker, const uint256& best, int32_t height)
    {
        int alerts = 0;
        int32_t lookbehind = std::min(height - 1,
            static_cast<int32_t>(PoolConfig::TARGET_LOOKBEHIND));
        if (lookbehind < 2)
            return 0;

        auto aps = tracker.get_pool_attempts_per_second(
            best, lookbehind, /*min_work=*/true);
        if (aps.IsNull())
            return 0;

        // expected_target = 2^256 / (SHARE_PERIOD * aps) - 1
        uint288 two_256;
        two_256.SetHex("10000000000000000000000000000000000000000000000000000000000000000");
        uint288 divisor = aps * static_cast<uint32_t>(PoolConfig::share_period());
        if (divisor.IsNull())
            return 0;
        uint288 expected_288 = two_256 / divisor;

        // actual_target = max_target from best share
        uint256 actual_target;
        tracker.chain.get_share(best).invoke([&](auto* obj) {
            actual_target = chain::bits_to_target(obj->m_max_bits);
        });

        double expected_d = static_cast<double>(expected_288.GetLow64());
        double actual_d = static_cast<double>(actual_target.GetLow64());
        if (expected_d <= 0)
            return 0;

        double ratio = actual_d / expected_d;

        if (ratio > DIFF_ANOMALY_FACTOR)
        {
            LOG_WARNING << "[MONITOR-DIFF] ALERT target_ratio=" << ratio
                        << " (actual easier than expected by " << ((ratio - 1) * 100) << "%)";
            ++alerts;
        }
        else if (ratio < 1.0 / DIFF_ANOMALY_FACTOR)
        {
            LOG_WARNING << "[MONITOR-DIFF] ALERT target_ratio=" << ratio
                        << " (actual harder than expected by " << ((1.0 / ratio - 1) * 100) << "%)";
            ++alerts;
        }
        else if (cycle_ % 10 == 0)
        {
            LOG_INFO << "[MONITOR-DIFF] ok target_ratio=" << ratio
                     << " pool=" << fmt_hashrate(static_cast<double>(aps.GetLow64())) << "H/s";
        }
        return alerts;
    }
};

} // namespace ltc
