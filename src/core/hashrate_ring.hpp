// HashrateRing — per-miner rolling hashrate tracker.
//
// Populates hashrate_hps / hashrate_series for the
// /pplns/current + /pplns/miner/<addr> endpoints per
// frstrtr/the/docs/c2pool-pplns-view-module-task.md §5.1, §5.2.
//
// Convention: a share at difficulty D represents D × 2^32 hashes
// of work on average (matches p2pool's target_to_average_attempts
// and the network_hashrate formulas already in web_server.cpp).
// Aggregated over an interval, hashes-per-second is
// sum(difficulty × 2^32) / elapsed_sec.
//
// Memory budget: one circular buffer per miner, capped at
// kMaxSamplesPerMiner = 512 (plenty for a 1-hour window at
// typical share cadence). Samples beyond kWindowSec are evicted
// lazily on record + query — no background cleanup thread.

#pragma once

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <deque>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

class HashrateRing {
public:
    struct SeriesPoint {
        int64_t t;
        double  hps;
    };

    static constexpr int    kWindowSec = 3600;
    static constexpr size_t kMaxSamplesPerMiner = 512;
    // 2^32 — hashes per share at difficulty 1.
    static constexpr double kHashesPerDifficultyShare = 4294967296.0;

    void record(const std::string& miner, double difficulty, int64_t t) {
        if (miner.empty() || !(difficulty > 0)) return;
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        auto& samples = m_samples[miner];
        samples.emplace_back(Sample{t, difficulty});
        // Evict old + enforce cap — keep samples inside (now - kWindowSec, now].
        const int64_t cutoff = t - kWindowSec;
        while (!samples.empty() && samples.front().t <= cutoff) {
            samples.pop_front();
        }
        while (samples.size() > kMaxSamplesPerMiner) {
            samples.pop_front();
        }
    }

    /// Rolling H/s over the trailing `window_sec` seconds (default
    /// kWindowSec). Returns 0 when no samples are in range.
    double hashrate(const std::string& miner,
                    int64_t now = 0,
                    int window_sec = kWindowSec) const {
        if (now <= 0) now = static_cast<int64_t>(std::time(nullptr));
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        auto it = m_samples.find(miner);
        if (it == m_samples.end()) return 0.0;
        const int64_t cutoff = now - window_sec;
        double sum_diff = 0;
        int64_t first_t = 0;
        for (const auto& s : it->second) {
            if (s.t <= cutoff) continue;
            if (first_t == 0) first_t = s.t;
            sum_diff += s.difficulty;
        }
        if (sum_diff <= 0 || first_t == 0) return 0.0;
        // Divisor: seconds from the first sample in range to `now`.
        // Bounded at 1 to avoid infinity on a single recent sample.
        const double elapsed = std::max<double>(1.0, now - first_t);
        return sum_diff * kHashesPerDifficultyShare / elapsed;
    }

    /// Bucketed series over the trailing window. Returns `buckets`
    /// points spaced evenly. Empty buckets are still emitted (hps = 0)
    /// so the client's sparkline has a consistent x-axis.
    std::vector<SeriesPoint> series(const std::string& miner,
                                    int64_t now = 0,
                                    int window_sec = kWindowSec,
                                    int buckets = 30) const {
        if (now <= 0) now = static_cast<int64_t>(std::time(nullptr));
        if (buckets <= 0) buckets = 30;
        std::vector<SeriesPoint> out;
        out.reserve(static_cast<size_t>(buckets));
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        const int bucket_sec = std::max(1, window_sec / buckets);
        const int64_t start = now - (int64_t)buckets * bucket_sec;

        std::vector<double> sums(static_cast<size_t>(buckets), 0.0);
        auto it = m_samples.find(miner);
        if (it != m_samples.end()) {
            for (const auto& s : it->second) {
                if (s.t <= start || s.t > now) continue;
                int idx = static_cast<int>((s.t - start) / bucket_sec);
                if (idx < 0) idx = 0;
                if (idx >= buckets) idx = buckets - 1;
                sums[static_cast<size_t>(idx)] += s.difficulty;
            }
        }
        for (int i = 0; i < buckets; ++i) {
            const int64_t bucket_end = start + (int64_t)(i + 1) * bucket_sec;
            const double hps = sums[static_cast<size_t>(i)]
                * kHashesPerDifficultyShare
                / static_cast<double>(bucket_sec);
            out.push_back({bucket_end, hps});
        }
        return out;
    }

    /// Drop stale miners that haven't submitted a share within
    /// `kWindowSec` — bounds the total map size. Safe to call
    /// occasionally from a low-priority path.
    void prune(int64_t now = 0) {
        if (now <= 0) now = static_cast<int64_t>(std::time(nullptr));
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        const int64_t cutoff = now - kWindowSec;
        for (auto it = m_samples.begin(); it != m_samples.end(); ) {
            while (!it->second.empty() && it->second.front().t <= cutoff) {
                it->second.pop_front();
            }
            if (it->second.empty()) it = m_samples.erase(it);
            else                    ++it;
        }
    }

    size_t miner_count() const {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        return m_samples.size();
    }

private:
    struct Sample {
        int64_t t;
        double  difficulty;
    };

    mutable std::shared_mutex m_mutex;
    std::unordered_map<std::string, std::deque<Sample>> m_samples;
};
