// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The merged (aux) chain payouts for one rebuild of the merged block.
///
/// They are the PPLNS split of the block's coinbase value by weights taken
/// from the sharechain tracker under its lock, which the compute thread holds
/// exclusively while it processes shares (on the sg-ltc canary for 15-47 s
/// at a stretch in steady state, 839 s while syncing). A rebuild that could
/// not take the lock got no payouts, and the chain went out of the
/// commitment for the stretch: no DOGE block could be found (~10 % of the
/// time).
///
/// The weights depend on the best share (and on how deep the tracker is
/// below it: chain_len = min(height(best), real_chain_length)); the amounts
/// depend on the weights and the coinbase value alone. So:
///   - the compute thread publishes the weights of each best share it
///     chooses, while it holds the lock (publish);
///   - a rebuild derives the amounts for its coinbase value from the weights
///     of the current best share without any lock; a new value (the fees
///     changed) is derived again, exactly;
///   - no weights for the current best share yet: compute them under the
///     lock if it is free, waiting for it up to max_wait where waiting is
///     allowed (the merged-mining RPC thread, not the network thread);
///   - still busy: the weights the compute thread published last. Their best
///     share is the tip of the best chain as the compute thread last decided
///     it (the current one differs only in the moment between that decision
///     and its publication, or when best_share_hash() falls back to another
///     verified head). A payout set seconds stale is a valid merged coinbase
///     (it sums to the value) and peers do not reconstruct it;
///   - else no payouts, with the reason ("tracker_busy").

#include <core/uint256.hpp>

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace c2pool {
namespace merged {

class MergedPayoutSource {
public:
    using Payouts = std::vector<std::pair<std::vector<unsigned char>, uint64_t>>;
    /// The amounts for a coinbase value, from weights taken under the lock.
    using Derive = std::function<Payouts(uint64_t coinbase_value)>;

    struct Weights {
        uint256 best;
        uint32_t chain_id{0};
        int32_t chain_len{0};
        Derive derive;   // empty: no weights for this best share (no payouts)
    };

    struct Stats {
        uint64_t published{0};           // weights published by the compute thread
        uint64_t from_weights{0};        // payouts derived from weights already there (no lock)
        uint64_t computed{0};            // weights computed on request (lock taken)
        uint64_t reused_across_best{0};  // the last published weights, current best had none
        uint64_t busy{0};                // no weights at all: no payouts
    };

    explicit MergedPayoutSource(std::chrono::milliseconds max_wait = std::chrono::milliseconds(250),
                                std::chrono::milliseconds step = std::chrono::milliseconds(5),
                                size_t keep = 8)
        : m_max_wait(max_wait), m_step(step), m_keep(keep)
    {
    }

    /// The compute thread, holding the tracker lock: the weights of the best
    /// share it just chose (or of the same one, deeper).
    void publish(Weights w)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_stats.published;
        m_latest[w.chain_id] = w;
        store_locked(std::move(w), /*authoritative=*/true);
    }

    /// try_compute() -> std::optional<Weights>: the weights for `best`, or
    /// nullopt when the tracker lock is busy. may_wait: this thread may block
    /// briefly. `miss` is set when the result is empty.
    template <typename TryCompute>
    Payouts get(const uint256& best, uint32_t chain_id, uint64_t value, bool may_wait,
                TryCompute&& try_compute, std::string& miss)
    {
        miss.clear();
        const auto deadline = std::chrono::steady_clock::now() + (may_wait ? m_max_wait : std::chrono::milliseconds(0));
        for (;;) {
            if (auto w = find(best, chain_id)) {
                bump(&Stats::from_weights);
                return derive(*w, value, miss);
            }
            if (auto computed = try_compute()) {
                bump(&Stats::computed);
                Weights w = std::move(*computed);
                if (w.derive) {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    store_locked(w, /*authoritative=*/false);
                }
                return derive(w, value, miss);
            }
            if (std::chrono::steady_clock::now() >= deadline)
                break;
            std::this_thread::sleep_for(m_step);
        }
        if (auto w = latest(chain_id)) {
            bump(&Stats::reused_across_best);
            return derive(*w, value, miss);
        }
        bump(&Stats::busy);
        miss = "tracker_busy";
        return {};
    }

    Stats stats() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_stats;
    }

    /// Payouts produced from weights of another best share than the current one.
    uint64_t reused() const { return stats().reused_across_best; }

private:
    static Payouts derive(const Weights& w, uint64_t value, std::string& miss)
    {
        Payouts p = w.derive ? w.derive(value) : Payouts{};
        if (p.empty())
            miss = "empty";
        return p;
    }

    void bump(uint64_t Stats::*field)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++(m_stats.*field);
    }

    /// One entry per (best, chain). A published one replaces what is there;
    /// one computed on request only if it is at least as deep (a request may
    /// race a publication of the same best share at a deeper chain_len).
    void store_locked(Weights w, bool authoritative)
    {
        for (auto& e : m_entries)
            if (e.best == w.best && e.chain_id == w.chain_id) {
                if (authoritative || w.chain_len >= e.chain_len)
                    e = std::move(w);
                return;
            }
        m_entries.push_back(std::move(w));
        while (m_entries.size() > m_keep)
            m_entries.pop_front();
    }

    std::optional<Weights> find(const uint256& best, uint32_t chain_id) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it = m_latest.find(chain_id);
        if (it != m_latest.end() && it->second.best == best)
            return it->second;
        for (const auto& e : m_entries)
            if (e.best == best && e.chain_id == chain_id)
                return e;
        return std::nullopt;
    }

    std::optional<Weights> latest(uint32_t chain_id) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it = m_latest.find(chain_id);
        if (it == m_latest.end())
            return std::nullopt;
        return it->second;
    }

    std::chrono::milliseconds m_max_wait;
    std::chrono::milliseconds m_step;
    size_t m_keep;
    mutable std::mutex m_mutex;
    std::deque<Weights> m_entries;
    std::map<uint32_t, Weights> m_latest;   // the last published weights per chain
    Stats m_stats;
};

} // namespace merged
} // namespace c2pool
