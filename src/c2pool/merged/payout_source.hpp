// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The merged (aux) chain payouts for one rebuild of the merged block.
///
/// They are computed under the sharechain tracker's lock, which the compute
/// thread holds exclusively while it processes shares. A non-blocking read
/// that finds it busy used to give no payouts: the rebuild then skipped the
/// chain and the miners' work could not be turned into a DOGE block until a
/// later rebuild got the lock (on the canary 15 % of the time).
///
/// The payouts are a function of (best share, chain, coinbase value): the
/// PPLNS window walks back from an immutable share, and the block target is
/// that share's. So:
///   - wait for the lock up to `max_wait` (only where waiting is allowed: the
///     merged-mining RPC thread, not the network thread);
///   - remember what was computed for a key;
///   - when the lock stays busy, reuse what was computed for the same key;
///   - else no payouts, with the reason ("tracker_busy").

#include <core/uint256.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
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

    explicit MergedPayoutSource(std::chrono::milliseconds max_wait = std::chrono::milliseconds(250),
                                std::chrono::milliseconds step = std::chrono::milliseconds(5),
                                size_t keep = 8)
        : m_max_wait(max_wait), m_step(step), m_keep(keep)
    {
    }

    /// try_compute() -> std::optional<Payouts>: the payouts, or nullopt when
    /// the tracker lock is busy. may_wait: this thread may block briefly.
    /// `miss` is set when the result is empty.
    template <typename TryCompute>
    Payouts get(const uint256& best, uint32_t chain_id, uint64_t value, bool may_wait,
                TryCompute&& try_compute, std::string& miss)
    {
        miss.clear();
        const auto deadline = std::chrono::steady_clock::now() + (may_wait ? m_max_wait : std::chrono::milliseconds(0));
        for (;;) {
            if (auto computed = try_compute()) {
                remember(best, chain_id, value, *computed);
                if (computed->empty())
                    miss = "empty";
                return std::move(*computed);
            }
            if (std::chrono::steady_clock::now() >= deadline)
                break;
            std::this_thread::sleep_for(m_step);
        }
        if (auto again = recall(best, chain_id, value)) {
            ++m_reused;
            return std::move(*again);
        }
        miss = "tracker_busy";
        return {};
    }

    /// Results reused because the lock stayed busy.
    uint64_t reused() const { return m_reused.load(std::memory_order_relaxed); }

private:
    struct Entry {
        uint256 best;
        uint32_t chain_id;
        uint64_t value;
        Payouts payouts;
    };

    void remember(const uint256& best, uint32_t chain_id, uint64_t value, const Payouts& p)
    {
        if (p.empty())
            return;
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& e : m_entries)
            if (e.best == best && e.chain_id == chain_id && e.value == value) {
                e.payouts = p;
                return;
            }
        m_entries.push_back({best, chain_id, value, p});
        while (m_entries.size() > m_keep)
            m_entries.pop_front();
    }

    std::optional<Payouts> recall(const uint256& best, uint32_t chain_id, uint64_t value)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& e : m_entries)
            if (e.best == best && e.chain_id == chain_id && e.value == value)
                return e.payouts;
        return std::nullopt;
    }

    std::chrono::milliseconds m_max_wait;
    std::chrono::milliseconds m_step;
    size_t m_keep;
    std::mutex m_mutex;
    std::deque<Entry> m_entries;
    std::atomic<uint64_t> m_reused{0};
};

} // namespace merged
} // namespace c2pool
