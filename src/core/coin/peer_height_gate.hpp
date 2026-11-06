// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The network tip height peers report in their version messages, as the
/// embedded header chains use it (LTC, DOGE): it switches no check (every
/// header above the checkpoint has its PoW verified whatever a peer
/// reports) and only sizes header batches and the sync progress line.
/// One peer's claim does not stand for the network's: the median of the
/// last REPORTS reports, at most what the chain can have grown to since our
/// best-work tip (one block per quarter of the target spacing since the
/// tip's timestamp, plus a retarget window of 2,016).

#include <algorithm>
#include <array>
#include <cstdint>
#include <mutex>

namespace core {
namespace coin {

class PeerHeightGate {
public:
    static constexpr size_t REPORTS = 8;
    static constexpr uint64_t GROWTH_MARGIN = 2016;

    void report(uint32_t height)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_reports[m_next % REPORTS] = height;
        ++m_next;
    }

    /// The median report (the upper median of an even count), 0 without one.
    uint32_t median() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        const size_t n = std::min<uint64_t>(m_next, REPORTS);
        if (n == 0)
            return 0;
        std::array<uint32_t, REPORTS> v{};
        std::copy(m_reports.begin(), m_reports.begin() + static_cast<std::ptrdiff_t>(n), v.begin());
        std::sort(v.begin(), v.begin() + static_cast<std::ptrdiff_t>(n));
        return v[n / 2];
    }

    /// median(), at most tip_height + (now - tip_time) / (spacing / 4) + GROWTH_MARGIN.
    uint32_t bounded(uint32_t tip_height, uint64_t tip_time, uint64_t now, uint64_t target_spacing) const
    {
        const uint64_t quarter = std::max<uint64_t>(1, target_spacing / 4);
        const uint64_t bound = uint64_t(tip_height) + (now > tip_time ? (now - tip_time) / quarter : 0) + GROWTH_MARGIN;
        return static_cast<uint32_t>(std::min<uint64_t>({uint64_t(median()), bound, UINT32_MAX}));
    }

private:
    mutable std::mutex m_mu;
    std::array<uint32_t, REPORTS> m_reports{};
    uint64_t m_next{0};
};

} // namespace coin
} // namespace core
