// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The embedded DOGE accrual set's 1-s cold-start tick (main_ltc.cpp wires
/// it to the DOGE header chain, UTXO set and BlockDownload; the KATs to
/// fakes):
///   - decide once, when the header chain is synced and caught up
///     (cold_start_ready): arm the Bootstrap over the plan's range
///     (cold_start_plan), or none for a warm set;
///   - while the Bootstrap runs: arm it again at the tip when it fell more
///     than `blocks` + its window behind (the partial set wiped first),
///     else take the tip into its range and move its download on;
///   - otherwise, while the set is behind the header chain's tip, chase its
///     next block: after a second of lag ask best + 1 of one peer, every 2 s,
///     of every peer from the fourth ask (the LTC lane's utxo_catchup rule).
///     The DOGE lane has no gap fill and nothing else re-asks a body: a tip
///     body its announcer never sent, a restart between a header and its
///     body, a header that came while the Bootstrap drained its last block
///     each left a hole for good (FRESH-VERIFY M1), and the block's
///     transactions in the DOGE mempool and in every merged template.

#include "utxo_order.hpp"

#include <core/coin/block_bootstrapper.hpp>
#include <core/coin/block_download.hpp>
#include <core/log.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>

namespace ltc {
namespace coin {

struct ColdStartTickHost {
    using Clock = std::chrono::steady_clock;

    /// The header chain: synced (tip age < 24 h), its tip's age (s), height.
    std::function<bool()> synced;
    std::function<int64_t()> tip_age_s;
    std::function<uint32_t()> tip;
    /// The UTXO set's best height (0: empty) and whether it holds no block.
    std::function<uint32_t()> utxo_best;
    std::function<bool()> utxo_empty;
    /// Wipe the partial set before a re-arm (false: failed, nothing armed).
    std::function<bool()> wipe;
    /// The Bootstrap was armed over [from, to], `asked` heights requested
    /// (log; start the fill's stall timer).
    std::function<void(uint32_t from, uint32_t to, uint32_t asked)> armed;
    /// Ask the best chain's block at height h of one peer (false: none) /
    /// of every peer, outside the Bootstrap's download.
    std::function<bool(uint32_t)> ask_one;
    std::function<void(uint32_t)> ask_all;
    /// The clock (optional; tests drive it).
    std::function<Clock::time_point()> now;
};

template <typename BlockT>
class AccrualColdStart {
public:
    using Fill = core::coin::BlockBootstrapState<BlockT>;
    using Clock = ColdStartTickHost::Clock;

    AccrualColdStart(Fill& fill, core::coin::BlockDownload& dl, uint32_t blocks, ColdStartTickHost host,
                     std::string tag = "[EMB-DOGE]")
        : m_fill(fill), m_dl(dl), m_blocks(blocks), m_host(std::move(host)), m_tag(std::move(tag))
    {
    }

    /// Chasing the set's next block: a second of lag before the first ask,
    /// then one every CHASE_EVERY; every peer from the CHASE_ONE_PEER+1-th.
    static constexpr std::chrono::seconds CHASE_LAG{1};
    static constexpr std::chrono::seconds CHASE_EVERY{2};
    static constexpr uint32_t CHASE_ONE_PEER = 3;

    /// The cold start has been decided (armed, or warm).
    bool decided() const { return m_decided; }

    /// The 1-s tick (the fill's thread).
    void tick()
    {
        const auto t = now();
        if (!m_decided) {
            if (!m_host.synced()) {
                m_synced_since = {};
                return;
            }
            if (m_synced_since == Clock::time_point{})
                m_synced_since = t;
            const int64_t synced_for =
                std::chrono::duration_cast<std::chrono::seconds>(t - m_synced_since).count();
            if (!cold_start_ready(true, m_host.tip_age_s(), synced_for))
                return;
            m_decided = true;
            if (m_fill.active)
                return;
            const uint32_t best = m_host.utxo_best();
            const ColdStart plan = cold_start_plan(m_blocks, true, m_host.tip(), best);
            if (plan.action != ColdStart::Action::Arm) {
                LOG_INFO << m_tag << " UTXO warm restart: best=" << best << " — no bootstrap needed";
                return;
            }
            arm(plan.from, plan.to);
            return;
        }
        if (!m_fill.active) {
            chase(t);
            return;
        }
        m_chase = {};
        const uint32_t tip = m_host.tip();
        if (auto r = cold_start_rearm(m_fill, tip, m_blocks)) {
            LOG_WARNING << m_tag << " Bootstrap at h=" << m_fill.next_height << " is " << tip - m_fill.next_height
                        << " blocks behind the tip h=" << tip << ": arming it again at [" << r->first << ".."
                        << r->second << "]";
            if (!m_host.utxo_empty() && !m_host.wipe())
                return;
            arm(r->first, r->second);
            return;
        }
        ordered_extend(m_fill, tip);
        m_dl.tick(m_fill);
    }

private:
    Clock::time_point now() const { return m_host.now ? m_host.now() : Clock::now(); }

    /// No fill runs: ask for the set's next block while it is behind the tip.
    void chase(Clock::time_point t)
    {
        const uint32_t best = m_host.utxo_best();
        const uint32_t tip = m_host.tip();
        if (best == 0 || best >= tip) {
            m_chase = {};
            return;
        }
        const uint32_t next = best + 1;
        if (m_chase.height != next) {
            m_chase = Chase{next, t, {}, 0};
            return;
        }
        if (t - m_chase.since < CHASE_LAG
            || (m_chase.last != Clock::time_point{} && t - m_chase.last < CHASE_EVERY))
            return;
        const bool all = m_chase.tries >= CHASE_ONE_PEER;
        if (all || !m_host.ask_one(next))
            m_host.ask_all(next);
        LOG_INFO << m_tag << " UTXO behind the tip (h=" << best << ", tip h=" << tip << ") — requesting h="
                 << next << (all ? " from all peers" : "");
        ++m_chase.tries;
        m_chase.last = t;
    }

    struct Chase {
        uint32_t          height{0};
        Clock::time_point since{};
        Clock::time_point last{};
        uint32_t          tries{0};
    };

    void arm(uint32_t from, uint32_t to)
    {
        cold_start_arm(m_fill, from, to);
        m_dl.reset();
        const uint32_t asked = m_dl.refill(m_fill);
        if (m_host.armed)
            m_host.armed(from, to, asked);
    }

    Fill&                      m_fill;
    core::coin::BlockDownload& m_dl;
    const uint32_t             m_blocks;
    ColdStartTickHost          m_host;
    std::string                m_tag;
    bool                       m_decided{false};
    Clock::time_point          m_synced_since{};
    Chase                      m_chase{};
};

} // namespace coin
} // namespace ltc
