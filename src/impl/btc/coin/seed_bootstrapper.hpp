// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// SeedBootstrapper — a repeating, rate-limited seed-candidate refill policy.
///
/// WHY THIS EXISTS
///   The shared merged::CoinPeerManager arms its fixed/HTTP seed fallback
///   exactly once (a 60s/90s one-shot that never re-arms), and gates that one
///   shot on the address *table* size rather than on live connections. A
///   restored peer DB full of stale entries therefore suppresses the single
///   fallback without a single live peer ever existing — permanent silent
///   starvation. (Two real defects in the shared shape; fixing them there is a
///   separate, fleet-wide change.)
///
///   BTC does not inherit that defect: NodeImpl::try_connect_peers already
///   counts ESTABLISHED outbound (not table entries) and already runs a 30s
///   maintenance loop. So bootstrap here is NOT a new lifecycle with its own
///   timer — it is a tick-driven candidate-refill escalation hung off that
///   existing exhaustion branch. Each maintenance tick, this policy decides
///   whether the normal dial path has run dry long enough to warrant injecting
///   more seed candidates, and if so injects a rate-limited, shuffled subset.
///
/// DESIGN NOTES
///   - Dependency-injected (PeerCounts / CandidateSink / Clock / tiers) so the
///     whole state machine is unit-testable with a fake clock and zero sockets.
///   - Built to be swappable for — or donatable to — the shared manager later,
///     not a permanent fork.
///
/// INVARIANT (assertable, and asserted in the unit test)
///   Seeds only ever ADD CANDIDATES (via the sink); they never connect. And no
///   term in this policy reads any *_seeds().size() as an admission/slot cap:
///   the per-tick injection cap is min(deficit_multiplier * deficit,
///   fixed_batch_cap). Growing a seed list tenfold cannot change how many peers
///   the node admits — it can only change which candidates are offered.

#include <algorithm>
#include <cstdint>
#include <functional>
#include <random>
#include <vector>

#include <core/netaddress.hpp>

namespace btc {
namespace coin {

class SeedBootstrapper
{
public:
    /// What the dial layer reports each tick. `candidates_exhausted` is the
    /// dual-condition guard: true iff the normal dial path could not fill the
    /// outbound deficit from its own good-peer set this cycle (in NodeImpl:
    /// get_good_peers(needed) yielded fewer than `needed`). Seeds fire only
    /// when starvation persists AND candidates are exhausted, so a node that is
    /// merely slow to connect through a healthy address book never seed-spams.
    struct Snapshot
    {
        std::size_t established_outbound = 0;
        std::size_t target_outbound = 0;
        bool candidates_exhausted = false;
    };

    enum class State { Healthy, Observing, Seeding, Cooldown };

    struct Result
    {
        State state = State::Healthy;
        std::size_t injected = 0;  // candidates handed to the sink this tick
        std::size_t tier = 0;      // tier index attempted this tick (if Seeding)
    };

    struct Config
    {
        // Starvation must persist this long (plus a per-node startup jitter)
        // before we escalate to seeds. Fixes permanent starvation; the jitter
        // decorrelates a fleet restarting together so they do not seed in lockstep.
        std::int64_t starve_secs = 30;
        std::int64_t startup_jitter_max = 30;

        // One maintenance cycle. After an injection we wait this long before
        // judging whether that tier admitted anyone (admission is async and
        // happens on the normal dial path, not here).
        std::int64_t settle_secs = 30;

        // Exponential backoff after a full-cycle failure, capped, with jitter.
        std::int64_t backoff_base_secs = 60;
        std::int64_t backoff_ceiling_secs = 1800;  // 30 min

        // failed_cycles resets only after ESTABLISHED >= target has HELD this
        // long continuously — hysteresis, so a flapping node cannot re-earn
        // full-rate seeding every time it briefly recovers.
        std::int64_t hysteresis_hold_secs = 600;   // 10 min

        // Per-tick injection cap: min(deficit_multiplier * deficit, fixed_batch_cap).
        std::size_t deficit_multiplier = 2;
        std::size_t fixed_batch_cap = 8;
    };

    using CountsFn = std::function<Snapshot()>;
    using SinkFn = std::function<void(const NetService&)>;
    using ClockFn = std::function<std::int64_t()>;  // unix seconds
    using TierFn = std::function<std::vector<NetService>()>;

    /// Tiers are tried in order (e.g. tier 0 = DNS, tier 1 = fixed). Keep the
    /// list open-ended so an HTTP tier is a data-plus-one-entry addition later.
    SeedBootstrapper(Config cfg,
                     CountsFn counts,
                     SinkFn sink,
                     ClockFn clock,
                     std::vector<TierFn> tiers,
                     std::uint64_t rng_seed)
        : m_cfg(cfg)
        , m_counts(std::move(counts))
        , m_sink(std::move(sink))
        , m_clock(std::move(clock))
        , m_tiers(std::move(tiers))
        , m_rng(rng_seed)
    {
        std::uniform_int_distribution<std::int64_t> jd(0, m_cfg.startup_jitter_max);
        m_startup_jitter = jd(m_rng);
    }

    /// Call once per NodeImpl dial-maintenance tick (the existing 30s loop).
    Result tick()
    {
        const std::int64_t now = m_clock();
        const Snapshot s = m_counts();
        Result r;

        // ---- Healthy: at or above target outbound -------------------------
        if (s.established_outbound >= s.target_outbound)
        {
            if (m_healthy_since == 0)
                m_healthy_since = now;
            if (now - m_healthy_since >= m_cfg.hysteresis_hold_secs)
                m_failed_cycles = 0;

            m_state = State::Healthy;
            m_starving_since = 0;
            m_tier = 0;
            m_last_attempt = 0;
            m_cooldown_until = 0;
            r.state = m_state;
            return r;
        }

        // ---- Starving -----------------------------------------------------
        m_healthy_since = 0;

        if (now < m_cooldown_until)
        {
            m_state = State::Cooldown;
            r.state = m_state;
            return r;
        }

        if (m_starving_since == 0)
        {
            m_starving_since = now;
            m_state = State::Observing;
            r.state = m_state;
            return r;
        }

        // Debounce: starvation must persist starve_secs + this node's jitter.
        if (now - m_starving_since < m_cfg.starve_secs + m_startup_jitter)
        {
            m_state = State::Observing;
            r.state = m_state;
            return r;
        }

        // Dual condition: only escalate to seeds when the normal dial path has
        // genuinely run out of its own candidates.
        if (!s.candidates_exhausted)
        {
            m_state = State::Observing;
            r.state = m_state;
            return r;
        }

        // Settle: after an attempt, wait one cycle before re-judging.
        if (m_last_attempt != 0 && now - m_last_attempt < m_cfg.settle_secs)
        {
            m_state = State::Seeding;
            r.state = m_state;
            r.tier = m_tier;
            return r;
        }

        // Still starving + exhausted a full settle after an attempt => that
        // tier did not admit anyone; advance to the next tier.
        if (m_last_attempt != 0)
        {
            ++m_tier;
            if (m_tier >= m_tiers.size())
            {
                // Full cycle exhausted (every tier tried, zero admissions):
                // back off exponentially, then observe afresh.
                ++m_failed_cycles;
                m_cooldown_until = now + backoff();
                m_tier = 0;
                m_starving_since = 0;
                m_last_attempt = 0;
                m_state = State::Cooldown;
                r.state = m_state;
                return r;
            }
        }

        // Inject this tier's candidates (candidates ONLY — never connect).
        std::vector<NetService> seeds = m_tiers.empty() ? std::vector<NetService>{}
                                                        : m_tiers[m_tier]();
        const std::size_t deficit = s.target_outbound - s.established_outbound;
        const std::size_t cap =
            std::min(m_cfg.deficit_multiplier * deficit, m_cfg.fixed_batch_cap);
        std::shuffle(seeds.begin(), seeds.end(), m_rng);
        const std::size_t n = std::min(cap, seeds.size());
        for (std::size_t i = 0; i < n; ++i)
            m_sink(seeds[i]);

        m_last_attempt = now;
        m_state = State::Seeding;
        r.state = m_state;
        r.injected = n;
        r.tier = m_tier;

        // An empty tier can never admit — let the next tick advance past it
        // immediately instead of burning a full settle interval on nothing.
        if (n == 0)
            m_last_attempt = now - m_cfg.settle_secs;

        return r;
    }

    // Introspection for tests / logging.
    State state() const { return m_state; }
    std::size_t tier() const { return m_tier; }
    unsigned failed_cycles() const { return m_failed_cycles; }
    std::int64_t startup_jitter() const { return m_startup_jitter; }

private:
    std::int64_t backoff()
    {
        unsigned e = m_failed_cycles > 0 ? m_failed_cycles - 1 : 0;
        if (e > 20) e = 20;  // guard the shift; ceiling clamps anyway
        std::int64_t b = m_cfg.backoff_base_secs * (static_cast<std::int64_t>(1) << e);
        if (b > m_cfg.backoff_ceiling_secs)
            b = m_cfg.backoff_ceiling_secs;
        std::uniform_int_distribution<std::int64_t> j(0, b / 4);  // +0..25% jitter
        return b + j(m_rng);
    }

    Config m_cfg;
    CountsFn m_counts;
    SinkFn m_sink;
    ClockFn m_clock;
    std::vector<TierFn> m_tiers;
    std::mt19937_64 m_rng;

    State m_state = State::Healthy;
    std::size_t m_tier = 0;
    std::int64_t m_starving_since = 0;
    std::int64_t m_cooldown_until = 0;
    std::int64_t m_healthy_since = 0;
    std::int64_t m_last_attempt = 0;
    std::int64_t m_startup_jitter = 0;
    unsigned m_failed_cycles = 0;
};

} // namespace coin
} // namespace btc
