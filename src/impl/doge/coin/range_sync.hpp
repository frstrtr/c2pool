// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded DOGE: the anchored, parallel hash schedule (DESIGN-ANCHORS §1, §3).
///
/// Range i = heights (STEP * i, STEP * (i + 1)] is asked as
/// getheaders(locator = {a_i}, stop = a_{i+1}) and stored only when the
/// answer is exactly it (HashSchedule::store_range): nothing partial is ever
/// stored, so nothing is ever cut. The window is the lowest WINDOW
/// undelivered ranges; at most PER_PEER in flight per peer and GLOBAL in
/// all, a range to one peer at a time; tick() every second.
///
/// Answers (on_headers, before the sequential sync and the header chain):
///   - the first header's parent is not an anchor (the header chain's
///     traffic, a peer answering from genesis for a range it cannot serve
///     lands on range 0): not ours unless it is an anchor's child;
///   - exact: stored, whoever sends it (exact = authentic given the anchor);
///   - short but linking from the anchor (a trickle, or a parser that
///     stopped early): ignored, counted (short_parses); the range stays in
///     flight until its peer times out;
///   - long, broken, or STEP linked headers ending at another hash than the
///     next anchor: the peer is excluded for the process, its ranges go
///     back to the window. VOTES distinct peers on the same other end hash:
///     the anchor is wrong; the schedule falls back to the sequential sync
///     from the delivered prefix (refused for good in the DB).
/// Timeouts: a peer that has delivered no exact range for REQUEST_TIMEOUT
/// since its oldest request (or its last delivery) loses its in-flight
/// ranges (one strike) and is cooled for PEER_COOLDOWN; STRIKES strikes
/// exclude it. A slow peer that keeps delivering is never timed out: its
/// requests queue behind each other on its connection. A range that every
/// usable peer (at least VOTES of them) timed out on twice is undeliverable
/// (an anchor nobody knows): the same fallback.
/// Thread safety: every public method takes the internal mutex.

#include <impl/doge/coin/hash_schedule.hpp>
#include <impl/doge/coin/schedule_anchors.hpp>

#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace doge {
namespace coin {

/// RangeSync's limits (DESIGN-ANCHORS §3.3); the KATs use smaller ones.
struct RangeSyncConfig {
    uint32_t window{64};                         // the lowest undelivered ranges asked
    uint32_t per_peer{8};                        // in flight per peer
    uint32_t global{48};                         // in flight in all
    std::chrono::seconds request_timeout{60};    // no exact range from a peer for this: a strike
    std::chrono::seconds peer_cooldown{600};     // a struck peer is not asked for this
    uint32_t strikes{3};                         // strikes that exclude a peer
    uint32_t votes{3};                           // peers that prove an anchor wrong
};

class RangeSync {
public:
    using Clock = std::chrono::steady_clock;
    using Feed = HashSchedule::RangeFeed;

    using Config = RangeSyncConfig;

    enum class Mode {
        Anchored,            // fetching the ranges
        Tail,                // the ranges are done; the sequential sync fetches the tail
        SequentialFallback,  // no usable anchors, or they were refused
        Complete,            // the schedule is proven
    };
    static const char* mode_name(Mode m)
    {
        switch (m) {
        case Mode::Anchored:           return "anchored";
        case Mode::Tail:               return "tail";
        case Mode::SequentialFallback: return "sequential-fallback";
        case Mode::Complete:           return "complete";
        }
        return "unknown";
    }

    enum class Answer {
        NotOurs,   // the sequential sync / the header chain takes it
        Stored,    // a range stored
        Complete,  // the last one: the schedule is proven
        Ignored,   // a range answer that stores nothing (short, done, excluded peer)
        Excluded,  // a range answer that is not the range: the peer is excluded
    };

    RangeSync(HashSchedule& schedule, const ScheduleAnchors& anchors, Config cfg = Config())
        : m_s(schedule)
        , m_cfg(cfg)
        , m_anchors(anchors)
    {
        for (uint32_t i = 0; i < m_anchors.hashes.size(); ++i)
            m_index.emplace(m_anchors.hashes[i], i);
        const auto rm = m_s.use_anchors(m_anchors);
        if (m_s.complete())
            m_mode = Mode::Complete;
        else if (rm == HashSchedule::RangeMode::None)
            m_mode = Mode::SequentialFallback;
        else if (m_s.ranges_done() == m_s.ranges_total())
            m_mode = Mode::Tail;
        else
            m_mode = Mode::Anchored;
        m_floor = m_s.frontier_height();
        if (m_mode == Mode::SequentialFallback)
            LOG_WARNING << "[EMB-DOGE] Hash schedule: no usable anchors"
                        << (m_anchors.empty() ? " in this build" : "") << ": the sequential sync from h="
                        << m_s.frontier_height();
    }

    Mode mode() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_mode;
    }
    /// The sequential sync runs (the fallback, or the tail past the anchors).
    bool sequential() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_mode == Mode::SequentialFallback || m_mode == Mode::Tail;
    }
    /// The sequential sync never cuts below this: the delivered prefix.
    uint32_t floor() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_floor;
    }

    struct Request {
        uint32_t             range{0};
        std::string          peer;
        std::vector<uint256> locator;  // {a_i}
        uint256              stop;     // a_{i+1}
    };

    /// Time out, then fill the window from `peers` (the connected peers).
    std::vector<Request> tick(const std::vector<std::string>& peers, Clock::time_point now)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        std::vector<Request> out;
        if (m_mode != Mode::Anchored)
            return out;
        time_out_locked(now);
        if (m_mode != Mode::Anchored)
            return out;
        check_undeliverable_locked(peers);
        if (m_mode != Mode::Anchored)
            return out;
        // The window: the lowest `window` undelivered ranges.
        const uint32_t n = m_anchors.ranges();
        uint32_t seen = 0;
        for (uint32_t i = m_s.first_undone_range(); i < n && seen < m_cfg.window; ++i) {
            if (m_s.range_done(i))
                continue;
            ++seen;
            if (m_inflight.count(i))
                continue;
            if (m_inflight.size() >= m_cfg.global)
                break;
            const std::string p = pick_locked(i, peers, now);
            if (p.empty())
                break;  // no peer has a free slot
            auto& ps = m_peers[p];
            if (ps.inflight == 0)
                ps.since = now;
            ++ps.inflight;
            m_inflight[i] = InFlight{p, now};
            out.push_back(Request{i, p, {m_anchors.hashes[i]}, m_anchors.hashes[i + 1]});
        }
        return out;
    }

    /// The getheaders for `range` did not go out to `peer`.
    void unsent(uint32_t range, const std::string& peer)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        auto it = m_inflight.find(range);
        if (it != m_inflight.end() && it->second.peer == peer)
            release_locked(it);
    }

    Answer on_headers(const std::string& peer, const std::vector<ltc::coin::BlockHeaderType>& headers,
                      Clock::time_point now)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (m_mode != Mode::Anchored || headers.empty())
            return Answer::NotOurs;
        auto ix = m_index.find(headers.front().m_previous_block);
        if (ix == m_index.end() || ix->second >= m_anchors.ranges())
            return Answer::NotOurs;
        const uint32_t i = ix->second;
        if (m_excluded.count(peer))
            return Answer::Ignored;
        uint256 end;
        const Feed r = m_s.store_range(i, headers, &end);
        switch (r) {
        case Feed::Stored:
        case Feed::Complete: {
            auto it = m_inflight.find(i);
            if (it != m_inflight.end())
                release_locked(it);
            auto& ps = m_peers[peer];
            ps.since = now;  // a delivery: its queue moves
            ++ps.delivered;
            m_used.insert(peer);
            m_range_timeouts.erase(i);
            m_end_votes.erase(i);
            m_stored_at.push_back(now);
            while (!m_stored_at.empty() && now - m_stored_at.front() > std::chrono::seconds(60))
                m_stored_at.pop_front();
            if (r == Feed::Complete) {
                m_mode = Mode::Complete;
                return Answer::Complete;
            }
            if (m_s.ranges_done() == m_s.ranges_total()) {
                m_mode = Mode::Tail;  // the anchors end below the checkpoint
                m_floor = m_s.frontier_height();
                LOG_INFO << "[EMB-DOGE] Hash schedule: every anchored range is stored; the sequential sync "
                         << "fetches h=" << m_floor << ".." << m_s.checkpoint_height();
            }
            return Answer::Stored;
        }
        case Feed::Short:
            ++m_short_parses;
            return Answer::Ignored;
        case Feed::Done:
            return Answer::Ignored;
        case Feed::Long:
        case Feed::Broken:
            exclude_locked(peer, Feed::Long == r ? "a range answer with more than 2000 headers"
                                                 : "a range answer that does not link");
            return Answer::Excluded;
        case Feed::WrongEnd: {
            exclude_locked(peer, "a range answer ending at another hash than the anchor");
            auto& voters = m_end_votes[i][end];
            voters.insert(peer);
            if (voters.size() >= m_cfg.votes)
                fall_back_locked("the anchor at h=" + std::to_string(ScheduleAnchors::STEP * (i + 1))
                                 + " is wrong: " + std::to_string(voters.size()) + " peers agree on "
                                 + end.GetHex());
            return Answer::Excluded;
        }
        case Feed::Rejected:
            // Every range stored but the prefix did not link (a disk fault):
            // the schedule reset itself; the ranges are fetched again.
            m_inflight.clear();
            for (auto& [p, ps] : m_peers)
                ps.inflight = 0;
            return Answer::Ignored;
        case Feed::Failed:
        case Feed::NotOurs:
            break;
        }
        return r == Feed::NotOurs ? Answer::NotOurs : Answer::Ignored;
    }

    struct Stats {
        uint32_t    ranges_done{0};
        uint32_t    ranges_total{0};
        uint32_t    inflight{0};
        uint32_t    peers_used{0};
        uint64_t    timeouts{0};
        uint32_t    excluded{0};
        uint64_t    short_parses{0};
        double      rate_hps{0};  // headers stored per second, last minute
        std::string mode;
    };
    Stats stats(Clock::time_point now) const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        Stats st;
        st.ranges_done = m_s.ranges_done();
        st.ranges_total = m_s.ranges_total();
        st.inflight = static_cast<uint32_t>(m_inflight.size());
        st.peers_used = static_cast<uint32_t>(m_used.size());
        st.timeouts = m_timeouts;
        st.excluded = static_cast<uint32_t>(m_excluded.size());
        st.short_parses = m_short_parses;
        size_t recent = 0;
        for (const auto& t : m_stored_at)
            if (now - t <= std::chrono::seconds(60))
                ++recent;
        st.rate_hps = recent * double(ScheduleAnchors::STEP) / 60.0;
        st.mode = mode_name(m_mode);
        return st;
    }

    /// In flight to `peer` now (KATs).
    uint32_t inflight_of(const std::string& peer) const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        auto it = m_peers.find(peer);
        return it == m_peers.end() ? 0 : it->second.inflight;
    }
    bool excluded(const std::string& peer) const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_excluded.count(peer) > 0;
    }

private:
    static constexpr size_t MAX_EXCLUDED = 4096;

    struct InFlight {
        std::string       peer;
        Clock::time_point at{};
    };
    struct PeerState {
        uint32_t          inflight{0};
        uint32_t          strikes{0};
        uint64_t          delivered{0};
        Clock::time_point since{};        // its oldest request, or its last delivery
        Clock::time_point cool_until{};
    };

    void release_locked(std::map<uint32_t, InFlight>::iterator it)
    {
        auto ps = m_peers.find(it->second.peer);
        if (ps != m_peers.end() && ps->second.inflight > 0)
            --ps->second.inflight;
        m_inflight.erase(it);
    }

    void exclude_locked(const std::string& peer, const char* why)
    {
        if (peer.empty() || m_excluded.count(peer))
            return;
        if (m_excluded.size() >= MAX_EXCLUDED)
            m_excluded.clear();
        m_excluded.insert(peer);
        for (auto it = m_inflight.begin(); it != m_inflight.end();)
            if (it->second.peer == peer) {
                auto next = std::next(it);
                release_locked(it);
                it = next;
            } else {
                ++it;
            }
        LOG_WARNING << "[EMB-DOGE] Hash schedule: " << peer << " excluded (" << why << ")";
    }

    void time_out_locked(Clock::time_point now)
    {
        std::set<std::string> struck;
        for (auto& [p, ps] : m_peers)
            if (ps.inflight > 0 && now - ps.since >= m_cfg.request_timeout)
                struck.insert(p);
        for (const auto& p : struck) {
            auto& ps = m_peers[p];
            for (auto it = m_inflight.begin(); it != m_inflight.end();)
                if (it->second.peer == p) {
                    ++m_range_timeouts[it->first][p];
                    ++m_timeouts;
                    auto next = std::next(it);
                    release_locked(it);
                    it = next;
                } else {
                    ++it;
                }
            ++ps.strikes;
            ps.cool_until = now + m_cfg.peer_cooldown;
            LOG_INFO << "[EMB-DOGE] Hash schedule: no range from " << p << " in "
                     << std::chrono::duration_cast<std::chrono::seconds>(now - ps.since).count()
                     << "s; its ranges go to other peers (strike " << ps.strikes << ")";
            if (ps.strikes >= m_cfg.strikes)
                exclude_locked(p, "timed out repeatedly");
        }
    }

    /// A range every usable peer (at least `votes` of them) timed out on
    /// twice: its anchor is not known to the network.
    void check_undeliverable_locked(const std::vector<std::string>& peers)
    {
        if (peers.empty())
            return;  // disconnected: nothing to conclude
        for (const auto& [range, by] : m_range_timeouts) {
            uint32_t twice = 0;
            for (const auto& [p, n] : by)
                if (n >= 2)
                    ++twice;
            if (twice < m_cfg.votes)
                continue;
            bool all = true;
            for (const auto& p : peers) {
                if (m_excluded.count(p))
                    continue;
                auto it = by.find(p);
                if (it == by.end() || it->second < 2) {
                    all = false;
                    break;
                }
            }
            if (all) {
                fall_back_locked("the range above h=" + std::to_string(ScheduleAnchors::STEP * range)
                                 + " is undeliverable: " + std::to_string(twice) + " peers timed out on it twice");
                return;
            }
        }
    }

    /// A peer with a free slot, not excluded nor cooling, preferring one that
    /// has not timed out on this range; round robin.
    std::string pick_locked(uint32_t range, const std::vector<std::string>& peers, Clock::time_point now)
    {
        if (peers.empty())
            return {};
        const auto rt = m_range_timeouts.find(range);
        std::string fallback;
        for (size_t k = 0; k < peers.size(); ++k) {
            const std::string& p = peers[(m_rr + k) % peers.size()];
            if (p.empty() || m_excluded.count(p))
                continue;
            auto ps = m_peers.find(p);
            if (ps != m_peers.end()
                && (ps->second.inflight >= m_cfg.per_peer || now < ps->second.cool_until))
                continue;
            const bool timed_out_here = rt != m_range_timeouts.end() && rt->second.count(p);
            if (!timed_out_here) {
                m_rr = (m_rr + k + 1) % peers.size();
                return p;
            }
            if (fallback.empty())
                fallback = p;
        }
        return fallback;
    }

    void fall_back_locked(const std::string& why)
    {
        LOG_ERROR << "[EMB-DOGE] Hash schedule: " << why << "; the sequential sync continues from h="
                  << m_s.frontier_height() << " (the delivered ranges are kept)";
        m_s.refuse_anchors();
        m_mode = Mode::SequentialFallback;
        m_floor = m_s.frontier_height();
        m_inflight.clear();
        for (auto& [p, ps] : m_peers)
            ps.inflight = 0;
    }

    HashSchedule&                   m_s;
    const Config                    m_cfg;
    const ScheduleAnchors           m_anchors;
    std::map<uint256, uint32_t>     m_index;  // anchor hash -> its index
    mutable std::mutex              m_mu;
    Mode                            m_mode{Mode::SequentialFallback};
    uint32_t                        m_floor{0};
    std::map<uint32_t, InFlight>    m_inflight;
    std::map<std::string, PeerState> m_peers;
    std::set<std::string>           m_excluded;
    std::set<std::string>           m_used;
    std::map<uint32_t, std::map<std::string, uint32_t>> m_range_timeouts;
    std::map<uint32_t, std::map<uint256, std::set<std::string>>> m_end_votes;
    std::deque<Clock::time_point>   m_stored_at;
    uint64_t                        m_timeouts{0};
    uint64_t                        m_short_parses{0};
    size_t                          m_rr{0};
};

/// The anchors of a complete schedule (`c2pool --dump-doge-schedule-anchors`):
/// the hash at STEP * i, i = 0 .. checkpoint / STEP. Refused for a schedule
/// that is not complete or a checkpoint that is not a multiple of STEP.
inline std::optional<ScheduleAnchors> anchors_from_schedule(const HashSchedule& s, std::string* err = nullptr)
{
    constexpr uint32_t STEP = ScheduleAnchors::STEP;
    auto fail = [&](const std::string& why) -> std::optional<ScheduleAnchors> {
        if (err)
            *err = why;
        return std::nullopt;
    };
    if (!s.complete())
        return fail("the schedule is not complete (at h=" + std::to_string(s.frontier_height()) + ")");
    const uint32_t cp = s.checkpoint_height();
    if (cp == 0 || cp % STEP != 0)
        return fail("the checkpoint " + std::to_string(cp) + " is not a multiple of " + std::to_string(STEP));
    ScheduleAnchors a;
    for (uint32_t h = 0; h <= cp; h += STEP) {
        const uint256 x = s.hash_at(h);
        if (x.IsNull())
            return fail("no hash at h=" + std::to_string(h));
        a.hashes.push_back(x);
    }
    return a;
}

} // namespace coin
} // namespace doge
