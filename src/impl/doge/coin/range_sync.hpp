// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded DOGE: the anchored, parallel hash schedule (DESIGN-ANCHORS §1, §3).
///
/// Range i = heights (STEP * i, STEP * (i + 1)] is asked as
/// getheaders(locator = {a_i}, stop = a_{i+1}) and stored only when the
/// answer is exactly it (HashSchedule::store_range): nothing partial is ever
/// stored, so nothing is ever cut. The window is the lowest WINDOW
/// undelivered ranges; at most PER_PEER in flight per peer, a range to one
/// peer at a time; tick() every second.
///
/// How many ranges are in flight (FRESH-NODE §6.4): a window per peer, as
/// Core's per-peer block window; no rate feedback.
///   - Per peer, in bytes (a range's are estimated: 1.6 MB above the AuxPoW
///     height, 162 KB below): it starts at one AuxPoW range, a range
///     delivered within REQUEST_TIMEOUT / 3 of its request adds its bytes (up
///     to PER_PEER AuxPoW ranges), one delivered after 2/3 of it halves it, a
///     timeout sets it back to one AuxPoW range; at most PER_PEER ranges. A
///     peer serves its requests in order, so a second range to it waits
///     behind the first. In bytes, 162-KB ranges answered at once do not
///     leave a peer with eight 1.6 MB ranges to serve in turn (live, the
///     first AuxPoW minutes of fresh-anchored3 run 1).
///   - In all: GLOBAL, and the ranges' estimated bytes within INFLIGHT_BYTES.
/// The rate budget this replaces measured its own output and settled at 2
/// whenever a range took more than 20 s (live: 4 ranges a minute for 100
/// minutes with the link to spare). Peers the caller names (the header
/// chain's sync peers, the block downloads' peers) are asked only when no
/// other usable peer is connected.
///
/// Answers (on_headers, before the sequential sync and the header chain):
///   - the first header's parent is not an anchor (the header chain's
///     traffic, a peer answering from genesis for a range it cannot serve
///     lands on range 0): not ours unless it is an anchor's child;
///   - exact: stored, whoever sends it (exact = authentic given the anchor);
///   - anything else is judged only as the answer of the peer the range is
///     in flight to; from any other peer (or an excluded one) it is not ours
///     and falls through to the header chain (VERIFY5 S1, N1):
///   - short, long or broken (a trickle, a liar, or the AuxPoW headers
///     parser losing its place: live, 825f4fd8c at 19:34Z, honest peers'
///     answers parsed to 1,780 and 1,798 headers with a broken link): the
///     request is over: the range goes back to the window (another peer
///     preferred) and the peer takes a strike. Counted (short_parses,
///     bad_parses);
///   - STEP linked headers ending at another hash than the next anchor (no
///     parse error yields that): the peer is excluded at once. VOTES
///     distinct asked peers on the same other end hash: the anchor is
///     wrong; the schedule falls back to the sequential sync from the
///     delivered prefix, for this process (the next start tries the anchors
///     again);
///   - every connected peer excluded for ALL_EXCLUDED_PATIENCE (a wrong
///     anchor with fewer than VOTES peers, VERIFY5 S2): the same fallback.
/// Timeouts: a peer that has delivered no exact range for REQUEST_TIMEOUT
/// since its oldest request (or its last delivery) is late: its window goes
/// back to one range. It is struck only when it has been silent for its
/// range's stall timeout (REQUEST_TIMEOUT, or the range's bytes at
/// STALL_BYTES_PER_S when longer: 160 s for an AuxPoW range) and has a
/// witness: another peer delivered a range asked after this peer's oldest
/// one, at a rate (that range's bytes over the time from its own request)
/// that brings this peer's range within half that timeout. A healthy peer
/// overtook a stalled one. Then its in-flight ranges go to other peers and
/// the strike cools it for PEER_COOLDOWN; STRIKES strikes exclude it; an
/// exact range it delivers forgives one. Without a witness the link, not the
/// peer, is the cause (a full link, nothing arriving from anyone, ranges
/// served in turn, every transfer slow): no strike, no cooldown, its ranges
/// stay with it (it is still sending them; asking again would double the
/// load). After NOBODY_PATIENCE with no range delivered by anyone, timeouts
/// are struck again (a network that serves no range reaches the fallback).
/// A range held for 3 x REQUEST_TIMEOUT that a later request overtook at a
/// rate that brings it within 1.5 x REQUEST_TIMEOUT goes to another peer
/// without a strike; a peer that disconnected releases its ranges. A range
/// that every usable peer (at least VOTES of them) timed out on twice is
/// undeliverable (an anchor nobody knows): the same fallback.
/// Thread safety: every public method takes the internal mutex.

#include <impl/doge/coin/hash_schedule.hpp>
#include <impl/doge/coin/schedule_anchors.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
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
    uint64_t inflight_bytes{64ull << 20};        // the ranges' estimated bytes in flight
    uint32_t auxpow_height{371337};              // ranges above it: AuxPoW headers (~800 B each)
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

    /// Time out, then fill the window from `peers` (the connected peers);
    /// `avoid` (the header chain's sync peers, the block downloads' peers)
    /// is asked only when no other usable peer is connected.
    std::vector<Request> tick(const std::vector<std::string>& peers, Clock::time_point now,
                              const std::set<std::string>& avoid = {})
    {
        std::lock_guard<std::mutex> lock(m_mu);
        std::vector<Request> out;
        if (m_mode != Mode::Anchored)
            return out;
        release_gone_locked(peers);
        time_out_locked(now);
        if (m_mode != Mode::Anchored)
            return out;
        check_undeliverable_locked(peers);
        if (m_mode != Mode::Anchored)
            return out;
        check_all_excluded_locked(peers, now);
        if (m_mode != Mode::Anchored)
            return out;
        if (m_last_any == Clock::time_point{})
            m_last_any = now;
        // The window: the lowest `window` undelivered ranges.
        const uint32_t n = m_anchors.ranges();
        uint64_t bytes = 0;
        for (const auto& [r, f] : m_inflight)
            bytes += range_bytes(r);
        uint32_t seen = 0;
        for (uint32_t i = m_s.first_undone_range(); i < n && seen < m_cfg.window; ++i) {
            if (m_s.range_done(i))
                continue;
            ++seen;
            if (m_inflight.count(i))
                continue;
            if (m_inflight.size() >= m_cfg.global)
                break;
            if (!m_inflight.empty() && bytes + range_bytes(i) > m_cfg.inflight_bytes)
                break;
            const std::string p = pick_locked(i, peers, now, avoid);
            if (p.empty())
                break;  // no peer has a free slot
            auto& ps = m_peers[p];
            if (ps.inflight == 0) {
                ps.since = now;
                ps.late = false;
            }
            ++ps.inflight;
            ps.bytes += range_bytes(i);
            m_inflight[i] = InFlight{p, now};
            bytes += range_bytes(i);
            out.push_back(Request{i, p, {m_anchors.hashes[i]}, m_anchors.hashes[i + 1]});
        }
        end_game_locked(peers, now, avoid, out);
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
            return Answer::NotOurs;
        auto held = m_inflight.find(i);
        const bool asked = held != m_inflight.end() && held->second.peer == peer;
        uint256 end;
        const Feed r = m_s.store_range(i, headers, &end);
        switch (r) {
        case Feed::Stored:
        case Feed::Complete: {
            auto it = m_inflight.find(i);
            if (it != m_inflight.end() && it->second.peer == peer)
                on_served_locked(peer, i, it->second.at, now);
            if (it != m_inflight.end())
                release_locked(it);
            auto& ps = m_peers[peer];
            ps.since = now;  // a delivery: its queue moves
            ps.late = false;
            m_last_any = now;
            ++ps.delivered;
            if (ps.strikes > 0)
                --ps.strikes;  // a delivery forgives one strike
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
        case Feed::Long:
        case Feed::Broken: {
            if (!asked)
                return Answer::NotOurs;  // not the answer to our request
            if (r == Feed::Short)
                ++m_short_parses;
            else
                ++m_bad_parses;
            // Our getheaders is answered, and not with the range: re-ask.
            ++m_range_timeouts[i][peer];
            release_locked(held);
            strike_locked(peer, now, r == Feed::Short ? "a short range answer"
                                     : r == Feed::Long ? "a range answer with more than 2000 headers"
                                                       : "a range answer that does not link");
            return m_excluded.count(peer) ? Answer::Excluded : Answer::Ignored;
        }
        case Feed::Done:
            return Answer::NotOurs;
        case Feed::WrongEnd: {
            if (!asked)
                return Answer::NotOurs;  // an unasked fake votes nothing
            ++m_bad_parses;
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
            for (auto& [p, ps] : m_peers) {
                ps.inflight = 0;
                ps.bytes = 0;
            }
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
        uint64_t    bad_parses{0};   // long, broken or wrong-end range answers
        uint64_t    strikes{0};      // timeouts and bad answers held against peers
        uint32_t    budget{0};       // the peers' windows, in AuxPoW ranges, within GLOBAL
        uint64_t    link_waits{0};   // peers late and not struck (no witness, or not yet stalled)
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
        st.bad_parses = m_bad_parses;
        st.strikes = m_strikes;
        uint64_t units = 0;
        for (const auto& [p, ps] : m_peers)
            if (!m_excluded.count(p))
                units += std::max<uint64_t>(1, window_bytes(ps) / AUXPOW_RANGE_BYTES);
        st.budget = static_cast<uint32_t>(std::min<uint64_t>(units, m_cfg.global));
        st.link_waits = m_link_waits;
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
    static constexpr std::chrono::seconds WITNESS_SPAN{300};
    static constexpr std::chrono::minutes NOBODY_PATIENCE{10};
    /// A peer slower than this on a range, with a healthy one beside it,
    /// stalls (live, a 1.6 MB range over a congested link: 20-50 KB/s).
    static constexpr uint64_t STALL_BYTES_PER_S = 10000;
    static constexpr uint64_t PLAIN_RANGE_BYTES = 2000 * 81;      // 80-byte headers + tx count
    static constexpr uint64_t AUXPOW_RANGE_BYTES = 2000 * 800;    // live: ~1.6 MB a range

    struct Delivered {
        Clock::time_point at;
        Clock::time_point sent;
        uint64_t          bytes;  // the range's estimate
        std::string       peer;
    };
    static constexpr std::chrono::minutes ALL_EXCLUDED_PATIENCE{5};

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
        uint64_t          bytes{0};       // the estimated bytes of its ranges in flight
        uint64_t          window{0};      // bytes it may hold (0: one AuxPoW range)
        bool              late{false};    // timed out without a witness, not since delivered
    };

    void release_locked(std::map<uint32_t, InFlight>::iterator it)
    {
        auto ps = m_peers.find(it->second.peer);
        if (ps != m_peers.end()) {
            if (ps->second.inflight > 0)
                --ps->second.inflight;
            ps->second.bytes -= std::min(ps->second.bytes, range_bytes(it->first));
        }
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

    /// A strike: the peer is cooled; STRIKES of them exclude it.
    void strike_locked(const std::string& peer, Clock::time_point now, const char* why)
    {
        auto& ps = m_peers[peer];
        ++ps.strikes;
        ++m_strikes;
        ps.cool_until = now + m_cfg.peer_cooldown;
        LOG_INFO << "[EMB-DOGE] Hash schedule: " << peer << ": " << why << " (strike " << ps.strikes << ")";
        if (ps.strikes >= m_cfg.strikes)
            exclude_locked(peer, "repeated timeouts or bad range answers");
    }

    /// The end game: every undelivered range in the window is in flight
    /// (the last ranges of the schedule). A range whose peer has been silent
    /// for REQUEST_TIMEOUT goes to a peer with nothing in flight, without a
    /// strike: the slow peer may still answer, and the first exact answer is
    /// stored. Live, fresh-anchored3 run 5: the last 13 ranges took more than
    /// 8 minutes on slow peers while the others had nothing to do.
    void end_game_locked(const std::vector<std::string>& peers, Clock::time_point now,
                         const std::set<std::string>& avoid, std::vector<Request>& out)
    {
        uint32_t seen = 0;
        for (uint32_t i = m_s.first_undone_range(); i < m_anchors.ranges() && seen < m_cfg.window; ++i) {
            if (m_s.range_done(i))
                continue;
            ++seen;
            if (!m_inflight.count(i))
                return;  // something is still to ask: not the end game
        }
        std::vector<std::pair<Clock::time_point, uint32_t>> held;
        for (const auto& [r, f] : m_inflight)
            if (now - f.at >= m_cfg.request_timeout && now - m_peers[f.peer].since >= m_cfg.request_timeout)
                held.emplace_back(f.at, r);
        std::sort(held.begin(), held.end());
        for (const auto& [at, r] : held) {
            std::string idle;
            for (int pass = 0; pass < 2 && idle.empty(); ++pass)
                for (const auto& p : peers) {
                    if (!usable_locked(p, now) || (pass == 0 && avoid.count(p)))
                        continue;
                    auto ps = m_peers.find(p);
                    if (ps == m_peers.end() || ps->second.inflight == 0) {
                        idle = p;
                        break;
                    }
                }
            if (idle.empty())
                return;
            auto it = m_inflight.find(r);
            ++m_timeouts;
            release_locked(it);
            auto& ps = m_peers[idle];
            ps.since = now;
            ps.late = false;
            ++ps.inflight;
            ps.bytes += range_bytes(r);
            m_inflight[r] = InFlight{idle, now};
            out.push_back(Request{r, idle, {m_anchors.hashes[r]}, m_anchors.hashes[r + 1]});
        }
    }

    /// A peer that is no longer connected releases its ranges (no strike).
    void release_gone_locked(const std::vector<std::string>& peers)
    {
        if (m_inflight.empty())
            return;
        const std::set<std::string> here(peers.begin(), peers.end());
        for (auto it = m_inflight.begin(); it != m_inflight.end();)
            if (!here.count(it->second.peer)) {
                auto next = std::next(it);
                release_locked(it);
                it = next;
            } else {
                ++it;
            }
    }

    void time_out_locked(Clock::time_point now)
    {
        while (!m_delivered.empty() && now - m_delivered.front().at > WITNESS_SPAN)
            m_delivered.pop_front();
        const bool nobody = now - m_last_any >= NOBODY_PATIENCE;
        std::set<std::string> struck;
        for (auto& [p, ps] : m_peers) {
            if (ps.inflight == 0 || now - ps.since < m_cfg.request_timeout)
                continue;
            const auto [oldest_at, oldest_range] = oldest_of_locked(p);
            const auto stall = stall_timeout(range_bytes(oldest_range));
            if ((now - ps.since >= stall && overtaken_locked(oldest_at, p, range_bytes(oldest_range), stall / 2))
                || (nobody && now - ps.since >= NOBODY_PATIENCE)) {
                struck.insert(p);
            } else if (!ps.late) {
                // No healthy peer overtook it: the link is the cause. Its ranges stay.
                ps.late = true;
                ps.window = 0;
                ++m_link_waits;
            }
        }
        for (const auto& p : struck) {
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
            auto& ps = m_peers[p];
            ps.window = 0;
            ps.late = false;
            strike_locked(p, now, "no range delivered in time while other peers delivered; its ranges go to "
                                  "other peers");
        }
        // A range held far too long that a later request overtook goes
        // elsewhere, with no strike (the peer is working).
        for (auto it = m_inflight.begin(); it != m_inflight.end();)
            if (now - it->second.at >= 3 * m_cfg.request_timeout
                && (overtaken_locked(it->second.at, it->second.peer, range_bytes(it->first),
                                     3 * m_cfg.request_timeout / 2)
                    || nobody)) {
                ++m_range_timeouts[it->first][it->second.peer];
                ++m_timeouts;
                auto next = std::next(it);
                release_locked(it);
                it = next;
            } else {
                ++it;
            }
    }

    /// How long a peer may be silent on a range of `bytes` before a strike:
    /// REQUEST_TIMEOUT, or longer for a range a peer at STALL_BYTES_PER_S
    /// needs longer for (an AuxPoW range: 160 s).
    Clock::duration stall_timeout(uint64_t bytes) const
    {
        const Clock::duration slow = std::chrono::duration_cast<Clock::duration>(
            std::chrono::duration<double>(double(bytes) / double(STALL_BYTES_PER_S)));
        return std::max<Clock::duration>(m_cfg.request_timeout, slow);
    }

    /// `peer`'s oldest request: when, and which range.
    std::pair<Clock::time_point, uint32_t> oldest_of_locked(const std::string& peer) const
    {
        std::pair<Clock::time_point, uint32_t> oldest{Clock::time_point::max(), 0};
        for (const auto& [r, f] : m_inflight)
            if (f.peer == peer && f.at < oldest.first)
                oldest = {f.at, r};
        return oldest;
    }

    /// A healthy peer overtook a request of `peer` sent at `since` for
    /// `bytes`: another peer delivered a range asked after it (ranges asked
    /// in the same tick are answered in their turn, not ahead of each other)
    /// at a rate, from its own request, that brings `bytes` within `within`.
    /// From the request, not from the peer's previous answer: answers queued
    /// on one connection arrive back to back and would look instant.
    bool overtaken_locked(Clock::time_point since, const std::string& peer, uint64_t bytes,
                          Clock::duration within) const
    {
        const double limit = std::chrono::duration<double>(within).count();
        for (const auto& d : m_delivered) {
            if (d.peer == peer || d.sent <= since)
                continue;
            const double took = std::chrono::duration<double>(d.at - d.sent).count();
            if (took * double(bytes) <= limit * double(d.bytes))
                return true;
        }
        return false;
    }

    uint64_t window_bytes(const PeerState& ps) const { return ps.window ? ps.window : AUXPOW_RANGE_BYTES; }

    /// `ps` may be asked for `range` too: under PER_PEER ranges, and the
    /// range within its window (its first range always).
    bool room_locked(const PeerState& ps, uint32_t range) const
    {
        if (ps.inflight >= m_cfg.per_peer)
            return false;
        return ps.inflight == 0 || ps.bytes + range_bytes(range) <= window_bytes(ps);
    }

    uint64_t range_bytes(uint32_t range) const
    {
        return uint64_t(ScheduleAnchors::STEP) * (range + 1) > m_cfg.auxpow_height ? AUXPOW_RANGE_BYTES
                                                                                    : PLAIN_RANGE_BYTES;
    }

    /// Range `range`, asked of `peer` at `sent`, arrived at `now`: the peer's
    /// window moves; the delivery is a witness for timeouts.
    void on_served_locked(const std::string& peer, uint32_t range, Clock::time_point sent, Clock::time_point now)
    {
        auto& ps = m_peers[peer];
        const auto timeout = m_cfg.request_timeout;
        const uint64_t cap = uint64_t(m_cfg.per_peer) * AUXPOW_RANGE_BYTES;
        if (now - sent < timeout / 3)
            ps.window = std::min(window_bytes(ps) + range_bytes(range), cap);
        else if (now - sent > 2 * timeout / 3)
            ps.window = std::max(AUXPOW_RANGE_BYTES, window_bytes(ps) / 2);
        m_delivered.push_back(Delivered{now, sent, range_bytes(range), peer});
    }

    bool usable_locked(const std::string& p, Clock::time_point now) const
    {
        if (p.empty() || m_excluded.count(p))
            return false;
        auto ps = m_peers.find(p);
        return ps == m_peers.end() || now >= ps->second.cool_until;
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

    /// Every connected peer excluded, for ALL_EXCLUDED_PATIENCE (new peers
    /// connect meanwhile): nothing can deliver the ranges.
    void check_all_excluded_locked(const std::vector<std::string>& peers, Clock::time_point now)
    {
        const bool all = !peers.empty()
                      && std::all_of(peers.begin(), peers.end(),
                                     [&](const std::string& p) { return m_excluded.count(p) > 0; });
        if (!all) {
            m_all_excluded_since = Clock::time_point{};
            return;
        }
        if (m_all_excluded_since == Clock::time_point{})
            m_all_excluded_since = now;
        else if (now - m_all_excluded_since >= ALL_EXCLUDED_PATIENCE)
            fall_back_locked("every connected peer (" + std::to_string(peers.size()) + ") is excluded");
    }

    /// A peer with room in its window, not excluded nor cooling, preferring
    /// one that has not timed out on this range; round robin. Peers in
    /// `avoid` only when no other usable peer is connected.
    std::string pick_locked(uint32_t range, const std::vector<std::string>& peers, Clock::time_point now,
                            const std::set<std::string>& avoid)
    {
        if (!avoid.empty()
            && std::any_of(peers.begin(), peers.end(),
                           [&](const std::string& p) { return !avoid.count(p) && usable_locked(p, now); })) {
            std::vector<std::string> others;
            for (const auto& p : peers)
                if (!avoid.count(p))
                    others.push_back(p);
            return pick_locked(range, others, now, {});
        }
        if (peers.empty())
            return {};
        const auto rt = m_range_timeouts.find(range);
        std::string fallback;
        for (size_t k = 0; k < peers.size(); ++k) {
            const std::string& p = peers[(m_rr + k) % peers.size()];
            if (!usable_locked(p, now))
                continue;
            auto ps = m_peers.find(p);
            if (ps != m_peers.end() && !room_locked(ps->second, range))
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
                  << m_s.frontier_height() << " (the delivered ranges are kept; the anchors are tried "
                  << "again on the next start)";
        m_s.refuse_anchors();
        m_mode = Mode::SequentialFallback;
        m_floor = m_s.frontier_height();
        m_inflight.clear();
        for (auto& [p, ps] : m_peers) {
            ps.inflight = 0;
            ps.bytes = 0;
        }
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
    uint64_t                        m_strikes{0};
    std::deque<Delivered>           m_delivered;      // asked ranges delivered, the last 5 minutes
    Clock::time_point               m_last_any{};     // the last exact range from anyone
    uint64_t                        m_link_waits{0};
    Clock::time_point               m_all_excluded_since{};
    uint64_t                        m_short_parses{0};
    uint64_t                        m_bad_parses{0};
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
