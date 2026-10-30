// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// One peer per block for an ordered fill (core::coin::BlockBootstrapState):
/// the cold-start Bootstrap of the embedded LTC UTXO set and of the DOGE
/// accrual set. The rules are the DOGE full lane's block download
/// (doge/full-utxo-set utxo_lane.hpp; Core net_processing.cpp
/// FindNextBlocksToDownload and the stalling-peer rule):
///   - every height in the fill's window that is neither buffered nor in
///     flight is asked of ONE peer: the least loaded eligible peer with
///     fewer than PER_PEER_IN_FLIGHT outstanding (round robin on ties);
///     eligible = the host's peers (handshaken, NODE_NETWORK) minus those
///     cooling down, or all of them when every one is;
///   - a request unanswered for REQUEST_TIMEOUT goes to another peer, and
///     its peer cools down for PEER_COOLDOWN;
///   - a peer holding the window's first height past the stall timeout
///     while the window cannot move (every height in it asked or buffered,
///     or the buffer at its byte bound) is rotated out and its requests
///     reassigned; the stall timeout doubles after each stall (2 s .. 64 s)
///     and halves again after 1,000 blocks drained without one;
///   - the fill's own stall timer (no block drained for 30 s) asks another
///     peer for the stalled height (its holder cools down), and every peer
///     only on the third stall of the same height;
///   - the bodies buffered but not drained are bounded in bytes: past
///     buffer_limit nothing is asked but the next height to drain, and a
///     body ahead of the window is not kept (it is asked again in order).
/// Before, the cold starts asked every peer for every height (FRESH-NODE
/// §2.2, §2.3): 113,551 LTC bodies for 52,062 heights, 14 GB in 95 minutes.
///
/// Thread safety: none; the fill's thread (ioc) calls every method.

#include <core/log.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace core {
namespace coin {

class BlockDownload {
public:
    using Clock = std::chrono::steady_clock;

    /// Core MAX_BLOCKS_IN_TRANSIT_PER_PEER.
    static constexpr uint32_t PER_PEER_IN_FLIGHT = 16;
    /// Core BLOCK_STALLING_TIMEOUT, doubled after each stall up to the max.
    static constexpr std::chrono::milliseconds STALL_TIMEOUT_MIN{2000};
    static constexpr std::chrono::milliseconds STALL_TIMEOUT_MAX{64000};
    /// A request unanswered this long goes to another peer.
    static constexpr std::chrono::seconds REQUEST_TIMEOUT{60};
    /// A stalling or timed-out peer is not asked this long.
    static constexpr std::chrono::seconds PEER_COOLDOWN{600};
    /// The fill's stall timer: the stalled height goes to every peer on this
    /// stall (to one other peer before).
    static constexpr uint32_t STALLS_BEFORE_BROADCAST = 3;
    /// Default bound of the bodies buffered but not drained.
    static constexpr size_t BUFFER_BYTES_MAX = 256u * 1024 * 1024;

    struct Host {
        /// The peers a body may be asked from (handshaken, NODE_NETWORK).
        std::function<std::vector<std::string>()> peers;
        /// Ask `peer` for the best chain's block at height h (false: not sent).
        std::function<bool(const std::string&, uint32_t)> request_from;
        /// Ask every peer for the best chain's block at height h.
        std::function<void(uint32_t)> request_all;
        /// The clock (optional; tests drive it).
        std::function<Clock::time_point()> now;
    };

    /// Counters for /local_stats. Atomic: read from the HTTP thread.
    struct Stats {
        std::atomic<uint64_t> requests{0};          // one-peer requests sent
        std::atomic<uint64_t> broadcasts{0};        // heights asked of every peer (3rd stall)
        std::atomic<uint64_t> delivered{0};         // bodies that answered a request
        std::atomic<uint64_t> request_timeouts{0};
        std::atomic<uint64_t> stalls{0};            // peers rotated out for holding the window
        std::atomic<uint64_t> fill_stalls{0};       // the fill's 30-s stall timer fired
        std::atomic<uint64_t> window_waits{0};      // refills stopped at the byte bound
        std::atomic<uint64_t> not_kept{0};          // bodies ahead of the window, not buffered
        std::atomic<uint64_t> inflight{0};
        std::atomic<uint64_t> peers_used{0};
        std::atomic<uint64_t> peers_cooling{0};
        std::atomic<uint64_t> buffer_bytes{0};
        std::atomic<uint64_t> stall_timeout_ms{0};

        nlohmann::json to_json() const
        {
            auto v = [](const std::atomic<uint64_t>& a) { return a.load(std::memory_order_relaxed); };
            return nlohmann::json{
                {"requests", v(requests)}, {"broadcasts", v(broadcasts)}, {"delivered", v(delivered)},
                {"request_timeouts", v(request_timeouts)}, {"stalls", v(stalls)},
                {"fill_stalls", v(fill_stalls)}, {"window_waits", v(window_waits)},
                {"not_kept", v(not_kept)}, {"inflight", v(inflight)}, {"peers_used", v(peers_used)},
                {"peers_cooling", v(peers_cooling)}, {"buffer_bytes", v(buffer_bytes)},
                {"stall_timeout_ms", v(stall_timeout_ms)},
            };
        }
    };

    BlockDownload(Host host, std::string tag, size_t buffer_limit = BUFFER_BYTES_MAX)
        : m_host(std::move(host)), m_tag(std::move(tag)), m_buffer_limit(buffer_limit)
    {
    }

    BlockDownload(const BlockDownload&) = delete;
    BlockDownload& operator=(const BlockDownload&) = delete;

    /// Forget the requests and the buffered sizes (the fill was armed again
    /// or stopped). Cooldowns and the stall timeout stay.
    void reset()
    {
        m_inflight.clear();
        m_load.clear();
        m_sizes.clear();
        m_buffer_bytes = 0;
        m_stall_height = 0;
        m_stall_count = 0;
        publish();
    }

    /// A body for height h arrived from `peer` (any block the fill's thread
    /// sees; a height not in flight is ignored).
    void delivered(uint32_t h, const std::string& /*peer*/)
    {
        auto it = m_inflight.find(h);
        if (it == m_inflight.end())
            return;
        drop_request(it);
        m_stats.delivered.fetch_add(1, std::memory_order_relaxed);
    }

    /// Should the fill keep (buffer) a best-chain body of `bytes` at height
    /// h? The next height always; one ahead of the window, or past the byte
    /// bound, not (it only extends the range and is asked in order).
    template <typename Fill>
    bool keep(const Fill& fill, uint32_t h, size_t bytes)
    {
        sync(fill);
        if (h == fill.next_height)
            return true;
        if (h < fill.next_height)
            return false;
        if (uint64_t(h) >= uint64_t(fill.next_height) + fill.window
            || m_buffer_bytes + bytes > m_buffer_limit) {
            m_stats.not_kept.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        return true;
    }

    /// The fill buffered a body of `bytes` at height h.
    void buffered(uint32_t h, size_t bytes)
    {
        auto [it, fresh] = m_sizes.try_emplace(h, bytes);
        if (fresh)
            m_buffer_bytes += bytes;
        m_stats.buffer_bytes.store(m_buffer_bytes, std::memory_order_relaxed);
    }

    /// The fill drained (connected) n blocks.
    void drained(uint32_t n)
    {
        m_drained_since_stall += n;
        if (m_drained_since_stall >= 1000 && m_stall_timeout > STALL_TIMEOUT_MIN) {
            m_stall_timeout = std::max(m_stall_timeout / 2, STALL_TIMEOUT_MIN);
            m_drained_since_stall = 0;
        }
    }

    /// Keep the window full: every height from the next to drain up to the
    /// window's end that is neither buffered nor in flight is asked of the
    /// least loaded eligible peer, while the buffer is under its byte bound.
    /// Returns how many were asked.
    template <typename Fill>
    uint32_t refill(const Fill& fill)
    {
        if (!fill.active)
            return 0;
        const auto t = now();
        sync(fill);
        auto peers = eligible_peers(t);
        uint32_t asked = 0;
        const uint64_t last = std::min<uint64_t>(fill.end_height, uint64_t(fill.next_height) + fill.window - 1);
        for (uint64_t hh = fill.next_height; hh <= last && !peers.empty(); ++hh) {
            const uint32_t h = static_cast<uint32_t>(hh);
            if (fill.buffer.count(h) || m_inflight.count(h))
                continue;
            // At the byte bound only the next height is asked (the drain
            // needs it; everything buffered waits for it).
            if (h != fill.next_height && m_buffer_bytes >= m_buffer_limit) {
                m_stats.window_waits.fetch_add(1, std::memory_order_relaxed);
                break;
            }
            // The least loaded peer with room; ties go round robin.
            std::string pick;
            uint32_t pick_load = PER_PEER_IN_FLIGHT;
            for (size_t i = 0; i < peers.size(); ++i) {
                const auto& p = peers[(m_peer_rr + i) % peers.size()];
                auto ld = m_load.find(p);
                const uint32_t l = ld == m_load.end() ? 0 : ld->second;
                if (l < pick_load) {
                    pick = p;
                    pick_load = l;
                }
            }
            if (pick.empty())
                break;  // every peer has PER_PEER_IN_FLIGHT outstanding
            ++m_peer_rr;
            if (!m_host.request_from(pick, h)) {
                peers.erase(std::remove(peers.begin(), peers.end(), pick), peers.end());
                m_peers_at = {};
                --hh;  // this height again, another peer
                continue;
            }
            m_inflight[h] = InFlight{pick, t};
            ++m_load[pick];
            ++asked;
            m_stats.requests.fetch_add(1, std::memory_order_relaxed);
        }
        publish();
        return asked;
    }

    /// The periodic check (every second): requests unanswered for
    /// REQUEST_TIMEOUT go to other peers; a peer holding the window's first
    /// height past the stall timeout while the window cannot move is rotated
    /// out; then the window is refilled.
    template <typename Fill>
    void tick(const Fill& fill)
    {
        if (!fill.active)
            return;
        const auto t = now();
        sync(fill);
        for (auto it = m_inflight.begin(); it != m_inflight.end();) {
            if (t - it->second.sent > REQUEST_TIMEOUT) {
                m_stats.request_timeouts.fetch_add(1, std::memory_order_relaxed);
                m_cooldown[it->second.peer] = t + PEER_COOLDOWN;
                m_peers_at = {};
                auto next = std::next(it);
                drop_request(it);
                it = next;
            } else {
                ++it;
            }
        }
        auto first = m_inflight.find(fill.next_height);
        if (first != m_inflight.end() && t - first->second.sent > m_stall_timeout) {
            // Core: a staller only when nothing more can be asked (the window
            // is full, or the buffer at its bound). A slow peer with room left
            // in the window is left to REQUEST_TIMEOUT.
            const uint32_t window_end = static_cast<uint32_t>(
                std::min<uint64_t>(fill.end_height, uint64_t(fill.next_height) + fill.window - 1));
            const size_t span = window_end - fill.next_height + 1;
            const bool window_waits = m_buffer_bytes >= m_buffer_limit
                || m_inflight.size() + fill.buffer.size() >= span;
            if (window_waits) {
                const std::string staller = first->second.peer;
                m_stats.stalls.fetch_add(1, std::memory_order_relaxed);
                LOG_INFO << m_tag << " peer " << staller << " stalls h=" << fill.next_height << " ("
                         << std::chrono::duration_cast<std::chrono::milliseconds>(t - first->second.sent).count()
                         << " ms, timeout " << m_stall_timeout.count() << " ms): rotated out, its requests reassigned";
                cool_down(staller, t);
                m_stall_timeout = std::min(m_stall_timeout * 2, STALL_TIMEOUT_MAX);
                m_drained_since_stall = 0;
            }
        }
        refill(fill);
    }

    /// The fill's stall timer fired for height h (no block drained for its
    /// STALL_TIMEOUT_SEC): another peer is asked for h (its holder cools
    /// down), every peer on the STALLS_BEFORE_BROADCAST-th stall of h.
    /// Returns true when every peer was asked.
    template <typename Fill>
    bool on_fill_stall(const Fill& fill, uint32_t h)
    {
        m_stats.fill_stalls.fetch_add(1, std::memory_order_relaxed);
        if (h != m_stall_height) {
            m_stall_height = h;
            m_stall_count = 0;
        }
        ++m_stall_count;
        if (m_stall_count >= STALLS_BEFORE_BROADCAST) {
            m_stall_count = 0;
            m_stats.broadcasts.fetch_add(1, std::memory_order_relaxed);
            LOG_WARNING << m_tag << " h=" << h << " stalled " << STALLS_BEFORE_BROADCAST
                        << " times: asking every peer";
            m_host.request_all(h);
            return true;
        }
        const auto t = now();
        auto it = m_inflight.find(h);
        if (it != m_inflight.end()) {
            LOG_WARNING << m_tag << " h=" << h << " stalled on peer " << it->second.peer
                        << ": asking another peer";
            cool_down(it->second.peer, t);
        }
        refill(fill);
        return false;
    }

    size_t in_flight() const { return m_inflight.size(); }
    size_t buffer_bytes() const { return m_buffer_bytes; }
    /// The peer asked for height h ("" = none).
    std::string asked_peer(uint32_t h) const
    {
        auto it = m_inflight.find(h);
        return it == m_inflight.end() ? std::string() : it->second.peer;
    }
    const Stats& stats() const { return m_stats; }
    nlohmann::json to_json() const { return m_stats.to_json(); }

private:
    struct InFlight {
        std::string peer;
        Clock::time_point sent;
    };

    Clock::time_point now() const { return m_host.now ? m_host.now() : Clock::now(); }

    void drop_request(std::map<uint32_t, InFlight>::iterator it)
    {
        auto load = m_load.find(it->second.peer);
        if (load != m_load.end() && load->second > 0 && --load->second == 0)
            m_load.erase(load);
        m_inflight.erase(it);
    }

    /// Forget requests and sizes the fill no longer covers (drained, a range
    /// moved, the fill stopped).
    template <typename Fill>
    void sync(const Fill& fill)
    {
        for (auto it = m_sizes.begin(); it != m_sizes.end();) {
            if (it->first < fill.next_height || !fill.buffer.count(it->first)) {
                m_buffer_bytes -= std::min(m_buffer_bytes, it->second);
                it = m_sizes.erase(it);
            } else {
                ++it;
            }
        }
        for (auto it = m_inflight.begin(); it != m_inflight.end();) {
            if (!fill.active || it->first < fill.next_height || it->first > fill.end_height
                || fill.buffer.count(it->first)) {
                auto next = std::next(it);
                drop_request(it);
                it = next;
            } else {
                ++it;
            }
        }
    }

    /// The host's peers minus the ones cooling down; all of them if every
    /// one is cooling.
    std::vector<std::string> eligible_peers(Clock::time_point t)
    {
        if (m_peers.empty() || t - m_peers_at > std::chrono::seconds(1)) {
            m_peers = m_host.peers();
            m_peers_at = t;
            if (!m_peers.empty()) {
                m_no_peers_since = {};
            } else if (m_no_peers_since == Clock::time_point{}) {
                m_no_peers_since = t;
            } else if (t - m_no_peers_since > std::chrono::seconds(60)
                       && t - m_no_peers_logged > std::chrono::minutes(10)) {
                m_no_peers_logged = t;
                LOG_WARNING << m_tag << " no peer to ask for "
                            << std::chrono::duration_cast<std::chrono::seconds>(t - m_no_peers_since).count()
                            << "s; nothing asked but the stall timer's";
            }
        }
        for (auto it = m_cooldown.begin(); it != m_cooldown.end();)
            it = it->second <= t ? m_cooldown.erase(it) : std::next(it);
        std::vector<std::string> out;
        for (const auto& p : m_peers)
            if (!m_cooldown.count(p))
                out.push_back(p);
        return out.empty() ? m_peers : out;
    }

    /// Rotate `peer` out for PEER_COOLDOWN; its requests go to other peers
    /// at the next refill.
    void cool_down(const std::string& peer, Clock::time_point t)
    {
        if (peer.empty())
            return;
        m_cooldown[peer] = t + PEER_COOLDOWN;
        for (auto it = m_inflight.begin(); it != m_inflight.end();) {
            if (it->second.peer == peer) {
                auto next = std::next(it);
                drop_request(it);
                it = next;
            } else {
                ++it;
            }
        }
        m_peers_at = {};
    }

    void publish()
    {
        m_stats.inflight.store(m_inflight.size(), std::memory_order_relaxed);
        m_stats.peers_used.store(m_load.size(), std::memory_order_relaxed);
        m_stats.peers_cooling.store(m_cooldown.size(), std::memory_order_relaxed);
        m_stats.buffer_bytes.store(m_buffer_bytes, std::memory_order_relaxed);
        m_stats.stall_timeout_ms.store(static_cast<uint64_t>(m_stall_timeout.count()),
                                       std::memory_order_relaxed);
    }

    Host        m_host;
    std::string m_tag;
    size_t      m_buffer_limit;
    Stats       m_stats;

    std::map<uint32_t, InFlight>                  m_inflight;  // height -> its request
    std::map<std::string, uint32_t>               m_load;      // peer -> requests outstanding
    std::map<std::string, Clock::time_point>      m_cooldown;  // peer -> not asked until
    std::map<uint32_t, size_t>                    m_sizes;     // buffered height -> bytes
    size_t                                        m_buffer_bytes{0};
    std::vector<std::string>                      m_peers;
    Clock::time_point                             m_peers_at{};
    size_t                                        m_peer_rr{0};
    std::chrono::milliseconds                     m_stall_timeout{STALL_TIMEOUT_MIN};
    uint32_t                                      m_drained_since_stall{0};
    uint32_t                                      m_stall_height{0};
    uint32_t                                      m_stall_count{0};
    Clock::time_point                             m_no_peers_since{};
    Clock::time_point                             m_no_peers_logged{};
};

} // namespace coin
} // namespace core
