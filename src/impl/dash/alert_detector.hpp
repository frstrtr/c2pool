// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Miner presence detector for the alert relay (D-MINER.7) -- pure, header-only,
// clock-injected, KAT-able.
//
// INPUT: one sample list per tick, built from the stratum worker registry
// (DASHWorkSource::get_stratum_workers(): a session is registered on authorize
// and unregistered on disconnect). Worker key = "ADDRESS.worker" (or the bare
// address), the same key /local_stats uses for miner_hash_rates.
//
// A worker is UP when at least one session maps to its key AND either the
// stall check is off (stall_after 0: presence only, a connection is up) or it
// showed LIVE EVIDENCE within stall_after seconds. Live evidence = a session's
// accepted-share counter advanced (a new session counts only if it arrives
// with accepted shares). A connection alone is NOT evidence: all nodes are
// peers, and a rig keeps a failover (standby) connection to a node it does not
// mine on. Hashrate is deliberately NOT evidence either: it is a 1000 s
// sliding average and keeps a dead rig "alive" for up to ~17 minutes.
//
// RULES (all seconds, clock injected):
//   OFFLINE     fires once a known worker has been DOWN continuously for
//               offline_after, not before startup_grace has elapsed since the
//               detector started, and not within min_interval of the previous
//               OFFLINE for the same worker.
//   BACK_ONLINE fires only for a worker whose OFFLINE was emitted, after it has
//               been UP continuously for online_after.
//   A worker that was never seen UP (in this process or in persisted state)
//   never produces an OFFLINE: a standby connection that never shared here
//   is normal, not a fault.
//   RETURNED: a worker that hashed here and then went down (disconnected or
//   stalled) is not paged if it is mining on another node -- its payout
//   address has a share MINTED ON ANOTHER NODE (received from a peer) newer
//   than the worker's last share here (by returned_margin) and within
//   returned_horizon, while no worker of that address is UP here. The worker
//   becomes standby here (as if it never hashed here); the node it mines on
//   now is the one that pages if it dies. When the chain cannot be read (busy
//   tracker), the decision waits up to returned_defer_max, then pages.
//   Shares carry the payout address, not the worker name: with rigs of one
//   address on two nodes, a hung rig here is masked while no sibling hashes
//   here, and a rig that returned to its first pool is paged while a sibling
//   still hashes here. Share times come from the minting node's clock
//   (NTP-synced peers assumed). The dashboard shows each rig's own state.
//   Global cap: at most max_per_hour OFFLINE/BACK_ONLINE events per rolling
//   hour; the first event refused by the cap produces ONE digest instead, and
//   refused events stay pending (they fire when the window frees up if the
//   condition still holds) -- nothing is silently lost.
//
// Persistence (restore()/persist()): known workers with their last-seen time,
// whether an OFFLINE is outstanding and, for a worker that was down, when its
// outage began, so a restart neither forgets a rig that never reconnects nor
// re-pages one already reported, and a later BACK_ONLINE reports the REAL
// outage length (not "since the node restarted").
//
// No money / consensus state: reads a worker key, a session id, a counter and
// (through an optional callback) per-address sharechain share times.

#include "alert_relay.hpp"   // Kind, kind_name

#include <nlohmann/json.hpp>

#include <cstdint>
#include <algorithm>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace dash::alert {

struct WorkerSample {
    std::string key;        // "ADDRESS.worker"
    std::string session;    // stratum session id
    uint64_t    accepted{0};
};

struct DetectorConfig {
    int64_t offline_after{300};
    int64_t online_after{60};
    int64_t min_interval{600};
    int64_t startup_grace{600};
    int64_t stall_after{900};          // 0 = presence only: connected = up, shares not checked
    int64_t returned_margin{60};       // other-node share must be this much newer than the last share here
    int64_t returned_horizon{900};     // ... and no older than this (address still mining)
    int64_t returned_defer_max{120};   // chain unreadable this long -> page anyway
    std::size_t max_per_hour{30};
    int64_t known_expiry{7 * 86400};   // forget workers absent this long
    std::size_t max_workers{4096};     // memory bound on tracked keys
};

struct DetectorEvent {
    Kind        kind{Kind::Offline};
    std::string worker;
    std::string detail;
    int64_t     ts{0};
};

inline std::string fmt_duration(int64_t s)
{
    if (s < 0) s = 0;
    if (s < 120) return std::to_string(s) + "s";
    if (s < 7200) return std::to_string(s / 60) + "m";
    return std::to_string(s / 3600) + "h" + std::to_string((s % 3600) / 60) + "m";
}

// Newest sharechain share time (unix seconds) carrying this payout address and
// minted on another node; 0 = none in the walked window; nullopt = the chain
// cannot be read right now.
using AddressActivityFn = std::function<std::optional<int64_t>(const std::string& address)>;

class AlertDetector {
public:
    struct State {
        bool present{false};
        bool up{false};
        int64_t up_since{0};
        int64_t down_since{0};
        int64_t last_evidence{0};
        int64_t last_seen{0};
        std::map<std::string, uint64_t> sessions;   // session id -> accepted
        // Hashed on this node (in this process or persisted). Only such a
        // worker can be paged OFFLINE.
        bool ever_up{false};
        int64_t defer_since{0};                     // RETURNED check waiting on the chain
        bool offline_alerted{false};
        int64_t last_offline_alert{0};
        std::string down_cause;
        // When the outage began as far as anyone observed (reported in the
        // alert texts). down_since drives the OFFLINE timer and is reset to
        // the detector start on restore; outage_since survives the restart.
        int64_t outage_since{0};
    };

    AlertDetector(DetectorConfig cfg, int64_t start_ts)
        : m_cfg(cfg), m_start(start_ts), m_grace_until(start_ts + cfg.startup_grace) {}

    const DetectorConfig& config() const { return m_cfg; }
    int64_t grace_until() const { return m_grace_until; }
    const std::map<std::string, State>& workers() const { return m_workers; }
    uint64_t suppressed_by_cap() const { return m_suppressed; }
    // Bumped whenever persisted state changes (new worker, up/down, alert
    // emitted, worker forgotten) -- NOT on the per-tick last_seen refresh.
    uint64_t generation() const { return m_gen; }

    void set_address_activity(AddressActivityFn fn) { m_activity = std::move(fn); }

    // Restore persisted known workers. They start DOWN at the detector start
    // (node downtime is not counted against them).
    void restore(const nlohmann::json& j)
    {
        if (!j.is_object()) return;
        for (auto it = j.begin(); it != j.end(); ++it) {
            if (!it.value().is_object()) continue;
            if (m_workers.size() >= m_cfg.max_workers) break;
            State s;
            s.last_seen = it.value().value("last_seen", int64_t{0});
            s.offline_alerted = it.value().value("offline_alerted", false);
            s.last_offline_alert = it.value().value("last_offline_alert", int64_t{0});
            if (m_start - s.last_seen > m_cfg.known_expiry) continue;
            s.up = false;
            s.ever_up = true;         // persisted only once it hashed here
            s.down_since = m_start;   // node downtime never shortens the OFFLINE timer
            // A worker persisted as down keeps its outage start; one that was up
            // was last observed at last_seen, so its outage began no earlier.
            const int64_t persisted_outage = it.value().value("outage_since", int64_t{0});
            s.outage_since = persisted_outage > 0 ? persisted_outage : (s.last_seen > 0 ? s.last_seen : m_start);
            if (s.outage_since > m_start) s.outage_since = m_start;
            s.down_cause = "not reconnected since node restart";
            m_workers.emplace(it.key(), std::move(s));
        }
        ++m_gen;
    }

    nlohmann::json persist() const
    {
        nlohmann::json j = nlohmann::json::object();
        for (const auto& [k, s] : m_workers) {
            // A standby-only worker is not persisted: after a restart it
            // would otherwise be paged as "not reconnected".
            if (!s.ever_up && !s.offline_alerted) continue;
            j[k] = {{"last_seen", s.last_seen},
                    {"offline_alerted", s.offline_alerted},
                    {"last_offline_alert", s.last_offline_alert},
                    {"outage_since", s.up ? int64_t{0} : s.outage_since}};
        }
        return j;
    }

    std::vector<DetectorEvent> tick(const std::vector<WorkerSample>& samples, int64_t now)
    {
        std::vector<DetectorEvent> out;

        // 1) aggregate the registry per worker key
        struct Agg { std::map<std::string, uint64_t> sessions; };
        std::map<std::string, Agg> agg;
        for (const auto& s : samples) {
            if (s.key.empty()) continue;
            auto& acc = agg[s.key].sessions[s.session];
            acc = std::max(acc, s.accepted);
        }

        // 2) fold into per-worker state
        for (auto& [key, a] : agg) {
            auto it = m_workers.find(key);
            if (it == m_workers.end()) {
                if (m_workers.size() >= m_cfg.max_workers) continue;   // bounded
                it = m_workers.emplace(key, State{}).first;
                ++m_gen;
            }
            State& st = it->second;
            bool evidence = false;
            for (const auto& [sid, acc] : a.sessions) {
                auto prev = st.sessions.find(sid);
                if (acc > (prev == st.sessions.end() ? 0 : prev->second)) { evidence = true; break; }
            }
            st.present = true;
            st.last_seen = now;
            st.sessions = std::move(a.sessions);
            if (evidence) st.last_evidence = now;
        }
        for (auto& [key, st] : m_workers) {
            if (agg.count(key)) continue;
            if (st.present) {
                st.present = false;
                st.sessions.clear();
            }
        }

        // 3) transitions
        prune_rate(now);
        std::set<std::string> up_addresses;
        for (auto& [key, st] : m_workers) {
            const bool is_up = st.present &&
                (m_cfg.stall_after <= 0 ||
                 (st.last_evidence > 0 && now - st.last_evidence < m_cfg.stall_after));
            if (is_up && !st.up) {
                st.up = true;
                st.up_since = now;
                if (!st.ever_up) st.ever_up = true;
                st.defer_since = 0;
                ++m_gen;
            } else if (!is_up && st.up) {
                st.up = false;
                st.down_since = now;
                st.outage_since = now;
                st.down_cause = st.present
                    ? "connected but no accepted shares for " + fmt_duration(now - st.last_evidence)
                    : "disconnected";
                ++m_gen;
            }
            if (st.up) up_addresses.insert(address_of(key));
        }

        // 4) events
        std::map<std::string, std::optional<int64_t>> activity;   // one lookup per address per tick
        for (auto& [key, st] : m_workers) {
            if (st.ever_up && !st.up && !st.offline_alerted && now >= m_grace_until &&
                now - st.down_since >= m_cfg.offline_after &&
                (st.last_offline_alert == 0 || now - st.last_offline_alert >= m_cfg.min_interval)) {
                if (m_activity) {
                    const std::string addr = address_of(key);
                    if (!up_addresses.count(addr)) {
                        auto [ait, fresh] = activity.try_emplace(addr);
                        if (fresh) ait->second = m_activity(addr);
                        const auto& newest = ait->second;
                        if (!newest) {
                            // Chain unreadable: wait, but never forever.
                            if (st.defer_since == 0) st.defer_since = now;
                            if (now - st.defer_since < m_cfg.returned_defer_max) continue;
                        } else if (*newest > (st.last_evidence > 0 ? st.last_evidence : outage_start(st))
                                                 + m_cfg.returned_margin &&
                                   *newest >= now - m_cfg.returned_horizon) {
                            // Mining on another node: standby here, no page.
                            // Forget the old evidence too, so a standby
                            // reconnect does not count as up.
                            st.ever_up = false;
                            st.last_evidence = 0;
                            st.defer_since = 0;
                            st.down_cause = "mining on another node";
                            ++m_gen;
                            continue;
                        }
                    }
                }
                st.defer_since = 0;
                if (!admit_rate(key, now, out)) continue;
                DetectorEvent ev;
                ev.kind = Kind::Offline;
                ev.worker = key;
                ev.ts = now;
                // A restored worker that reconnected but never shared since.
                const std::string cause = st.present && st.last_evidence == 0
                    ? std::string("connected, no accepted share since node restart")
                    : st.down_cause;
                ev.detail = cause + "; down " + fmt_duration(now - outage_start(st));
                out.push_back(std::move(ev));
                st.offline_alerted = true;
                st.last_offline_alert = now;
                ++m_gen;
            } else if (st.up && st.offline_alerted && now - st.up_since >= m_cfg.online_after) {
                if (!admit_rate(key, now, out)) continue;
                DetectorEvent ev;
                ev.kind = Kind::BackOnline;
                ev.worker = key;
                ev.ts = now;
                ev.detail = "back online after " + fmt_duration(st.up_since - outage_start(st)) +
                            " down; up " + fmt_duration(now - st.up_since);
                out.push_back(std::move(ev));
                st.offline_alerted = false;
                ++m_gen;
            }
        }

        // 5) forget long-absent workers (bounded memory)
        for (auto it = m_workers.begin(); it != m_workers.end(); ) {
            if (!it->second.present && now - it->second.last_seen > m_cfg.known_expiry) {
                it = m_workers.erase(it);
                ++m_gen;
            } else
                ++it;
        }
        return out;
    }

    nlohmann::json status_json(int64_t now) const
    {
        nlohmann::json w = nlohmann::json::object();
        for (const auto& [k, s] : m_workers)
            w[k] = {{"up", s.up},
                    {"since", s.up ? s.up_since : s.down_since},
                    {"offline_alerted", s.offline_alerted},
                    {"sessions", s.sessions.size()},
                    // Never hashed here (or returned to another node): a
                    // failover connection, not paged.
                    {"standby", !s.ever_up && !s.offline_alerted}};
        return {{"workers", w},
                {"grace_until", m_grace_until},
                {"in_grace", now < m_grace_until},
                {"suppressed_by_cap", m_suppressed}};
    }

private:
    // Payout address of a worker key ("ADDRESS.worker" or the bare address).
    static std::string address_of(const std::string& key)
    {
        const auto dot = key.find('.');
        return dot == std::string::npos ? key : key.substr(0, dot);
    }

    static int64_t outage_start(const State& st)
    {
        return st.outage_since > 0 && st.outage_since < st.down_since ? st.outage_since : st.down_since;
    }

    void prune_rate(int64_t now)
    {
        while (!m_rate.empty() && m_rate.front() + 3600 <= now) m_rate.pop_front();
        if (m_rate.size() < m_cfg.max_per_hour) { m_digest_sent = false; m_held.clear(); }
    }

    // Charge one event against the hourly cap. When refused, emit the single
    // digest for this saturation episode and report false (event stays pending).
    bool admit_rate(const std::string& key, int64_t now, std::vector<DetectorEvent>& out)
    {
        if (m_rate.size() < m_cfg.max_per_hour) {
            m_rate.push_back(now);
            return true;
        }
        // Count each held worker once per saturation episode (not once per tick).
        if (m_held.insert(key).second) ++m_suppressed;
        if (!m_digest_sent) {
            m_digest_sent = true;
            DetectorEvent d;
            d.kind = Kind::Digest;
            d.ts = now;
            d.detail = "alert cap of " + std::to_string(m_cfg.max_per_hour) +
                       "/h reached; further worker changes are held until the hourly window frees";
            out.push_back(std::move(d));
        }
        return false;
    }

    DetectorConfig m_cfg;
    int64_t m_start;
    int64_t m_grace_until;
    std::map<std::string, State> m_workers;
    std::deque<int64_t> m_rate;
    bool m_digest_sent{false};
    std::set<std::string> m_held;   // workers held by the cap in this episode
    uint64_t m_suppressed{0};
    uint64_t m_gen{0};
    AddressActivityFn m_activity;
};

} // namespace dash::alert
