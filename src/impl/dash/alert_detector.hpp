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
// A worker is UP when at least one session maps to its key AND (stall check
// disabled OR it showed LIVE EVIDENCE within stall_after seconds). Live
// evidence = a new session appeared or the summed accepted-share counter
// advanced. Hashrate is deliberately NOT evidence: it is a 1000 s sliding
// average and keeps a dead rig "alive" for up to ~17 minutes.
//
// RULES (all seconds, clock injected):
//   OFFLINE     fires once a known worker has been DOWN continuously for
//               offline_after, not before startup_grace has elapsed since the
//               detector started, and not within min_interval of the previous
//               OFFLINE for the same worker.
//   BACK_ONLINE fires only for a worker whose OFFLINE was emitted, after it has
//               been UP continuously for online_after.
//   A worker that was never seen UP (in this process or in persisted state)
//   never produces an OFFLINE.
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
// No money / consensus state: reads a worker key, a session id and a counter.

#include "alert_relay.hpp"   // Kind, kind_name

#include <nlohmann/json.hpp>

#include <cstdint>
#include <deque>
#include <map>
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
    int64_t stall_after{900};          // 0 = never flag a connected worker as down
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

class AlertDetector {
public:
    struct State {
        bool present{false};
        bool up{false};
        int64_t up_since{0};
        int64_t down_since{0};
        int64_t last_evidence{0};
        int64_t last_seen{0};
        uint64_t last_accepted{0};
        std::set<std::string> sessions;
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
        for (const auto& [k, s] : m_workers)
            j[k] = {{"last_seen", s.last_seen},
                    {"offline_alerted", s.offline_alerted},
                    {"last_offline_alert", s.last_offline_alert},
                    {"outage_since", s.up ? int64_t{0} : s.outage_since}};
        return j;
    }

    std::vector<DetectorEvent> tick(const std::vector<WorkerSample>& samples, int64_t now)
    {
        std::vector<DetectorEvent> out;

        // 1) aggregate the registry per worker key
        struct Agg { std::set<std::string> sessions; uint64_t accepted{0}; };
        std::map<std::string, Agg> agg;
        for (const auto& s : samples) {
            if (s.key.empty()) continue;
            auto& a = agg[s.key];
            a.sessions.insert(s.session);
            a.accepted += s.accepted;
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
            for (const auto& sid : a.sessions)
                if (!st.sessions.count(sid)) { evidence = true; break; }
            if (a.accepted > st.last_accepted) evidence = true;
            st.present = true;
            st.last_seen = now;
            st.sessions = std::move(a.sessions);
            st.last_accepted = a.accepted;
            if (evidence) st.last_evidence = now;
        }
        for (auto& [key, st] : m_workers) {
            if (agg.count(key)) continue;
            if (st.present) {
                st.present = false;
                st.sessions.clear();
                st.last_accepted = 0;
            }
        }

        // 3) transitions + events
        prune_rate(now);
        for (auto& [key, st] : m_workers) {
            const bool is_up = st.present &&
                (m_cfg.stall_after <= 0 || now - st.last_evidence < m_cfg.stall_after);
            if (is_up && !st.up) {
                st.up = true;
                st.up_since = now;
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

            if (!st.up && !st.offline_alerted && now >= m_grace_until &&
                now - st.down_since >= m_cfg.offline_after &&
                (st.last_offline_alert == 0 || now - st.last_offline_alert >= m_cfg.min_interval)) {
                if (!admit_rate(key, now, out)) continue;
                DetectorEvent ev;
                ev.kind = Kind::Offline;
                ev.worker = key;
                ev.ts = now;
                ev.detail = st.down_cause + "; down " + fmt_duration(now - outage_start(st));
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

        // 4) forget long-absent workers (bounded memory)
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
                    {"sessions", s.sessions.size()}};
        return {{"workers", w},
                {"grace_until", m_grace_until},
                {"in_grace", now < m_grace_until},
                {"suppressed_by_cap", m_suppressed}};
    }

private:
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
};

} // namespace dash::alert
