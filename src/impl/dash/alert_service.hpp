// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Miner-offline alert relay SERVICE (D-MINER.7) -- the runtime that ties the
// detector, the origin retry ledger, the relay outbox and the forwarding
// policy together. Header-only, transport-injected, clock-injected: the whole
// multi-node behaviour is drivable in-process from a KAT with a fake mesh.
//
// ROLES (any combination; all OFF = this object is never constructed):
//   origin    -- samples the stratum worker registry, emits OFFLINE /
//                BACK_ONLINE / digest / test alerts sealed for each configured
//                relay, retransmits until a signed ack arrives.
//   telegram  -- accepts alerts addressed to its own key from allowlisted
//                origins, appends them to <state>/outbox.jsonl (0600) for the
//                Telegram sidecar, acks status 4 (queued) and, once the sidecar
//                appends the id to <state>/delivered.jsonl, acks status 1.
//   forward   -- store-and-forward for alerts not addressed to this node
//                (implied by the two roles above).
//
// DELIVERY SEMANTICS (honest by construction):
//   * The origin retransmits the SAME signed frame every retry_every seconds
//     (DPI-latched flows are recycled by TCP_USER_TIMEOUT and redialled; a
//     retransmit rides the fresh flow). Before the frame would leave the relay's
//     +/-900 s replay window it is re-issued with a fresh timestamp + nonce, so an
//     alert survives a long outage (bounded by retry_max and max_event_age).
//   * Forwarders dedupe by (origin pubkey, nonce); a duplicate is re-forwarded
//     at most once per kReforwardSec (so a retransmit can cross a hop whose
//     earlier forward was lost), and a cached ack is re-sent to the sender (so
//     a lost ack is repaired without reaching the relay again).
//   * The relay dedupes across restarts with a persisted accepted-id set, so a
//     frame is appended to the outbox once and Telegram is paged once per frame.
//     A re-issued frame (new nonce) after a lost ack CAN page twice -- a
//     duplicate page is preferred to a lost one; documented.
//   * "delivered" on the origin means the relay's sidecar got ok:true from
//     Telegram and the relay signed that; "queued_at_relay" means only that the
//     relay durably holds it. Nothing is ever reported delivered on a guess.
//
// THREADING: every method except status_json() runs on the node IO thread
// (peer handlers + the tick timer), same confinement as m_known_txs /
// m_inject_seen. status_json() reads a snapshot published under a mutex.
//
// No money / consensus state is reachable from here.

#include "alert_detector.hpp"
#include "alert_relay.hpp"

#include <core/log.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace dash::alert {

struct ServiceConfig {
    bool origin{false};
    bool telegram{false};
    bool forward{false};
    std::string state_dir;             // <data-dir>/<net>/alert_relay
    std::string label;                 // origin display label (<= 32)
    std::vector<Bytes> relays;         // origin: relay pubkeys to seal for
    std::vector<Bytes> accept;         // telegram: allowlisted origin pubkeys
    int64_t retry_every{60};
    int     retry_max{60};             // total transmissions per event
    int64_t reissue_after{600};        // < kReplayWindowSec
    int64_t max_event_age{6 * 3600};
    uint8_t hops{kDefaultHops};
    bool    test_on_start{false};
    int64_t test_delay{30};
    DetectorConfig det;
};

// Injected by the node (NodeImpl) -- or by a KAT's fake mesh.
struct Transport {
    std::function<bool(uint64_t peer, const AlertFrame&)>              send_alert;
    std::function<std::size_t(uint64_t except, const AlertFrame&)>     broadcast_alert;
    std::function<bool(uint64_t peer, const AckFrame&)>                send_ack;
    std::function<std::size_t(uint64_t except, const AckFrame&)>       broadcast_ack;
};

enum class Verdict {
    RateLimited, RejectedShape, RejectedStale, RejectedSig, Own, Duplicate,
    Forwarded, NotForwarded, Queued, RefusedNotAllowed, RefusedInvalid, Deferred,
    AckConsumed, AckForwarded, AckDropped,
};

inline const char* verdict_name(Verdict v)
{
    switch (v) {
    case Verdict::RateLimited:       return "rate-limited";
    case Verdict::RejectedShape:     return "rejected-shape";
    case Verdict::RejectedStale:     return "rejected-stale";
    case Verdict::RejectedSig:       return "rejected-signature";
    case Verdict::Own:               return "own";
    case Verdict::Duplicate:         return "duplicate";
    case Verdict::Forwarded:         return "forwarded";
    case Verdict::NotForwarded:      return "not-forwarded";
    case Verdict::Queued:            return "queued";
    case Verdict::RefusedNotAllowed: return "refused-not-allowlisted";
    case Verdict::RefusedInvalid:    return "refused-invalid";
    case Verdict::Deferred:          return "deferred";
    case Verdict::AckConsumed:       return "ack-consumed";
    case Verdict::AckForwarded:      return "ack-forwarded";
    case Verdict::AckDropped:        return "ack-dropped";
    }
    return "unknown";
}

class AlertRelayService {
public:
    static constexpr int64_t     kReforwardSec   = 20;
    static constexpr std::size_t kMaxPending     = 1000;
    static constexpr int64_t     kAcceptedKeepSec = 2 * 3600;       // final statuses
    static constexpr int64_t     kQueuedKeepSec   = 7 * 86400;      // awaiting sidecar
    static constexpr std::size_t kMaxAccepted    = 20000;
    static constexpr uintmax_t   kMaxOutboxBytes = 16u * 1024u * 1024u;

    struct Counters {
        uint64_t alert_in{0}, alert_out{0}, ack_in{0}, ack_out{0};
        uint64_t forwarded{0}, duplicates{0}, rate_limited{0};
        uint64_t rejected_shape{0}, rejected_stale{0}, rejected_sig{0};
        uint64_t refused_allowlist{0}, refused_invalid{0};
        uint64_t queued_outbox{0}, delivered_telegram{0}, outbox_errors{0};
        uint64_t events{0}, delivered{0}, queued_at_relay{0}, refused{0};
        uint64_t undelivered{0}, dropped{0}, reissued{0}, retransmits{0};
        uint64_t ack_forwarded{0}, ack_dropped{0};
    };

    struct PendingEvent {
        uint64_t event_id{0};
        uint8_t  kind{0};
        std::string worker, detail;
        int64_t  event_ts{0};
        Bytes    relay_pub;
        AlertFrame frame;
        std::set<uint64_t> nonces;
        int64_t  first_sent{0}, last_sent{0}, issued_at{0};
        int      attempts{0};
        bool     queued_at_relay{false};
    };

    struct Accepted { uint8_t status{0}; int64_t received{0}; };

    AlertRelayService(ServiceConfig cfg, std::optional<KeyPair> keys, int64_t start_ts)
        : m_cfg(std::move(cfg)), m_keys(std::move(keys)), m_start(start_ts),
          m_detector(m_cfg.det, start_ts)
    {
        if (m_keys) m_key_id = key_id(m_keys->pubkey);
        for (const auto& a : m_cfg.accept) m_accept.insert(a);
        m_next_nonce = static_cast<uint64_t>(start_ts) << 16;
    }

    // Load persisted state; create the state dir. Returns false (with err) only
    // on a fatal problem (unwritable state dir).
    bool init(std::string& err)
    {
        std::error_code ec;
        std::filesystem::create_directories(m_cfg.state_dir, ec);
        if (ec) { err = "cannot create alert-relay state dir " + m_cfg.state_dir + ": " + ec.message(); return false; }
        std::ifstream f(state_path());
        if (f) {
            auto j = nlohmann::json::parse(f, nullptr, /*allow_exceptions=*/false);
            if (j.is_object()) {
                uint64_t persisted = j.value("next_nonce", uint64_t{0});
                if (persisted > m_next_nonce) m_next_nonce = persisted;
                m_delivered_offset = j.value("delivered_offset", uint64_t{0});
                if (j.contains("accepted") && j["accepted"].is_object())
                    for (auto it = j["accepted"].begin(); it != j["accepted"].end(); ++it)
                        m_accepted[it.key()] = Accepted{it.value().value("status", uint8_t{0}),
                                                        it.value().value("received", int64_t{0})};
                if (m_cfg.origin && j.contains("workers")) m_detector.restore(j["workers"]);
                if (m_cfg.origin && m_keys && j.contains("pending") && j["pending"].is_array())
                    for (const auto& pj : j["pending"]) restore_pending(pj);
            } else {
                LOG_WARNING << "[alert-relay] state file " << state_path() << " unreadable; starting fresh";
            }
        }
        return save_state(err);
    }

    void set_transport(Transport t) { m_tx = std::move(t); }

    const ServiceConfig& config() const { return m_cfg; }
    const Counters& counters() const { return m_c; }
    const std::map<uint64_t, PendingEvent>& pending() const { return m_pending; }
    const AlertDetector& detector() const { return m_detector; }
    const NodeAlertSeen& seen() const { return m_seen; }
    const std::optional<KeyPair>& keys() const { return m_keys; }
    bool can_forward() const { return m_cfg.forward || m_cfg.origin || m_cfg.telegram; }

    std::string outbox_path() const { return m_cfg.state_dir + "/outbox.jsonl"; }
    std::string delivered_path() const { return m_cfg.state_dir + "/delivered.jsonl"; }
    std::string ledger_path() const { return m_cfg.state_dir + "/ledger.jsonl"; }
    std::string state_path() const { return m_cfg.state_dir + "/state.json"; }

    // ── inbound: alert ─────────────────────────────────────────────────────
    Verdict on_alert(const AlertFrame& f, uint64_t from, PeerAlertGuard& guard, int64_t now)
    {
        ++m_c.alert_in;
        if (!guard.admit_alert(now)) { ++m_c.rate_limited; return Verdict::RateLimited; }
        if (const char* why = alert_shape_error(f)) {
            ++m_c.rejected_shape;
            LOG_DEBUG_POOL << "[alert-relay] dropping malformed alert (" << why << ")";
            return Verdict::RejectedShape;
        }
        if (m_keys && f.origin_pubkey == m_keys->pubkey) return Verdict::Own;

        if (SeenEntry* e = m_seen.find(f.origin_pubkey, f.nonce)) {
            ++m_c.duplicates;
            if (e->ack) {
                // Repair a lost ack: answer the retransmitting sender directly.
                if (m_tx.send_ack && m_tx.send_ack(from, *e->ack)) ++m_c.ack_out;
            } else {
                e->from_peer = from;   // newest live path for the eventual ack
                if (!e->for_me && can_forward() && e->frame.hops_left > 0 &&
                    now - e->last_forward >= kReforwardSec) {
                    forward(e->frame, from);
                    e->last_forward = now;
                }
            }
            return Verdict::Duplicate;
        }

        const bool for_me = m_keys && m_cfg.telegram && f.to_key_id == m_key_id;
        const int64_t skew = now - static_cast<int64_t>(f.timestamp);
        if (skew > kReplayWindowSec || skew < -kReplayWindowSec) {
            ++m_c.rejected_stale;
            if (for_me && verify_alert_sig(f)) {
                // Tell the origin its clock / queue is off (diagnostic, final).
                if (auto a = build_ack(*m_keys, f.origin_pubkey, f.nonce, AckStatus::RefusedInvalid))
                    send_or_broadcast_ack(from, *a);
                LOG_WARNING << "[alert-relay] alert from " << short_hex(f.origin_pubkey)
                            << " outside the +/-" << kReplayWindowSec << "s window (skew "
                            << skew << "s) -- check the origin clock";
            }
            return Verdict::RejectedStale;
        }
        if (!verify_alert_sig(f)) {
            ++m_c.rejected_sig;
            LOG_DEBUG_POOL << "[alert-relay] bad alert signature from peer nonce " << from;
            return Verdict::RejectedSig;
        }

        SeenEntry& e = m_seen.insert(f, from, now);
        e.for_me = for_me;
        if (for_me) return deliver_local(e, from, now);

        if (can_forward() && f.hops_left > 0) {
            forward(f, from);
            e.last_forward = now;
            return Verdict::Forwarded;
        }
        return Verdict::NotForwarded;
    }

    // ── inbound: ack ───────────────────────────────────────────────────────
    Verdict on_ack(const AckFrame& a, uint64_t from, PeerAlertGuard& guard, int64_t now)
    {
        ++m_c.ack_in;
        if (!guard.admit_ack(now)) { ++m_c.rate_limited; return Verdict::RateLimited; }
        if (ack_shape_error(a)) { ++m_c.rejected_shape; return Verdict::RejectedShape; }

        if (m_keys && a.origin_pubkey == m_keys->pubkey) return consume_ack(a, now);

        SeenEntry* e = m_seen.find(a.origin_pubkey, a.nonce);
        if (!e || e->for_me || key_id(a.relay_pubkey) != e->frame.to_key_id) {
            ++m_c.ack_dropped;
            return Verdict::AckDropped;
        }
        if (e->ack && !supersedes(a.status, e->ack->status)) { ++m_c.duplicates; return Verdict::Duplicate; }
        if (!verify_ack_sig(a)) { ++m_c.rejected_sig; return Verdict::RejectedSig; }
        e->ack = a;
        if (!(e->from_peer && m_tx.send_ack && m_tx.send_ack(e->from_peer, a)))
            if (m_tx.broadcast_ack) m_tx.broadcast_ack(from, a);
        ++m_c.ack_forwarded;
        return Verdict::AckForwarded;
    }

    // ── periodic (IO thread) ───────────────────────────────────────────────
    void on_tick(const std::vector<WorkerSample>& samples, int64_t now)
    {
        if (m_cfg.origin) {
            for (auto& ev : m_detector.tick(samples, now)) {
                enqueue_event(ev, now);
                m_state_dirty = true;
            }
            if (m_cfg.test_on_start && !m_test_sent && now >= m_start + m_cfg.test_delay) {
                m_test_sent = true;
                DetectorEvent t;
                t.kind = Kind::Test;
                t.ts = now;
                t.detail = "alert relay test from " + (m_cfg.label.empty() ? std::string("origin") : m_cfg.label);
                enqueue_event(t, now);
            }
            retransmit(now);
        }
        if (m_cfg.telegram) poll_delivered(now);
        prune_accepted(now);
        if (m_state_dirty || now - m_last_save >= 60) {
            std::string err;
            if (!save_state(err)) LOG_WARNING << "[alert-relay] " << err;
            m_last_save = now;
        }
        publish_status(now);
    }

    // Origin: queue one event for every configured relay and send it now.
    void enqueue_event(const DetectorEvent& ev, int64_t now)
    {
        if (!m_keys) return;
        ++m_c.events;
        LOG_INFO << "[alert-relay] event " << kind_name(static_cast<uint8_t>(ev.kind))
                 << (ev.worker.empty() ? std::string() : " worker=" + ev.worker)
                 << " (" << ev.detail << ")";
        for (const auto& relay : m_cfg.relays) {
            PendingEvent p;
            p.kind = static_cast<uint8_t>(ev.kind);
            p.worker = ev.worker;
            p.detail = ev.detail;
            p.event_ts = ev.ts;
            p.relay_pub = relay;
            p.first_sent = now;
            if (!issue(p, now)) continue;
            p.event_id = *p.nonces.begin();
            while (m_pending.size() >= kMaxPending) {
                auto oldest = m_pending.begin();
                ++m_c.dropped;
                LOG_WARNING << "[alert-relay] pending cap " << kMaxPending << " reached; dropping oldest event "
                            << oldest->first;
                finalize(oldest, "dropped_cap", now);
            }
            auto it = m_pending.emplace(p.event_id, std::move(p)).first;
            transmit(it->second, now);
        }
        std::string err;   // durable before the next tick: a crash cannot lose the event
        if (!save_state(err)) LOG_WARNING << "[alert-relay] " << err;
    }

    // Web thread: last snapshot published by the IO thread.
    nlohmann::json status_json() const
    {
        std::lock_guard<std::mutex> lk(m_status_mutex);
        return m_status;
    }

    // IO thread: rebuild the published snapshot now (also done every tick).
    void publish_status(int64_t now)
    {
        nlohmann::json s;
        s["role"] = {{"origin", m_cfg.origin}, {"telegram", m_cfg.telegram}, {"forward", can_forward()}};
        s["pubkey"] = m_keys ? to_hex(m_keys->pubkey) : std::string();
        nlohmann::json relays = nlohmann::json::array();
        for (const auto& r : m_cfg.relays) relays.push_back(to_hex(key_id(r)));
        s["relays"] = relays;
        s["allowlist"] = m_accept.size();
        if (m_cfg.origin) s["detector"] = m_detector.status_json(now);
        std::size_t awaiting = 0, queued = 0;
        for (const auto& [id, p] : m_pending) (p.queued_at_relay ? queued : awaiting)++;
        s["outbox"] = {{"pending", m_pending.size()}, {"awaiting_ack", awaiting}, {"queued_at_relay", queued},
                       {"delivered", m_c.delivered}, {"undelivered", m_c.undelivered},
                       {"refused", m_c.refused}, {"dropped", m_c.dropped},
                       {"retransmits", m_c.retransmits}, {"reissued", m_c.reissued}, {"events", m_c.events}};
        std::size_t pending_sidecar = 0;
        for (const auto& [id, a] : m_accepted) if (a.status == static_cast<uint8_t>(AckStatus::Queued)) ++pending_sidecar;
        s["relay"] = {{"accepted", m_c.queued_outbox}, {"refused_allowlist", m_c.refused_allowlist},
                      {"refused_invalid", m_c.refused_invalid}, {"refused_sig", m_c.rejected_sig},
                      {"rejected_stale", m_c.rejected_stale}, {"rejected_shape", m_c.rejected_shape},
                      {"duplicates", m_c.duplicates}, {"forwarded", m_c.forwarded},
                      {"rate_limited", m_c.rate_limited}, {"pending_sidecar", pending_sidecar},
                      {"delivered_telegram", m_c.delivered_telegram}, {"outbox_errors", m_c.outbox_errors},
                      {"seen", m_seen.size()}};
        s["p2p"] = {{"alert_in", m_c.alert_in}, {"alert_out", m_c.alert_out},
                    {"ack_in", m_c.ack_in}, {"ack_out", m_c.ack_out},
                    {"ack_forwarded", m_c.ack_forwarded}, {"ack_dropped", m_c.ack_dropped}};
        s["now"] = now;
        std::lock_guard<std::mutex> lk(m_status_mutex);
        m_status = std::move(s);
    }

    bool save_state(std::string& err)
    {
        nlohmann::json j;
        j["version"] = 1;
        j["next_nonce"] = m_next_nonce;
        j["delivered_offset"] = m_delivered_offset;
        nlohmann::json acc = nlohmann::json::object();
        for (const auto& [id, a] : m_accepted) acc[id] = {{"status", a.status}, {"received", a.received}};
        j["accepted"] = acc;
        if (m_cfg.origin) {
            j["workers"] = m_detector.persist();
            nlohmann::json pend = nlohmann::json::array();
            for (const auto& [id, p] : m_pending) pend.push_back(pending_json(p));
            j["pending"] = pend;
        }
        if (!atomic_write(state_path(), j.dump(), err)) return false;
        m_state_dirty = false;
        return true;
    }

private:
    static std::string short_hex(const Bytes& b) { return to_hex(b).substr(0, 16); }

    // Origin pending events survive a restart: the exact signed frame is kept
    // so a retransmit after restart reuses the SAME nonce (the relay dedupes it,
    // no double page); a frame too old for the relay window is re-issued.
    static nlohmann::json pending_json(const PendingEvent& p)
    {
        nlohmann::json nonces = nlohmann::json::array();
        for (uint64_t n : p.nonces) nonces.push_back(n);
        return {{"event_id", p.event_id}, {"kind", p.kind}, {"worker", p.worker}, {"detail", p.detail},
                {"event_ts", p.event_ts}, {"relay", to_hex(p.relay_pub)}, {"nonces", nonces},
                {"first_sent", p.first_sent}, {"issued_at", p.issued_at}, {"attempts", p.attempts},
                {"queued_at_relay", p.queued_at_relay},
                {"frame", {{"hops", p.frame.hops_left}, {"ts", p.frame.timestamp}, {"nonce", p.frame.nonce},
                           {"to", to_hex(p.frame.to_key_id)}, {"body", to_hex(p.frame.body)},
                           {"sig", to_hex(p.frame.signature)}}}};
    }

    void restore_pending(const nlohmann::json& pj)
    {
        if (!pj.is_object() || m_pending.size() >= kMaxPending) return;
        PendingEvent p;
        p.event_id = pj.value("event_id", uint64_t{0});
        p.kind = pj.value("kind", uint8_t{0});
        p.worker = pj.value("worker", std::string());
        p.detail = pj.value("detail", std::string());
        p.event_ts = pj.value("event_ts", int64_t{0});
        auto relay = from_hex(pj.value("relay", std::string()));
        if (!p.event_id || !relay || !is_valid_pubkey(*relay)) return;
        // Only keep events for relays still configured.
        bool configured = false;
        for (const auto& r : m_cfg.relays) configured = configured || r == *relay;
        if (!configured) return;
        p.relay_pub = *relay;
        if (pj.contains("nonces") && pj["nonces"].is_array())
            for (const auto& n : pj["nonces"]) if (n.is_number_unsigned()) p.nonces.insert(n.get<uint64_t>());
        p.first_sent = pj.value("first_sent", int64_t{0});
        p.issued_at = pj.value("issued_at", int64_t{0});
        p.attempts = pj.value("attempts", 0);
        p.queued_at_relay = pj.value("queued_at_relay", false);
        const auto& fj = pj.contains("frame") ? pj["frame"] : nlohmann::json::object();
        auto to = from_hex(fj.value("to", std::string()));
        auto body = from_hex(fj.value("body", std::string()));
        auto sig = from_hex(fj.value("sig", std::string()));
        if (!to || !body || !sig) return;
        p.frame.version = kWireVersion;
        p.frame.hops_left = fj.value("hops", m_cfg.hops);
        p.frame.timestamp = fj.value("ts", uint32_t{0});
        p.frame.nonce = fj.value("nonce", uint64_t{0});
        p.frame.origin_pubkey = m_keys->pubkey;
        p.frame.to_key_id = *to;
        p.frame.body = *body;
        p.frame.signature = *sig;
        if (alert_shape_error(p.frame) || !verify_alert_sig(p.frame)) return;   // never resend a bad frame
        p.last_sent = 0;   // retransmit on the first tick after restart
        p.nonces.insert(p.frame.nonce);
        for (uint64_t n : p.nonces) m_nonce_to_event[n] = p.event_id;
        m_pending.emplace(p.event_id, std::move(p));
    }

    static bool supersedes(uint8_t incoming, uint8_t cached)
    {
        return cached == static_cast<uint8_t>(AckStatus::Queued) && incoming != cached;
    }

    static bool atomic_write(const std::string& path, const std::string& data, std::string& err)
    {
        const std::string tmp = path + ".tmp";
        int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) { err = "cannot write " + tmp; return false; }
        bool ok = ::write(fd, data.data(), data.size()) == static_cast<ssize_t>(data.size());
        ok = (::fsync(fd) == 0) && ok;
        ::close(fd);
        if (!ok || std::rename(tmp.c_str(), path.c_str()) != 0) { err = "cannot persist " + path; return false; }
        return true;
    }

    static bool append_line(const std::string& path, const std::string& line)
    {
        int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (fd < 0) return false;
        const std::string l = line + "\n";
        bool ok = ::write(fd, l.data(), l.size()) == static_cast<ssize_t>(l.size());
        ok = (::fsync(fd) == 0) && ok;
        ::close(fd);
        return ok;
    }

    void forward(const AlertFrame& f, uint64_t from)
    {
        AlertFrame out = f;
        out.hops_left = static_cast<uint8_t>(f.hops_left - 1);
        std::size_t n = m_tx.broadcast_alert ? m_tx.broadcast_alert(from, out) : 0;
        m_c.alert_out += n;
        ++m_c.forwarded;
    }

    void send_or_broadcast_ack(uint64_t to, const AckFrame& a)
    {
        if (to && m_tx.send_ack && m_tx.send_ack(to, a)) { ++m_c.ack_out; return; }
        if (m_tx.broadcast_ack) m_c.ack_out += m_tx.broadcast_ack(0, a);
    }

    bool allowlisted(const Bytes& origin) const { return m_accept.count(origin) != 0; }

    Verdict deliver_local(SeenEntry& e, uint64_t from, int64_t now)
    {
        const AlertFrame& f = e.frame;
        const std::string id = alert_id_string(f.origin_pubkey, f.nonce);
        auto ack_with = [&](AckStatus st) {
            if (auto a = build_ack(*m_keys, f.origin_pubkey, f.nonce, st)) {
                e.ack = *a;
                send_or_broadcast_ack(from, *a);
            }
        };

        if (auto it = m_accepted.find(id); it != m_accepted.end()) {
            // Already accepted before a restart: re-ack, never re-append.
            ++m_c.duplicates;
            ack_with(static_cast<AckStatus>(it->second.status));
            return Verdict::Duplicate;
        }
        if (!allowlisted(f.origin_pubkey)) {
            ++m_c.refused_allowlist;
            auto& last = m_refused_log[f.origin_pubkey];
            if (last == 0 || now - last >= 3600) {
                last = now;
                LOG_WARNING << "[alert-relay] refusing alert from non-allowlisted origin "
                            << to_hex(f.origin_pubkey) << " (add it with --alert-relay-accept)";
            }
            ack_with(AckStatus::RefusedNotAllowed);
            return Verdict::RefusedNotAllowed;
        }
        auto body = open_alert(*m_keys, f);
        if (!body) {
            ++m_c.refused_invalid;
            ack_with(AckStatus::RefusedInvalid);
            return Verdict::RefusedInvalid;
        }
        std::error_code ec;
        const auto sz = std::filesystem::exists(outbox_path(), ec) ? std::filesystem::file_size(outbox_path(), ec) : 0;
        nlohmann::json row = {
            {"id", id}, {"origin", to_hex(f.origin_pubkey)}, {"nonce", f.nonce},
            {"kind", kind_name(body->kind)}, {"label", body->label}, {"worker", body->worker},
            {"detail", body->detail}, {"event_ts", body->event_ts}, {"sent_ts", f.timestamp},
            {"received_ts", now}};
        if (sz > kMaxOutboxBytes || !append_line(outbox_path(), row.dump())) {
            // Disk trouble: do NOT ack -- forget the frame so the origin's next
            // retransmit is processed afresh instead of as a duplicate.
            ++m_c.outbox_errors;
            LOG_ERROR << "[alert-relay] cannot append to " << outbox_path() << " (size " << sz << ")";
            m_seen.entries.erase(AlertId{f.origin_pubkey, f.nonce});
            return Verdict::Deferred;
        }
        m_accepted[id] = Accepted{static_cast<uint8_t>(AckStatus::Queued), now};
        std::string err;
        if (!save_state(err)) LOG_WARNING << "[alert-relay] " << err;
        ++m_c.queued_outbox;
        LOG_INFO << "[alert-relay] queued alert " << kind_name(body->kind) << " from "
                 << (body->label.empty() ? short_hex(f.origin_pubkey) : body->label)
                 << " for the Telegram sidecar (id " << short_hex(f.origin_pubkey) << ":" << f.nonce << ")";
        ack_with(AckStatus::Queued);
        return Verdict::Queued;
    }

    Verdict consume_ack(const AckFrame& a, int64_t now)
    {
        auto nit = m_nonce_to_event.find(a.nonce);
        if (nit == m_nonce_to_event.end()) { ++m_c.duplicates; return Verdict::Duplicate; }
        auto pit = m_pending.find(nit->second);
        if (pit == m_pending.end()) { ++m_c.duplicates; return Verdict::Duplicate; }
        PendingEvent& p = pit->second;
        if (a.relay_pubkey != p.relay_pub) { ++m_c.ack_dropped; return Verdict::AckDropped; }
        if (!verify_ack_sig(a)) { ++m_c.rejected_sig; return Verdict::RejectedSig; }
        switch (static_cast<AckStatus>(a.status)) {
        case AckStatus::Delivered:
            ++m_c.delivered;
            finalize(pit, "delivered", now);
            break;
        case AckStatus::Queued:
            if (!p.queued_at_relay) {
                p.queued_at_relay = true;
                m_state_dirty = true;
                ++m_c.queued_at_relay;
                ledger(p, "queued_at_relay", now);
                LOG_INFO << "[alert-relay] event " << p.event_id << " queued at relay "
                         << short_hex(p.relay_pub) << " (awaiting Telegram delivery)";
            }
            break;
        default:
            ++m_c.refused;
            finalize(pit, ack_status_name(a.status), now);
            break;
        }
        return Verdict::AckConsumed;
    }

    bool issue(PendingEvent& p, int64_t now)
    {
        AlertBody b;
        b.kind = p.kind;
        b.event_ts = static_cast<uint32_t>(p.event_ts);
        b.label = m_cfg.label;
        b.worker = p.worker;
        b.detail = p.detail;
        const uint64_t nonce = m_next_nonce++;
        // Persist the counter BEFORE the frame leaves: a crash can skip a nonce
        // but can never reuse one.
        std::string err;
        if (!save_state(err)) LOG_WARNING << "[alert-relay] " << err;
        auto f = build_alert(*m_keys, p.relay_pub, b, static_cast<uint32_t>(now), nonce, m_cfg.hops);
        if (!f) {
            LOG_ERROR << "[alert-relay] could not build alert for relay " << short_hex(p.relay_pub);
            return false;
        }
        p.frame = std::move(*f);
        p.nonces.insert(nonce);
        p.issued_at = now;
        if (p.event_id) m_nonce_to_event[nonce] = p.event_id;
        else m_nonce_to_event[nonce] = nonce;
        return true;
    }

    void transmit(PendingEvent& p, int64_t now)
    {
        std::size_t n = m_tx.broadcast_alert ? m_tx.broadcast_alert(0, p.frame) : 0;
        m_c.alert_out += n;
        ++p.attempts;
        p.last_sent = now;
        m_state_dirty = true;
        if (n == 0)
            LOG_DEBUG_POOL << "[alert-relay] event " << p.event_id << " not sent (no peers); will retry";
    }

    void retransmit(int64_t now)
    {
        for (auto it = m_pending.begin(); it != m_pending.end(); ) {
            PendingEvent& p = it->second;
            if (p.queued_at_relay) {
                if (now - p.event_ts > m_cfg.max_event_age) { it = forget(it); continue; }
                ++it;
                continue;
            }
            if (now - p.event_ts > m_cfg.max_event_age || p.attempts >= m_cfg.retry_max) {
                ++m_c.undelivered;
                LOG_WARNING << "[alert-relay] event " << p.event_id << " ("
                            << kind_name(p.kind) << " " << p.worker << ") UNDELIVERED after "
                            << p.attempts << " attempts";
                it = finalize(it, "undelivered", now);
                continue;
            }
            if (now - p.issued_at >= m_cfg.reissue_after) {
                if (issue(p, now)) { ++m_c.reissued; transmit(p, now); }
            } else if (now - p.last_sent >= m_cfg.retry_every) {
                ++m_c.retransmits;
                transmit(p, now);
            }
            ++it;
        }
    }

    void ledger(const PendingEvent& p, const std::string& status, int64_t now)
    {
        nlohmann::json row = {{"event_id", p.event_id}, {"kind", kind_name(p.kind)}, {"worker", p.worker},
                              {"event_ts", p.event_ts}, {"relay", to_hex(key_id(p.relay_pub))},
                              {"first_sent", p.first_sent}, {"attempts", p.attempts},
                              {"status", status}, {"ts", now}};
        if (!append_line(ledger_path(), row.dump()))
            LOG_WARNING << "[alert-relay] cannot append to " << ledger_path();
    }

    std::map<uint64_t, PendingEvent>::iterator forget(std::map<uint64_t, PendingEvent>::iterator it)
    {
        for (uint64_t n : it->second.nonces) m_nonce_to_event.erase(n);
        m_state_dirty = true;
        return m_pending.erase(it);
    }

    std::map<uint64_t, PendingEvent>::iterator finalize(std::map<uint64_t, PendingEvent>::iterator it,
                                                        const std::string& status, int64_t now)
    {
        ledger(it->second, status, now);
        if (status == "delivered")
            LOG_INFO << "[alert-relay] event " << it->second.event_id << " ("
                     << kind_name(it->second.kind) << " " << it->second.worker
                     << ") DELIVERED via relay " << short_hex(it->second.relay_pub);
        return forget(it);
    }

    void poll_delivered(int64_t now)
    {
        std::error_code ec;
        if (!std::filesystem::exists(delivered_path(), ec)) return;
        const auto size = std::filesystem::file_size(delivered_path(), ec);
        if (ec) return;
        if (size < m_delivered_offset) m_delivered_offset = 0;   // truncated / rotated
        if (size == m_delivered_offset) return;
        std::ifstream f(delivered_path(), std::ios::binary);
        if (!f) return;
        f.seekg(static_cast<std::streamoff>(m_delivered_offset));
        std::string line;
        uint64_t consumed = m_delivered_offset;
        while (std::getline(f, line)) {
            if (f.eof()) break;              // partial last line: re-read next tick
            consumed += line.size() + 1;
            auto j = nlohmann::json::parse(line, nullptr, false);
            if (!j.is_object() || !j.contains("id") || !j["id"].is_string()) continue;
            mark_delivered(j["id"].get<std::string>(), now);
        }
        if (consumed != m_delivered_offset) {
            m_delivered_offset = consumed;
            m_state_dirty = true;
        }
    }

    void mark_delivered(const std::string& id, int64_t now)
    {
        auto it = m_accepted.find(id);
        if (it == m_accepted.end() || it->second.status != static_cast<uint8_t>(AckStatus::Queued)) return;
        it->second.status = static_cast<uint8_t>(AckStatus::Delivered);
        it->second.received = now;   // restart the keep window from delivery
        ++m_c.delivered_telegram;
        m_state_dirty = true;
        auto colon = id.rfind(':');
        if (colon == std::string::npos) return;
        auto pub = from_hex(id.substr(0, colon));
        if (!pub || pub->size() != kPubkeyLen) return;
        const uint64_t nonce = std::strtoull(id.c_str() + colon + 1, nullptr, 10);
        auto a = build_ack(*m_keys, *pub, nonce, AckStatus::Delivered);
        if (!a) return;
        uint64_t to = 0;
        if (SeenEntry* e = m_seen.find(*pub, nonce)) { e->ack = *a; to = e->from_peer; }
        send_or_broadcast_ack(to, *a);
        LOG_INFO << "[alert-relay] sidecar delivered " << id.substr(0, 16) << ":" << nonce << " -> ack delivered";
    }

    void prune_accepted(int64_t now)
    {
        for (auto it = m_accepted.begin(); it != m_accepted.end(); ) {
            const bool queued = it->second.status == static_cast<uint8_t>(AckStatus::Queued);
            if (now - it->second.received > (queued ? kQueuedKeepSec : kAcceptedKeepSec)) {
                it = m_accepted.erase(it);
                m_state_dirty = true;
            } else {
                ++it;
            }
        }
        while (m_accepted.size() > kMaxAccepted) {
            // Evict the oldest record (bounded memory / state-file size).
            auto oldest = m_accepted.begin();
            for (auto it = m_accepted.begin(); it != m_accepted.end(); ++it)
                if (it->second.received < oldest->second.received) oldest = it;
            m_accepted.erase(oldest);
            m_state_dirty = true;
        }
    }

    ServiceConfig m_cfg;
    std::optional<KeyPair> m_keys;
    Bytes m_key_id;
    std::set<Bytes> m_accept;
    int64_t m_start;
    AlertDetector m_detector;
    Transport m_tx;
    NodeAlertSeen m_seen;
    Counters m_c;

    uint64_t m_next_nonce{1};
    std::map<uint64_t, PendingEvent> m_pending;       // event_id -> event (origin)
    std::map<uint64_t, uint64_t> m_nonce_to_event;    // any issued nonce -> event_id
    std::map<std::string, Accepted> m_accepted;       // relay: id -> status
    std::map<Bytes, int64_t> m_refused_log;           // throttle "not allowlisted" logs
    uint64_t m_delivered_offset{0};
    bool m_state_dirty{false};
    int64_t m_last_save{0};
    bool m_test_sent{false};

    mutable std::mutex m_status_mutex;
    nlohmann::json m_status = nlohmann::json::object();
};

} // namespace dash::alert
