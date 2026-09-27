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
//   * A queued_at_relay event is re-probed with the SAME frame every
//     kQueuedReprobeSec: the relay (and a forwarder holding only the queued
//     ack) answers a known id with its CURRENT status, so a lost "delivered"
//     ack is recovered. Still unconfirmed at max_event_age -> ledger
//     "expired_at_relay"; the relay no longer knowing the id -> "lost_at_relay".
//     Neither is ever silent.
//
// THREADING: every method except status_json() runs on the node IO thread
// (peer handlers + the tick timer), same confinement as m_known_txs /
// m_inject_seen. status_json() reads a snapshot published under a mutex.
// File writes (state, outbox, ledger; each fsync'd) never run on the IO
// thread: they are queued to a FileWriter worker (alert_io.hpp) and their
// results are drained back on the IO thread at the top of every handler and
// tick. A "queued" ack is sent only after the outbox row is on disk.
//
// No money / consensus state is reachable from here.

#include "alert_detector.hpp"
#include "alert_io.hpp"
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
    bool    inline_io{false};          // KATs: run file jobs on the caller's thread
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
    // Final statuses are kept past the origin's default max_event_age (6 h), so
    // a re-probe of a queued event is still answered "delivered" hours later.
    static constexpr int64_t     kAcceptedKeepSec = 8 * 3600;
    static constexpr int64_t     kQueuedKeepSec   = 7 * 86400;      // awaiting sidecar
    static constexpr std::size_t kMaxAccepted    = 20000;
    static constexpr uintmax_t   kMaxOutboxBytes = 16u * 1024u * 1024u;
    static constexpr int64_t     kQueuedReprobeSec = 600;           // origin: re-ask a queued event
    static constexpr int64_t     kRefreshSaveSec   = 300;           // origin: refresh worker last_seen
    static constexpr int64_t     kRefusedLogSec    = 3600;          // one "not allowlisted" warning per hour
    // Nonces are reserved in blocks: the persisted reservation (not every
    // issued nonce) is what a restart resumes above, so issuing a nonce needs
    // no disk write. The next block is reserved when half of the current one
    // is used, long before it can run out.
    static constexpr uint64_t    kNonceBlock       = 65536;
    static constexpr uint8_t     kStatusWriting    = 0;             // accepted, outbox write in flight

    struct Counters {
        uint64_t alert_in{0}, alert_out{0}, ack_in{0}, ack_out{0};
        uint64_t forwarded{0}, duplicates{0}, rate_limited{0};
        uint64_t rejected_shape{0}, rejected_stale{0}, rejected_sig{0};
        uint64_t refused_allowlist{0}, refused_invalid{0};
        uint64_t queued_outbox{0}, delivered_telegram{0}, outbox_errors{0};
        uint64_t events{0}, delivered{0}, queued_at_relay{0}, refused{0};
        uint64_t undelivered{0}, dropped{0}, reissued{0}, retransmits{0};
        uint64_t ack_forwarded{0}, ack_dropped{0};
        uint64_t reprobes{0}, expired_at_relay{0}, lost_at_relay{0}, io_errors{0};
        uint64_t refused_log_suppressed{0};
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
          m_detector(m_cfg.det, start_ts),
          m_io(std::make_unique<FileWriter>(m_cfg.inline_io))
    {
        if (m_keys) m_key_id = key_id(m_keys->pubkey);
        for (const auto& a : m_cfg.accept) m_accept.insert(a);
        m_next_nonce = static_cast<uint64_t>(start_ts) << 16;
    }

    // Load persisted state; create the state dir. Returns false (with err) only
    // on a fatal problem (unwritable state dir). Runs once at startup and
    // WAITS for its own state write (the only blocking write, before any peer
    // or miner is served).
    bool init(std::string& err)
    {
        std::error_code ec;
        std::filesystem::create_directories(m_cfg.state_dir, ec);
        if (ec) { err = "cannot create alert-relay state dir " + m_cfg.state_dir + ": " + ec.message(); return false; }
        std::ifstream f(state_path());
        if (f) {
            auto j = nlohmann::json::parse(f, nullptr, /*allow_exceptions=*/false);
            if (j.is_object()) {
                const uint64_t persisted = std::max(j.value("next_nonce", uint64_t{0}),
                                                    j.value("nonce_reserved", uint64_t{0}));
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
        f.close();
        {
            std::error_code sec;
            const bool exists = std::filesystem::is_regular_file(outbox_path(), sec);
            m_outbox_bytes = exists ? static_cast<uintmax_t>(std::filesystem::file_size(outbox_path(), sec)) : 0;
            if (sec) m_outbox_bytes = 0;
        }
        m_nonce_reserved = m_next_nonce + kNonceBlock;
        bool ok = false;
        const uint64_t reserved = m_nonce_reserved;
        save_state_async([this, &ok, reserved](const FileJobResult& r) {
            ok = r.ok;
            if (r.ok) m_nonce_durable = std::max(m_nonce_durable, reserved);
        });
        m_io->flush();
        drain_io();
        if (!ok) { err = "cannot persist " + state_path(); return false; }
        return true;
    }

    void set_transport(Transport t) { m_tx = std::move(t); }

    const ServiceConfig& config() const { return m_cfg; }
    const Counters& counters() const { return m_c; }
    const std::map<uint64_t, PendingEvent>& pending() const { return m_pending; }
    const AlertDetector& detector() const { return m_detector; }
    const NodeAlertSeen& seen() const { return m_seen; }
    const std::optional<KeyPair>& keys() const { return m_keys; }
    FileWriter& io() { return *m_io; }
    uint64_t next_nonce() const { return m_next_nonce; }
    uint64_t nonce_durable() const { return m_nonce_durable; }

    // IO thread: apply finished file jobs (acks that waited for the disk,
    // failures). Called at the top of every handler and tick; KATs call it
    // after io().flush().
    void drain_io()
    {
        for (auto& r : m_io->take_results()) {
            if (!r.ok) {
                ++m_c.io_errors;
                LOG_WARNING << "[alert-relay] cannot persist " << r.failed_path;
            }
            if (!r.tag) continue;
            auto it = m_io_done.find(r.tag);
            if (it == m_io_done.end()) continue;
            auto fn = std::move(it->second);
            m_io_done.erase(it);
            fn(r);
        }
    }
    bool can_forward() const { return m_cfg.forward || m_cfg.origin || m_cfg.telegram; }

    std::string outbox_path() const { return m_cfg.state_dir + "/outbox.jsonl"; }
    std::string delivered_path() const { return m_cfg.state_dir + "/delivered.jsonl"; }
    std::string ledger_path() const { return m_cfg.state_dir + "/ledger.jsonl"; }
    std::string state_path() const { return m_cfg.state_dir + "/state.json"; }

    // ── inbound: alert ─────────────────────────────────────────────────────
    Verdict on_alert(const AlertFrame& f, uint64_t from, PeerAlertGuard& guard, int64_t now)
    {
        drain_io();
        ++m_c.alert_in;
        // A frame claiming an allowlisted origin is charged to the peer's
        // trusted window (see PeerAlertGuard), everything else to the shared one.
        const bool trusted = m_cfg.telegram && allowlisted(f.origin_pubkey);
        if (!(trusted ? guard.admit_trusted_alert(now) : guard.admit_alert(now))) {
            ++m_c.rate_limited;
            return Verdict::RateLimited;
        }
        if (const char* why = alert_shape_error(f)) {
            ++m_c.rejected_shape;
            LOG_DEBUG_POOL << "[alert-relay] dropping malformed alert (" << why << ")";
            return Verdict::RejectedShape;
        }
        if (m_keys && f.origin_pubkey == m_keys->pubkey) return Verdict::Own;

        if (SeenEntry* e = m_seen.find(f.origin_pubkey, f.nonce)) {
            ++m_c.duplicates;
            // Only a FINAL cached ack ends the frame's journey here. A cached
            // "queued" ack is answered AND the frame is passed on (throttled):
            // it may be the origin re-probing for the "delivered" ack.
            const bool final_ack = e->ack && e->ack->status != static_cast<uint8_t>(AckStatus::Queued);
            if (e->ack) {
                // Repair a lost ack: answer the retransmitting sender directly.
                if (m_tx.send_ack && m_tx.send_ack(from, *e->ack)) ++m_c.ack_out;
            }
            if (!final_ack) {
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
            if (for_me && verify_alert_sig(f)) {
                // An id this relay already accepted is answered with its current
                // status whatever its age: that is a re-probe, not a replay (it
                // can never be appended twice).
                auto acc = m_accepted.find(alert_id_string(f.origin_pubkey, f.nonce));
                if (acc != m_accepted.end()) {
                    ++m_c.duplicates;
                    if (acc->second.status != kStatusWriting) {
                        if (auto a = build_ack(*m_keys, f.origin_pubkey, f.nonce,
                                               static_cast<AckStatus>(acc->second.status)))
                            send_or_broadcast_ack(from, *a);
                    }
                    return Verdict::Duplicate;
                }
                ++m_c.rejected_stale;
                // Tell the origin its clock / queue is off (diagnostic, final).
                if (auto a = build_ack(*m_keys, f.origin_pubkey, f.nonce, AckStatus::RefusedInvalid))
                    send_or_broadcast_ack(from, *a);
                LOG_WARNING << "[alert-relay] alert from " << short_hex(f.origin_pubkey)
                            << " outside the +/-" << kReplayWindowSec << "s window (skew "
                            << skew << "s) -- check the origin clock";
                return Verdict::RejectedStale;
            }
            ++m_c.rejected_stale;
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
        drain_io();
        ++m_c.ack_in;
        // An ack for THIS origin from a configured relay has its own window.
        const bool trusted = m_cfg.origin && m_keys && a.origin_pubkey == m_keys->pubkey &&
                             relay_configured(a.relay_pubkey);
        if (!(trusted ? guard.admit_trusted_ack(now) : guard.admit_ack(now))) {
            ++m_c.rate_limited;
            return Verdict::RateLimited;
        }
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
        drain_io();
        if (m_cfg.origin) {
            for (auto& ev : m_detector.tick(samples, now)) enqueue_event(ev, now);
            if (m_detector.generation() != m_detector_gen) {
                m_detector_gen = m_detector.generation();
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
        // Save only what changed. The one exception is a slow refresh of the
        // known workers' last_seen on an origin that tracks any (bounded, and
        // off the IO thread like every other write).
        const bool refresh = m_cfg.origin && !m_detector.workers().empty() &&
                             now - m_last_save >= kRefreshSaveSec;
        if (m_state_dirty || refresh) {
            save_state_async();
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
        // ONE state write per event (queued to the writer; durable within
        // milliseconds, never on the IO thread).
        save_state_async();
        m_last_save = now;
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
                       {"expired_at_relay", m_c.expired_at_relay}, {"lost_at_relay", m_c.lost_at_relay},
                       {"retransmits", m_c.retransmits}, {"reprobes", m_c.reprobes},
                       {"reissued", m_c.reissued}, {"events", m_c.events}};
        std::size_t pending_sidecar = 0;
        for (const auto& [id, a] : m_accepted)
            if (a.status == static_cast<uint8_t>(AckStatus::Queued) || a.status == kStatusWriting) ++pending_sidecar;
        s["relay"] = {{"accepted", m_c.queued_outbox}, {"refused_allowlist", m_c.refused_allowlist},
                      {"refused_invalid", m_c.refused_invalid}, {"refused_sig", m_c.rejected_sig},
                      {"rejected_stale", m_c.rejected_stale}, {"rejected_shape", m_c.rejected_shape},
                      {"duplicates", m_c.duplicates}, {"forwarded", m_c.forwarded},
                      {"rate_limited", m_c.rate_limited}, {"pending_sidecar", pending_sidecar},
                      {"delivered_telegram", m_c.delivered_telegram}, {"outbox_errors", m_c.outbox_errors},
                      {"outbox_bytes", m_outbox_bytes}, {"seen", m_seen.size()}};
        s["io"] = {{"backlog", m_io->backlog()}, {"jobs", m_io->done()}, {"coalesced", m_io->coalesced()},
                   {"errors", m_c.io_errors}};
        s["p2p"] = {{"alert_in", m_c.alert_in}, {"alert_out", m_c.alert_out},
                    {"ack_in", m_c.ack_in}, {"ack_out", m_c.ack_out},
                    {"ack_forwarded", m_c.ack_forwarded}, {"ack_dropped", m_c.ack_dropped}};
        s["now"] = now;
        std::lock_guard<std::mutex> lk(m_status_mutex);
        m_status = std::move(s);
    }

    // Queue a full state snapshot to the writer (coalesced with a not yet
    // started save). `done` (optional) runs on the IO thread via drain_io().
    void save_state_async(std::function<void(const FileJobResult&)> done = {})
    {
        std::vector<FileOp> ops;
        ops.push_back(FileOp{FileOp::Type::Replace, state_path(), state_snapshot()});
        submit_io(std::move(ops), std::move(done));
    }

private:
    // Serialize the persisted state. Clears the dirty flag: the caller queues
    // the snapshot. An entry whose outbox write is in flight is written as
    // "queued": every job queued after that write runs after it (FIFO), and a
    // failed write re-dirties the state.
    std::string state_snapshot()
    {
        nlohmann::json j;
        j["version"] = 1;
        j["next_nonce"] = m_next_nonce;
        j["nonce_reserved"] = m_nonce_reserved;
        j["delivered_offset"] = m_delivered_offset;
        nlohmann::json acc = nlohmann::json::object();
        for (const auto& [id, a] : m_accepted) {
            const uint8_t st = a.status == kStatusWriting ? static_cast<uint8_t>(AckStatus::Queued) : a.status;
            acc[id] = {{"status", st}, {"received", a.received}};
        }
        j["accepted"] = acc;
        if (m_cfg.origin) {
            j["workers"] = m_detector.persist();
            nlohmann::json pend = nlohmann::json::array();
            for (const auto& [id, p] : m_pending) pend.push_back(pending_json(p));
            j["pending"] = pend;
        }
        m_state_dirty = false;
        return j.dump();
    }

    void submit_io(std::vector<FileOp> ops, std::function<void(const FileJobResult&)> done = {})
    {
        uint64_t tag = 0;
        if (done) {
            tag = m_next_tag++;
            m_io_done.emplace(tag, std::move(done));
        }
        m_io->submit(tag, std::move(ops));
    }

    bool relay_configured(const Bytes& relay_pub) const
    {
        for (const auto& r : m_cfg.relays) if (r == relay_pub) return true;
        return false;
    }

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

    void log_refused(const Bytes& origin, int64_t now)
    {
        // ONE global throttle (not a per-key map: keys are free to mint, so a
        // per-key table would grow without bound on a public relay).
        if (m_last_refused_log != 0 && now - m_last_refused_log < kRefusedLogSec) {
            ++m_c.refused_log_suppressed;
            LOG_DEBUG_POOL << "[alert-relay] refusing alert from non-allowlisted origin " << short_hex(origin);
            return;
        }
        LOG_WARNING << "[alert-relay] refusing alert from non-allowlisted origin " << to_hex(origin)
                    << " (add it with --alert-relay-accept)";
        if (m_c.refused_log_suppressed)
            LOG_WARNING << "[alert-relay] " << m_c.refused_log_suppressed
                        << " more non-allowlisted alert(s) were refused since the previous warning";
        m_c.refused_log_suppressed = 0;
        m_last_refused_log = now;
    }

    Verdict deliver_local(SeenEntry& e, uint64_t from, int64_t now)
    {
        const AlertFrame f = e.frame;   // copy: a drained completion may erase `e`
        const std::string id = alert_id_string(f.origin_pubkey, f.nonce);
        auto ack_with = [&](AckStatus st) {
            if (auto a = build_ack(*m_keys, f.origin_pubkey, f.nonce, st)) {
                e.ack = *a;
                send_or_broadcast_ack(from, *a);
            }
        };

        if (auto it = m_accepted.find(id); it != m_accepted.end()) {
            // Already accepted (before a restart, or a re-probe): re-ack with
            // the CURRENT status, never re-append. An in-flight write acks on
            // completion.
            ++m_c.duplicates;
            if (it->second.status != kStatusWriting) ack_with(static_cast<AckStatus>(it->second.status));
            return Verdict::Duplicate;
        }
        if (!allowlisted(f.origin_pubkey)) {
            ++m_c.refused_allowlist;
            log_refused(f.origin_pubkey, now);
            ack_with(AckStatus::RefusedNotAllowed);
            return Verdict::RefusedNotAllowed;
        }
        auto body = open_alert(*m_keys, f);
        if (!body) {
            ++m_c.refused_invalid;
            ack_with(AckStatus::RefusedInvalid);
            return Verdict::RefusedInvalid;
        }
        nlohmann::json row = {
            {"id", id}, {"origin", to_hex(f.origin_pubkey)}, {"nonce", f.nonce},
            {"kind", kind_name(body->kind)}, {"label", body->label}, {"worker", body->worker},
            {"detail", body->detail}, {"event_ts", body->event_ts}, {"sent_ts", f.timestamp},
            {"received_ts", now}};
        std::string line = row.dump();
        const uintmax_t row_bytes = line.size() + 1;
        if (m_outbox_bytes + row_bytes > kMaxOutboxBytes) {
            // Full: do NOT ack -- forget the frame so the origin's next
            // retransmit is processed afresh instead of as a duplicate.
            ++m_c.outbox_errors;
            LOG_ERROR << "[alert-relay] outbox " << outbox_path() << " is full (" << m_outbox_bytes
                      << " bytes); not accepting alert " << short_hex(f.origin_pubkey) << ":" << f.nonce;
            m_seen.erase(f.origin_pubkey, f.nonce);
            return Verdict::Deferred;
        }
        // Accept: the outbox row, THEN the state that records the id, as ONE
        // writer job (the state write is skipped if the append fails). The
        // "queued" ack goes out only once the row is on disk.
        m_outbox_bytes += row_bytes;
        m_accepted[id] = Accepted{kStatusWriting, now};
        std::vector<FileOp> ops;
        ops.push_back(FileOp{FileOp::Type::Append, outbox_path(), std::move(line)});
        ops.push_back(FileOp{FileOp::Type::Replace, state_path(), state_snapshot()});
        submit_io(std::move(ops),
                  [this, origin = f.origin_pubkey, nonce = f.nonce, id, row_bytes,
                   kind = body->kind, label = body->label](const FileJobResult& r) {
                      on_outbox_written(r, origin, nonce, id, row_bytes, kind, label);
                  });
        drain_io();   // inline writer: completes here; threaded: on a later handler / tick
        return m_accepted.count(id) ? Verdict::Queued : Verdict::Deferred;
    }

    void on_outbox_written(const FileJobResult& r, const Bytes& origin, uint64_t nonce, const std::string& id,
                           uintmax_t row_bytes, uint8_t kind, const std::string& label)
    {
        auto it = m_accepted.find(id);
        if (it == m_accepted.end()) return;
        if (!r.ok && r.failed_path == outbox_path()) {
            // Disk trouble: no ack; forget the id everywhere (map AND FIFO) so
            // the origin's next retransmit of the same nonce is processed afresh.
            ++m_c.outbox_errors;
            m_outbox_bytes = m_outbox_bytes >= row_bytes ? m_outbox_bytes - row_bytes : 0;
            LOG_ERROR << "[alert-relay] cannot append to " << outbox_path();
            m_accepted.erase(it);
            m_seen.erase(origin, nonce);
            return;
        }
        if (!r.ok) m_state_dirty = true;   // row is durable; the state save is retried
        ++m_c.queued_outbox;
        LOG_INFO << "[alert-relay] queued alert " << kind_name(kind) << " from "
                 << (label.empty() ? short_hex(origin) : label)
                 << " for the Telegram sidecar (id " << short_hex(origin) << ":" << nonce << ")";
        // The sidecar may already have reported it (mark_delivered accepts an
        // in-flight id): never downgrade "delivered" to "queued".
        if (it->second.status != kStatusWriting) return;
        it->second.status = static_cast<uint8_t>(AckStatus::Queued);
        if (auto a = build_ack(*m_keys, origin, nonce, AckStatus::Queued)) {
            uint64_t to = 0;
            if (SeenEntry* e = m_seen.find(origin, nonce)) { e->ack = *a; to = e->from_peer; }
            send_or_broadcast_ack(to, *a);
        }
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
            if (p.queued_at_relay) {
                // The relay durably queued it earlier and now no longer knows
                // the id (state lost / pruned): report that, not a refusal.
                ++m_c.lost_at_relay;
                LOG_WARNING << "[alert-relay] event " << p.event_id << " (" << kind_name(p.kind) << " "
                            << p.worker << ") was queued at relay " << short_hex(p.relay_pub)
                            << " but the relay no longer knows it (" << ack_status_name(a.status)
                            << "); delivery unconfirmed";
                finalize(pit, "lost_at_relay", now);
                break;
            }
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
        // A crash can skip nonces but never reuse one: a restart resumes above
        // the persisted reservation. Reserve the next block early (async)...
        if (m_next_nonce + kNonceBlock / 2 > m_nonce_reserved) {
            m_nonce_reserved = m_next_nonce + kNonceBlock;
            const uint64_t reserved = m_nonce_reserved;
            save_state_async([this, reserved](const FileJobResult& r) {
                if (r.ok) m_nonce_durable = std::max(m_nonce_durable, reserved);
            });
        }
        // ...and only if the durable reservation were ever overtaken (a disk
        // that stalls for half a block of events) wait for it.
        if (nonce >= m_nonce_durable) {
            m_io->flush();
            drain_io();
            if (nonce >= m_nonce_durable)
                LOG_WARNING << "[alert-relay] nonce reservation is not on disk (" << state_path()
                            << " unwritable?); sending anyway";
        }
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
                if (now - p.event_ts > m_cfg.max_event_age) {
                    ++m_c.expired_at_relay;
                    LOG_WARNING << "[alert-relay] event " << p.event_id << " (" << kind_name(p.kind) << " "
                                << p.worker << ") queued at relay " << short_hex(p.relay_pub)
                                << " but no delivery confirmation within " << m_cfg.max_event_age << "s";
                    it = finalize(it, "expired_at_relay", now);
                    continue;
                }
                // Re-probe with the SAME frame: the relay answers a known id with
                // its current status, so a lost "delivered" ack is recovered.
                if (now - p.last_sent >= kQueuedReprobeSec) {
                    ++m_c.reprobes;
                    transmit(p, now);
                }
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
        std::vector<FileOp> ops;
        ops.push_back(FileOp{FileOp::Type::Append, ledger_path(), row.dump()});
        submit_io(std::move(ops));   // a failure is logged by drain_io()
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
        // An id whose outbox write has not been drained yet is on disk already
        // (the sidecar read it), so it counts as queued here.
        if (it == m_accepted.end() ||
            (it->second.status != static_cast<uint8_t>(AckStatus::Queued) && it->second.status != kStatusWriting))
            return;
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
            const bool queued = it->second.status == static_cast<uint8_t>(AckStatus::Queued) ||
                                it->second.status == kStatusWriting;
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
    int64_t m_last_refused_log{0};                    // global "not allowlisted" log throttle
    uint64_t m_delivered_offset{0};
    uintmax_t m_outbox_bytes{0};
    uint64_t m_nonce_reserved{0};                     // highest reservation queued to disk
    uint64_t m_nonce_durable{0};                      // highest reservation confirmed on disk
    uint64_t m_detector_gen{0};
    bool m_state_dirty{false};
    int64_t m_last_save{0};
    bool m_test_sent{false};

    mutable std::mutex m_status_mutex;
    nlohmann::json m_status = nlohmann::json::object();

    // Declared LAST: destroyed FIRST, so the worker finishes the queued writes
    // and joins while everything above is still alive.
    uint64_t m_next_tag{1};
    std::map<uint64_t, std::function<void(const FileJobResult&)>> m_io_done;
    std::unique_ptr<FileWriter> m_io;
};

} // namespace dash::alert
