// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ============================================================================
// tip_refresh.hpp — the DASH "new work is available" fan-out, in ONE place.
//
// Every tip-change source on the DASH path (coin tip via ZMQ/poll, embedded
// state-dirty, sharechain best-share advance) has to do the SAME three things,
// in this order:
//
//   1. bump_work_generation()          — invalidate the served work payload so
//                                        the next get_work/notify re-sources;
//   2. notify_all()                    — PUSH mining.notify to every subscribed
//                                        session with clean_jobs=true, so rigs
//                                        drop the previous prev_share_hash job
//                                        IMMEDIATELY (p2pool behaviour);
//   3. trigger_work_refresh_debounced()— move the dashboard/graphs off the poll
//                                        timer onto the real event.
//
// Step (2) is the one that was silently missing on the SHARECHAIN tip-change
// leg: bump_work_generation() only invalidates a cache, it pushes nothing, so
// connected rigs kept hashing the previous prev_share_hash until their per-
// session keepalive timer fired (StratumConfig::keepalive_notify_sec, 25 s on
// DASH). Because the producer job_cache is keyed (prev_share_hash, payout
// script), every solve inside that window rebuilt the SAME frozen job — i.e.
// siblings at one sharechain height instead of a linear chain.
//
// Display/liveness only: nothing here touches share bytes, the coinbase, the
// payee, PPLNS math or the won-block path. A tip change means a NEW
// prev_share_hash, hence a new job_cache key and a fresh build_producer_job —
// no existing share's committed bytes can change.
//
// Templated on the three collaborators so the fan-out is KAT-able without a
// live work source / stratum acceptor / dashboard (test_dash_stratum_notify_
// roundtrip). Header-only, fenced to src/impl/dash/.
// ============================================================================

namespace dash::stratum {

/// Fire the full new-work fan-out. Every leg is null-tolerant: the stratum
/// acceptor is absent with --stratum-port 0 (and is constructed AFTER the
/// sharechain callback is bound, so the call site passes it late), and the
/// dashboard is absent when the web port is off.
template <typename WorkSourceT, typename StratumServerT, typename WebServerT>
inline void fire_share_tip_refresh(WorkSourceT* work_source,
                                   StratumServerT* stratum_server,
                                   WebServerT* web_server)
{
    if (work_source)    work_source->bump_work_generation();
    if (stratum_server) stratum_server->notify_all();
    if (web_server)     web_server->trigger_work_refresh_debounced();
}

} // namespace dash::stratum
