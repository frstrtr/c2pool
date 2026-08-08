// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// dash::coin::SmlResyncWatchdog — re-ask for the tip mnlistdiff when the one we
// asked for never came back.
//
// ── THE GAP THIS CLOSES (measured, hotel node 109.161.52.148, 2026-08-06) ────
//
// The SML advances on exactly one trigger: a tip change fires
// `send_getmnlistd(sml_base, new_tip)` (main_dash.cpp) and the reply moves
// `sml_current_hash` forward. There is NO retry anywhere — the only other
// getmnlistd call sites are the handshake, the RPC seed, and the historical
// work-block snapshot requests. So a single request that is never sent or never
// answered leaves the SML behind the tip until the NEXT block fires the trigger
// again, roughly one block interval (~2.6 min on mainnet) of serving from the
// dashd fallback instead of the embedded arm.
//
// That is not a hypothesis. Over a 5h33m window the embedded arm spent 943 s on
// the fallback, and 586 s of it — 62% of the total, and 99% of all `dmn-stale`
// time — sat in just FIVE episodes of 275/156/103/51/1 s. Every one was closed
// by `[EMB-DASH] tip advanced`, i.e. by the chain moving, never by the SML
// catching up at the tip it was already on. Traced at h=2517141:
//
//     07:34:37.559  [EMBED-GATE] DECLINED cause=dmn-stale
//        ... 156 s of dashd-fallback serving, no [SML] line at all ...
//     07:37:12.924  [EMB-DASH] tip advanced h=2517141      <-- the NEXT BLOCK
//     07:37:13.471  [COIN-P2P] mnlistdiff: base=...1f tip=...11 +1mn
//     07:37:13.491  [EMBED-GATE] RESUMED
//
// The two other explanations were eliminated rather than assumed:
//   * NOT the base-continuity guard — zero `[SML] REJECT` lines in the window.
//   * NOT the historical demux stealing the reply — QuorumMemberSource::
//     on_mnlistdiff matches STRICTLY on (baseBlockHash.IsNull() AND blockHash
//     in the await set), so a tip INCREMENTAL can never be claimed by it.
//
// ── WHAT THIS IS NOT ────────────────────────────────────────────────────────
//
// It is NOT a relaxation of anything. The `dmn-stale` predicate, the serve
// gate, the base-continuity guard and every consensus check are untouched: this
// only re-sends a request that was already supposed to have been answered, so
// the state the gate reads becomes ready SOONER. A gate that is satisfied
// earlier because its input arrived is categorically different from a gate that
// is satisfied because it was lowered. Nothing here can cause a template to be
// served that would not have been served one block later anyway.
//
// It is also NOT for the ordinary per-tip window. 104 of 109 `dmn-stale`
// episodes in the same window were sub-second (~54 ms — the normal tip-change
// round trip) and are the irreducible floor. `min_quiet` exists precisely so
// this never fires on those: a retry at 54 ms would be pure duplicate traffic.
//
// ── POLICY ──────────────────────────────────────────────────────────────────
//
// Fail-QUIET and strictly bounded, because the failure mode of a retry is
// hammering a peer that is already struggling:
//   * only while the SML is actually behind the tip;
//   * only after `min_quiet` seconds of no SML progress (well above a normal
//     round trip, well below a block interval);
//   * geometric backoff between attempts;
//   * at most `max_attempts` per stuck (tip, sml) pair — after that we wait for
//     the next block exactly as today, so a genuinely unreachable peer sees the
//     same traffic it sees now plus a bounded constant;
//   * any observed SML progress, or a tip change, resets everything.

#include <cstdint>
#include <optional>

#include <core/uint256.hpp>

namespace dash {
namespace coin {

class SmlResyncWatchdog {
public:
    struct Config {
        /// Seconds of no SML progress before the FIRST re-request. Must sit
        /// well above a healthy round trip (measured ~54 ms) so the ordinary
        /// per-tip window never triggers it, and well below a block interval
        /// (~156 s measured) so a stuck SML is recovered inside the same block
        /// rather than by the next one.
        int64_t  min_quiet_sec{20};
        /// Multiplier applied to the wait after each attempt.
        int64_t  backoff_mult{2};
        /// Hard cap per stuck (tip, sml) pair. After this we go quiet and let
        /// the next tip change do what it does today.
        uint32_t max_attempts{3};
    };

    /// What the caller should send: getmnlistd(base = sml_at, target = tip).
    struct Request {
        uint256  base;
        uint256  target;
        uint32_t attempt{0};   ///< 1-based, for the log line
    };

    SmlResyncWatchdog() = default;
    explicit SmlResyncWatchdog(Config c) : m_cfg(c) {}

    /// Feed the CURRENT observation. Returns a request when one is due.
    ///
    /// `sml_at` is the block the SML is current at (ZERO = cold/wiped);
    /// `tip` is the block we are building on. Call it on any convenient
    /// cadence — the decision is time-based, not call-count-based, so a slow
    /// or jittery timer changes when a retry happens but never whether the
    /// bounds hold.
    std::optional<Request> observe(const uint256& tip, const uint256& sml_at,
                                   int64_t now_sec)
    {
        // Cold SML: a ZERO base is a FULL-snapshot re-seed, which is a
        // different (and much heavier) request than a tip incremental, and the
        // cold path already has its own drivers. Never our business.
        if (sml_at.IsNull()) { reset(now_sec); return std::nullopt; }

        // In sync: nothing to do, and this is the state we return to after
        // every successful recovery.
        if (sml_at == tip) { reset(now_sec); return std::nullopt; }

        // A NEW stuck pair (either axis moved) restarts the whole policy: the
        // SML made progress, or we are now chasing a different tip, and in both
        // cases the previous attempt budget describes a situation that no
        // longer exists.
        if (tip != m_tip || sml_at != m_sml_at) {
            m_tip        = tip;
            m_sml_at     = sml_at;
            m_since_sec  = now_sec;
            m_attempts   = 0;
            m_last_try   = -1;
            return std::nullopt;   // never retry on the FIRST sighting
        }

        if (m_attempts >= m_cfg.max_attempts) return std::nullopt;

        // Wait: min_quiet before the first attempt, then geometric backoff.
        int64_t wait = m_cfg.min_quiet_sec;
        for (uint32_t i = 0; i < m_attempts; ++i) wait *= m_cfg.backoff_mult;
        const int64_t since = (m_last_try >= 0) ? m_last_try : m_since_sec;
        if (now_sec - since < wait) return std::nullopt;

        m_last_try = now_sec;
        ++m_attempts;
        return Request{sml_at, tip, m_attempts};
    }

    /// Attempts spent against the current stuck pair (0 when in sync).
    uint32_t attempts() const { return m_attempts; }

private:
    void reset(int64_t now_sec)
    {
        m_tip.SetNull();
        m_sml_at.SetNull();
        m_since_sec = now_sec;
        m_attempts  = 0;
        m_last_try  = -1;
    }

    Config   m_cfg;
    uint256  m_tip;
    uint256  m_sml_at;
    int64_t  m_since_sec{0};
    int64_t  m_last_try{-1};
    uint32_t m_attempts{0};
};

}  // namespace coin
}  // namespace dash
