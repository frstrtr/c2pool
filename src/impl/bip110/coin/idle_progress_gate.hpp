// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <cstdint>

namespace bip110
{
namespace coin
{
namespace p2p
{

// IdleProgressGate — decides when the peer-eviction (stall) window should be
// armed, reset, kept, or stopped, gating eviction on FORWARD PROGRESS rather
// than on raw bytes received.
//
// Motivation (milestone BTC-IDLE.PROGRESS): NodeP2P::handle() runs on every
// inbound RawMessage. The legacy idle timer restarted a fixed window on every
// byte (on_activity()), so a peer that keeps chattering (inv / addr / ping)
// while never answering our outstanding block/header requests would never be
// evicted; and — symmetrically — a fully-synced peer with nothing outstanding
// could be dropped merely for going quiet.
//
// The gate is sampled AFTER each post-handshake message is dispatched, from two
// signals taken from the peer's ReplyMatchers (m_watchers):
//   * has_pending    — is any block/header request still outstanding?
//   * progress_epoch — monotonic count of REAL request answers (got_response).
//                      A per-request Matcher timeout fires an empty callback
//                      WITHOUT advancing this, so only a genuine peer reply
//                      counts as forward progress.
//
// Guard-rails (integrator, 2026-07-30) — all enforced here:
//   1. Never evict a fully-synced, zero-pending idle peer: the window arms only
//      while a request is outstanding (has_pending). No pending -> Stop.
//   2. The window itself is owned by NodeP2P and is deliberately >> the
//      per-request Connection::REQUEST_TIMEOUT_SEC, so each request's own
//      timeout drives fine-grained recovery first and eviction is the coarse
//      backstop for a peer failing to progress across many request cycles.
//      (Enforced by a static_assert in p2p_node.hpp.)
//   3. When eviction is disabled (single-peer coins such as BCH that run their
//      own block-download stall recovery), the gate is a no-op — the only peer
//      is never dropped by this path.
class IdleProgressGate
{
public:
    enum class Action
    {
        KeepAsIs,  // leave a running window untouched — chatter must NOT reset it
        Arm,       // begin measuring: a request is outstanding, window was idle
        Reset,     // forward progress while still pending — restart the window
        Stop,      // synced/idle, or eviction disabled — no window
    };

    // Evaluate one post-dispatch sample. `progress_epoch` MUST be monotonic
    // for the lifetime of a single connection; call reset() on (re)connect so a
    // fresh Connection (whose epoch restarts at 0) is not compared against a
    // stale high-water mark from the previous connection.
    Action evaluate(bool eviction_enabled, bool has_pending, uint64_t progress_epoch)
    {
        // Guard-rail 3: eviction disabled -> never measure, never evict.
        if (!eviction_enabled)
        {
            m_window_active = false;
            m_last_progress_epoch = progress_epoch;
            return Action::Stop;
        }

        const bool progressed = progress_epoch > m_last_progress_epoch;
        m_last_progress_epoch = progress_epoch;

        if (progressed)
        {
            // A real answer arrived. If work remains, restart the window from
            // now (forward progress). Otherwise we are caught up -> stop.
            if (has_pending)
            {
                m_window_active = true;
                return Action::Reset;
            }
            m_window_active = false;      // guard-rail 1: synced/idle
            return Action::Stop;
        }

        // No forward progress on this message: it is chatter, or a freshly
        // issued / re-issued request — neither counts as progress.
        if (!has_pending)
        {
            // Nothing outstanding and no progress: synced/idle peer.
            m_window_active = false;      // guard-rail 1
            return Action::Stop;
        }

        // A request is outstanding but this message made no progress.
        if (m_window_active)
            return Action::KeepAsIs;      // already measuring — do NOT reset

        m_window_active = true;           // 0->pending edge: begin measuring
        return Action::Arm;
    }

    bool window_active() const { return m_window_active; }

    // Reset cross-connection state. MUST be called on (re)connect and on
    // disconnect so the epoch high-water mark tracks the current Connection.
    void reset()
    {
        m_window_active = false;
        m_last_progress_epoch = 0;
    }

private:
    bool     m_window_active{false};
    uint64_t m_last_progress_epoch{0};
};

} // namespace p2p
} // namespace coin
} // namespace bip110
