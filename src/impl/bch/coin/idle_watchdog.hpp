// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// bch::idle_watchdog -- progress-gated block-download stall watchdog (pure).
//
// PROBLEM. NodeP2P::on_activity() restarts the connection-liveness timeout on
// ANY inbound message (handle() calls it before dispatch). That reset-on-
// traffic policy is correct for the STEADY state -- a synced node sitting at
// the BCH tip sees ~10 min between blocks and relies on ping/pong keepalive to
// prove the socket is alive, so we must NOT drop it for lack of block traffic.
// But it is WRONG during IBD: a peer that keeps the socket warm with keepalive
// / addr / already-known inv chatter while never delivering a REQUESTED block
// body never trips IDLE_TIMEOUT. The block-download window's own expiry then
// merely requeues the same stalled heights to the same single peer forever --
// a self-perpetuating stall the liveness timer can never break.
//
// FIX. Gate a stricter watchdog on FORWARD PROGRESS (the tick of the last
// accepted block body) instead of raw traffic, and arm it ONLY while block
// bodies are actually in flight. At tip (in_flight == 0) it is disarmed, so a
// synced node never churns; mid-IBD, a peer that stops delivering accepted
// bodies for IDLE_TIMEOUT is dropped so reconnect can pick a fresh peer.
//
// Pure: no clock, no socket, no config. The single decision predicate lives
// here so it is unit-testable in isolation (idle_watchdog_kat_test), mirroring
// header_sync / block_download's PURE-and-tested posture.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>

namespace bch::idle_watchdog {

// Sentinel for "watchdog disarmed" -- no forward-progress baseline is armed
// (either we are at tip with nothing in flight, or block download has not yet
// begun). now_tick_sec() is monotonic-since-connect, so 0 collides only with
// the first second after connect, which is harmless (one extra ~tick of slop).
inline constexpr uint64_t DISARMED = 0;

// Decide whether the progress-gated block-download watchdog should drop the
// peer THIS tick.
//   in_flight            -- outstanding getdata(MSG_BLOCK) requests right now.
//   now_tick             -- current monotonic-since-connect second.
//   last_progress_tick   -- tick of the last ACCEPTED block body, or DISARMED.
//   idle_timeout_sec     -- the no-progress budget (IDLE_TIMEOUT_SEC).
// Returns true iff we are actively downloading (in_flight > 0), the watchdog is
// armed (last_progress_tick != DISARMED), the clock has not run backwards, and
// no accepted body has advanced us for at least idle_timeout_sec.
inline bool should_drop_on_stall(std::size_t in_flight,
                                 uint64_t now_tick,
                                 uint64_t last_progress_tick,
                                 uint64_t idle_timeout_sec)
{
    if (in_flight == 0)                      return false;  // at tip / idle -> never churn
    if (last_progress_tick == DISARMED)      return false;  // not armed yet (arm this tick)
    if (now_tick < last_progress_tick)       return false;  // clock skew guard (monotonic)
    return (now_tick - last_progress_tick) >= idle_timeout_sec;
}

} // namespace bch::idle_watchdog
