// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The LTC (+ merged DOGE) stratum config before the CLI / YAML overlay:
// main_ltc.cpp starts from this, and the KATs read the same function, so the
// tests see what the node runs.
#ifndef C2POOL_IMPL_LTC_STRATUM_DEFAULTS_HPP
#define C2POOL_IMPL_LTC_STRATUM_DEFAULTS_HPP

#include <core/stratum_types.hpp>

namespace ltc {

inline core::stratum::StratumConfig default_stratum_config()
{
    core::stratum::StratumConfig c;   // min=0.0005, max=65536, target=3.0s, vardiff=true
    c.coin_symbol = "LTC";            // runtime coin tag for coin-agnostic core log lines

    // Idle keepalive-notify (cross-coin reuse of DASH's D9 mitigation): many
    // ASIC/proxy clients drop a pool connection that receives no mining.notify
    // within ~60 s (LTC/DOGE ~2.5 min block cadence gives long idle gaps at high
    // fixed diff). 25 s is safely under any reasonable client watchdog and kept
    // identical to the other coins for consistency. Re-notify the CURRENT job
    // (non-clean, so no ASIC work reset and NO work-generation bump); this is
    // transport/liveness only -- ZERO wire-byte and consensus change.
    c.keepalive_notify_sec = 25;

    // Zombie sessions (the BTC / DASH profile, same values). Left off, a
    // NAT-dropped rig's half-open socket and a client that connects and never
    // authorizes each hold a slot forever: at max_stratum_connections the node
    // then refuses every real miner (field: 100/100, refused_total=264674).
    // Transport/liveness only; ZERO wire-byte and consensus change.
    c.tcp_keepalive_enabled      = true;   // kernel probes dead NAT paths (the root fix)
    c.tcp_keepalive_idle_sec     = 60;
    c.tcp_keepalive_interval_sec = 10;
    c.tcp_keepalive_count        = 3;      // ~90 s to detect a dead peer
    c.handshake_timeout_sec      = 30;     // drop a connection that never authorizes
    // Idle reaper: a BACKSTOP to TCP keepalive. It counts INBOUND lines only,
    // and with keepalive on it never reaps an authorized session (core::
    // StratumSession::idle_reapable), so a live rig that only receives notifies
    // -- a low hashrate on a high fixed difficulty can go minutes between
    // pseudoshares, against LTC's 15 s share period and 3 s pseudoshare target
    // -- stays connected. 1800 s as on BTC / DASH.
    c.session_idle_timeout_sec   = 1800;
    c.max_write_queue_depth      = 256;    // drop a peer that stopped reading
    return c;
}

} // namespace ltc

#endif // C2POOL_IMPL_LTC_STRATUM_DEFAULTS_HPP
