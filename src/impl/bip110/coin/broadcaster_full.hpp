// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// bip110 M3 PR-C2 — Bip110BroadcasterFull: the FOUND-BLOCK keystone (dual-arm).
// One rung above the Bip110Broadcaster peer-pool LEAF (broadcaster.hpp):
//
//     p2p_connection -> p2p_node -> broadcaster -> [broadcaster_full]
//
// Mirrors the DASH #152 keystone (src/impl/dash/broadcaster_full.hpp
// DashBroadcasterFull) and the python NetworkBroadcaster's broadcast_block call
// site (p2pool/work.py). on_block_found routes a WON block to the fork network
// over BOTH arms of the money-robustness gate:
//
//   ARM A — EMBEDDED FORK-P2P FAN-OUT (the new robustness path)
//     drives the pool's submit_block_raw_all(), pushing the full BIP144 witness
//     block in parallel to every LIVE NODE_BLAKE2B slot for propagation below
//     what a single coin-peer submit reaches. GUARDED: a throwing fan-out must
//     NOT prevent ARM B.
//
//   ARM B — PRIMARY relay + optional submitblock RPC (never removed)
//     hands the block to the injected primary sink (main wires this to
//     coin_node.submit_block_with_fallback, which is TODAY's M2 path: the
//     primary coin-P2P peer relay + the optional submitblock RPC backup). This
//     arm is the standing safety net — attempted independently of ARM A, so a
//     cold/empty pool can never silence the primary path. GUARDED identically.
//
// reached_network() is TRUE iff at least one arm placed the block on the wire
// (>=1 fan-out peer OR the primary sink returned true). A won block that reached
// NEITHER returns reached_network()==false — the caller MUST treat that as
// "block not relayed", never a silent drop.
//
// The whole object is constructed ONLY on the --bip110-sharechain flag-ON path;
// with the flag OFF main calls coin_node.submit_block_with_fallback directly
// (exactly ARM B, nothing else) so the OFF path is byte-identical to M2.
//
// Lock discipline: on_block_found runs on the stratum submit thread and touches
// NO sharechain tracker lock — the fan-out reads only the coin-P2P pool, never
// the share tracker, so there is no held-exclusive-lock-across-fanout risk.

#include "broadcaster.hpp"

#include <cstdint>
#include <exception>
#include <functional>
#include <vector>

#include <core/log.hpp>

namespace bip110
{
namespace coin
{

template <typename ConfigType>
class Bip110BroadcasterFull
{
public:
    using config_t = ConfigType;
    using Pool = Bip110Broadcaster<config_t>;

    // ARM B — the primary relay sink. Returns true iff the block reached at least
    // one primary sink (coin-P2P primary peer OR submitblock RPC). main wires
    // this to coin_node.submit_block_with_fallback. Defaults unset; when unset
    // ARM B is simply not attempted (never a silent removal — it is opt-in by
    // wiring, and main always wires it).
    using PrimarySubmitFn = std::function<bool(const std::vector<unsigned char>&)>;

    struct Outcome
    {
        size_t peers_reached{0};    // live fan-out slots that accepted the block
        bool   primary_attempted{false};
        bool   primary_ok{false};   // primary relay / submitblock accepted

        bool reached_network() const { return peers_reached > 0 || primary_ok; }
    };

    explicit Bip110BroadcasterFull(Pool* pool) : m_pool(pool) {}

    void set_primary_submit(PrimarySubmitFn f) { m_primary_submit = std::move(f); }
    bool has_primary_arm() const { return static_cast<bool>(m_primary_submit); }
    Pool* pool() const { return m_pool; }

    // Relay a WON block (already packed to BIP144 witness wire bytes) over both
    // arms. Both are attempted independently and independently guarded.
    Outcome on_block_found(const std::vector<unsigned char>& block_bytes)
    {
        Outcome out;

        // ARM A — embedded fork-P2P fan-out.
        if (m_pool) {
            try {
                out.peers_reached = m_pool->submit_block_raw_all(block_bytes);
            } catch (const std::exception& e) {
                LOG_ERROR << "[BIP110-BroadcastFull] ARM A (fork-P2P fan-out) threw ("
                          << e.what() << ") — falling through to primary/RPC.";
            } catch (...) {
                LOG_ERROR << "[BIP110-BroadcastFull] ARM A (fork-P2P fan-out) threw "
                             "(non-std) — falling through to primary/RPC.";
            }
        }

        // ARM B — primary relay + optional submitblock RPC (never masked).
        if (m_primary_submit) {
            out.primary_attempted = true;
            try {
                out.primary_ok = m_primary_submit(block_bytes);
            } catch (const std::exception& e) {
                LOG_ERROR << "[BIP110-BroadcastFull] ARM B (primary relay) threw ("
                          << e.what() << ") — ARM A win (if any) preserved.";
            } catch (...) {
                LOG_ERROR << "[BIP110-BroadcastFull] ARM B (primary relay) threw "
                             "(non-std) — ARM A win (if any) preserved.";
            }
        }

        if (out.reached_network())
            LOG_INFO << "[BIP110-BroadcastFull] won block relayed: fanout_peers="
                     << out.peers_reached
                     << " primary=" << (out.primary_ok ? "ok" : "no");
        else
            LOG_WARNING << "[BIP110-BroadcastFull] won block NOT relayed — no live "
                           "fan-out peers and primary arm failed! block bytes="
                        << block_bytes.size();
        return out;
    }

private:
    Pool*           m_pool{};
    PrimarySubmitFn m_primary_submit;
};

} // namespace coin
} // namespace bip110
