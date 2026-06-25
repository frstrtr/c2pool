#pragma once

// Phase S8 — DashBroadcasterFull: the won-block KEYSTONE (dual-path #83).
//
// One rung above the DashBroadcaster peer-pool LEAF (broadcaster.hpp, #405):
//
//     p2p_connection -> p2p_node -> broadcaster -> [broadcaster_full]
//
// The leaf is a PURE peer-pool + discovery + fan-out *scaffold* whose
// submit_block_raw_all() only iterates the LIVE slots invoking an injectable
// no-op hook. This keystone closes the loop: it routes a WON block to the
// network over BOTH arms of the dual-path gate every other coin already passes:
//
//   ARM A — EMBEDDED P2P FAN-OUT
//     on_block_found() drives the leaf's submit_block_raw_all(), whose fan-out
//     hook is wired here to the per-slot submit seam (m_peer_submit). The block
//     is pushed in parallel to every LIVE dashd P2P slot for low-latency
//     propagation below what a single submitblock can reach.
//
//   ARM B — submitblock RPC FALLBACK (dashd authoritative; NEVER removed)
//     on_block_found() also hands the packed block to the injected submitblock
//     RPC callback (m_rpc_submit), so the block reaches the network through the
//     local dashd even when the embedded peer-pool is empty/cold. This arm is
//     the standing safety net per the dashd-RPC-fallback invariant: it is
//     attempted whenever configured, independent of the embedded arm.
//
// reached_network() is TRUE iff at least one arm placed the block on the wire
// (>=1 embedded peer reached OR the RPC submit succeeded). A won block with
// zero live peers AND no RPC arm returns reached_network()==false — the caller
// MUST treat that as "block not relayed" rather than silently dropping it.
//
// 3-WAY RECONCILE NOTE (honest): the dash-spv-embedded reference
// broadcaster_full.hpp ports c2pool-ltc's CoinBroadcaster verbatim and depends
// on c2pool/merged/coin_peer_manager.hpp, coin/node_interface.hpp,
// coin/transaction.hpp, coin/block.hpp and NodeP2P::submit_block — NONE of
// which are on master. A wholesale copy would (1) fail to compile, (2) drag in
// the shared merged/ tree, breaking the single-coin DASH isolation fence, and
// (3) regress the newer master broadcaster.hpp(#405)/p2p_node/config. So this
// keystone is reconciled against what master ACTUALLY carries: it composes the
// #405 DashBroadcaster leaf's FanOutHook/submit_block_raw_all seam (embedded
// arm) and an injectable submitblock-RPC callback (dashd arm). The concrete
// per-slot NodeP2P::submit_block_raw and the live getpeerinfo RPC tick land
// when those node methods exist on master; the seams here are exactly where
// they bolt in. Header-only, single dash tree, NO src/core / NO merged/ adds.

#include "broadcaster.hpp"
#include "config.hpp"

#include <cstdint>
#include <functional>
#include <span>
#include <string>

#include <core/log.hpp>

namespace dash
{

// Won-block keystone: wraps the DashBroadcaster peer-pool and routes a found
// block to the network over the embedded-P2P and submitblock-RPC arms.
class DashBroadcasterFull
{
public:
    // Per-slot block submit (embedded arm). Pushes the packed block to ONE live
    // dashd P2P slot. Defaults to a no-op: the concrete NodeP2P::submit_block_raw
    // lands on master separately; this seam is where it bolts in. Tests inject a
    // capturing fn to prove each live peer received the exact bytes.
    using PeerSubmitFn =
        std::function<void(dash::coin::p2p::NodeP2P& /*slot*/,
                           std::span<const unsigned char> /*block_bytes*/)>;

    // submitblock RPC fallback (dashd arm). Returns true iff dashd accepted the
    // block. Defaults unset; when unset the RPC arm is simply not attempted (the
    // dashd-RPC fallback is opt-in by wiring, never removed). main_dash wires
    // this to the NodeRPC submitblock call.
    using RpcSubmitFn = std::function<bool(const std::string& /*block_hex*/)>;

    // Outcome of a won-block relay attempt across both arms.
    struct Outcome
    {
        size_t peers_reached{0};   // live embedded P2P slots the block fanned to
        bool   rpc_attempted{false};
        bool   rpc_submitted{false}; // dashd accepted via submitblock

        // The gate predicate: did the won block actually reach the network on
        // AT LEAST ONE arm?
        bool reached_network() const { return peers_reached > 0 || rpc_submitted; }
    };

    explicit DashBroadcasterFull(DashBroadcaster* pool)
        : m_pool(pool)
        , m_peer_submit(
              [](dash::coin::p2p::NodeP2P&, std::span<const unsigned char>) {})
    {
        // Wire the leaf's fan-out hook to OUR per-slot submit seam so that
        // submit_block_raw_all() actually pushes bytes to live peers instead of
        // running the leaf's default no-op.
        if (m_pool)
            m_pool->set_fan_out_hook(
                [this](dash::coin::p2p::NodeP2P& slot,
                       std::span<const unsigned char> bytes) {
                    m_peer_submit(slot, bytes);
                });
    }

    // ── injection seams (main_dash / tests) ──────────────────────────────

    void set_peer_submit(PeerSubmitFn f)
    {
        m_peer_submit = std::move(f);
        // Re-bind the leaf hook so it forwards to the updated submit fn.
        if (m_pool)
            m_pool->set_fan_out_hook(
                [this](dash::coin::p2p::NodeP2P& slot,
                       std::span<const unsigned char> bytes) {
                    m_peer_submit(slot, bytes);
                });
    }

    void set_rpc_submit(RpcSubmitFn f) { m_rpc_submit = std::move(f); }

    bool has_rpc_arm() const { return static_cast<bool>(m_rpc_submit); }

    // ── the won-block path ────────────────────────────────────────────────

    // Relay a WON block (already packed to wire bytes by submit_validator) to
    // the network over BOTH arms:
    //   ARM A: fan out to every live embedded P2P peer (parallel propagation).
    //   ARM B: hand to dashd via submitblock RPC (authoritative; if wired).
    // Both arms are attempted independently — the RPC fallback fires whenever it
    // is configured, NOT only when the peer-pool is empty, so a cold pool can
    // never silence the authoritative dashd path. Returns the per-arm Outcome.
    Outcome on_block_found(std::span<const unsigned char> block_bytes)
    {
        Outcome out;

        // ARM A — embedded P2P fan-out via the leaf scaffold.
        if (m_pool)
            out.peers_reached = m_pool->submit_block_raw_all(block_bytes);

        // ARM B — submitblock RPC fallback (dashd authoritative).
        if (m_rpc_submit) {
            out.rpc_attempted = true;
            out.rpc_submitted = m_rpc_submit(to_hex(block_bytes));
        }

        if (out.reached_network())
            LOG_INFO << "[DashBroadcastFull] won block relayed: peers="
                     << out.peers_reached
                     << " rpc=" << (out.rpc_submitted ? "ok" : "no");
        else
            LOG_WARNING << "[DashBroadcastFull] won block NOT relayed — "
                           "no live peers and no RPC arm! block bytes="
                        << block_bytes.size();
        return out;
    }

    // Lowercase hex of the packed block, as dashd submitblock expects.
    static std::string to_hex(std::span<const unsigned char> bytes)
    {
        static const char* k = "0123456789abcdef";
        std::string s;
        s.reserve(bytes.size() * 2);
        for (unsigned char b : bytes) {
            s.push_back(k[b >> 4]);
            s.push_back(k[b & 0x0f]);
        }
        return s;
    }

    DashBroadcaster* pool() const { return m_pool; }

private:
    DashBroadcaster* m_pool{};
    PeerSubmitFn     m_peer_submit;
    RpcSubmitFn      m_rpc_submit;
};

} // namespace dash
