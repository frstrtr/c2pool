// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::broadcast_won_block -- the DGB dual-path won-block dispatcher.
//
// 1:1 contract mirror of bch::coin::EmbeddedDaemon::broadcast_won_block
// (src/impl/bch/coin/embedded_daemon.hpp @90a35536): on a won block it fires
// BOTH broadcast sinks --
//   PRIMARY  : embedded P2P relay (fastest propagation), supplied by the
//              run-loop as a sink fn (DGB has no submit_block_p2p_raw on
//              coin::Node yet -- the EmbeddedDaemon/NodeP2P port binds this).
//   FALLBACK : external digibyted submitblock via the CoinNode seam
//              (core::coin::ICoinNode::submit_block_hex) -- fired ALWAYS, per
//              the broadcaster-gate dual-path rule, NOT a P2P-only path with
//              RPC as a catch. A duplicate on the RPC leg after a P2P accept
//              still proves both paths reached the node; landed_first records
//              which won the race. ignore_failure=true so an already-have on
//              the fallback never masks the P2P win.
//
// This is the sink the DGB pool node wires tracker().m_on_block_found to so an
// in-operation win emits immediately (the remaining #82 run-loop slice; the
// pool-node wiring mirrors bch @9fed4955). Decoupled from the (not-yet-ported)
// DGB EmbeddedDaemon by taking the P2P sink as a std::function and the seam as
// an ICoinNode*, so it is build-verifiable now and the run-loop binds the live
// objects when NodeP2P lands.
//
// DGB-Scrypt is a STANDALONE parent in the V36 default build -- no merged-
// coinbase leg (DOGE aux is -DAUX_DOGE=ON stretch, a separate parent path).
// p2pool-merged-v36 surface: NONE -- block dispatch only, no PoW hash, share
// format, coinbase commitment, or PPLNS math is touched. Per-coin isolation:
// src/impl/dgb/coin/ only.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <exception>
#include <functional>
#include <string>
#include <vector>

#include <core/coin/node_iface.hpp>
#include <core/log.hpp>

namespace dgb
{
namespace coin
{

// Embedded P2P relay sink: the run-loop binds this to NodeP2P::submit_block_p2p_raw
// once the embedded daemon is stood up. Empty == no embedded P2P sink present.
using P2pRelaySink = std::function<void(const std::vector<unsigned char>&)>;

// Outcome of a won-block broadcast: which of the two sinks fired and whether
// the external node acked. P2P is primary; the submitblock RPC fallback fires
// ALWAYS (dual-path rule). landed_first records which path won the race.
struct BlockBroadcast
{
    bool        p2p_sent     = false;   // embedded P2P relay issued (sink present)
    bool        rpc_ok       = false;   // submitblock returned ok OR duplicate
    const char* landed_first = "none";  // "p2p" | "rpc" | "none"
    bool any() const { return p2p_sent || rpc_ok; }
};

// Fire a won block down BOTH broadcast paths. `block_bytes` is the pre-
// serialized block blob the embedded P2P relay sends; `block_hex` is the same
// block hex for the external submitblock fallback. `p2p_relay` may be empty
// (no embedded sink yet); `seam` may be null or RPC-less -- each leg is wrapped
// in try/catch so a throwing sink can NEVER propagate out of the dispatcher: a
// throwing P2P leg falls through to the always-fire submitblock RPC fallback
// (no silent won-block drop / lost subsidy), and a throwing RPC leg is a no-ack
// that never masks a P2P win. The dispatcher also never dereferences a null sink.
inline BlockBroadcast broadcast_won_block(const P2pRelaySink& p2p_relay,
                                          core::coin::ICoinNode* seam,
                                          const std::vector<unsigned char>& block_bytes,
                                          const std::string& block_hex)
{
    BlockBroadcast r;

    // PRIMARY: embedded P2P relay (fastest propagation). Guarded so a throwing
    // relay sink can NEVER propagate out and skip the always-fire RPC fallback
    // below -- a P2P-leg fault must degrade to the fallback, not silently drop a
    // won block (lost subsidy).
    if (p2p_relay) {
        try {
            p2p_relay(block_bytes);
            r.p2p_sent = true;
            r.landed_first = "p2p";
            LOG_INFO << "[EMB-DGB] won-block P2P relay issued (" << block_bytes.size()
                     << " bytes) -- primary path.";
        } catch (const std::exception& e) {
            LOG_ERROR << "[EMB-DGB] won-block P2P relay threw (" << e.what()
                      << ") -- falling through to submitblock RPC fallback.";
        } catch (...) {
            LOG_ERROR << "[EMB-DGB] won-block P2P relay threw (non-std) -- "
                         "falling through to submitblock RPC fallback.";
        }
    } else {
        LOG_WARNING << "[EMB-DGB] won-block: no embedded P2P sink; relying on RPC fallback.";
    }

    // FALLBACK (always fired): external digibyted submitblock. A duplicate here
    // after a P2P accept is success, not failure -- ignore_failure=true so a
    // duplicate/already-have does not mask the P2P win.
    if (seam && seam->has_rpc()) {
        try {
            r.rpc_ok = seam->submit_block_hex(block_hex, /*ignore_failure=*/true);
            if (r.rpc_ok && !r.p2p_sent) r.landed_first = "rpc";
            LOG_INFO << "[EMB-DGB] won-block submitblock RPC fallback "
                     << (r.rpc_ok ? "ok/duplicate" : "no-ack") << ".";
        } catch (const std::exception& e) {
            LOG_ERROR << "[EMB-DGB] won-block submitblock RPC fallback threw ("
                      << e.what() << ") -- no-ack; not masking any P2P win.";
        } catch (...) {
            LOG_ERROR << "[EMB-DGB] won-block submitblock RPC fallback threw "
                         "(non-std) -- no-ack; not masking any P2P win.";
        }
    } else {
        LOG_WARNING << "[EMB-DGB] won-block: no external digibyted-RPC fallback sink wired.";
    }

    if (!r.any())
        LOG_ERROR << "[EMB-DGB] won-block had NEITHER broadcast sink -- block NOT relayed!";
    else
        LOG_INFO << "[EMB-DGB] won-block broadcast: p2p=" << (r.p2p_sent ? "sent" : "off")
                 << " rpc=" << (r.rpc_ok ? "ok" : "off")
                 << " landed_first=" << r.landed_first << ".";
    return r;
}

} // namespace coin
} // namespace dgb