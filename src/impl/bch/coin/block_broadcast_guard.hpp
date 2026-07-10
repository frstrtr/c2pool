// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin -- guarded dual-path won-block broadcast.
//
// A won block must reach the network down BOTH paths: embedded P2P relay
// (PRIMARY) AND external BCHN submitblock RPC (FALLBACK, fired ALWAYS). The
// dual-path gate FORBIDS letting a throwing P2P relay (a) propagate out of the
// dispatcher and skip the always-fire submitblock fallback -- that silently
// DROPS a won block (lost subsidy) AND runtime-removes the external-daemon
// fallback the gate requires; or (b) let a throwing RPC submit mask a P2P win.
//
// Each leg is therefore INDEPENDENTLY guarded so the dispatcher never throws:
//   * P2P leg throws  -> swallow, leave p2p_sent=false, FALL THROUGH to RPC.
//   * RPC leg throws   -> no-ack (rpc_ok=false); never masks a recorded P2P win.
//
// This is the v36-native shared-structure shape (bucket 2 -> v37): the same
// "each leg guarded, fallback always fires" contract btc-heap-opt landed for
// NMC (#468). Kept bch-fenced here (src/impl/bch/coin only); v37 unifies the
// CODE, not the per-coin isolation primitives.
//
// p2pool-merged-v36 SURFACE: NONE (block dispatch, not share/PPLNS/coinbase
// /AuxPoW bytes). Header-only; the helper is the SINGLE source of guard truth
// shared by the production dispatcher and the throw-injection KATs.
// ---------------------------------------------------------------------------
#pragma once

#include <exception>
#include <core/log.hpp>

namespace bch {
namespace coin {

/// Outcome of a won-block broadcast: which of the two sinks fired and whether
/// the network accepted. P2P is primary; the external BCHN-RPC submitblock is
/// the dual-path FALLBACK (fired ALWAYS). A `duplicate` on the RPC leg AFTER a
/// P2P accept still proves both paths reached the node; `landed_first` records
/// which won the race.
struct BlockBroadcast {
    bool        p2p_sent     = false; // submit_block_p2p_raw issued (sink present, no throw)
    bool        rpc_ok       = false; // submitblock returned ok OR duplicate
    const char* landed_first = "none"; // "p2p" | "rpc" | "none"
    bool any() const { return p2p_sent || rpc_ok; }
};

/// Fire a won block down BOTH paths with each leg independently guarded.
/// `p2p_relay` issues the embedded P2P relay (returns void; throwing is an
/// error that must NOT skip the fallback). `rpc_submit` issues the external
/// submitblock and returns true on ok/duplicate (throwing = no-ack). A leg is
/// attempted only when its sink is present (have_p2p / have_rpc).
template <class P2PRelayFn, class RpcSubmitFn>
inline BlockBroadcast guarded_dual_broadcast(bool have_p2p, P2PRelayFn&& p2p_relay,
                                             bool have_rpc, RpcSubmitFn&& rpc_submit)
{
    BlockBroadcast r;

    // PRIMARY: embedded P2P relay. A throw here MUST fall through to the
    // always-fire submitblock fallback, never propagate out and drop the block.
    if (have_p2p) {
        try {
            p2p_relay();
            r.p2p_sent = true;
            r.landed_first = "p2p";
        } catch (const std::exception& e) {
            LOG_ERROR << "[EMB-BCH] won-block P2P relay THREW (" << e.what()
                      << ") -- falling through to submitblock RPC fallback (block NOT dropped).";
        } catch (...) {
            LOG_ERROR << "[EMB-BCH] won-block P2P relay threw (non-std) -- "
                         "falling through to submitblock RPC fallback (block NOT dropped).";
        }
    }

    // FALLBACK (always fired): external BCHN submitblock. A throw here is a
    // no-ack that must NOT mask a P2P win already recorded above.
    if (have_rpc) {
        try {
            r.rpc_ok = rpc_submit();
            if (r.rpc_ok && !r.p2p_sent) r.landed_first = "rpc";
        } catch (const std::exception& e) {
            LOG_WARNING << "[EMB-BCH] won-block submitblock RPC THREW (" << e.what()
                        << ") -- no-ack; not masking any P2P win.";
            r.rpc_ok = false;
        } catch (...) {
            LOG_WARNING << "[EMB-BCH] won-block submitblock RPC threw (non-std) -- no-ack.";
            r.rpc_ok = false;
        }
    }

    return r;
}

} // namespace coin
} // namespace bch