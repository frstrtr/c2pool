// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// nmc::coin::broadcast_won_aux_block -- the NMC (Namecoin) dual-path won-block
// dispatcher for a merge-mined aux block under a BTC SHA256d parent.
//
// 1:1 contract mirror of dgb::coin::broadcast_won_block (block dispatch half)
// and bch::coin::EmbeddedDaemon::broadcast_won_block. When a found share's
// parent BTC PoW also satisfies the NMC aux-network target, a REAL Namecoin
// block (parent header + AuxPow proof) is formed and MUST reach the Namecoin
// network. Per the broadcaster-gate dual-path rule it is fired down BOTH sinks:
//   PRIMARY  : embedded P2P relay to namecoin peers (fastest propagation),
//              supplied by the run-loop as a sink fn -- the same authoritative
//              embedded route AuxChainEmbedded::submit_block() drives today.
//   FALLBACK : external namecoind `submitauxblock` RPC (to the .140 testnet
//              namecoind), fired ALWAYS, NOT a P2P-only path with RPC as a
//              catch. submitauxblock of an already-accepted aux block returns a
//              harmless rejection at the daemon, so a duplicate after a P2P
//              accept still proves the RPC path reached the node; ignore-failure
//              semantics mean that duplicate must never mask the P2P win.
//
// This is the sink the NMC run-loop wires the won-aux-block trigger to so an
// in-operation win emits immediately. Decoupled from the (live) namecoind RPC
// client by taking BOTH legs as std::function sinks: the dispatch CONTRACT is
// build-verifiable and KAT-locked now, and the run-loop binds the live P2P
// relay + the .140 submitauxblock client when they are stood up (PE item 3
// live-client slice; the soak gate, item 4, follows once the RPC leg is live).
//
// Standardized v36-native shape: identical dual-path contract to dgb/bch so the
// v37 multichain migration is a clean lift, not a reconciliation of divergent
// dialects. Per-coin isolation: src/impl/nmc/ only; consumes core/* only, pulls
// no btc/ or dgb/ symbol. p2pool-merged-v36 surface: NONE -- block dispatch
// only; no PoW hash, share format, aux commitment, or PPLNS math is touched.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <exception>
#include <functional>
#include <string>
#include <vector>

#include <core/log.hpp>

namespace nmc
{
namespace coin
{

// Embedded P2P relay sink: the run-loop binds this to the namecoin P2P relay
// (the embedded submit_block route). Empty == no embedded P2P sink present.
using P2pRelaySink = std::function<void(const std::vector<unsigned char>&)>;

// External submitauxblock RPC sink: the run-loop binds this to the live .140
// testnet namecoind submitauxblock client. Takes the NMC block hash hex and the
// serialized AuxPow hex; returns true on daemon accept OR harmless duplicate.
// Empty == no RPC fallback sink wired.
using AuxRpcSink =
    std::function<bool(const std::string& block_hash_hex, const std::string& auxpow_hex)>;

// Outcome of a won-aux-block broadcast: which sinks fired and whether the
// external namecoind acked. P2P is primary; the submitauxblock RPC fallback is
// fired ALWAYS (dual-path rule). landed_first records which path won the race.
struct AuxBlockBroadcast
{
    bool        p2p_sent     = false;   // embedded P2P relay issued (sink present)
    bool        rpc_ok       = false;   // submitauxblock accepted OR duplicate
    const char* landed_first = "none";  // "p2p" | "rpc" | "none"
    bool any() const { return p2p_sent || rpc_ok; }
};

// Fire a won aux block down BOTH broadcast paths. `block_bytes` is the pre-
// serialized NMC block blob the embedded P2P relay sends; `block_hash_hex` and
// `auxpow_hex` are passed to the external submitauxblock fallback. `p2p_relay`
// may be empty (no embedded sink yet); `aux_rpc` may be empty (no live RPC
// client yet) -- each leg is guarded so the dispatcher never throws or
// dereferences an unset sink. Never silent-drops a won block: with NEITHER sink
// present it logs an ERROR (lost-subsidy scream) and returns any()==false.
// --- v37 BUCKET CLASSIFICATION (3-bucket rule) -------------------------------
// BUCKET 1 (per-coin isolation invariant) -- KEEP, do NOT standardize/converge.
// This dispatcher deliberately does NOT delegate to
// core::broadcast_block_with_fallback() (src/core/block_broadcast.hpp). That
// core SSOT SHORT-CIRCUITS on a P2P win (if p2p_ok return true) to avoid
// a double-broadcast -- correct for a single-chain won block (BTC delegates to
// it). NMC is merge-mined: the external namecoind submitauxblock RPC leg is
// fired ALWAYS, even after a P2P win (a duplicate aux submission is a harmless
// daemon rejection, never a silent drop). Converging NMC onto the core short-
// circuit SSOT would DROP the always-fire aux leg -- a consensus-path
// regression. The always-fire property is KAT-locked by
// NmcAuxBlockBroadcast.DualPathAlwaysFiresFallback. v37 multichain migration
// MUST preserve this per-coin aux contract, not collapse it onto the SSOT.
// -----------------------------------------------------------------------------
inline AuxBlockBroadcast broadcast_won_aux_block(const P2pRelaySink& p2p_relay,
                                                 const AuxRpcSink&   aux_rpc,
                                                 const std::vector<unsigned char>& block_bytes,
                                                 const std::string& block_hash_hex,
                                                 const std::string& auxpow_hex)
{
    AuxBlockBroadcast r;

    // PRIMARY: embedded P2P relay (fastest propagation). GUARDED: a throwing
    // relay sink must NOT prevent the always-fire submitauxblock fallback below
    // -- otherwise a P2P-leg fault silently drops a won block AND skips its
    // safety net. p2p_sent is only set after the sink returns cleanly.
    if (p2p_relay) {
        try {
            p2p_relay(block_bytes);
            r.p2p_sent = true;
            r.landed_first = "p2p";
            LOG_INFO << "[EMB-NMC] won-aux-block P2P relay issued (" << block_bytes.size()
                     << " bytes) -- primary path.";
        } catch (const std::exception& e) {
            LOG_ERROR << "[EMB-NMC] won-aux-block P2P relay threw (" << e.what()
                      << ") -- falling through to submitauxblock RPC fallback.";
        } catch (...) {
            LOG_ERROR << "[EMB-NMC] won-aux-block P2P relay threw (non-std) -- "
                         "falling through to submitauxblock RPC fallback.";
        }
    } else {
        LOG_WARNING << "[EMB-NMC] won-aux-block: no embedded P2P sink; relying on submitauxblock RPC fallback.";
    }

    // FALLBACK (always fired): external namecoind submitauxblock. A duplicate
    // after a P2P accept is success, not failure -- the sink uses ignore-failure
    // semantics so a duplicate/already-have never masks the P2P win.
    if (aux_rpc) {
        try {
            r.rpc_ok = aux_rpc(block_hash_hex, auxpow_hex);
            if (r.rpc_ok && !r.p2p_sent) r.landed_first = "rpc";
            LOG_INFO << "[EMB-NMC] won-aux-block submitauxblock RPC fallback "
                     << (r.rpc_ok ? "accept/duplicate" : "no-ack") << ".";
        } catch (const std::exception& e) {
            LOG_ERROR << "[EMB-NMC] won-aux-block submitauxblock RPC fallback threw ("
                      << e.what() << ") -- treated as no-ack, P2P win (if any) preserved.";
        } catch (...) {
            LOG_ERROR << "[EMB-NMC] won-aux-block submitauxblock RPC fallback threw (non-std) -- treated as no-ack.";
        }
    } else {
        LOG_WARNING << "[EMB-NMC] won-aux-block: no external namecoind submitauxblock fallback sink wired.";
    }

    if (!r.any())
        LOG_ERROR << "[EMB-NMC] won-aux-block had NEITHER broadcast sink -- block NOT relayed!";
    else
        LOG_INFO << "[EMB-NMC] won-aux-block broadcast: p2p=" << (r.p2p_sent ? "sent" : "off")
                 << " rpc=" << (r.rpc_ok ? "ok" : "off")
                 << " landed_first=" << r.landed_first << ".";
    return r;
}

} // namespace coin
} // namespace nmc