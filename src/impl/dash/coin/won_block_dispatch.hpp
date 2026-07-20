// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dash::coin::broadcast_won_block -- the DASH dual-path won-block dispatcher
// (S8: closes the broadcaster dual-path gate).
//
// Contract mirror of dgb::coin::broadcast_won_block (block_broadcast.hpp) and
// bch::coin::EmbeddedDaemon::broadcast_won_block, conformed to the DASH stratum
// path where the won block is ALREADY reconstructed to wire bytes by the
// DASHWorkSource submit path (so there is no reconstruct closure here -- the
// caller hands us the finished block blob + its hex).
//
// A won DASH block reaches the network by TWO independent arms:
//
//   ARM A -- EMBEDDED P2P RELAY (ALWAYS-PRIMARY, daemonless)
//     Relay the packed block straight onto the coin P2P network via the E1
//     CoinClient (submit_block_p2p_raw). This is the DAEMONLESS critical path:
//     with NO local dashd, a won block still reaches the network on this arm
//     alone. Supplied by the run-loop as a P2pRelaySink; EMPTY when no
//     --coin-p2p-connect peer is dialed OR --no-p2p-relay suppresses it.
//
//   ARM B -- submitblock RPC BACKUP (on-demand)
//     Hand the block hex to the local dashd via submitblock. Fires whenever the
//     RPC arm is configured (a local dashd is present) -- so it also carries the
//     block if the embedded relay is cold or faulted. A duplicate/already-have
//     here after ARM A landed is SUCCESS, not failure (ignore_failure=true), and
//     never masks an ARM A win. Supplied as an RpcSubmitSink; EMPTY when no
//     dashd creds are armed (the daemonless deployment).
//
// NEVER SILENT-DROP: each arm is wrapped so a throwing sink can never propagate
// out and skip the other arm; and if a won block reaches NEITHER sink the
// dispatcher logs LOUDLY (LOG_ERROR) and reports any()==false so the caller
// treats it as "block NOT relayed", never a silent lost subsidy.
//
// Reward/consensus-NEUTRAL: broadcast path only. No PoW hash, share format,
// coinbase commitment, or PPLNS math is touched. Per-coin isolation:
// src/impl/dash/ only.
// ---------------------------------------------------------------------------

#include <exception>
#include <functional>
#include <string>
#include <vector>

#include <core/log.hpp>

namespace dash
{
namespace coin
{

// Embedded P2P relay sink (ARM A, primary): the run-loop binds this to the E1
// CoinClient's submit_block_p2p_raw. EMPTY == no embedded P2P sink present
// (no --coin-p2p-connect peer, or --no-p2p-relay suppression).
using P2pRelaySink = std::function<void(const std::vector<unsigned char>&)>;

// submitblock RPC sink (ARM B, backup): the run-loop binds this to
// NodeRPC::submit_block_hex. Returns true iff dashd accepted (or duplicate).
// EMPTY == no dashd RPC arm armed (the daemonless deployment).
using RpcSubmitSink = std::function<bool(const std::string&)>;

// Outcome of a won-block broadcast across both arms. ARM A is primary; the
// submitblock RPC backup fires whenever it is configured. landed_first records
// which path was engaged first for the record.
struct BlockBroadcast
{
    bool        p2p_sent     = false;   // embedded P2P relay issued (sink present)
    bool        rpc_ok       = false;   // submitblock returned ok OR duplicate
    const char* landed_first = "none";  // "p2p" | "rpc" | "none"

    // The gate predicate: did the won block engage AT LEAST ONE broadcast sink?
    bool any() const { return p2p_sent || rpc_ok; }
};

// Fire a won block down BOTH broadcast arms. `block_bytes` is the pre-serialized
// block blob the embedded P2P relay sends; `block_hex` is the same block hex for
// the submitblock backup. `p2p_relay` may be empty (no embedded sink);
// `rpc_submit` may be empty (daemonless, no dashd). Each leg is wrapped in
// try/catch so a throwing sink can NEVER propagate out of the dispatcher: a
// throwing primary arm falls through to the RPC backup (no silent drop), and a
// throwing backup is a no-ack that never masks a primary win.
inline BlockBroadcast broadcast_won_block(const P2pRelaySink& p2p_relay,
                                          const RpcSubmitSink& rpc_submit,
                                          const std::vector<unsigned char>& block_bytes,
                                          const std::string& block_hex)
{
    BlockBroadcast r;

    // ARM A -- embedded P2P relay (ALWAYS-PRIMARY, daemonless). Guarded so a
    // throwing relay sink can NEVER propagate out and skip the RPC backup below
    // -- a primary-leg fault must degrade to the backup, not silently drop a won
    // block (lost subsidy).
    if (p2p_relay) {
        try {
            p2p_relay(block_bytes);
            r.p2p_sent = true;
            r.landed_first = "p2p";
            LOG_INFO << "[EMB-DASH] won-block embedded P2P relay issued ("
                     << block_bytes.size() << " bytes) -- primary path.";
        } catch (const std::exception& e) {
            LOG_ERROR << "[EMB-DASH] won-block embedded P2P relay threw (" << e.what()
                      << ") -- falling through to submitblock RPC backup.";
        } catch (...) {
            LOG_ERROR << "[EMB-DASH] won-block embedded P2P relay threw (non-std) -- "
                         "falling through to submitblock RPC backup.";
        }
    } else {
        LOG_WARNING << "[EMB-DASH] won-block: no embedded P2P sink "
                       "(no --coin-p2p-connect peer / suppressed); relying on RPC backup.";
    }

    // ARM B -- submitblock RPC backup (on-demand; fires whenever a local dashd is
    // armed, so it also carries the block if the primary relay is cold/faulted).
    // ignore_failure=true so a duplicate/already-have after an ARM A accept is
    // success, not failure, and does not mask the primary win.
    if (rpc_submit) {
        try {
            r.rpc_ok = rpc_submit(block_hex);
            if (r.rpc_ok && !r.p2p_sent) r.landed_first = "rpc";
            LOG_INFO << "[EMB-DASH] won-block submitblock RPC backup "
                     << (r.rpc_ok ? "ok/duplicate" : "no-ack") << ".";
        } catch (const std::exception& e) {
            LOG_ERROR << "[EMB-DASH] won-block submitblock RPC backup threw ("
                      << e.what() << ") -- no-ack; not masking any primary win.";
        } catch (...) {
            LOG_ERROR << "[EMB-DASH] won-block submitblock RPC backup threw "
                         "(non-std) -- no-ack; not masking any primary win.";
        }
    } else {
        LOG_WARNING << "[EMB-DASH] won-block: no dashd submitblock backup arm wired "
                       "(daemonless deployment).";
    }

    if (!r.any())
        LOG_ERROR << "[EMB-DASH] won-block reached NEITHER sink -- block NOT relayed!";
    else
        LOG_INFO << "[EMB-DASH] won-block broadcast: p2p=" << (r.p2p_sent ? "sent" : "off")
                 << " rpc=" << (r.rpc_ok ? "ok" : "off")
                 << " landed_first=" << r.landed_first << ".";
    return r;
}

} // namespace coin
} // namespace dash
