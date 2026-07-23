// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// block_broadcast.hpp — Cross-coin WON-block broadcast fallback orchestration
// (SINGLE SOURCE OF TRUTH).
//
// Every coin c2pool mines reaches the network the same way when it WINS a
// block: P2P relay is PRIMARY, and the coin daemon submitblock RPC is the
// FALLBACK that fires ONLY when P2P is unavailable or the relay did not
// succeed. This orchestration carries no per-coin state — the sinks are passed
// in as callables — so the policy (primary/fallback ordering + the throw
// guards that stop a won block silently vanishing) belongs here in core/
// rather than being re-spelled per coin dispatcher.
//
// SCOPE — what this SSOT owns and does NOT own:
//   OWNS:   the broadcast POLICY — primary-then-fallback ordering, the
//           "no unconditional double-broadcast", and the both-legs-guarded
//           never-silent-drop invariant.
//   NOT:    HOW a coin relays over P2P or HOW it shapes its submitblock RPC.
//           Those are coin-specific and live behind the two callables.
//
// P2P relay is PRIMARY; the submitblock RPC is the FALLBACK and fires ONLY
// when P2P is unavailable or the relay did not succeed. This is deliberately
// NOT always-both / double-broadcast: a coin daemon dedupes a duplicate
// submitblock harmlessly, but the fallback gives us robustness against a silent
// P2P-unavailable / relay-failed hole without an unconditional double submit.
//
// `relay_p2p`  -> returns true on a successful P2P relay.
// `submit_rpc` -> returns true when the coin daemon accepts the block.
//
// Returns true iff the block reached AT LEAST ONE sink. A false return means
// the block reached NEITHER sink: the caller MUST treat that as a lost
// subsidy and scream (never silent-drop a won block).
//
// BOTH legs are guarded so a throwing sink can never bypass the fallback or
// escape this function: a THROWING relay_p2p() is a relay-FAILED mode, not a
// reason to skip the fallback -- without the guard the exception would unwind
// PAST this function, bypassing the submitblock fallback and silently dropping
// the won block (the exact hole the fallback exists to close). A throwing
// submit_rpc() (last-resort sink) collapses to a definite false return so the
// caller's documented "reached neither sink, scream" path fires instead of an
// exception escaping the won-block handler.
//
#include <functional>

namespace core
{

inline bool broadcast_block_with_fallback(
    const std::function<bool()>& relay_p2p,
    const std::function<bool()>& submit_rpc)
{
    bool p2p_ok = false;
    try {
        p2p_ok = (relay_p2p && relay_p2p());
    } catch (...) {
        p2p_ok = false;              // relay threw -> treat as relay-failed
    }
    if (p2p_ok)
        return true;                 // primary succeeded -> no double-broadcast

    if (submit_rpc) {
        try {
            return submit_rpc();     // fallback path
        } catch (...) {
            return false;            // last-resort sink threw -> caller screams
        }
    }
    return false;                    // reached neither sink
}

} // namespace core