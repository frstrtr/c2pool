#pragma once

#include <functional>

namespace btc
{
namespace coin
{

// FALLBACK broadcast orchestration for a WON block.
//
// P2P relay is PRIMARY; the submitblock RPC is the FALLBACK and fires ONLY
// when P2P is unavailable or the relay did not succeed. This is deliberately
// NOT always-both / double-broadcast: bitcoind dedupes a duplicate submitblock
// harmlessly, but the fallback gives us robustness against a silent
// P2P-unavailable / relay-failed hole without an unconditional double submit.
//
// `relay_p2p`  -> returns true on a successful P2P relay.
// `submit_rpc` -> returns true when bitcoind accepts the block.
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

} // namespace coin
} // namespace btc
