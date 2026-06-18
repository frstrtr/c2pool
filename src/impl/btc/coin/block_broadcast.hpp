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
inline bool broadcast_block_with_fallback(
    const std::function<bool()>& relay_p2p,
    const std::function<bool()>& submit_rpc)
{
    if (relay_p2p && relay_p2p())
        return true;                 // primary succeeded -> no double-broadcast
    if (submit_rpc)
        return submit_rpc();         // fallback path
    return false;                    // reached neither sink
}

} // namespace coin
} // namespace btc
