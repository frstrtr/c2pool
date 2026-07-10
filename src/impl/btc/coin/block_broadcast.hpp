// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// FALLBACK broadcast orchestration for a WON block.
//
// The canonical implementation now lives in the cross-coin SSOT
// core::broadcast_block_with_fallback (<core/block_broadcast.hpp>): the
// primary-then-fallback policy and the both-legs-guarded never-silent-drop
// invariant are IDENTICAL for every coin, so they are owned once in core/
// rather than re-spelled per coin. This btc::coin entry point is retained as a
// thin, signature-stable delegate so existing BTC call sites (and the other
// coin trees that cross-include this header) keep resolving the same symbol.
//
// P2P relay is PRIMARY; the submitblock RPC is the FALLBACK and fires ONLY
// when P2P is unavailable or the relay did not succeed (NOT always-both /
// double-broadcast). Returns true iff the block reached AT LEAST ONE sink; a
// false return means it reached NEITHER and the caller MUST treat it as a lost
// subsidy and scream. See the core header for the full guard rationale.

#include <functional>

#include <core/block_broadcast.hpp>

namespace btc
{
namespace coin
{

inline bool broadcast_block_with_fallback(
    const std::function<bool()>& relay_p2p,
    const std::function<bool()>& submit_rpc)
{
    return core::broadcast_block_with_fallback(relay_p2p, submit_rpc);
}

// CONNECT-AUTHORITATIVE broadcast (BTC lane ONLY). Distinct policy from the
// cross-coin FALLBACK orchestration above: a P2P relay "success" only means
// the block was ANNOUNCED to a peer (a cmpctblock header). Under compact-block
// relay the daemon then requests the body via getblocktxn, which the c2pool
// broadcaster does NOT serve, so the daemon never ConnectBlock()s the block and
// the full subsidy is silently lost even though relay_p2p() returned true. The
// submitblock RPC, by contrast, delivers the FULL block and is therefore
// connect-authoritative. So the connect path ALWAYS fires the RPC leg, in
// ADDITION to the P2P relay (kept for best-effort fast propagation). Returns
// true iff the block reached at least one sink.
//
// This is BTC-lane-fenced and deliberately does NOT alter the cross-coin
// core::broadcast_block_with_fallback contract: the give-submitblock-primacy /
// always-fire convergence is the v37 broadcaster-convergence shape held on HOLD
// (#500/#498). Only the BTC won-block connect path opts into it here.
inline bool broadcast_block_for_connect(
    const std::function<bool()>& relay_p2p,
    const std::function<bool()>& submit_rpc)
{
    bool relayed   = relay_p2p  ? relay_p2p()  : false;  // best-effort fast propagation
    bool connected = submit_rpc ? submit_rpc() : false;  // ALWAYS - connect-authoritative
    return relayed || connected;
}

} // namespace coin
} // namespace btc