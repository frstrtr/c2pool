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

} // namespace coin
} // namespace btc
