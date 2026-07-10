// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// DGB+DOGE (phase DC) — broadcast-path ELECTION + single-fire ledger.
//
// Fenced / test-only contract. Pins the HARD precondition the integrator set
// for any DC live-wire (UID2478): the submitauxblock RPC fallback MUST NOT
// double-fire the same DOGE block hash alongside the embedded submit path.
// Both paths must be mutually exclusive PER WON BLOCK.
//
// This complements coin/aux_dual_target_select.hpp (#490), which decides WHICH
// chain a scrypt pow_hash hits. This header decides, once a DOGE-aux win
// exists, WHICH broadcast path carries it to the network — and proves exactly
// one ever does.
//
// Two orthogonal guards compose into single-fire:
//
//   ELECTION (mutual exclusion AT one decision point): the embedded
//     submit_block path (frozen fully-assembled block -> P2P relay) is PRIMARY,
//     mirroring aux_chain_embedded.hpp where submit_block is the primary method
//     and submit_aux_block is the "no daemon to submit to" fallback. RPC
//     submitauxblock is elected ONLY when no embedded relay is available. A win
//     must be present for any path to fire. The function is total and returns
//     exactly one AuxBroadcastPath — never "both".
//
//   LEDGER (mutual exclusion ACROSS TIME / retries): even with a correct
//     election, a retry or a both-paths-attempted race could re-broadcast the
//     same DOGE block hash. AuxBroadcastLedger::try_fire records a hash on its
//     first authorization and suppresses every later attempt for that hash,
//     regardless of which path attempts it. This is the idempotent guard the
//     integrator named ("idempotent guard or path-election before broadcast").
//
// Pure helpers; links only core (uint256) + <set>. Consumes nothing in
// src/impl/doge and touches no node seam (the seam stays parked on the live
// DC slice). Non-circular: the primary-embedded / fallback-RPC posture is
// restated by value here, mirroring aux_chain_embedded.hpp's documented method
// roles without including it.
// ---------------------------------------------------------------------------
#pragma once

#include <set>
#include <core/uint256.hpp>

namespace dgb
{
namespace coin
{

// The broadcast carrier for a won DOGE-aux block. Exactly one is ever elected.
enum class AuxBroadcastPath
{
    None,                  // no win, or no carrier available
    EmbeddedSubmitBlock,   // PRIMARY: frozen block via embedded P2P relay
    RpcSubmitAuxBlock,     // FALLBACK: external daemon submitauxblock RPC
};

// Path-election. Total function: returns exactly one path. Embedded is primary;
// RPC fallback only when embedded relay is unavailable; None when there is no
// win or no carrier at all. By construction the two fire-paths are mutually
// exclusive — there is no input for which both EmbeddedSubmitBlock and
// RpcSubmitAuxBlock are "selected", because the result is a single enum value.
inline AuxBroadcastPath elect_aux_broadcast_path(bool have_doge_aux_win,
                                                 bool embedded_relay_available,
                                                 bool rpc_submit_available)
{
    if (!have_doge_aux_win)        return AuxBroadcastPath::None;
    if (embedded_relay_available)  return AuxBroadcastPath::EmbeddedSubmitBlock;
    if (rpc_submit_available)      return AuxBroadcastPath::RpcSubmitAuxBlock;
    return AuxBroadcastPath::None;
}

// Idempotent single-fire ledger keyed on the DOGE block hash. try_fire returns
// true EXACTLY ONCE per distinct hash (first call records + authorizes); every
// later call for the same hash returns false (double-fire suppressed),
// independent of which path attempts it. Distinct hashes are independent.
class AuxBroadcastLedger
{
public:
    // Authorize-and-record. true => fresh, caller should broadcast.
    // false => this hash was already broadcast; suppress.
    bool try_fire(const uint256& doge_block_hash)
    {
        return m_fired.insert(doge_block_hash).second;
    }

    bool already_fired(const uint256& doge_block_hash) const
    {
        return m_fired.find(doge_block_hash) != m_fired.end();
    }

private:
    std::set<uint256> m_fired;
};

// Convenience composition: elect a path AND consult the ledger in one call.
// Returns the path that should actually broadcast — None if no win, no carrier,
// OR the hash was already fired. On a non-None return the hash is recorded, so
// a subsequent call with the same hash yields None (single-fire guaranteed even
// if BOTH carrier conditions are true on the retry).
inline AuxBroadcastPath elect_and_claim(AuxBroadcastLedger&  ledger,
                                        const uint256&       doge_block_hash,
                                        bool                 have_doge_aux_win,
                                        bool                 embedded_relay_available,
                                        bool                 rpc_submit_available)
{
    const AuxBroadcastPath path = elect_aux_broadcast_path(
        have_doge_aux_win, embedded_relay_available, rpc_submit_available);
    if (path == AuxBroadcastPath::None) return AuxBroadcastPath::None;
    if (!ledger.try_fire(doge_block_hash)) return AuxBroadcastPath::None;
    return path;
}

} // namespace coin
} // namespace dgb