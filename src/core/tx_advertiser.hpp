// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Send side of the p2pool `have_tx` / `losing_tx` tx-pool advertisement.
//
// c2pool has always been RECEIVE-ONLY for these two messages: every coin lane
// ingests a peer's `have_tx` into Peer::m_remote_txs (and drops on `losing_tx`),
// but never advertises its OWN known-tx set. The visible consequence is that
// every canonical p2pool dashboard renders a c2pool peer with txpool = 0 while
// real p2pool nodes report 12k-16k, and remember_tx forwarding is less efficient
// than it should be because peers cannot tell which txs we already hold.
//
// ── Canonical semantics being mirrored ──────────────────────────────────────
// Reference: p2pool python fork, p2pool/p2p.py (Protocol.connectionMade →
// _think / post-handshake block):
//
//   p2p.py:276  self.send_have_tx(tx_hashes=self.node.known_txs_var.value.keys())
//                 — one FULL advert of the current known-tx set, immediately
//                   after the version handshake completes.
//   p2p.py:243-248  known_txs_var.added   → send_have_tx(list(added))
//   p2p.py:250-259  known_txs_var.removed → send_losing_tx(list(removed))
//   p2p.py:261-274  known_txs_var.transitioned → send_have_tx(added) THEN
//                                                send_losing_tx(removed)
//
// So canonical p2pool sends DELTAS against the per-peer view established by the
// initial full advert. It has no explicit per-peer "advertised" set because the
// reactive VariableDict hands it the delta directly; the per-peer view is
// (full set at handshake) + (every subsequent delta). c2pool has no reactive
// variable, so an explicit per-peer advertised set (TxAdvertState, parked on the
// coin's Peer struct next to the existing m_remote_txs) reconstructs exactly the
// same sequence of messages.
//
// Cadence: canonical fires on the change EVENT, and the events are themselves
// naturally batched — additions arrive one work-refresh at a time and removals
// arrive from node.py's `forget_old_txs` RobustLoopingCall, started at
// node.py:298 with t.start(10), i.e. a 10-second sweep. c2pool therefore drives
// the delta sweep from a 10-second timer (TX_ADVERT_INTERVAL_SECONDS) rather
// than firing per inbound remember_tx: same eventual per-peer view, strictly
// fewer and larger messages than canonical, and no way for a burst of inbound
// txs to turn into a burst of outbound adverts.
//
// Size bound: canonical wraps oversized sends in p2p.py:230 `fragment()`, which
// recursively halves a payload that raises p2protocol.TooLong (the 3 MiB
// max_payload of p2p.py:41). Rather than reproduce the throw/retry, we chunk
// up-front at TX_ADVERT_MAX_HASHES_PER_MESSAGE = 10000 hashes -> ~320 KB, which
// is an order of magnitude under the canonical 3 MiB ceiling and is exactly the
// bound canonical itself applies to the RECEIVING side of have_tx
// (p2p.py:494-495 truncates remote_tx_hashes to 10000), so a larger chunk could
// never be fully retained by the peer anyway.
//
// REWARD-SAFETY: advertisement only. Nothing here reads or writes consensus
// state, share validation, subsidy, coinbase, payee, or the won-block path. A
// have_tx/losing_tx message carries tx HASHES only and never affects which
// shares verify or what a block pays.

#pragma once

#include <chrono>
#include <cstddef>
#include <set>
#include <vector>

#include <core/uint256.hpp>

namespace core {

// Max tx hashes per have_tx / losing_tx message. Mirrors the canonical
// receive-side cap (p2p.py:494 truncates remote_tx_hashes to 10000) and keeps
// every emitted payload ~320 KB, far under canonical's 3 MiB max_payload.
inline constexpr std::size_t TX_ADVERT_MAX_HASHES_PER_MESSAGE = 10000;

// Delta-sweep cadence in seconds. Mirrors node.py:298 forget_old_txs t.start(10).
inline constexpr int TX_ADVERT_INTERVAL_SECONDS = 10;

// What one sweep would put on the wire for one peer.
struct TxAdvertPlan
{
    std::vector<uint256> m_have;   // newly known -> have_tx
    std::vector<uint256> m_losing; // no longer known -> losing_tx

    bool empty() const { return m_have.empty() && m_losing.empty(); }
};

// Per-peer reconstruction of "what this peer believes we hold". Lives on the
// coin's Peer struct alongside m_remote_txs (which is the mirror image: what the
// peer told US it holds).
struct TxAdvertState
{
    std::set<uint256> m_advertised;
    bool m_initial_sent{false};
};

// Pure diff: current known-tx hash set vs what the peer has already been told.
// `current` may be any ordered/unordered set of uint256 supporting find()/end().
template <typename HashSet>
inline TxAdvertPlan plan_tx_advert(const TxAdvertState& state, const HashSet& current)
{
    TxAdvertPlan plan;
    for (const auto& h : current)
        if (state.m_advertised.find(h) == state.m_advertised.end())
            plan.m_have.push_back(h);
    for (const auto& h : state.m_advertised)
        if (current.find(h) == current.end())
            plan.m_losing.push_back(h);
    return plan;
}

// Fold a committed plan into the per-peer view.
inline void commit_tx_advert(TxAdvertState& state, const TxAdvertPlan& plan)
{
    for (const auto& h : plan.m_have)
        state.m_advertised.insert(h);
    for (const auto& h : plan.m_losing)
        state.m_advertised.erase(h);
    state.m_initial_sent = true;
}

// Split a hash list into wire-sized chunks (see TX_ADVERT_MAX_HASHES_PER_MESSAGE).
// An empty input yields no chunks — we never emit an empty message.
inline std::vector<std::vector<uint256>>
chunk_tx_hashes(const std::vector<uint256>& hashes, std::size_t max_per_message)
{
    std::vector<std::vector<uint256>> out;
    if (hashes.empty() || max_per_message == 0)
        return out;
    for (std::size_t i = 0; i < hashes.size(); i += max_per_message)
    {
        const std::size_t n = std::min(max_per_message, hashes.size() - i);
        out.emplace_back(hashes.begin() + i, hashes.begin() + i + n);
    }
    return out;
}

// Drive one advert sweep for one peer.
//
// Computes the delta, emits it through the coin-specific senders in canonical
// order (have_tx before losing_tx, p2p.py:264-267), chunked to the wire bound,
// and folds the result into `state`. Returns the plan so callers can log/test.
//
// send_have / send_losing are invoked as f(const std::vector<uint256>&) once per
// chunk and are never called with an empty vector. They MUST NOT throw; a coin
// wrapper that can fail should swallow and let the next sweep retry (the state
// is only committed after the senders return).
template <typename HashSet, typename SendHave, typename SendLosing>
inline TxAdvertPlan run_tx_advert(TxAdvertState& state, const HashSet& current,
                                  SendHave&& send_have, SendLosing&& send_losing,
                                  std::size_t max_per_message = TX_ADVERT_MAX_HASHES_PER_MESSAGE)
{
    TxAdvertPlan plan = plan_tx_advert(state, current);

    // Canonical sends nothing when a change event carries no entries
    // (p2p.py:244 `if added:` / p2p.py:251 `if removed:`). The one exception is
    // the handshake advert (p2p.py:276), which canonical issues unconditionally
    // — including with an empty tx_hashes list — so a peer that has just
    // connected always learns our (possibly empty) view exactly once.
    const bool initial = !state.m_initial_sent;
    if (plan.empty() && !initial)
        return plan;

    if (initial && plan.m_have.empty())
    {
        send_have(std::vector<uint256>{});
    }
    else
    {
        for (const auto& chunk : chunk_tx_hashes(plan.m_have, max_per_message))
            send_have(chunk);
    }
    for (const auto& chunk : chunk_tx_hashes(plan.m_losing, max_per_message))
        send_losing(chunk);

    commit_tx_advert(state, plan);
    return plan;
}

} // namespace core
