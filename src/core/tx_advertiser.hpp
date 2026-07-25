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
// ── Write-safety: ONE MESSAGE PER PEER, AND NEVER TWO IN FLIGHT ─────────────
// This is a HARD constraint imposed by c2pool's socket layer, not by canonical.
//
// core::Socket::write (core/socket.cpp:110-137) starts a composed
// boost::asio::async_write IMMEDIATELY — there is NO outbound queue. Asio's
// contract forbids initiating a second composed write on a descriptor before the
// first completes: two overlapping composed writes interleave their
// async_write_some continuations FIFO per descriptor, so a write that needs more
// than one round splices bytes INTO THE MIDDLE of the other message. The result
// is a framing/checksum error and the canonical peer drops us.
//
// Note what that does NOT say: it is not about fitting in one write_some. A
// ~32 KB framed message needs >= 2 rounds at the Linux default tcp_wmem[1] of
// 16384, and that is fine — a multi-round write is only dangerous if ANOTHER
// write is initiated while it drains. So the invariants are about exclusivity,
// not about message size:
//
//   1. ONE MESSAGE PER SWEEP per peer. Never a chunk burst, never have_tx
//      immediately followed by losing_tx. Nothing else is written to that peer
//      in the same event, so within a sweep there is exactly one write.
//   2. ONE MESSAGE IN FLIGHT per peer. A sweep is not the same thing as a
//      completed write: if the next sweep fired while the previous advert was
//      still draining (fresh socket, high RTT, or a stalled/zero-window peer),
//      it would initiate the overlapping write anyway. TX_ADVERT_MIN_EMIT_
//      INTERVAL_SECONDS enforces a minimum gap between emits to the SAME peer,
//      which closes that window without needing a completion callback.
//   3. Only what was ACTUALLY emitted is committed to the per-peer view, so the
//      remainder is recomputed and sent by a later sweep. A 10k-tx pool simply
//      converges over ~100 s instead of one multi-chunk burst — which is
//      indistinguishable to a canonical peer, since have_tx is advisory.
//
// TX_ADVERT_MAX_HASHES_PER_MESSAGE then exists to bound the message, not to
// guarantee a single round: it keeps per-write cost and per-peer memory
// predictable and stays far inside what a canonical peer will accept.
//
// Canonical solves the size problem differently: p2p.py:230 `fragment()`
// recursively halves a payload that raises p2protocol.TooLong (against the 3 MiB
// max_payload of p2p.py:41). We cannot use that shape, because fragment() emits
// the halves BACK-TO-BACK — exactly the overlapping-write pattern our socket
// layer cannot survive. Spreading across sweeps is the queue-free equivalent.
//
// FOLLOW-UP (deliberately NOT done here): the proper fix is an outbound write
// queue in core::Socket, which would make both guards unnecessary and would also
// cure the PRE-EXISTING violation in the share-broadcast path
// (dash/node.cpp:1290/1301/1307 issues three back-to-back writes) for every
// coin. That is a core change needing its own review.
//
// REWARD-SAFETY: advertisement only. Nothing here reads or writes consensus
// state, share validation, subsidy, coinbase, payee, or the won-block path. A
// have_tx/losing_tx message carries tx HASHES only and never affects which
// shares verify or what a block pays.

#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <iterator>
#include <set>
#include <vector>

#include <core/uint256.hpp>

namespace core {

// Max tx hashes in a single have_tx / losing_tx message.
//
// 1000 hashes = 32000 bytes of payload plus a 3-byte list varint and the packet
// header, ~32 KB on the wire. This does NOT fit a single write_some on a typical
// Linux socket (default tcp_wmem[1] = 16384, so >= 2 rounds) and it does not need
// to: a multi-round write is safe as long as no OTHER write is initiated while it
// drains, which is what the one-message-per-sweep rule and
// TX_ADVERT_MIN_EMIT_INTERVAL_SECONDS guarantee (see the header comment).
//
// The bound exists to keep the message SIZE predictable — bounded per-write cost,
// bounded per-peer memory, and a drain time short enough that the min-emit
// interval is never the limiting factor. Canonical's own receive side truncates
// its view of a peer's tx set at 10000 hashes (p2p.py:494-495), so this is well
// inside anything a canonical peer would retain, and two orders of magnitude
// under canonical's 3 MiB max_payload (p2p.py:41).
inline constexpr std::size_t TX_ADVERT_MAX_HASHES_PER_MESSAGE = 1000;

// Delta-sweep cadence in seconds. Mirrors node.py:298 forget_old_txs t.start(10).
inline constexpr int TX_ADVERT_INTERVAL_SECONDS = 10;

// Minimum gap between two emits to the SAME peer.
//
// One message per SWEEP is not one message IN FLIGHT. If the sweep timer fires
// while a previous advert to that peer is still draining, core::Socket::write
// would initiate a second composed write and the two can interleave (see the
// header comment). The realistic window is the ~1-RTT period right after the
// handshake advert on a fresh socket, or any time against a stalled/zero-window
// peer; without this guard the odds are roughly drain_time/sweep_interval per
// handshake (~1% at 100 ms RTT). The consequence is a bad checksum -> canonical
// disconnect -> reconnect with fresh per-peer state: self-healing, no ban, not
// reward-affecting, but a real defect.
//
// 5 s is half the sweep cadence, so in steady state (sweeps 10 s apart) this
// never suppresses anything; it only ever suppresses a sweep that lands right on
// top of the direct handshake advert. Suppressed hashes are NOT lost — nothing
// was committed for them, so the next sweep recomputes and sends them.
inline constexpr int TX_ADVERT_MIN_EMIT_INTERVAL_SECONDS = 5;

// A set of hashes destined for the wire. Used both for the FULL outstanding
// delta (plan_tx_advert) and for the truncated subset a single sweep actually
// emits (run_tx_advert's return value).
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
    // When we last put a message on this peer's socket. Default-constructed
    // (epoch) means "never emitted", which always passes the min-interval guard
    // so a freshly handshaked peer is advertised to immediately. IO-thread-local
    // — it is only ever read and written from the sweep, so it needs no locking.
    std::chrono::steady_clock::time_point m_last_emit{};
};

// Pure diff: current known-tx hash set vs what the peer has already been told.
// `current` may be any ordered/unordered set of uint256 supporting find()/end().
// Does NOT mutate `state`.
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

// Fold an EMITTED plan into the per-peer view. Only ever called with hashes that
// actually reached the socket — committing more than was sent is a permanent
// per-peer desync, because the un-sent remainder would never resurface in a
// later diff.
inline void commit_tx_advert(TxAdvertState& state, const TxAdvertPlan& emitted)
{
    for (const auto& h : emitted.m_have)
        state.m_advertised.insert(h);
    for (const auto& h : emitted.m_losing)
        state.m_advertised.erase(h);
    state.m_initial_sent = true;
}

// Drive one advert sweep for one peer.
//
// Emits AT MOST ONE message (see the write-safety section in the header
// comment): the first `max_per_message` outstanding have_tx hashes if there are
// any, otherwise the first `max_per_message` outstanding losing_tx hashes.
// Additions therefore always precede retractions across sweeps, preserving
// canonical's have-before-losing ordering (p2p.py:264-267). Whatever is left
// over is recomputed from scratch by the next sweep, so nothing is lost and
// nothing is sent twice.
//
// Emits NOTHING if this peer was advertised to less than `min_interval` ago —
// one message per sweep is not one message in flight, and initiating a second
// composed write while the previous one still drains is exactly the interleaving
// hazard. Suppression is free: nothing is committed, so the same delta is simply
// recomputed on the following sweep.
//
// `now` is injected so the KATs can drive the interval deterministically; in
// production callers pass a single steady_clock::now() taken once per sweep.
//
// Returns the subset that was ACTUALLY emitted (and committed).
//
// send_have / send_losing are invoked as f(const std::vector<uint256>&) at most
// once each, and at most one of the two per call. They MUST NOT throw; the state
// is only committed after the sender returns.
template <typename HashSet, typename SendHave, typename SendLosing>
inline TxAdvertPlan run_tx_advert(
    TxAdvertState& state, const HashSet& current,
    SendHave&& send_have, SendLosing&& send_losing,
    std::size_t max_per_message = TX_ADVERT_MAX_HASHES_PER_MESSAGE,
    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now(),
    std::chrono::seconds min_interval =
        std::chrono::seconds(TX_ADVERT_MIN_EMIT_INTERVAL_SECONDS))
{
    // A zero budget can emit nothing, so it must also COMMIT nothing — otherwise
    // the per-peer view would record hashes that never reached the wire and the
    // diff would never resurface them (permanent desync). Fail closed.
    if (max_per_message == 0)
        return {};

    // Min-emit interval: never start a second write to this peer while the
    // previous one may still be draining. A default-constructed m_last_emit
    // means "never emitted" and always passes, so a freshly handshaked peer is
    // advertised to immediately. Nothing is committed on the suppressed path.
    if (state.m_last_emit != std::chrono::steady_clock::time_point{} &&
        now - state.m_last_emit < min_interval)
        return {};

    const TxAdvertPlan outstanding = plan_tx_advert(state, current);
    const bool initial = !state.m_initial_sent;

    // Canonical sends nothing when a change event carries no entries
    // (p2p.py:244 `if added:` / p2p.py:251 `if removed:`). The one exception is
    // the handshake advert (p2p.py:276), which canonical issues unconditionally
    // — including with an empty tx_hashes list — so a peer that has just
    // connected always learns our (possibly empty) view exactly once.
    if (outstanding.empty() && !initial)
        return {};

    TxAdvertPlan emitted;
    if (!outstanding.m_have.empty())
    {
        const auto n = static_cast<std::ptrdiff_t>(
            std::min(max_per_message, outstanding.m_have.size()));
        emitted.m_have.assign(outstanding.m_have.begin(),
                              std::next(outstanding.m_have.begin(), n));
        send_have(emitted.m_have);
    }
    else if (!outstanding.m_losing.empty())
    {
        const auto n = static_cast<std::ptrdiff_t>(
            std::min(max_per_message, outstanding.m_losing.size()));
        emitted.m_losing.assign(outstanding.m_losing.begin(),
                                std::next(outstanding.m_losing.begin(), n));
        send_losing(emitted.m_losing);
    }
    else
    {
        // initial && nothing outstanding: the unconditional p2p.py:276 advert.
        send_have(std::vector<uint256>{});
    }

    commit_tx_advert(state, emitted);
    // Stamp AFTER the send: this is the "a message is on this peer's socket"
    // marker the interval guard above keys on. The unconditional empty
    // handshake advert counts — it is a real write like any other.
    state.m_last_emit = now;
    return emitted;
}

} // namespace core
