// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// #157 M2 — sharechain-p2p tx-injection RELAY LOGIC (pure, header-only, KAT-able).
//
// This is the transport-side policy that sits IN FRONT of the M1 submit gate
// (NodeCoinState::submit_inject). It answers ONE question per inbound peer
// tx_inject frame: do we (a) route it through submit_inject, and (b) fan it out
// to our other peers? The actual consensus validity — type-0, vin/vout, DoS
// caps, script-armed, BIP68 fail-closed, MoneyRange, dedup, already-confirmed —
// stays entirely inside submit_inject (M1). This layer adds ONLY:
//
//   * FLAG SHORT-CIRCUIT: injection disabled ⇒ ignore, mutate nothing, forward
//     nothing (a peer cannot make a non-participating node do inject work).
//   * PER-PEER DoS GUARD: a sliding-window rate cap + a per-peer txid dedup set,
//     so one peer cannot force repeated (script-checking) submit_inject calls.
//   * NODE-LEVEL SEEN SET: a txid we have already decided on (accepted OR
//     rejected) is not re-validated when a DIFFERENT peer re-sends it — a
//     rejected tx costs a script check, so re-deciding it is the DoS the seen
//     set closes. Bounded (cap + FIFO eviction).
//   * FIRST-SEE FAN-OUT: only a first-see ACCEPT is forwarded (txid-deduped),
//     mirroring p2pool's remember_tx first-see relay. A duplicate, a rate-limit,
//     a rejection, or a disabled node forwards NOTHING.
//
// REWARD-SAFETY: this file touches NO coinbase / subsidy / PPLNS / payee /
// won-block state. It reads a txid, a byte size, and a clock; it calls an
// opaque submit_fn. It cannot move a single duff.
//
// Pure over <deque>/<map>/<set> + core::uint256 + a caller-supplied submit_fn —
// no node.hpp, no mempool, no NodeCoinState include — so the whole verdict path
// is drivable from a rig-free KAT with a stub submit_fn, and separately wired to
// the real submit_inject in the integration KAT.

#include <core/uint256.hpp>

#include <cstdint>
#include <ctime>
#include <deque>
#include <functional>
#include <string>
#include <map>

namespace dash {

// The outcome the M1 gate hands back, reduced to what the relay layer needs.
// (NodeCoinState::submit_inject returns the richer InjectSubmitResult; the
// handler collapses it into this so this header stays decoupled from M1.)
struct InjectSubmitOutcome {
    bool        ok{false};
    std::string cause{"inject-disabled"};
};

// What the handler must do with one inbound tx_inject frame.
struct InjectRelayVerdict {
    enum class Kind {
        Disabled,     // feature OFF — ignored, nothing mutated, nothing forwarded
        Duplicate,    // already seen (this peer, or node-wide) — not re-validated
        RateLimited,  // this peer exceeded its per-window inject budget
        Rejected,     // submit_inject refused it (cause carried)
        Accepted      // submit_inject admitted it
    };
    Kind        kind{Kind::Disabled};
    std::string cause;      // submit_inject's named cause (Rejected/Accepted), or a relay reason
    uint256     txid;
    bool        forward{false};  // fan out to other peers? (first-see ACCEPT only)

    static const char* kind_name(Kind k) {
        switch (k) {
            case Kind::Disabled:    return "disabled";
            case Kind::Duplicate:   return "duplicate";
            case Kind::RateLimited: return "rate-limited";
            case Kind::Rejected:    return "rejected";
            case Kind::Accepted:    return "accepted";
        }
        return "unknown";
    }
};

// Per-peer DoS state (lives on dash::Peer). A sliding time window bounds how many
// injects one peer can push per minute, and a bounded txid set stops a single
// peer re-sending the same tx to cost repeated node-level lookups.
struct PeerInjectGuard {
    // Canonical cap: injections are a rare operator/miner action, not a
    // high-rate advert. 30/min is generous for a human-driven submitter and
    // still bounds a hostile peer to ~1 script-check attempt every 2 s.
    static constexpr std::size_t kMaxInjectsPerPeerPerWindow = 30;
    static constexpr std::time_t kWindowSeconds = 60;
    // Per-peer txid memory cap (FIFO eviction). Bounds the set a peer can grow.
    static constexpr std::size_t kMaxPeerSeen = 4096;

    std::deque<std::time_t> window;   // submit timestamps inside kWindowSeconds
    std::deque<uint256>     seen_order;
    std::map<uint256, char> seen;  // txid -> present (this peer only)

    // Drop timestamps older than the window; return the count still inside it.
    std::size_t prune_window(std::time_t now) {
        while (!window.empty() && window.front() + kWindowSeconds <= now)
            window.pop_front();
        return window.size();
    }

    bool peer_has_seen(const uint256& txid) const {
        return seen.find(txid) != seen.end();
    }

    void remember_peer_seen(const uint256& txid) {
        if (seen.emplace(txid, 1).second) {
            seen_order.push_back(txid);
            if (seen_order.size() > kMaxPeerSeen) {
                seen.erase(seen_order.front());
                seen_order.pop_front();
            }
        }
    }

    void record_window(std::time_t now) { window.push_back(now); }
};

// Node-level seen set: a txid we have ALREADY decided (accepted or rejected) so
// a re-send from a different peer does not pay for another submit_inject. Bounded
// (cap + FIFO). Records the ACCEPT/REJECT outcome so a re-offer can be reported
// as a duplicate without re-validation. IO-thread-confined (same discipline as
// NodeImpl::m_known_txs) — no internal locking.
struct NodeInjectSeen {
    static constexpr std::size_t kMaxNodeSeen = 8192;

    std::deque<uint256>              order;
    std::map<uint256, bool> accepted;  // txid -> was accepted

    bool contains(const uint256& txid) const {
        return accepted.find(txid) != accepted.end();
    }

    void remember(const uint256& txid, bool was_accepted) {
        auto it = accepted.find(txid);
        if (it != accepted.end()) { it->second = was_accepted; return; }
        accepted.emplace(txid, was_accepted);
        order.push_back(txid);
        if (order.size() > kMaxNodeSeen) {
            accepted.erase(order.front());
            order.pop_front();
        }
    }

    std::size_t size() const { return accepted.size(); }
};

// Decide + (via submit_fn) route ONE inbound peer tx_inject. submit_fn is invoked
// AT MOST ONCE, and ONLY when the tx is genuinely new (not disabled, not a per-
// peer or node-wide duplicate, not rate-limited) — so a rejected tx costs exactly
// one script check no matter how many peers replay it.
//
//   enabled     — NodeCoinState::tx_inject_enabled() (flag short-circuit)
//   node_seen   — node-level decided-txid set (IO-thread-confined)
//   peer_guard  — this peer's DoS state
//   txid        — dash_txid(msg.m_tx), self-computed by the caller
//   byte_size   — informational (reserved; DoS byte caps live in submit_inject)
//   now         — one clock reading for the whole decision
//   submit_fn   — () -> InjectSubmitOutcome, wrapping NodeCoinState::submit_inject
template <typename SubmitFn>
InjectRelayVerdict ingest_peer_inject(bool enabled,
                                      NodeInjectSeen& node_seen,
                                      PeerInjectGuard& peer_guard,
                                      const uint256& txid,
                                      std::uint32_t byte_size,
                                      std::time_t now,
                                      SubmitFn&& submit_fn)
{
    (void)byte_size;
    InjectRelayVerdict v;
    v.txid = txid;

    // FLAG SHORT-CIRCUIT: a disabled node is inert — no state mutation, no
    // submit, no forward. (submit_inject would refuse anyway; this is the belt.)
    if (!enabled) {
        v.kind = InjectRelayVerdict::Kind::Disabled;
        v.cause = "inject-disabled";
        v.forward = false;
        return v;
    }

    // Per-peer dedup: this peer already sent this txid — never re-decide.
    if (peer_guard.peer_has_seen(txid)) {
        v.kind = InjectRelayVerdict::Kind::Duplicate;
        v.cause = "peer-duplicate";
        v.forward = false;
        return v;
    }

    // Node-wide dedup: some peer already had this txid decided — do not pay for
    // another submit. Record it against THIS peer too so its own dedup tracks it.
    if (node_seen.contains(txid)) {
        peer_guard.remember_peer_seen(txid);
        v.kind = InjectRelayVerdict::Kind::Duplicate;
        v.cause = "node-duplicate";
        v.forward = false;
        return v;
    }

    // Per-peer sliding-window rate cap. Count BEFORE recording so the Nth+1
    // request in a window is the one refused. No submit, no state beyond noting
    // we saw the peer act (window untouched so a slowed peer recovers).
    if (peer_guard.prune_window(now) >= PeerInjectGuard::kMaxInjectsPerPeerPerWindow) {
        v.kind = InjectRelayVerdict::Kind::RateLimited;
        v.cause = "peer-rate-limited";
        v.forward = false;
        return v;
    }

    // Genuinely new + within budget: charge the window, remember the peer saw it,
    // and route through the M1 gate exactly once.
    peer_guard.record_window(now);
    peer_guard.remember_peer_seen(txid);

    InjectSubmitOutcome out = submit_fn();
    node_seen.remember(txid, out.ok);

    if (out.ok) {
        v.kind = InjectRelayVerdict::Kind::Accepted;
        v.cause = out.cause;   // "ok"
        v.forward = true;      // first-see accept — fan out
    } else {
        v.kind = InjectRelayVerdict::Kind::Rejected;
        v.cause = out.cause;   // named refusal from submit_inject
        v.forward = false;
    }
    return v;
}

} // namespace dash
