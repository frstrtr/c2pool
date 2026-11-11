// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// GOVSYNC-COMPLETENESS DETERMINATION (E-SUPERBLOCK R5). The reward-critical
/// question the superblock serve path asks before it trusts the daemonless
/// GovernanceStore's winning trigger: has our governance view provably CAUGHT
/// UP to the network's, or are we still mid-sync?
///
/// The dangerous failure mode is a PARTIAL view: a store missing the higher-yes
/// competing trigger (or its votes) yields a CONFIDENT wrong winner — dashd
/// validates the block against ITS best trigger and rejects it (bad-cb-payee).
/// A per-trigger funding threshold cannot see what it never received, so
/// trigger-confidence alone is NOT sufficient to serve; the view must first be
/// COMPLETE.
///
/// REUSE — this models dashcore's own governance-sync-status logic, CMasternodeSync
/// (masternode/sync.cpp): the MASTERNODE_SYNC_GOVERNANCE asset requests objects
/// + votes from peers and declares governance SYNCED (IsSynced(), after which
/// dashd trusts its governance view for superblock validation) when
///   (a) it has requested the governance set from enough peers, AND
///   (b) no NEW governance object/vote has arrived for MASTERNODE_SYNC_TIMEOUT
///       seconds (the stream has quiesced — nTimeLastBumped stopped advancing).
/// There is no explicit "done" message on the wire; completeness IS the
/// peer-coverage + time-quiescence determination. We reproduce exactly that:
/// peer coverage (redundancy against a single withholding/partial peer) plus a
/// quiescence window since the last arrival, plus a settle floor since the
/// first request so an empty store cannot be declared "complete" before objects
/// have had time to arrive.
///
/// FAIL-CLOSED BY CONSTRUCTION: default state (no request issued) is INCOMPLETE.
/// Every uncertain / under-covered / not-yet-quiesced view returns false, so the
/// NodeCoinState superblock guard routes to the reward-safe dashd fallback.
/// This is a NECESSARY (not sufficient) gate: the serve path additionally
/// requires a tri-state verdict that is not Unknown (superblock.hpp: a funded
/// winner, or provable absence — no outstanding/unverified/ambiguous trigger)
/// and the R6/C5 desync latch to be clear — defence in depth.

#include <cstdint>
#include <set>
#include <string>

namespace dash {
namespace coin {

/// dashcore masternode/sync.h MASTERNODE_SYNC_TIMEOUT_SECONDS (the no-new-data
/// window after which a sync asset is considered complete). Used as the default
/// quiescence window.
inline constexpr int64_t DASH_GOVSYNC_QUIESCE_SECS_DEFAULT = 30;

/// Settle floor since the first govsync request before completeness can be
/// asserted at all — guards against declaring an empty store "complete" in the
/// instant between issuing the request and the first objects arriving. dashcore
/// gets this implicitly from its multi-tick asset progression; we make it
/// explicit.
inline constexpr int64_t DASH_GOVSYNC_SETTLE_SECS_DEFAULT = 60;

/// Peer-coverage floor: the number of DISTINCT peers we must have requested the
/// governance set from before a quiesced view counts as complete. Redundancy is
/// the only defence against a single peer that withholds the winning trigger
/// (or its votes) — a one-peer "quiesced" view is exactly the partial-view
/// hazard. dashcore syncs governance from multiple peers for the same reason.
/// DEFAULT 2 (fail-closed leaning): a single-peer deployment can NEVER assert
/// completeness, so it stays on the reward-safe dashd fallback. The multi-peer
/// govsync leg that primes >= 2 distinct peers is the coin-P2P verack handler:
/// per session it asks THAT peer for the full object set exactly once per expiry
/// window (CoinClient::send_govsync_prime_to), so both the primary and every
/// witness peer are covered; each real prime reports its peer_key (via
/// set_on_govsync_primed) into note_govsync_requested here.
inline constexpr size_t DASH_GOVSYNC_MIN_PEERS_DEFAULT = 2;

/// Tracks daemonless governance-sync progress and answers is_complete(now).
/// Pure/clock-injected (the caller passes wall-seconds), so it is deterministic
/// under test. Not thread-safe by itself — the maintainer owns the single
/// instance and drives it from the same reception path as the GovernanceStore.
class GovSyncStatus {
public:
    /// Tunables (main_dash wires these from chain/deployment; the KAT drives
    /// them directly). All three must be crossed for completeness.
    void set_params(size_t min_peers, int64_t settle_secs, int64_t quiesce_secs) {
        m_min_peers    = min_peers;
        m_settle_secs  = settle_secs;
        m_quiesce_secs = quiesce_secs;
    }

    /// A govsync (MNGOVERNANCESYNC) request was issued to `peer_key` at `now`.
    /// Records peer coverage and (re-)arms quiescence: a fresh request means we
    /// expect a stream, so the view is not yet quiesced. The first request also
    /// starts the settle clock.
    void note_govsync_requested(const std::string& peer_key, int64_t now) {
        if (m_first_request_time == 0) m_first_request_time = now;
        m_requested_peers.insert(peer_key);
        // A (re-)prime re-opens this peer's proof: coverage counts only once
        // the peer has ANSWERED this request (note_govsync_answered).
        m_answered_peers.erase(peer_key);
        // A new request re-arms the quiescence window (dashcore bumps
        // nTimeLastBumped when it (re)asks a peer): we must not call a view
        // "quiesced" the instant after asking a fresh peer.
        if (now > m_last_activity_time) m_last_activity_time = now;
    }

    /// `peer_key` ANSWERED our govsync: it sent SYNCSTATUSCOUNT(GOVOBJ, n),
    /// announced >= n objects on this connection and every one of them has
    /// been received (the coin-P2P client's coverage proof — CoinClient
    /// GovPeerSync). Only answered peers count toward min_peers: a pruned,
    /// -disablegovernance or not-yet-synced dashd never answers
    /// (net_governance.cpp:86-91), so a request alone proves nothing and an
    /// empty store behind silent peers must never read as complete.
    void note_govsync_answered(const std::string& peer_key, int64_t now) {
        m_answered_peers.insert(peer_key);
        if (now > m_last_activity_time) m_last_activity_time = now;
    }
    /// The peer's proof lapsed (disconnected, re-primed, a newly announced
    /// object not yet received).
    void note_govsync_unanswered(const std::string& peer_key) {
        m_answered_peers.erase(peer_key);
    }

    /// A governance OBJECT (govobj) arrived at `now` — the stream is still
    /// delivering, so re-arm quiescence. Stamped on ANY object arrival (trigger,
    /// proposal, or malformed), because activity of any kind proves the peer is
    /// still streaming its set (matching dashcore's per-message bump).
    void note_object_arrival(int64_t now) {
        ++m_objects;
        if (now > m_last_activity_time) m_last_activity_time = now;
    }

    /// A governance VOTE (govobjvote) arrived at `now` — re-arm quiescence.
    void note_vote_arrival(int64_t now) {
        ++m_votes;
        if (now > m_last_activity_time) m_last_activity_time = now;
    }

    /// Wipe sync progress (store reset / reorg / desync clear). Forces the view
    /// back to INCOMPLETE until a fresh govsync round re-covers the peers and
    /// re-quiesces — a re-proof obligation, never trust a torn view.
    void reset() {
        m_requested_peers.clear();
        m_answered_peers.clear();
        m_first_request_time = 0;
        m_last_activity_time = 0;
        m_objects = 0;
        m_votes = 0;
    }

    /// The completeness determination. TRUE only when ALL hold:
    ///   1. at least one govsync was requested (m_first_request_time set), AND
    ///   2. >= min_peers DISTINCT peers ANSWERED it (note_govsync_answered —
    ///      requested-but-silent peers do not count), AND
    ///   3. the settle floor has elapsed since the first request, AND
    ///   4. no new object/vote has arrived for >= quiesce window (quiesced).
    /// Anything else (default, mid-sync, under-covered, not-yet-quiesced) is
    /// FALSE => the superblock arm fails closed to dashd.
    ///
    /// NOTE it deliberately does NOT require objects>0: a genuinely unfunded
    /// cycle has no trigger at all (testnet live: `gobject count` triggers 0),
    /// and that complete-but-empty view is EXACTLY what lets a superblock
    /// height be served as NotTriggered (superblock.hpp resolve_superblock_
    /// payments: R5 complete AND strict absence). This predicate cannot tell
    /// "no trigger this cycle" from "peer withheld it" — the peer-coverage
    /// floor (>= DASH_GOVSYNC_MIN_PEERS_DEFAULT distinct peers) is what
    /// defends the latter, which is why it is never lowered by default.
    bool is_complete(int64_t now) const {
        if (m_first_request_time == 0) return false;               // never asked
        if (m_answered_peers.size() < m_min_peers) return false;   // under-covered
        if (now - m_first_request_time < m_settle_secs) return false;   // not settled
        if (now - m_last_activity_time < m_quiesce_secs) return false;  // not quiesced
        return true;
    }

    // ── observability (logs / tests) ────────────────────────────────────────
    size_t   requested_peer_count() const { return m_requested_peers.size(); }
    size_t   answered_peer_count() const { return m_answered_peers.size(); }
    uint64_t object_count() const { return m_objects; }
    uint64_t vote_count() const { return m_votes; }
    int64_t  first_request_time() const { return m_first_request_time; }
    int64_t  last_activity_time() const { return m_last_activity_time; }

private:
    std::set<std::string> m_requested_peers;
    std::set<std::string> m_answered_peers;
    int64_t m_first_request_time{0};
    int64_t m_last_activity_time{0};
    uint64_t m_objects{0};
    uint64_t m_votes{0};
    size_t  m_min_peers{DASH_GOVSYNC_MIN_PEERS_DEFAULT};
    int64_t m_settle_secs{DASH_GOVSYNC_SETTLE_SECS_DEFAULT};
    int64_t m_quiesce_secs{DASH_GOVSYNC_QUIESCE_SECS_DEFAULT};
};

} // namespace coin
} // namespace dash
