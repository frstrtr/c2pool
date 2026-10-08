// SPDX-License-Identifier: AGPL-3.0-or-later
//
// LTC peer misbehavior scoring for INVALID-PROOF-OF-WORK shares (issue #1601).
//
// THE GAP: a share whose scrypt hash does not meet its own claimed target
// ("share PoW hash does not meet target", share_check.hpp) is dropped and freed
// on the verify pool, but the peer that sent it pays no cost — it can stream
// junk that pins the ingest budget and wastes scrypt cycles indefinitely.
//
// WHY THIS IS DELIBERATELY CONSERVATIVE: c2pool runs a PUBLIC pool. A false
// disconnect drops an honest miner's connection and loses its hashrate (=
// shares/payout). So this scorer:
//
//   * counts ONLY a genuine CRYPTOGRAPHIC PoW failure — a share hash that does
//     not meet the share's own claimed target. The caller wires it to the
//     single share_check.hpp throw site for that condition (SharePoWTargetMiss),
//     NOT to the many honest reasons a share is dropped later: stale/old,
//     duplicate, orphan/unknown-parent, or valid-but-losing. Those never reach
//     this scorer, so a race-condition loser is never penalised.
//   * NEVER hard-bans on the first (or a handful of) offence. It accumulates a
//     decaying score and acts only past a HIGH threshold (BAN_THRESHOLD).
//   * decays the score over time (HALFLIFE_SECONDS), so a peer that emitted a
//     burst of bad shares long ago, then behaved, is not punished for ancient
//     history — only a SUSTAINED flood reaches the threshold.
//
// All three tunables are named, documented constants so the ban behaviour is
// easy to audit and adjust. The score is a pure function of the (peer, time)
// note stream, so it is unit-tested deterministically by injecting `now_s`.
//
// REUSE NOTE (#1601 asked to reuse an existing scorer first): c2pool's p2p
// layer (pool::SharechainNode) has a ban LIST + whitelist + is_banned() and an
// existing auto-ban path (NodeImpl think(): result.bad_peer_addresses ->
// m_ban_list), but NO misbehavior SCORE with decay anywhere — the auto-ban path
// is an immediate hard ban keyed off think()'s unverifiable-share result, not a
// windowed counter. This class adds only the missing scoring layer; when a peer
// crosses the threshold the caller reuses the EXISTING m_ban_list + m_ban_duration
// + connection-close machinery to actually disconnect it. No second ban store.
#pragma once

#include <cmath>
#include <cstddef>
#include <map>

namespace ltc
{

/// Decaying per-peer misbehavior score for invalid-PoW shares.
///
/// Keyed on any comparable peer identity (NodeImpl uses NetService). Not
/// thread-safe: NodeImpl touches it only on the io thread (the verify-pool
/// worker that detects the failure posts note_invalid_pow_share() back to the
/// io thread), the same discipline m_ban_list already follows.
template <class Key>
class PeerMisbehaviorScorer
{
public:
    // ── Tunable, documented policy constants (#1601) ─────────────────────
    // One genuine invalid-PoW share adds this much to the peer's score.
    static constexpr double SCORE_PER_INVALID_POW = 1.0;
    // The peer is disconnected/banned only once its DECAYED score reaches this.
    // 100 => a peer must deliver ~100 cryptographically-invalid shares within
    // the decay window before ANY action. Honest peers on the p2p share path do
    // not produce PoW-invalid shares at all (their shares meet the share target;
    // sub-target stratum pseudoshares never cross the wire), so this threshold
    // is far above anything an honest peer can reach, yet trivially reached by a
    // deliberate junk flood.
    static constexpr double BAN_THRESHOLD = 100.0;
    // The score halves every this-many seconds. A slow trickle of invalid
    // shares decays away faster than it accumulates and never bans; only a
    // sustained flood outruns the decay and crosses the threshold.
    static constexpr double HALFLIFE_SECONDS = 600.0; // 10 minutes

    /// Record ONE genuine invalid-PoW share from `peer` observed at wall time
    /// `now_s` (monotonic seconds). Applies time-decay to the peer's prior
    /// score, adds SCORE_PER_INVALID_POW, and returns true exactly when the
    /// resulting decayed score reaches BAN_THRESHOLD — at which point the caller
    /// should ban/disconnect the peer and call clear(peer).
    bool note_invalid_pow(const Key& peer, double now_s)
    {
        auto& e = m_scores[peer];
        e.score = decayed(e, now_s) + SCORE_PER_INVALID_POW;
        e.last_s = now_s;
        return e.score >= BAN_THRESHOLD;
    }

    /// Current decayed score for `peer` at `now_s` (0 if untracked). Read-only:
    /// does not advance last_s. For telemetry and tests.
    double score(const Key& peer, double now_s) const
    {
        auto it = m_scores.find(peer);
        if (it == m_scores.end()) return 0.0;
        return decayed(it->second, now_s);
    }

    /// Forget a peer entirely (call after banning, or on disconnect).
    void clear(const Key& peer) { m_scores.erase(peer); }

    /// Drop entries that have decayed below `floor` at `now_s`, so the map
    /// cannot grow without bound as transient offenders age out.
    void prune(double now_s, double floor = 0.01)
    {
        for (auto it = m_scores.begin(); it != m_scores.end(); )
        {
            if (decayed(it->second, now_s) < floor) it = m_scores.erase(it);
            else ++it;
        }
    }

    std::size_t tracked_peers() const { return m_scores.size(); }

private:
    struct Entry { double score{0.0}; double last_s{0.0}; };

    static double decayed(const Entry& e, double now_s)
    {
        const double dt = now_s - e.last_s;
        if (dt <= 0.0) return e.score;          // out-of-order/first note: no decay
        return e.score * std::exp2(-dt / HALFLIFE_SECONDS);
    }

    std::map<Key, Entry> m_scores;
};

} // namespace ltc
