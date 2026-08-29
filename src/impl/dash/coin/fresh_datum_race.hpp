// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// PR-2 RACE THE FRESHEST DATUM (dashd-cut coin-P2P stack, task #154 line).
///
/// Header-only pure policy — NO I/O, NO clock, NO coin state, standard library
/// only — exactly like arrival_timing.hpp (PR-0), so it folds into the
/// allowlisted dash test targets and links NOTHING. It answers ONE question and
/// enforces ONE reward-safety invariant.
///
/// THE LEVER. When the embedded arm falls off its template it waits on the
/// SINGLE freshest object — the just-announced tip body, the mnlistdiff for the
/// new fold base, or the qrinfo for a rotating quorum. Today that request goes
/// to ONE carrier (rotate-on-stall, #1329) and the arm waits a whole wall-clock
/// re-ask interval if that carrier is slow. select_race_targets() instead names
/// the K fastest-scored CanServeBlocks peers in DISTINCT netgroups, so the SAME
/// idempotent, self-checked request is issued in parallel and the arm resumes
/// on whichever valid reply lands FIRST. K=1 reproduces today's single carrier
/// EXACTLY. Bulk/historical fetch is untouched — this is the freshest-object
/// path only.
///
/// THE REWARD-SAFETY INVARIANT, encoded in FreshDatumRaceInflight. Racing
/// changes only WHEN and FROM-WHOM a datum arrives, never WHAT is derived:
///
///   * The winner is the FIRST reply that PASSES the identical DIP-4 / merkle /
///     payee / BLS self-check the single-carrier path already runs. `valid` is
///     that check's verdict; this policy never re-implements or weakens it.
///   * The fold/apply is licensed EXACTLY ONCE (Fold), on that first valid
///     reply. Every later copy of the same object — the K-1 slower racers — is
///     a DropDuplicate: claimed and discarded so a past-dated snapshot can
///     never leak to the live tip SML, and the expensive derive never re-runs.
///   * A carrier whose copy FAILS the self-check does NOT fail-close the fold
///     while a sibling is still outstanding (DropKeepRacing); it is dropped and
///     we keep waiting. Only when the LAST outstanding racer has failed does the
///     await go Exhausted — i.e. fail-closed exactly as the single-carrier path
///     does today (K=1: one racer, one failure => Exhausted immediately).
///   * A reply for an object we are not racing is NotArmed — the caller handles
///     it exactly as before this policy existed.
///
/// Worst case is therefore extra connections/traffic on already-verified small
/// objects. Flag default-OFF => the selector returns the single top peer and the
/// inflight tracker is never armed, so an unflagged binary is byte-identical to
/// master.

#include <algorithm>
#include <set>
#include <string>
#include <vector>

namespace dash {
namespace coin {

// ─────────────────────────────────────────────────────────────────────────────
// FLAG + K CONFIG (default-OFF; K default 2, floored at 1)
// ─────────────────────────────────────────────────────────────────────────────
//
// --embedded-fresh-datum-race arms the flag; the K count is a separate config.
// Both live as function-local statics so the header stays dependency-free and a
// KAT can drive them deterministically.

inline bool& fresh_datum_race_flag_ref() { static bool f = false; return f; }
inline bool  fresh_datum_race_enabled()  { return fresh_datum_race_flag_ref(); }
inline void  set_fresh_datum_race_enabled(bool v) { fresh_datum_race_flag_ref() = v; }

inline int& fresh_datum_race_k_ref() { static int k = 2; return k; }
/// The configured fan-out width, floored at 1. K==1 is single-carrier (today).
inline int  fresh_datum_race_k() { const int k = fresh_datum_race_k_ref(); return k < 1 ? 1 : k; }
inline void set_fresh_datum_race_k(int k) { fresh_datum_race_k_ref() = k < 1 ? 1 : k; }

/// The EFFECTIVE fan-out for THIS request: 1 unless the flag is armed, then K.
/// Every caller sizes its race with this, so flag-OFF is single-carrier by
/// construction and there is one place the two knobs combine.
inline int fresh_datum_race_width()
{
    return fresh_datum_race_enabled() ? fresh_datum_race_k() : 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// TARGET SELECTION — the K fastest-scored CanServeBlocks peers, distinct groups
// ─────────────────────────────────────────────────────────────────────────────

/// One candidate carrier, projected from a live PeerSession by the caller. This
/// policy never touches a socket; it ranks the projection.
struct RaceCandidate
{
    std::string key;        ///< the demux key (addr.to_string())
    std::string netgroup;   ///< /16 IPv4 or /32 IPv6 group; empty => key is its own group
    int         score{0};   ///< higher = better/faster (peer scorer or -EWMA)
    bool        can_serve{false};  ///< dashd CanServeBlocks (NODE_NETWORK | LIMITED)
    bool        eligible{false};   ///< handshaked AND not demoted
};

/// Rank candidates and return up to `width` peer KEYS to race the freshest
/// object to:
///   * keep only CanServeBlocks + eligible carriers (the same gate the bulk and
///     stateful selectors apply — racing never asks a peer that cannot serve);
///   * order by score DESC (fastest first), ties broken by key for determinism;
///   * take at most ONE per netgroup (Sybil-resistant fan-out: two sockets in
///     one /16 are one point of failure, not two independent races).
/// width<=1 returns at most one key — today's single-carrier behaviour. An
/// empty result means the caller falls back to its existing single-carrier send
/// (no eligible peer to race), so racing can never REMOVE a request.
inline std::vector<std::string>
select_race_targets(std::vector<RaceCandidate> cands, int width)
{
    if (width < 1) width = 1;

    std::vector<RaceCandidate> pool;
    pool.reserve(cands.size());
    for (auto& c : cands)
        if (c.can_serve && c.eligible) pool.push_back(std::move(c));

    std::stable_sort(pool.begin(), pool.end(),
        [](const RaceCandidate& a, const RaceCandidate& b) {
            if (a.score != b.score) return a.score > b.score;
            return a.key < b.key;   // deterministic tie-break
        });

    std::vector<std::string> out;
    std::set<std::string> groups_used;
    for (auto& c : pool) {
        if (static_cast<int>(out.size()) >= width) break;
        const std::string grp = c.netgroup.empty() ? c.key : c.netgroup;
        if (!groups_used.insert(grp).second) continue;  // group already raced
        out.push_back(c.key);
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// SINGLE-FLIGHT DEDUP / FIRST-VALID-WINS — the reward-safety state machine
// ─────────────────────────────────────────────────────────────────────────────

/// What the caller must do with a reply to a raced object.
enum class RaceReplyAction
{
    NotArmed,        ///< no race for this key — handle exactly as pre-PR-2
    Fold,            ///< first VALID reply — run the self-checked fold ONCE
    DropDuplicate,   ///< a copy arriving after the race was already won — claim & drop
    DropKeepRacing,  ///< this carrier's copy FAILED the self-check, siblings remain — claim & drop, stay pending
    Exhausted        ///< the LAST outstanding racer failed — fail-closed, as today
};

/// Tracks ONE outstanding race for the freshest object, keyed by the object's
/// identity (uint256 block hash in the lane; any equality-comparable, copyable
/// key in a KAT). Not thread-aware: the lane touches it only on its single
/// io_context thread, exactly like every other lane member.
template <class Key>
class FreshDatumRaceInflight
{
public:
    /// Arm a race for `key` with `n` outstanding parallel requests (n>=1). n==1
    /// is single-flight: one valid reply folds, one failure exhausts — today's
    /// behaviour with no racing.
    void arm(const Key& key, int n)
    {
        m_key         = key;
        m_have        = true;
        m_satisfied   = false;
        m_outstanding = n < 1 ? 1 : n;
    }

    /// Forget the race (a fresh begin_fold for a different height, or a reset).
    void clear()
    {
        m_have        = false;
        m_satisfied   = false;
        m_outstanding = 0;
        m_key         = Key{};
    }

    bool have()        const { return m_have; }
    bool satisfied()   const { return m_satisfied; }
    int  outstanding() const { return m_outstanding; }
    const Key& key()   const { return m_key; }

    /// Classify a reply. `valid` is the verdict of the IDENTICAL self-check the
    /// single-carrier path runs — this policy never weakens or re-runs it. See
    /// RaceReplyAction for the contract. A reply whose key does not match the
    /// armed race (or no race is armed) is NotArmed and the caller proceeds as
    /// it did before PR-2.
    RaceReplyAction on_reply(const Key& key, bool valid)
    {
        if (!m_have || !(key == m_key)) return RaceReplyAction::NotArmed;
        if (m_satisfied) return RaceReplyAction::DropDuplicate;

        if (m_outstanding > 0) --m_outstanding;

        if (valid) {
            m_satisfied = true;             // the race is won; later copies dup
            return RaceReplyAction::Fold;   // license the fold EXACTLY once
        }
        // This carrier served an object that failed the self-check.
        if (m_outstanding > 0) return RaceReplyAction::DropKeepRacing;
        return RaceReplyAction::Exhausted;  // last racer failed -> fail-closed
    }

private:
    Key  m_key{};
    bool m_have{false};
    bool m_satisfied{false};
    int  m_outstanding{0};
};

}  // namespace coin
}  // namespace dash
