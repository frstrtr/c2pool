// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// EMBEDDED getmnlistd SLOT TRACKER (dashd-cut coin-P2P stack, task #154 line).
///
/// Header-only pure policy — NO I/O, NO clock of its own, NO coin state,
/// standard library only — exactly like arrival_timing.hpp (PR-0) and
/// fresh_datum_race.hpp (PR-2), so it folds into the allowlisted dash test
/// targets and links NOTHING. It answers TWO questions the wall-clock re-ask
/// ladder answers badly, and it never touches WHAT is derived.
///
/// THE BUG BEING REMOVED. The stateful getmnlistd re-ask today is a SINGLE
/// growing wall-clock interval (the "re-ask after N seconds, then longer"
/// ladder). A slot that lands on a silent carrier is punished by GROWING the
/// wait, so a structurally-incapable or merely-slow peer stretches the whole
/// fold/ondemand-mnlist window. dashd does NOT grow the interval: it re-asks a
/// stalled object on a FIXED per-class cadence (net_processing.cpp:1585-1599
/// GetObjectInterval) and lets EXPIRY — not growth — bound the wait
/// (:1601/:1614). It also refuses answer-rate scoring of peers
/// (:6547-6551/:6552-6607): a peer that has served is preferred, but the
/// preference is BOOLEAN and session-local, never a persistent numeric score.
///
/// THE PORT, in TWO composed structures that share ONE budget K:
///
///   * PARALLELISM is owned by the PR-2 fresh-datum race: K = fresh_datum_race
///     _width() distinct-netgroup slots, first strict-matcher-passing reply
///     wins, siblings cancel, late copies drop. This tracker does NOT re-own
///     parallelism; it consumes the SAME K.
///
///   * TIME is owned HERE. Each of the K slots carries its OWN fixed 10s timer
///     (kSlotIntervalMs). NO backoff. When a slot's 10s lapses with no answer
///     it RETARGETS to the next candidate not currently holding a slot — the
///     old ask is abandoned, a fresh candidate takes the slot, and the set
///     NEVER grows past K. The bound on the whole wait is EXPIRY
///     (kExpiryMs = 10x), whose action is ESCALATE (churn the peer set / signal
///     the lane to re-plan to a fresher target), never "repeat the same ask to
///     the same set" (a no-op).
///
/// CANDIDATE ORDERING is THREE BOOLEAN TIERS, round-robin within each — NOT a
/// numeric answer-rate score (the scoring dashd refuses):
///
///   T1  outbound peers that ANSWERED >=1 getmnlistd THIS SESSION (boolean,
///       reset on disconnect);
///   T2  never-asked-this-session;
///   T3  struck-this-rotation (re-eligible after a FULL rotation).
///
/// All three are SESSION-LOCAL. They never feed connection lifetime, addrman,
/// or any cross-restart persistence — a disconnect erases a peer's tier state
/// entirely.
///
/// THE CAPABILITY FILTER. A candidate is only eligible for a slot if it
/// advertises a protocol version that can SERVE getmnlistd/GETMNLISTDIFF
/// (kServeProtoVersion, DIP-4). NODE_NETWORK proves nothing — the silent
/// carriers ARE NODE_NETWORK — so the filter is on the PROTOCOL VERSION (plus
/// whatever service gate the race already applies), and a 10s slot therefore
/// never lands on a structurally-incapable peer.
///
/// REWARD-SAFETY. This structure decides only WHEN a slot retargets and
/// FROM-WHOM the next ask goes. It never admits a reply (admission stays
/// content-addressed: diff.blockHash == m_snapshot_hash, the strict matcher,
/// untouched — a peer-identity term is NEVER added to admission, that would
/// break the K-race), never applies a list, never publishes, never rewinds a
/// fold. A late or duplicate MNLISTDIFF from a peer genuinely asked this
/// session for this (base,target) draws NO misbehaviour strike. Expiry abandons
/// a pending REQUEST through the lane's EXISTING remember_abandoned() seam;
/// applied folds stay applied.
///
/// FLAG default-OFF => the tracker is never consulted and the existing
/// wall-clock ladder runs verbatim, so an unflagged binary is byte-identical to
/// master.

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace dash {
namespace coin {

// ─────────────────────────────────────────────────────────────────────────────
// FLAG (default-OFF)
// ─────────────────────────────────────────────────────────────────────────────
//
// --embedded-getmnlistd-tracker arms the slot tracker. Lives as a function-local
// static so the header stays dependency-free and a KAT can drive it
// deterministically. OFF => callers read NONE of the machinery below.

inline bool& embedded_getmnlistd_tracker_flag_ref() { static bool f = false; return f; }
inline bool  embedded_getmnlistd_tracker_enabled()  { return embedded_getmnlistd_tracker_flag_ref(); }
inline void  set_embedded_getmnlistd_tracker_enabled(bool v) { embedded_getmnlistd_tracker_flag_ref() = v; }

// ─────────────────────────────────────────────────────────────────────────────
// CAPABILITY FILTER — protocol version that can serve getmnlistd/GETMNLISTDIFF
// ─────────────────────────────────────────────────────────────────────────────
//
// DIP-4 (deterministic masternode lists) introduced GETMNLISTDIFF/MNLISTDIFF at
// Dash Core protocol version 70214 (LLMQS_PROTO_VERSION). A peer advertising an
// older version cannot serve the object no matter what service bits it sets, so
// it must never occupy a 10s slot.
static constexpr uint32_t kGetmnlistdServeProtoVersion = 70214;

/// TRUE iff a peer at this advertised protocol version can serve getmnlistd.
inline bool getmnlistd_capable(uint32_t peer_proto_version)
{
    return peer_proto_version >= kGetmnlistdServeProtoVersion;
}

// ─────────────────────────────────────────────────────────────────────────────
// TIMING CONSTANTS — fixed per-slot interval, expiry at 10x (dashd parity)
// ─────────────────────────────────────────────────────────────────────────────
//
// Per-slot re-ask cadence is FIXED (dashd GetObjectInterval; no growth). Expiry
// — the bound on the whole wait — is 10x the slot interval; its action is
// ESCALATE, never a repeated identical ask.
static constexpr int64_t kGetmnlistdSlotIntervalMs = 10000;    // 10s per slot, FIXED
static constexpr int64_t kGetmnlistdExpiryMs       = 100000;   // 100s = 10x -> ESCALATE

/// The bound on the whole wait is EXPIRY, not interval growth. At expiry the
/// lane must ESCALATE (peer-set churn / re-plan to a fresher target), never
/// repeat the same ask to the same set (a no-op).
enum class GetmnlistdExpiryAction
{
    Wait,       ///< the oldest outstanding ask is younger than expiry — keep racing
    Escalate    ///< expiry reached — churn the peer set / signal the lane to re-plan
};

/// Classify the oldest outstanding ask against the 100s expiry.
inline GetmnlistdExpiryAction
classify_getmnlistd_expiry(int64_t now, int64_t first_asked_at)
{
    return (now - first_asked_at) >= kGetmnlistdExpiryMs
               ? GetmnlistdExpiryAction::Escalate
               : GetmnlistdExpiryAction::Wait;
}

// ─────────────────────────────────────────────────────────────────────────────
// CANDIDATE — projected from a live PeerSession by the caller
// ─────────────────────────────────────────────────────────────────────────────

/// One candidate carrier for a getmnlistd slot. The caller projects this from a
/// live session; the tracker owns the SESSION-LOCAL tier bookkeeping keyed by
/// `key`, so only the immutable facts about the peer live here.
struct GetmnlistdCandidate
{
    std::string key;                ///< the demux key (addr.to_string())
    std::string netgroup;           ///< /16 IPv4 or /32 IPv6 group; empty => key is its own group
    uint32_t    proto_version{0};   ///< advertised Dash Core protocol version
    bool        serve_eligible{false}; ///< the race's own gate (handshaked, CanServeBlocks, not demoted)
};

/// The boolean tier a NON-in-flight, capable, non-struck candidate falls in.
/// Lower ordinal = preferred. Struck peers are excluded from selection until a
/// full rotation, then re-admitted (that is the T3 "re-eligible" transition).
enum class GetmnlistdTier
{
    Answered   = 0,   ///< T1: answered >=1 getmnlistd this session
    NeverAsked = 1,   ///< T2: never asked this session
    Asked      = 2    ///< T3: asked-this-session, not (yet) answered
};

// ─────────────────────────────────────────────────────────────────────────────
// SLOT TRACKER — K slots, each its own 10s timer; 3 boolean tiers, round-robin
// ─────────────────────────────────────────────────────────────────────────────
//
// LOAD-BEARING: the RACE (PR-2) owns PARALLELISM (K distinct-netgroup slots) and
// this tracker owns TIME (each slot's own 10s timer; on lapse RETARGET). They
// share ONE budget K, so the in-flight set never grows past K:
//
//   ASSERT INVARIANT: in_flight() <= K at every instant.
//
// Not thread-aware: the lane/client touches it only on its single io_context
// thread, exactly like every other coin-P2P member.
class GetmnlistdSlotTracker
{
public:
    /// Configure the parallelism budget K (>=1). K == fresh_datum_race_width().
    void configure(int k) { m_k = k < 1 ? 1 : k; }
    int  k() const { return m_k; }

    /// A slot currently occupied by an outstanding ask.
    struct Slot
    {
        std::string key;         ///< the carrier the ask went to
        std::string netgroup;    ///< its netgroup (distinct-netgroup enforcement)
        int64_t     asked_at{0}; ///< m_now() when this slot's ask went out
    };

    int  in_flight() const { return static_cast<int>(m_slots.size()); }
    bool holds(const std::string& key) const
    {
        for (const auto& s : m_slots) if (s.key == key) return true;
        return false;
    }

    /// The oldest outstanding ask's timestamp (for the 100s expiry check). If no
    /// slot is occupied, returns `now` (nothing outstanding => never expired).
    int64_t oldest_asked_at(int64_t now) const
    {
        int64_t o = now;
        bool have = false;
        for (const auto& s : m_slots) {
            if (!have || s.asked_at < o) { o = s.asked_at; have = true; }
        }
        return o;
    }

    /// Session-local disconnect: erase ALL tier state for `key` and free any
    /// slot it holds. This is the ONLY lifetime coupling — a disconnect resets
    /// the T1 "answered" boolean, exactly as the spec requires.
    void on_disconnect(const std::string& key)
    {
        m_answered.erase(key);
        m_asked.erase(key);
        m_struck.erase(key);
        m_last_selected_seq.erase(key);
        free_slot(key);
    }

    /// A getmnlistd reply from `key` was admitted by the strict content-address
    /// matcher (the RACE was won). Mark the carrier T1 (answered), and free the
    /// slot it held. Sibling slots are freed by win_race() below — NOT struck:
    /// they were genuinely asked, so a late/duplicate copy earns NO strike.
    void note_answered(const std::string& key)
    {
        m_answered.insert(key);
        m_asked.insert(key);
        m_struck.erase(key);   // a peer that answered is not "struck this rotation"
        free_slot(key);
    }

    /// The race is WON: free EVERY sibling slot without striking. A sibling that
    /// was asked this session and did not win is neither T1 nor penalised — it
    /// becomes T3 (asked-not-answered) on the next rotation, deprioritised but
    /// not struck. Late copies from these siblings draw NO misbehaviour strike.
    void win_race() { m_slots.clear(); }

    /// Fill empty slots and RETARGET lapsed ones, up to K, from `cands`. Returns
    /// the keys newly assigned a slot NOW (the caller sends getmnlistd to each).
    /// Enforces, in order:
    ///   * a lapsed slot (asked_at + 10s <= now) is STRUCK and freed BEFORE
    ///     refilling — the old ask is abandoned, never re-grown;
    ///   * only CAPABLE (proto >= serve version) + serve-eligible candidates are
    ///     selectable — a 10s slot never lands on a structurally-incapable peer;
    ///   * at most ONE slot per netgroup (the PR-2 Sybil-resistant fan-out);
    ///   * tier order T1 > T2 > T3, round-robin (least-recently-selected) within
    ///     a tier; struck peers are benched until a full rotation, then the whole
    ///     struck set is cleared (re-eligible) and selection retries.
    /// in_flight() is <= K on entry and on exit — the set never grows past K.
    std::vector<std::string> plan(const std::vector<GetmnlistdCandidate>& cands,
                                  int64_t now)
    {
        // (1) STRIKE + free any slot whose 10s timer has lapsed. Retarget, do
        // NOT grow the wait: the old ask is abandoned.
        for (size_t i = 0; i < m_slots.size();) {
            if (now - m_slots[i].asked_at >= kGetmnlistdSlotIntervalMs) {
                m_struck.insert(m_slots[i].key);
                m_slots.erase(m_slots.begin() + i);
            } else {
                ++i;
            }
        }

        std::vector<std::string> sent;
        // netgroups already occupied by a live slot are off-limits.
        std::set<std::string> groups_used;
        for (const auto& s : m_slots)
            groups_used.insert(s.netgroup.empty() ? s.key : s.netgroup);

        // (2) FILL empty slots up to K.
        bool cleared_rotation = false;
        while (in_flight() < m_k) {
            const GetmnlistdCandidate* pick = select_one(cands, groups_used);
            if (!pick) {
                // Nothing selectable. If the ONLY thing blocking us is that every
                // remaining capable candidate is struck, a FULL rotation has
                // elapsed: clear the struck set (T3 re-eligible) and retry ONCE.
                if (!cleared_rotation && !m_struck.empty()
                    && any_capable_but_all_struck(cands, groups_used)) {
                    m_struck.clear();
                    cleared_rotation = true;
                    continue;
                }
                break;   // genuinely no eligible carrier — caller keeps waiting
            }
            const std::string grp = pick->netgroup.empty() ? pick->key : pick->netgroup;
            groups_used.insert(grp);
            m_slots.push_back(Slot{pick->key, grp, now});
            m_asked.insert(pick->key);
            m_last_selected_seq[pick->key] = ++m_seq;
            sent.push_back(pick->key);
        }
        return sent;
    }

    /// The tier a candidate falls in, for tests and diagnostics. Only meaningful
    /// for a capable, non-in-flight, non-struck candidate.
    GetmnlistdTier tier_of(const std::string& key) const
    {
        if (m_answered.count(key)) return GetmnlistdTier::Answered;
        if (!m_asked.count(key))   return GetmnlistdTier::NeverAsked;
        return GetmnlistdTier::Asked;
    }

    bool is_struck(const std::string& key) const { return m_struck.count(key) != 0; }
    bool answered(const std::string& key)  const { return m_answered.count(key) != 0; }
    bool asked(const std::string& key)     const { return m_asked.count(key) != 0; }

    /// Forget all outstanding slots (a fresh begin_fold for a new target). Tier
    /// bookkeeping (answered/asked) survives — it is session-local, not
    /// per-request — but the struck set is per-rotation, so it is cleared too.
    void reset_slots()
    {
        m_slots.clear();
        m_struck.clear();
    }

private:
    void free_slot(const std::string& key)
    {
        for (size_t i = 0; i < m_slots.size(); ++i) {
            if (m_slots[i].key == key) { m_slots.erase(m_slots.begin() + i); return; }
        }
    }

    /// TRUE iff at least one capable, serve-eligible, distinct-netgroup, not-in-
    /// flight candidate exists but EVERY such candidate is struck — i.e. the
    /// rotation is complete and the struck set is the only thing left to try.
    bool any_capable_but_all_struck(const std::vector<GetmnlistdCandidate>& cands,
                                    const std::set<std::string>& groups_used) const
    {
        bool any = false;
        for (const auto& c : cands) {
            if (!selectable_ignoring_struck(c, groups_used)) continue;
            any = true;
            if (!m_struck.count(c.key)) return false;   // a non-struck option exists
        }
        return any;
    }

    /// A candidate is selectable (ignoring the struck bench) iff it is capable,
    /// serve-eligible, not already holding a slot, and its netgroup is free.
    bool selectable_ignoring_struck(const GetmnlistdCandidate& c,
                                    const std::set<std::string>& groups_used) const
    {
        if (!c.serve_eligible) return false;
        if (!getmnlistd_capable(c.proto_version)) return false;
        if (holds(c.key)) return false;
        const std::string grp = c.netgroup.empty() ? c.key : c.netgroup;
        return groups_used.find(grp) == groups_used.end();
    }

    /// Pick the single best candidate: lowest tier, then round-robin
    /// (least-recently-selected) within the tier, then key for determinism.
    /// Struck candidates are excluded (benched until a full rotation).
    const GetmnlistdCandidate* select_one(const std::vector<GetmnlistdCandidate>& cands,
                                          const std::set<std::string>& groups_used) const
    {
        const GetmnlistdCandidate* best = nullptr;
        int      best_tier = 1 << 30;
        int64_t  best_seq  = 0;
        for (const auto& c : cands) {
            if (!selectable_ignoring_struck(c, groups_used)) continue;
            if (m_struck.count(c.key)) continue;   // benched this rotation
            const int t = static_cast<int>(tier_of(c.key));
            int64_t seq = 0;
            auto it = m_last_selected_seq.find(c.key);
            if (it != m_last_selected_seq.end()) seq = it->second;
            const bool better =
                !best
                || t < best_tier
                || (t == best_tier && seq < best_seq)
                || (t == best_tier && seq == best_seq && c.key < best->key);
            if (better) { best = &c; best_tier = t; best_seq = seq; }
        }
        return best;
    }

    int m_k{1};
    std::vector<Slot> m_slots;                       ///< occupied slots (<= K)
    std::set<std::string> m_answered;                ///< T1 (session-local)
    std::set<std::string> m_asked;                   ///< asked-this-session
    std::set<std::string> m_struck;                  ///< struck-this-rotation
    std::map<std::string, int64_t> m_last_selected_seq; ///< round-robin ordinal
    int64_t m_seq{0};
};

}  // namespace coin
}  // namespace dash
