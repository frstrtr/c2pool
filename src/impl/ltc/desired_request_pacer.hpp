#pragma once

// desired_request_pacer.hpp — pure, per-hash futility backoff for the desired
// parent-share request drain (node.cpp drain_pending_desired). Extracted into a
// header so the backoff policy can be exercised by a KAT without a live node.
//
// WHY. run_think's IO phase recomputes result.desired authoritatively every
// cycle and hands it to the budgeted drain. On a large persisted sharechain that
// set is huge, and when the shares it names are not obtainable the replies come
// back EMPTY — so the set is refilled unchanged next think() and the drain runs
// at full rate forever. Measured on the public LTC node (chain=17950) after the
// #1556 cutover: 6146 requests over 210s (~29/s) for 5137 DISTINCT hashes,
// answered ~1:1 by "[Pool] Share request empty for", with the io thread pinned
// at 98% CPU (ps -L: one thread in R, the other 13 sleeping) and :8080
// unreachable for 12.7 minutes without a single 200. The process never aborts —
// #1556 removed the watchdog kill — it just burns a core and stops serving.
//
// This is NOT the per-(hash,peer) failover memory in share_fetch_failover.hpp.
// That one answers "WHICH peer should I ask for this hash", and suppresses a
// hash only once EVERY connected peer has failed it, for a flat 90s TTL. It
// cannot damp a desired set whose members are each failing their FIRST attempt
// across a rotating peer set. This one answers "should I ask for this hash AT
// ALL right now", with an exponential, per-hash backoff.
//
// EXPIRY IS PART OF THE CONTRACT, not an optimization. A hash nobody can serve
// now may be servable later, when a peer carrying that history connects. The
// backoff therefore has a ceiling (never an indefinite ban) and entries are
// dropped outright once they age well past eligibility, so the hash returns to
// the normal request path. A permanent denylist here would convert a transient
// gap into a permanent chain hole.
//
// Pure / templated: no c2pool types, no consensus surface, no reward surface.
// HashT is any ordered, copyable key type (production: uint256).

#include <cstddef>
#include <map>

namespace ltc {

template <typename HashT>
class DesiredRequestPacer {
public:
    // First empty reply costs kBaseBackoff; each subsequent one doubles, up to
    // kMaxBackoff. 5s is above the observed reply latency (so a hash is never
    // backed off while its own request is still in flight); the 300s ceiling is
    // ~2 SHARE_PERIODs, short enough that a newly-connected peer with the
    // history is used promptly.
    static constexpr double kBaseBackoff = 5.0;
    static constexpr double kMaxBackoff = 300.0;

    // Entries are forgotten once they have been eligible again for this long
    // without being re-requested — bounds memory and guarantees no permanent ban.
    static constexpr double kForgetAfter = 2.0 * kMaxBackoff;

    explicit DesiredRequestPacer(double base = kBaseBackoff,
                                 double cap = kMaxBackoff,
                                 double forget_after = kForgetAfter)
        : m_base(base), m_cap(cap), m_forget_after(forget_after) {}

    double base() const { return m_base; }
    double cap() const { return m_cap; }

    // May we issue a request for `hash` right now? Unknown hashes are always
    // eligible — the pacer only ever damps hashes that have actually failed.
    bool eligible(const HashT& hash, double now) const
    {
        auto it = m_state.find(hash);
        return it == m_state.end() || now >= it->second.next_eligible;
    }

    // An empty reply came back for `hash`: double its backoff (clamped to cap).
    void record_empty(const HashT& hash, double now)
    {
        auto& s = m_state[hash];
        double delay = m_base;
        for (int i = 0; i < s.attempts && delay < m_cap; ++i)
            delay *= 2.0;
        if (delay > m_cap)
            delay = m_cap;
        ++s.attempts;
        s.next_eligible = now + delay;
    }

    // The hash was served — it is healthy again, forget it entirely so a later
    // failure starts from the base delay rather than a stale exponent.
    void record_success(const HashT& hash)
    {
        m_state.erase(hash);
    }

    // Drop entries that have been eligible again for longer than kForgetAfter.
    // Called once per think() cycle alongside the failover-memory prune.
    void prune(double now)
    {
        for (auto it = m_state.begin(); it != m_state.end();) {
            if (now - it->second.next_eligible > m_forget_after)
                it = m_state.erase(it);
            else
                ++it;
        }
    }

    std::size_t size() const { return m_state.size(); }

    // Backoff currently applied to `hash` (0 if none) — diagnostics and KAT.
    int attempts(const HashT& hash) const
    {
        auto it = m_state.find(hash);
        return it == m_state.end() ? 0 : it->second.attempts;
    }

private:
    struct State {
        int attempts{0};
        double next_eligible{0.0};
    };

    std::map<HashT, State> m_state;
    double m_base;
    double m_cap;
    double m_forget_after;
};

}  // namespace ltc
