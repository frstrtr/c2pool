// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef C2POOL_IMPL_XMR_XMR_CARRIER_DOS_BUDGET_HPP
#define C2POOL_IMPL_XMR_XMR_CARRIER_DOS_BUDGET_HPP
//
// xmr_carrier_dos_budget.hpp — the W3 (relay-layer, NON-consensus) DoS budget
// for a keyed_heavy (RandomX) lane: a per-peer token bucket that meters RandomX
// evaluations, a global backstop bucket, and a ban-on-invalid-PoW policy.
//
// THE THREAT (v37-monero-randomx-lane-scoping.md §1.3 item 3 / §1.4 item 3, and
// the annex P1 §2.4):
//   Family-B receipt verification runs RandomX LAST (xmr_admission.hpp), so a
//   carrier reaches the ~10-15 ms light-mode RandomX hash only after passing the
//   microsecond dedup/expiry/structural/R-1 checks. Those cheap checks are
//   satisfiable by a STRUCTURALLY valid carrier whose PoW simply does not meet
//   the opened T_origin — trivial and free for an attacker to mint (any nonce
//   that misses target), yet each one costs the verifier one full RandomX hash.
//   At ~15 ms/hash one light-mode core does ~66.7 hashes/s, so
//
//        1 / 0.015 s  =  ~66.7   =>  ~65 bogus carriers/s SATURATE one core.
//
//   That is the number this file exists to cap. The mitigation named in the
//   scoping note is exactly p2pool's: a per-peer token bucket on UNVERIFIED
//   carriers + a ban on invalid PoW (SChernykh/p2pool SideChain::add_external_block
//   bans on bad PoW, and re-hashes a failing share in forced light mode to flag
//   "UNSTABLE HARDWARE DETECTED" before trusting the failure).
//
// WHERE THE TOKEN IS SPENT (the load-bearing seam):
//   The bucket meters RANDOMX EVALUATIONS, not messages. A token is taken at the
//   moment a carrier is about to be handed to the RandomX step (admission stage 5),
//   i.e. only AFTER stages 1-4 passed. The relay wires this by having the
//   admission `seed_for_bin` hook consult grant_randomx() (see
//   xmr_carrier_relay.hpp): no token => the hook returns false => admission
//   reports stage-5 reject with spent_randomx == FALSE (a "not verifiable now"
//   defer, NO penalty), and rx_check is never called. rx_check therefore runs
//   ONLY on a granted token, so its outcome is unambiguous:
//       * PoW meets target  -> Accept, spent_randomx == true  -> refund the token
//                              (honest work; it is already PoW-rate-limited).
//       * PoW below target  -> stage-5 reject, spent_randomx == true -> the token
//                              stays spent AND the peer is (optionally re-verified
//                              then) BANNED: an unmet target on a completed hash
//                              is incontrovertible proof of a bogus carrier.
//   With refund-on-valid (default), the per-peer bucket depletes ONLY on wasted
//   (invalid) RandomX. A flooder is throttled to `refill` wasted hashes/s until
//   the ban lands; an honest peer never depletes it.
//
// SIZING (the defaults; all are per-instance knobs, operator-ratified at wiring):
//   Honest per-peer demand is tiny. Carriers are difficulty-gated at the ~10-s
//   share cadence and each carrier drives <= 1 + R_MAX (= 3 at R_MAX_XMR=2)
//   RandomX hashes; dedup collapses the duplicate relays of the same carrier
//   before any hash. So a single honest peer forces well under 1 wasted hash/s.
//   Defaults: refill = 1 token/s (=> a throttled flooder costs <= ~1.5% of one
//   core), capacity = 20 (a short burst). Backstop: a GLOBAL grant bucket sized
//   to a target aggregate core fraction, because N per-peer buckets still sum to
//   N * refill * 15 ms; at refill=1 that is one core at ~66 concurrent hostile
//   peers, so the global bucket (default refill 16/s, capacity 256 => <= ~25% of
//   one core sustained) is the real aggregate ceiling and the per-peer bucket is
//   the fairness layer that stops any single peer eating it.
//
// ISOLATION: header-only, per-instance policy objects + pure predicates, in the
// spirit of src/impl/dash/min_protocol_gate.hpp. NO consensus state, NO wire
// bytes, NO RandomX dependency. The LIVE call site (relay ingress, peer
// disconnect/ban-list) is xmr_carrier_relay.hpp + the reception slice, out of
// scope here. A monotone injected clock is the only environment coupling.

#include <cstdint>
#include <string>
#include <unordered_map>

namespace c2pool {
namespace xmr {

using u32 = std::uint32_t;
using u64 = std::uint64_t;

// ---------------------------------------------------------------------------
// Monotone time. Injected so the buckets are unit-testable and the policy holds
// no wall-clock dependency. Nanoseconds since an arbitrary steady epoch.
// ---------------------------------------------------------------------------
using nanos_t = std::int64_t;

// ---------------------------------------------------------------------------
// TokenBucket — classic leaky/token bucket in floating tokens, refilled
// continuously at `refill` tokens/second up to `capacity`. One token == one
// permitted RandomX evaluation. try_take() is the grant; refund() returns a
// token (bounded by capacity) after a hash proved valid.
// ---------------------------------------------------------------------------
struct TokenBucket {
    double  capacity = 20.0;   // burst
    double  refill   = 1.0;    // tokens/second
    double  tokens   = 20.0;   // current fill (starts full)
    nanos_t last     = 0;      // last refill instant (ns)

    TokenBucket() = default;
    TokenBucket(double cap, double rate) : capacity(cap), refill(rate), tokens(cap) {}

    void advance(nanos_t now) {
        if (last == 0) { last = now; return; }
        if (now <= last) return;                        // monotone; ignore regressions
        const double dt = double(now - last) * 1e-9;    // ns -> s
        tokens = tokens + dt * refill;
        if (tokens > capacity) tokens = capacity;
        last = now;
    }
    // Take one token if available. Returns true iff granted.
    bool try_take(nanos_t now) {
        advance(now);
        if (tokens >= 1.0) { tokens -= 1.0; return true; }
        return false;
    }
    // Return a previously-taken token (a hash that turned out valid), capped.
    void refund(nanos_t now) {
        advance(now);
        tokens += 1.0;
        if (tokens > capacity) tokens = capacity;
    }
    double level(nanos_t now) { advance(now); return tokens; }
};

// ---------------------------------------------------------------------------
// Per-peer accounting: its RandomX-grant bucket plus a coarse misbehavior score.
// The score counts CONFIRMED invalid-PoW carriers (hard) and, at a far higher
// tolerance, cheap structural/dedup faults (soft). Banning is score-driven so
// the operator can pick "ban on first confirmed invalid PoW" (p2pool default:
// hard_penalty = ban_threshold) or a tolerance for hardware flaps.
// ---------------------------------------------------------------------------
struct PeerState {
    TokenBucket rx;                 // RandomX-evaluation budget for this peer
    u32         score       = 0;    // misbehavior score
    u64         granted      = 0;   // RandomX evaluations granted (diagnostics)
    u64         invalid_pow  = 0;   // confirmed invalid-PoW carriers (diagnostics)
    u64         structural   = 0;   // cheap stage 1-4 rejects (diagnostics)
    u64         deferred     = 0;   // grants denied by budget / seed not resident
    bool        banned       = false;
};

// ---------------------------------------------------------------------------
// Policy constants (per-instance knobs).
// ---------------------------------------------------------------------------
struct DosPolicy {
    // per-peer RandomX bucket
    double per_peer_capacity = 20.0;   // burst of unverified carriers
    double per_peer_refill   = 1.0;    // ~1 wasted hash/s => ~1.5% core when throttled

    // global backstop bucket (aggregate RandomX-grant ceiling across all peers)
    double global_capacity   = 256.0;
    double global_refill     = 16.0;   // ~16 hashes/s => ~24% of one light core

    // ban scoring
    u32  score_invalid_pow   = 100;    // per CONFIRMED invalid-PoW carrier
    u32  score_structural    = 1;      // per cheap stage 1-4 reject (soft)
    u32  ban_threshold       = 100;    // default: one confirmed invalid PoW bans
                                       // (p2pool parity). Raise for hardware-flap
                                       // tolerance when confirm_invalid re-verify
                                       // is enabled.
    bool refund_on_valid     = true;   // meter only WASTED randomx (recommended)
};

// The decision the relay acts on for one carrier, produced by this policy.
enum class Action : std::uint8_t {
    Grant,     // a RandomX evaluation is authorized (token taken) — run stage 5
    Defer,     // no budget / global backstop hit — drop or queue; NO penalty
    Ban,       // peer is (now) banned — disconnect + add to ban list
    Drop,      // cheap reject already; peer kept (score bumped) — just drop
};

// ---------------------------------------------------------------------------
// CarrierDosBudget — the per-node policy object. One instance per pool node
// (per-coin binary), holding the global bucket and the per-peer table. Not
// thread-safe by itself; the relay owns it on the single p2p-reactor thread
// (c2pool runs one pool node per process), exactly like p2p_stats().
// ---------------------------------------------------------------------------
class CarrierDosBudget {
public:
    explicit CarrierDosBudget(DosPolicy p = {})
        : policy_(p), global_(p.global_capacity, p.global_refill) {}

    // (1) GRANT GATE — called at admission stage 5 entry (seed resolved, resident),
    // via the relay's seed_for_bin hook. Takes one token from BOTH the per-peer
    // and the global bucket. Returns true iff a RandomX evaluation is authorized.
    // On denial by either bucket the carrier is DEFERRED (no penalty): a
    // budget-starved carrier is not proven hostile.
    bool grant_randomx(u32 peer_id, nanos_t now) {
        PeerState& ps = peer(peer_id);
        if (ps.banned) return false;
        // Global first so a single peer can't drain the aggregate under the
        // per-peer allowance; refund the global take if the per-peer take fails.
        if (!global_.try_take(now)) { ++ps.deferred; return false; }
        if (!ps.rx.try_take(now))   { global_.refund(now); ++ps.deferred; return false; }
        ++ps.granted;
        return true;
    }

    // (2a) A granted evaluation proved the PoW VALID (Accept). Refund the tokens
    // if policy says meter-only-wasted (default). Honest, PoW-rate-limited work.
    void on_valid_pow(u32 peer_id, nanos_t now) {
        if (!policy_.refund_on_valid) return;
        PeerState& ps = peer(peer_id);
        ps.rx.refund(now);
        global_.refund(now);
    }

    // (2b) A granted evaluation proved the PoW INVALID (stage-5 reject,
    // spent_randomx == true). Tokens stay spent. Bump the hard score and ban if
    // it crosses the threshold. `confirmed` must be true only after any
    // UNSTABLE-HARDWARE re-verify already agreed the PoW is bad (see
    // confirm_invalid() below); a single unconfirmed local miss must NOT ban.
    Action on_invalid_pow(u32 peer_id, bool confirmed) {
        PeerState& ps = peer(peer_id);
        ++ps.invalid_pow;
        if (!confirmed) return Action::Drop;              // hardware flap suspected
        ps.score += policy_.score_invalid_pow;
        if (ps.score >= policy_.ban_threshold) { ps.banned = true; return Action::Ban; }
        return Action::Drop;
    }

    // (3) A cheap stage 1-4 reject (bad structure / expired / dedup / bad frame).
    // Costs ~us; bump the soft score only. A structural flooder is bounded by the
    // coarse message-rate limit, not by banning honest reorg-races, so this
    // reaches the ban threshold only under sustained garbage.
    Action on_cheap_reject(u32 peer_id) {
        PeerState& ps = peer(peer_id);
        ++ps.structural;
        ps.score += policy_.score_structural;
        if (ps.score >= policy_.ban_threshold) { ps.banned = true; return Action::Ban; }
        return Action::Drop;
    }

    bool banned(u32 peer_id) { return peer(peer_id).banned; }
    void forget(u32 peer_id) { peers_.erase(peer_id); }   // on peer disconnect

    // diagnostics / tests
    const PeerState& state(u32 peer_id) { return peer(peer_id); }
    double global_level(nanos_t now)    { return global_.level(now); }
    const DosPolicy& policy() const     { return policy_; }

private:
    PeerState& peer(u32 id) {
        auto it = peers_.find(id);
        if (it != peers_.end()) return it->second;
        PeerState ps;
        ps.rx = TokenBucket(policy_.per_peer_capacity, policy_.per_peer_refill);
        return peers_.emplace(id, ps).first->second;
    }

    DosPolicy                           policy_;
    TokenBucket                         global_;
    std::unordered_map<u32, PeerState>  peers_;
};

// ---------------------------------------------------------------------------
// confirm_invalid — the p2pool "UNSTABLE HARDWARE DETECTED" guard. p2pool, on a
// share whose PoW fails, RE-HASHES it in forced light mode; if the second hash
// differs from the first it blames local hardware, not the peer. Model that as a
// caller-supplied re-verify: given the two independent light-mode hashes of the
// same (seed, blob), the failure is CONFIRMED (=> ban-eligible) only if the two
// hashes AGREE and both still miss target. A disagreement means our own verifier
// is unstable — we must not ban the peer for our fault.
inline bool confirm_invalid(const std::uint8_t hash_a[32],
                            const std::uint8_t hash_b[32],
                            bool a_below_target, bool b_below_target) {
    for (int i = 0; i < 32; ++i) if (hash_a[i] != hash_b[i]) return false; // unstable HW
    return a_below_target && b_below_target;
}

} // namespace xmr
} // namespace c2pool

#endif // C2POOL_IMPL_XMR_XMR_CARRIER_DOS_BUDGET_HPP
