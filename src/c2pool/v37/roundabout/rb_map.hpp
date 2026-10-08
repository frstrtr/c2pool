#pragma once
// S3 — the roundabout map derivation library. PURE, deterministic, integer-
// only (u128 / U256; no floats, no clocks, no RNG, no node-local state).
//
//   Map_e = derive_map(Map_{e-1}, finalized prefix_{e-1} summary, gate)
//
// There is NO vote: every node that holds the same finalized prefix derives the
// byte-identical Map_e (map_digest pins it). Inputs are the FINALIZED prefix
// only: per-roundabout PoW-backed finalized work W_i for the period (from the
// S4 summaries) and per-identity finalized raw work h_obs(id).
//
// Trigger (H_hat = PoW-backed finalized work / time over the whole period,
// never miner count or gossip load; T = period seconds, k = 2^m):
//   split m -> m+1  iff  H_hat / k >= 2 * H_ref * (1 + delta)    (and 2k <= k_max)
//   merge m -> m-1  iff  H_hat / k <  H_ref * (1 - delta)        (and m > 0)
// One step per period. A split leaves each child at >= H_ref*(1+delta), above
// the merge line, so the hysteresis band cannot flap in one step.
//
// Missing summaries: a roundabout whose summary is absent for the period
// contributes its last seen W decayed by halving per missed period, and W = 0
// once `miss_grace` (G) consecutive periods are missed. A missing summary never
// vetoes or stalls the map.
//
// Placement (D2): every stripe (id, s < n(id)) is homed at the top m bits of
// its salt-free stripe_key. Bounded load: stripes are placed in canonical
// stripe_key ASCENDING order against cap = ceil((1+eps) * total / k); a stripe
// whose home would exceed the cap probes home ^ 1, home ^ 2, ..., home ^ (k-1)
// (XOR distance = prefix-tree distance: the sibling first, so overflow stays
// inside the parent roundabout's stripe set wherever the sibling has room)
// and takes the first that fits; if none fits it takes the least-loaded in
// that probe order (first minimum). Only non-home placements are stored
// (overrides); everything else — including every fresh identity (n = 1) — is
// recomputed from the key alone.

#include <algorithm>
#include <map>
#include <optional>
#include <utility>
#include <vector>

#include "rb_gate.hpp"
#include "rb_params.hpp"
#include "rb_stripe.hpp"

namespace c2pool::v37n::rb {

// One identity's finalized raw work over the prior map period.
struct IdWork {
    bytes32 id_key{};   // PayoutDescriptor::identity_key() / MinerIntern::key()
    u128    h_obs = 0;
};

// The finalized-prefix summary of the period that just closed (e-1).
struct PeriodInput {
    // Indexed by the PREVIOUS map's rb_index; nullopt = that roundabout's
    // summary is missing for this period.
    std::vector<std::optional<u128>> W_by_rb;
    // Per-identity finalized raw work (any order, duplicates are summed).
    std::vector<IdWork> ids;
};

struct Map {
    ChainId  chain = 0;
    MapEpoch epoch = 0;
    unsigned m = 0;                           // k = 2^m
    std::map<bytes32, std::uint32_t> n;       // id_key -> n(id), only n > 1
    std::map<bytes32, RbIndex> overrides;     // stripe_key -> rb, only != home
    // Summary-decay state per roundabout (index = rb_index of THIS map).
    std::vector<u128> last_W;                 // size k
    std::vector<std::uint8_t> missed;         // size k

    RbIndex k() const { return RbIndex(1) << m; }

    std::uint32_t n_of(const bytes32& id_key) const {
        auto it = n.find(id_key);
        return it == n.end() ? 1u : it->second;
    }
    RbIndex assign_key(const bytes32& skey) const {
        auto it = overrides.find(skey);
        return it == overrides.end() ? rb_home(skey, m) : it->second;
    }
    RbIndex assign(const bytes32& id_key, Stripe s) const {
        return assign_key(stripe_key(chain, id_key, s));
    }

    // Canonical serialization (map_digest preimage). std::map iterates keys
    // ascending, so the byte order is canonical by construction.
    std::vector<std::uint8_t> canonical_bytes() const {
        std::vector<std::uint8_t> b;
        put_tag(b, TAG_MAP);
        put_u32(b, chain);
        put_u64(b, epoch);
        put_u32(b, m);
        put_u32(b, static_cast<std::uint32_t>(n.size()));
        for (const auto& [id, nn] : n) { put_b32(b, id); put_u32(b, nn); }
        put_u32(b, static_cast<std::uint32_t>(overrides.size()));
        for (const auto& [sk, r] : overrides) { put_b32(b, sk); put_u32(b, r); }
        put_u32(b, static_cast<std::uint32_t>(last_W.size()));
        for (std::size_t i = 0; i < last_W.size(); ++i) {
            put_u128(b, last_W[i]);
            put_u8(b, i < missed.size() ? missed[i] : 0);
        }
        return b;
    }
    bytes32 digest() const { return hash_bytes(canonical_bytes()); }

    bool operator==(const Map&) const = default;
};

// The genesis (and gate-OFF) map: one roundabout, no state.
inline Map genesis_map(ChainId chain) {
    Map mp;
    mp.chain = chain;
    mp.epoch = 0;
    mp.m = 0;
    mp.last_W.assign(1, 0);
    mp.missed.assign(1, 0);
    return mp;
}

// Diagnostics of one derivation (NOT part of the map; for KATs/reporting).
struct DeriveReport {
    u128 H_total = 0;                 // Σ effective W_i over the period
    int  step = 0;                    // +1 split, -1 merge, 0 hold
    u128 total_load = 0;              // Σ stripe loads placed
    u128 cap = 0;                     // bounded-load cap
    std::vector<u128> load_home;      // per-rb load if every stripe sat at home
    std::vector<u128> load_final;     // per-rb load after the bounded-load probe
    std::size_t stripes = 0;          // stripes placed
    std::size_t overridden = 0;       // stripes placed off-home
    std::size_t unfit = 0;            // stripes that fit nowhere (least-loaded)
};

// ceil(total * (1+eps) / k) = ceil(total * (eden+enum) / (k * eden)), u128,
// split into quotient/remainder so no intermediate exceeds 2^128 for any
// total < 2^110 (every realistic period: BTC-network-scale work is < 2^90).
inline u128 load_cap(u128 total, RbIndex k, const RoundaboutGate& g) {
    const u128 den = u128(k) * g.eps_den;
    const u128 mul = u128(g.eps_den) + g.eps_num;
    const u128 q = total / den, r = total % den;
    const u128 rp = r * mul;
    return q * mul + rp / den + ((rp % den) ? 1 : 0);
}

// The trigger (+1 / -1 / 0), integer-exact via U256:
//   split iff H_total * dden >= 2 * k * Href * T * (dden + dnum)
//   merge iff H_total * dden <      k * Href * T * (dden - dnum)
inline int trigger(u128 H_total, unsigned m, const RoundaboutGate& g) {
    const u64 k = u64(1) << m;
    const U256 lhs = U256::from_u128(H_total).mul_small(g.delta_den);
    const U256 unit = U256::from_u128(ref_work_per_period(g));   // Href * T
    const U256 split_rhs = unit.mul_small(2 * k).mul_small(u64(g.delta_den) + g.delta_num);
    const U256 merge_rhs = unit.mul_small(k).mul_small(u64(g.delta_den) - g.delta_num);
    const bool can_split = (k << 1) <= g.k_max;
    if (can_split && !(lhs < split_rhs)) return +1;
    if (m > 0 && lhs < merge_rhs) return -1;
    return 0;
}

// Effective W of one roundabout after `missed` consecutive missing periods.
inline u128 decayed_W(u128 last, unsigned missed, const RoundaboutGate& g) {
    if (missed == 0) return last;
    if (missed >= g.miss_grace) return 0;
    return last >> missed;
}

// Map_e = derive_map(Map_{e-1}, finalized summary of e-1, gate). Pure.
inline Map derive_map(const Map& prev, const PeriodInput& in, const RoundaboutGate& g,
                      DeriveReport* rep = nullptr) {
    Map nx;
    nx.chain = prev.chain;
    nx.epoch = prev.epoch + 1;
    if (g.is_off() || !g.well_formed()) {          // OFF / fail-safe: k = 1
        nx.m = 0;
        nx.last_W.assign(1, 0);
        nx.missed.assign(1, 0);
        if (rep) *rep = DeriveReport{};
        return nx;
    }

    // (1) per-roundabout effective W with miss decay (never a veto).
    const RbIndex k_prev = prev.k();
    std::vector<u128> lastW(k_prev, 0);
    std::vector<std::uint8_t> miss(k_prev, 0);
    u128 H_total = 0;
    for (RbIndex i = 0; i < k_prev; ++i) {
        const u128 pl = i < prev.last_W.size() ? prev.last_W[i] : 0;
        const unsigned pm = i < prev.missed.size() ? prev.missed[i] : 0;
        const bool have = i < in.W_by_rb.size() && in.W_by_rb[i].has_value();
        if (have) { lastW[i] = *in.W_by_rb[i]; miss[i] = 0; }
        else {
            lastW[i] = pl;
            miss[i] = static_cast<std::uint8_t>(std::min<unsigned>(pm + 1, g.miss_grace));
        }
        H_total += decayed_W(lastW[i], miss[i], g);
    }

    // (2) one step per period.
    const int step = trigger(H_total, prev.m, g);
    nx.m = static_cast<unsigned>(int(prev.m) + step);
    const RbIndex k = nx.k();
    nx.last_W.assign(k, 0);
    nx.missed.assign(k, 0);
    for (RbIndex i = 0; i < k_prev; ++i) {
        if (step > 0) {            // split: children 2i, 2i+1 inherit halves
            nx.last_W[2 * i]     = lastW[i] - lastW[i] / 2;
            nx.last_W[2 * i + 1] = lastW[i] / 2;
            nx.missed[2 * i] = nx.missed[2 * i + 1] = miss[i];
        } else if (step < 0) {     // merge: parent i/2 sums, keeps the min miss
            const RbIndex p = i >> 1;
            nx.last_W[p] += lastW[i];
            nx.missed[p] = (i & 1) ? std::min(nx.missed[p], miss[i]) : miss[i];
        } else {
            nx.last_W[i] = lastW[i];
            nx.missed[i] = miss[i];
        }
    }

    // (3) aggregate identities canonically (dup ids summed, zero work dropped
    // => those ids are "fresh": n = 1, home placement, no stored state).
    std::map<bytes32, u128> agg;
    for (const auto& w : in.ids) {
        if (w.h_obs == 0) continue;
        u128& a = agg[w.id_key];
        const u128 room = ~u128(0) - a;
        a += (w.h_obs > room) ? room : w.h_obs;    // saturate, never wrap
    }

    // (4) stripes with their loads, in canonical stripe_key order.
    struct St { bytes32 skey; u128 load; };
    std::vector<St> st;
    u128 total = 0;
    for (const auto& [id, h] : agg) {
        const std::uint32_t n = n_of(h, g);
        if (n > 1) nx.n[id] = n;
        for (std::uint32_t s = 0; s < n; ++s) {
            const u128 L = stripe_load(h, n, static_cast<Stripe>(s));
            st.push_back(St{stripe_key(nx.chain, id, static_cast<Stripe>(s)), L});
            total += L;
        }
    }
    std::sort(st.begin(), st.end(), [](const St& a, const St& b) { return a.skey < b.skey; });

    // (5) bounded-load probe.
    const u128 cap = load_cap(total, k, g);
    std::vector<u128> load(k, 0), load_home(k, 0);
    std::size_t over = 0, unfit = 0;
    for (const auto& x : st) {
        const RbIndex home = rb_home(x.skey, nx.m);
        load_home[home] += x.load;
        RbIndex pick = home;
        bool fit = false;
        RbIndex best = home;
        for (RbIndex t = 0; t < k; ++t) {
            const RbIndex r = home ^ t;
            if (load[r] + x.load <= cap) { pick = r; fit = true; break; }
            if (load[r] < load[best]) best = r;
        }
        if (!fit) { pick = best; ++unfit; }
        load[pick] += x.load;
        if (pick != home) { nx.overrides[x.skey] = pick; ++over; }
    }

    if (rep) {
        rep->H_total = H_total;
        rep->step = step;
        rep->total_load = total;
        rep->cap = cap;
        rep->load_home = std::move(load_home);
        rep->load_final = std::move(load);
        rep->stripes = st.size();
        rep->overridden = over;
        rep->unfit = unfit;
    }
    return nx;
}

// max load / mean load, in parts-per-million (1'000'000 == perfectly even).
inline u64 max_over_mean_ppm(const std::vector<u128>& loads) {
    if (loads.empty()) return 0;
    u128 tot = 0, mx = 0;
    for (u128 l : loads) { tot += l; mx = std::max(mx, l); }
    if (tot == 0) return 0;
    // mx / (tot / k) * 1e6 = mx * k * 1e6 / tot
    return static_cast<u64>((mx * u128(loads.size()) * 1000000u) / tot);
}

// ── churn measurement between two consecutive maps ─────────────────────────
// For every identity present in either period: stripes s < min(n_prev,n_next)
// are COMPARED; a stripe is "moved" when its roundabout changed beyond the
// topology relation (same m: rb changed; split: new>>1 != old; merge:
// new != old>>1). Stripes that appear/disappear because n changed are counted
// separately (created/removed); they are the x2 / /2 steps of D2.
struct ChurnStats {
    std::size_t ids = 0;
    std::size_t n_changes = 0;        // identities whose n changed
    std::size_t compared = 0;         // stripes present in both maps
    std::size_t moved = 0;            // compared stripes that moved (see above)
    std::size_t created = 0;          // stripes added by n growth
    std::size_t removed = 0;          // stripes dropped by n shrink
    std::size_t renumbered = 0;       // split/merge: index changed but moved stayed in-family
    u128 moved_load = 0;              // Σ next-period load of moved stripes
    u128 total_load = 0;              // Σ next-period load of all stripes
};

inline ChurnStats churn(const Map& a, const Map& b,
                        const std::map<bytes32, u128>& next_work,
                        const std::vector<bytes32>& ids) {
    ChurnStats c;
    std::vector<bytes32> all = ids;
    std::sort(all.begin(), all.end());
    all.erase(std::unique(all.begin(), all.end()), all.end());
    c.ids = all.size();
    for (const auto& id : all) {
        const std::uint32_t na = a.n_of(id), nb = b.n_of(id);
        if (na != nb) ++c.n_changes;
        if (nb > na) c.created += nb - na; else c.removed += na - nb;
        const auto wit = next_work.find(id);
        const u128 h = wit == next_work.end() ? 0 : wit->second;
        for (std::uint32_t s = 0; s < nb; ++s) c.total_load += stripe_load(h, nb, Stripe(s));
        const std::uint32_t nm = std::min(na, nb);
        for (std::uint32_t s = 0; s < nm; ++s) {
            ++c.compared;
            const RbIndex ra = a.assign(id, Stripe(s)), rbb = b.assign(id, Stripe(s));
            bool moved;
            if (b.m == a.m)          moved = (ra != rbb);
            else if (b.m == a.m + 1) moved = ((rbb >> 1) != ra);
            else                     moved = (rbb != (ra >> 1));
            if (!moved && ra != rbb) ++c.renumbered;
            if (moved) { ++c.moved; c.moved_load += stripe_load(h, nb, Stripe(s)); }
        }
    }
    return c;
}

}  // namespace c2pool::v37n::rb
